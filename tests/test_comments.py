import json
import socket

import httpx
import pytest

from onionflash.comments import (CommentError, _compose, analysis_content, analysis_context, enrich_comments,
                                fetch_comments, merge_cached_comments, status)
from onionflash.config import DEFAULTS, load_config
from onionflash.store import Store
from onionflash.transport import FetchError, HttpClient, Response
from test_core import DATE, FakeClient, config, item, source


PROJECT = "tpo/core/tor"
ORIGIN = "https://gitlab.torproject.org"
ENDPOINT = ORIGIN + "/api/graphql"
URL = ORIGIN + "/" + PROJECT + "/-/work_items/41473"


def issue_source(**kw):
    return source(id="tor-issues", kind="gitlab_issue", gitlab_project=PROJECT,
                  url=ORIGIN + "/api/v4/projects/426/issues", **kw)


def issue(**kw):
    return item(**{"source_id": "tor-issues", "url": URL, **kw})


def note(ident="1", **kw):
    return {"id": "gid://gitlab/Note/" + ident, "body": "The operator reports that the keys remain untrusted.",
            "internal": False, "system": False, "createdAt": DATE, "updatedAt": DATE,
            "url": URL + "#note_" + ident, "author": {"username": "operator"}, **kw}


def payload(notes=None, **project_changes):
    project = {"id": "gid://gitlab/Project/426", "fullPath": PROJECT, "visibility": "public",
               "webUrl": ORIGIN + "/" + PROJECT, "issue": {
                   "iid": "41473", "confidential": False, "webUrl": URL,
                   "notes": {"nodes": notes if notes is not None else [note()],
                             "pageInfo": {"hasPreviousPage": False, "startCursor": None}}}}
    project.update(project_changes)
    return {"data": {"project": project}}


def response(data):
    return Response(200, json.dumps(data).encode(), {}, ENDPOINT)


def settings(**kw):
    return {**DEFAULTS["comments"], **kw}


def comments_config(tmp_path, **kw):
    cfg = config(tmp_path)
    cfg["sources"] = [issue_source()]
    cfg["comments"] = settings(enabled=True, **kw)
    return cfg


@pytest.mark.parametrize("location", [ENDPOINT + "/redirected", "https://other.example/api/graphql"])
def test_owned_anonymous_client_refuses_redirect_before_following(tmp_path, monkeypatch, location):
    cfg = comments_config(tmp_path)
    requests = []

    def respond(request):
        requests.append(str(request.url))
        return httpx.Response(302, headers={"Location": location})

    def client(settings):
        assert settings["max_redirects"] == 0
        return HttpClient(settings, transport=httpx.MockTransport(respond),
                          resolver=lambda host, port, *args: [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", port))])

    monkeypatch.setattr("onionflash.comments.HttpClient", client)
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(issue(), DATE)
        result = enrich_comments(cfg, store, DATE)
        assert result["failed"] == 1
    assert requests == [ENDPOINT]
    assert cfg["http"]["max_redirects"] == DEFAULTS["http"]["max_redirects"]


@pytest.mark.parametrize("visibility", [None, "private", "internal", "PUBLIC", False])
def test_unknown_or_nonpublic_project_fails_closed(visibility):
    with pytest.raises(CommentError, match="Public project"):
        fetch_comments(FakeClient([response(payload(visibility=visibility))]), issue_source(), issue(), settings())


@pytest.mark.parametrize("confidential", [None, True, 0, "false"])
def test_confidential_flag_must_be_exact_false(confidential):
    data = payload()
    data["data"]["project"]["issue"]["confidential"] = confidential
    with pytest.raises(CommentError, match="Public issue"):
        fetch_comments(FakeClient([response(data)]), issue_source(), issue(), settings())


@pytest.mark.parametrize("change", [{"fullPath": "other/project"}, {"id": "gid://gitlab/Project/99"}, {"webUrl": "https://evil.example/tpo/core/tor"}])
def test_wrong_project_identity_is_rejected(change):
    with pytest.raises(CommentError):
        fetch_comments(FakeClient([response(payload(**change))]), issue_source(), issue(), settings())


def test_internal_and_system_notes_never_cross_boundary(tmp_path):
    data = payload([note("1", internal=True, body="SECRET1"),
                    note("3", system=True, body="SECRET3"), note("5")])
    cfg = comments_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(issue(), DATE)
        result = enrich_comments(cfg, store, DATE, client=FakeClient([response(data)]))
        assert result["checked"] == 1 and result["failed"] == 0
        saved = json.loads(store.db.execute("SELECT payload FROM items").fetchone()[0])
        assert len(saved["public_comments"]) == 1
        assert saved["public_comments"][0]["id"].endswith("/5")
        assert "SECRET" not in "\n".join(store.db.iterdump())
        assert saved["published_at"] == saved["updated_at"] == DATE


@pytest.mark.parametrize("flag", ["internal", "system"])
def test_unknown_note_visibility_does_not_create_a_partial_snapshot(tmp_path, flag):
    cfg = comments_config(tmp_path)
    data = payload([note("1"), note("2", **{flag: None}, body="SECRET unknown visibility")])
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(issue(), DATE)
        before = dict(store.db.execute("SELECT * FROM items").fetchone())
        report = enrich_comments(cfg, store, DATE, client=FakeClient([response(data)]))
        assert report["failed"] == 1 and report["changed"] == 0
        assert dict(store.db.execute("SELECT * FROM items").fetchone()) == before
        assert "SECRET" not in "\n".join(store.db.iterdump())


def test_reverse_pagination_cursors_and_bounds():
    first = payload([note("2")])
    first["data"]["project"]["issue"]["notes"]["pageInfo"] = {"hasPreviousPage": True, "startCursor": "opaque"}
    client = FakeClient([response(first), response(payload([note("1")]))])
    notes, truncated = fetch_comments(client, issue_source(), issue(), settings(page_size=1))
    assert [n["id"] for n in notes] == ["gid://gitlab/Note/2", "gid://gitlab/Note/1"]
    assert not truncated
    assert client.calls[1][2]["json_body"]["variables"]["before"] == "opaque"
    assert all(c[0] == "POST" and c[1] == ENDPOINT for c in client.calls)
    client = FakeClient([response(first)])
    assert fetch_comments(client, issue_source(), issue(), settings(max_pages=1))[1]


def test_repeated_cursor_and_partial_failure_discard_entire_snapshot():
    data = payload()
    data["data"]["project"]["issue"]["notes"]["pageInfo"] = {"hasPreviousPage": True, "startCursor": "repeat"}
    with pytest.raises(CommentError, match="cursor"):
        fetch_comments(FakeClient([response(data), response(data)]), issue_source(), issue(), settings())
    with pytest.raises(FetchError):
        fetch_comments(FakeClient([response(data), FetchError("HTTP 503")]), issue_source(), issue(), settings())


def test_overlapping_note_versions_cannot_replace_new_text_with_an_older_page():
    newer = payload([note(body="Newer public evidence", updatedAt="2026-11-08T12:01:00Z")])
    newer["data"]["project"]["issue"]["notes"]["pageInfo"] = {"hasPreviousPage": True, "startCursor": "older-page"}
    older = payload([note(body="Older public evidence")])
    notes, _ = fetch_comments(FakeClient([response(newer), response(older)]), issue_source(), issue(), settings(), observed="2026-11-08T12:02:00Z")
    assert len(notes) == 1 and notes[0]["body"] == "Newer public evidence"
    with pytest.raises(CommentError, match="Conflicting"):
        fetch_comments(FakeClient([response(payload([note(body="One account"), note(body="Contradictory account")]))]), issue_source(), issue(), settings())


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(errors=[{"message": "SECRET upstream text"}]),
    lambda d: d["data"].update(project=None),
    lambda d: d["data"]["project"]["issue"].update(notes=None),
    lambda d: d["data"]["project"]["issue"]["notes"].update(pageInfo={}),
    lambda d: d["data"]["project"]["issue"]["notes"]["nodes"][0].update(url="https://evil.example/note"),
])
def test_malformed_and_partial_graphql_responses_fail_closed(mutate):
    data = payload()
    mutate(data)
    with pytest.raises((CommentError, ValueError)) as error:
        fetch_comments(FakeClient([response(data)]), issue_source(), issue(), settings())
    assert "SECRET" not in str(error.value)


def test_anonymous_transport_never_reuses_set_cookie_or_auth():
    requests = []
    data = payload()
    data["data"]["project"]["issue"]["notes"]["pageInfo"] = {"hasPreviousPage": True, "startCursor": "next"}
    def handler(request):
        requests.append(request)
        return httpx.Response(200, json=data if len(requests) == 1 else payload([]),
                              headers={"Set-Cookie": "_gitlab_session=secret; Path=/"})
    resolver = lambda *args: [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))]
    with HttpClient(DEFAULTS["http"], transport=httpx.MockTransport(handler), resolver=resolver) as client:
        fetch_comments(client, issue_source(), issue(), settings())
    assert len(requests) == 2
    for request in requests:
        assert not any(key in request.headers for key in ["cookie", "authorization", "private-token"])


def test_cache_backoff_edits_deletion_and_refresh(tmp_path):
    cfg = comments_config(tmp_path, interval_seconds=30)
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(issue(), DATE)
        assert enrich_comments(cfg, store, DATE, client=FakeClient([response(payload())]))["changed"] == 1
        original_id = store.db.execute("SELECT id FROM items").fetchone()[0]
        assert enrich_comments(cfg, store, DATE, client=FakeClient([]))["checked"] == 0
        fresh = issue(content="The original issue description was corrected.", updated_at="2026-11-08T12:00:10Z")
        merged = merge_cached_comments(store, fresh, issue_source())
        assert merged["source_content"] == fresh["content"] and len(merged["public_comments"]) == 1
        store.ingest(merged, "2026-11-08T12:00:10Z")
        stale = merge_cached_comments(store, issue(), issue_source())
        assert stale["source_content"] == fresh["content"] and stale["updated_at"] == fresh["updated_at"]
        edited = payload([note(body="The operator reports a mitigation, without confirming its effectiveness.")])
        assert enrich_comments(cfg, store, "2026-11-08T12:01:00Z", client=FakeClient([response(edited)]))["changed"] == 1
        assert enrich_comments(cfg, store, "2026-11-08T12:02:00Z", client=FakeClient([response(payload([]))]))["changed"] == 1
        row = store.db.execute("SELECT * FROM items").fetchone()
        assert row["id"] == original_id
        saved = json.loads(row["payload"])
        assert saved["public_comments"] == [] and saved["content"] == fresh["content"]
        assert saved["updated_at"] == fresh["updated_at"]
        failed = enrich_comments(cfg, store, "2026-11-08T12:03:00Z", client=FakeClient([FetchError("HTTP 503")]))
        assert failed["failed"] == 1
        assert enrich_comments(cfg, store, "2026-11-08T12:04:00Z", client=FakeClient([]))["checked"] == 0
        enrich_comments(cfg, store, "2026-11-08T12:08:00Z", client=FakeClient([FetchError("HTTP 503")]))
        assert store.db.execute("SELECT failures FROM comment_sources").fetchone()[0] == 2


def test_old_published_issues_rotate_with_bounded_cache(tmp_path):
    cfg = comments_config(tmp_path, max_issues_per_run=1, max_issues_per_source=1, max_cache_entries=1)
    with Store(cfg["storage"]["database"]) as store:
        for iid in [41473, 41474]:
            store.ingest(issue(url=URL.replace("41473", str(iid))), "2020-01-01T00:00:00Z")
        store.db.execute("UPDATE items SET story_id='published',status='done'")
        store.db.commit()
        seen = []
        class Dynamic:
            def request(self, method, endpoint, **kw):
                iid = kw["json_body"]["variables"]["iid"]
                seen.append(iid)
                data = payload([])
                data["data"]["project"]["issue"].update(iid=iid, webUrl=URL.replace("41473", iid))
                return response(data)
        enrich_comments(cfg, store, DATE, client=Dynamic())
        enrich_comments(cfg, store, DATE, client=Dynamic())
        assert sorted(seen) == ["41473", "41474"]
        assert store.db.execute("SELECT COUNT(*) FROM comment_cache").fetchone()[0] == 1


def test_context_retains_note_body_after_long_description():
    notes, _ = fetch_comments(FakeClient([response(payload())]), issue_source(), issue(), settings())
    enriched = _compose(issue(content="description " * 3000), notes, DATE)
    for limit in [1000, 14000]:
        text = analysis_content(enriched, limit)
        assert len(text) <= limit
        assert "The operator reports" in text and "@operator" in text
        assert "description" in text


def test_analysis_context_exposes_only_exact_supplied_body_prefixes():
    raw = [note(str(i), body=(f"Distinct note {i}. " * 300) + f"UNSEEN TAIL {i}") for i in range(1, 9)]
    notes, _ = fetch_comments(FakeClient([response(payload(raw))]), issue_source(), issue(),
                             settings(comment_chars=10000, total_chars=40000), observed=DATE)
    enriched = _compose(issue(content="Long description. " * 3000), notes, DATE)
    original = json.dumps(enriched, sort_keys=True)
    for limit in [1000, 14000]:
        text, supplied = analysis_context(enriched, limit)
        assert text == analysis_content(enriched, limit)
        assert len(text) <= limit and "Long description." in text
        assert 0 < len(supplied) <= len(notes)
        if limit == 1000:
            assert len(supplied) < len(notes)
        by_id = {n["id"]: n for n in notes}
        for public_note in supplied:
            full = by_id[public_note["id"]]
            assert full["body"].startswith(public_note["body"])
            assert len(public_note["body"]) < len(full["body"])
            assert public_note["body"] in text
            assert all(public_note[k] == full[k] for k in full if k != "body")
        assert "UNSEEN TAIL" not in text
    assert analysis_context(enriched, 200) == (enriched["source_content"][:200], [])
    assert json.dumps(enriched, sort_keys=True) == original


def test_note_limits_apply_before_any_persistence():
    notes, truncated = fetch_comments(FakeClient([response(payload([note(str(i), body="a" * 1000) for i in range(8)]))]),
                                     issue_source(), issue(), settings(max_comments=3, comment_chars=200, total_chars=450))
    assert len(notes) == 3 and sum(len(n["body"]) for n in notes) == 450 and truncated


def test_future_note_times_cannot_pin_story_dates():
    data = payload([note("1", updatedAt="2099-01-01T00:00:00Z", body="future edit"),
                    note("2", createdAt="2099-01-01T00:00:00Z", updatedAt="2099-01-01T00:00:00Z", body="future creation"), note("3")])
    notes, _ = fetch_comments(FakeClient([response(data)]), issue_source(), issue(), settings(), observed=DATE)
    assert [n["id"] for n in notes] == ["gid://gitlab/Note/3"]
    bad = payload([note(updatedAt="2026-11-07T00:00:00Z")])
    with pytest.raises(CommentError, match="attribution"):
        fetch_comments(FakeClient([response(bad)]), issue_source(), issue(), settings(), observed=DATE)


def test_status_is_read_only_and_contains_only_scheduling_metadata(tmp_path):
    cfg = comments_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        assert status(store) == {"watched_issues": 0, "sources": []}
        assert not store.db.execute("SELECT name FROM sqlite_master WHERE name='comment_cache'").fetchone()
        store.ingest(issue(), DATE)
        enrich_comments(cfg, store, DATE, client=FakeClient([response(payload())]))
        result = status(store)
        assert result["watched_issues"] == 1 and result["sources"][0]["cached_issues"] == 1
        assert result["sources"][0]["last_checked_at"] == DATE
        assert "body" not in json.dumps(result) and "operator" not in json.dumps(result)


def test_visibility_failure_preserves_only_previously_verified_context(tmp_path):
    cfg = comments_config(tmp_path, interval_seconds=30)
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(issue(), DATE)
        enrich_comments(cfg, store, DATE, client=FakeClient([response(payload())]))
        original = store.db.execute("SELECT payload FROM items").fetchone()[0]
        assert "Public issue comments" in json.loads(original)["content"]
        enrich_comments(cfg, store, "2026-11-08T12:01:00Z", client=FakeClient([response(payload(visibility="private"))]))
        saved = json.loads(store.db.execute("SELECT payload FROM items").fetchone()[0])
        assert saved == json.loads(original)
        retained = merge_cached_comments(store, issue(), issue_source())
        assert retained["public_comments"] == saved["public_comments"]
        assert retained["comments_checked_at"] == DATE


@pytest.mark.parametrize("status_value", ["published", "dismissed"])
def test_outage_and_recovery_do_not_requeue_or_oscillate_unchanged_comments(tmp_path, status_value):
    cfg = comments_config(tmp_path, interval_seconds=30)
    with Store(cfg["storage"]["database"]) as store:
        original = issue()
        store.ingest(original, DATE)
        enrich_comments(cfg, store, DATE, client=FakeClient([response(payload())]))
        store.db.execute("UPDATE items SET status=?,story_id='accepted-story'", (status_value,))
        store.db.commit()
        before = dict(store.db.execute("SELECT * FROM items").fetchone())
        failed = enrich_comments(cfg, store, "2026-11-08T12:01:00Z", client=FakeClient([FetchError("HTTP 503")]))
        assert failed["failed"] == 1 and failed["changed"] == 0
        assert dict(store.db.execute("SELECT * FROM items").fetchone()) == before
        merged = merge_cached_comments(store, issue(), issue_source())
        assert merged["public_comments"] == json.loads(before["payload"])["public_comments"]
        assert merged["comments_checked_at"] == DATE
        assert not store.ingest(merged, "2026-11-08T12:02:00Z")
        recovered = enrich_comments(cfg, store, "2026-11-08T12:07:00Z", client=FakeClient([response(payload())]))
        assert recovered["failed"] == recovered["changed"] == 0
        after = dict(store.db.execute("SELECT * FROM items").fetchone())
        assert after["status"] == status_value and after["content_hash"] == before["content_hash"]
        assert json.loads(after["payload"])["comments_checked_at"] == "2026-11-08T12:07:00Z"


def test_verified_snapshot_survives_scheduling_cache_eviction_but_not_identity_change(tmp_path):
    cfg = comments_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(issue(), DATE)
        enrich_comments(cfg, store, DATE, client=FakeClient([response(payload())]))
        with store.db:
            store.db.execute("DELETE FROM comment_cache")
        retained = merge_cached_comments(store, issue(), issue_source())
        assert len(retained["public_comments"]) == 1 and retained["comments_checked_at"] == DATE
        assert merge_cached_comments(store, issue(), issue_source(comments_graphql_url=ORIGIN + "/other-api")) == issue()
        with store.db:
            old = json.loads(store.db.execute("SELECT payload FROM items").fetchone()[0])
            old.pop("comments_source_key")
            store.db.execute("UPDATE items SET payload=?", (json.dumps(old),))
        assert merge_cached_comments(store, issue(), issue_source()) == issue()


def test_merge_does_not_create_scheduling_tables(tmp_path):
    cfg = comments_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(issue(), DATE)
        assert merge_cached_comments(store, issue(), issue_source()) == issue()
        assert not store.db.execute("SELECT 1 FROM sqlite_master WHERE name='comment_cache'").fetchone()


@pytest.mark.parametrize("bad_payload", ["broken JSON", '{"kind":"gitlab_issue","title":"Cold item"}',
                                        '{"kind":"gitlab_issue","title":"Missing URL","content":"body"}',
                                        json.dumps(issue(content="invalid\ud800text"))])
def test_bad_local_history_does_not_back_off_other_issues(tmp_path, bad_payload):
    cfg = comments_config(tmp_path, max_issues_per_source=4)
    with Store(cfg["storage"]["database"]) as store:
        for iid in [41473, 41474]:
            store.ingest(issue(url=URL.replace("41473", str(iid))), DATE)
        ids = [row[0] for row in store.db.execute("SELECT id FROM items ORDER BY id")]
        with store.db:
            store.db.execute("UPDATE items SET status='published',story_id='accepted'")
            store.db.execute("UPDATE items SET payload=? WHERE id=?", (bad_payload, ids[0]))
        fetched = []

        class Dynamic:
            def request(self, method, endpoint, **kwargs):
                iid = kwargs["json_body"]["variables"]["iid"]
                fetched.append(iid)
                data = payload([])
                data["data"]["project"]["issue"].update(iid=iid, webUrl=URL.replace("41473", iid))
                return response(data)

        report = enrich_comments(cfg, store, DATE, client=Dynamic())
        assert report["skipped"] == 1 and report["checked"] == 1 and report["failed"] == 0
        assert len(fetched) == 1
        assert store.db.execute("SELECT failures,next_fetch_at FROM comment_sources").fetchone()[:] == (0, None)


def test_history_cursor_does_not_advance_past_an_unattempted_tail(tmp_path):
    cfg = comments_config(tmp_path, max_issues_per_run=1, max_issues_per_source=4)
    with Store(cfg["storage"]["database"]) as store:
        for iid in [41473, 41474, 41475]:
            store.ingest(issue(url=URL.replace("41473", str(iid))), DATE)
        with store.db:
            store.db.execute("UPDATE items SET status='published',story_id='accepted'")
        ids = [row[0] for row in store.db.execute("SELECT id FROM items ORDER BY id")]
        fetched = []

        class Dynamic:
            def request(self, method, endpoint, **kwargs):
                iid = kwargs["json_body"]["variables"]["iid"]
                fetched.append(iid)
                data = payload([])
                data["data"]["project"]["issue"].update(iid=iid, webUrl=URL.replace("41473", iid))
                return response(data)

        enrich_comments(cfg, store, DATE, client=Dynamic())
        assert store.db.execute("SELECT rotation_cursor FROM comment_sources").fetchone()[0] == ids[0]
        enrich_comments(cfg, store, DATE, client=Dynamic())
        assert store.db.execute("SELECT rotation_cursor FROM comment_sources").fetchone()[0] == ids[1]
        enrich_comments(cfg, store, DATE, client=Dynamic())
        assert store.db.execute("SELECT rotation_cursor FROM comment_sources").fetchone()[0] == ids[2]
        assert len(set(fetched)) == 3


def test_history_and_recent_issues_share_a_single_slot_over_multiple_runs(tmp_path):
    cfg = comments_config(tmp_path, max_issues_per_run=1, max_issues_per_source=1)
    with Store(cfg["storage"]["database"]) as store:
        for iid in [41473, 41474]:
            store.ingest(issue(url=URL.replace("41473", str(iid))), DATE)
        with store.db:
            store.db.execute("UPDATE items SET status='published',story_id='accepted'")
        fetched = []

        class Dynamic:
            def request(self, method, endpoint, **kwargs):
                iid = kwargs["json_body"]["variables"]["iid"]
                fetched.append(iid)
                data = payload([])
                data["data"]["project"]["issue"].update(iid=iid, webUrl=URL.replace("41473", iid))
                return response(data)

        for number in range(4):
            observed = f"2026-11-08T12:0{number}:00Z"
            store.ingest(issue(url=URL.replace("41473", str(42000 + number))), observed)
            assert enrich_comments(cfg, store, observed, client=Dynamic())["checked"] == 1
            with store.db:
                store.db.execute("UPDATE items SET status='ignored' WHERE story_id IS NULL")
        assert {"41473", "41474"} <= set(fetched)
        assert sum(int(iid) >= 42000 for iid in fetched) == 2


def test_success_on_another_issue_does_not_reset_item_failure_backoff(tmp_path):
    cfg = comments_config(tmp_path, max_issues_per_run=1, max_issues_per_source=1, interval_seconds=3600)
    with Store(cfg["storage"]["database"]) as store:
        for iid in [41473, 41474]:
            store.ingest(issue(url=URL.replace("41473", str(iid))), DATE)
        with store.db:
            store.db.execute("UPDATE items SET status='published',story_id='accepted'")
        rows = store.db.execute("SELECT id,url FROM items ORDER BY id").fetchall()
        failed_id = rows[0]["id"]
        failed_iid = rows[0]["url"].rsplit("/", 1)[1]

        class Dynamic:
            def request(self, method, endpoint, **kwargs):
                iid = kwargs["json_body"]["variables"]["iid"]
                if iid == failed_iid:
                    raise FetchError("HTTP 503")
                data = payload([])
                data["data"]["project"]["issue"].update(iid=iid, webUrl=URL.replace("41473", iid))
                return response(data)

        assert enrich_comments(cfg, store, DATE, client=Dynamic())["failed"] == 1
        assert enrich_comments(cfg, store, "2026-11-08T12:05:00Z", client=Dynamic())["failed"] == 0
        assert enrich_comments(cfg, store, "2026-11-08T12:06:00Z", client=Dynamic())["failed"] == 1
        cached = store.db.execute("SELECT failures,next_fetch_at FROM comment_cache WHERE item_id=?", (failed_id,)).fetchone()
        assert tuple(cached) == (2, "2026-11-08T12:16:00Z")
        assert enrich_comments(cfg, store, "2026-11-08T12:11:00Z", client=FakeClient([]))["checked"] == 0


def test_invalid_issue_and_redirect_destinations_are_never_followed():
    client = FakeClient([])
    with pytest.raises(CommentError):
        fetch_comments(client, issue_source(), issue(url=URL.replace("tpo/core/tor", "other/project")), settings())
    assert not client.calls
    redirected = Response(200, json.dumps(payload()).encode(), {}, ORIGIN + "/other")
    with pytest.raises(CommentError, match="redirected"):
        fetch_comments(FakeClient([redirected]), issue_source(), issue(), settings())


def test_comment_config_requires_explicit_clean_identity(tmp_path):
    text = '[comments]\nenabled=true\n[[sources]]\nid="x"\nkind="gitlab_issue"\nurl="https://gitlab.torproject.org/api/v4/projects/426/issues"\ngitlab_project="tpo/core/tor"\n'
    path = tmp_path / "config.toml"
    path.write_text(text)
    assert load_config(path)["comments"]["enabled"]
    for endpoint in ['https://evil.example/api/graphql', ENDPOINT + '?private_token=secret']:
        path.write_text(text + f'comments_graphql_url="{endpoint}"\n')
        with pytest.raises(ValueError, match="anonymous"):
            load_config(path)
