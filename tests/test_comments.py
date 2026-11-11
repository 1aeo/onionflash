import json
import socket
import time
from unittest import mock

import httpx
import pytest

from onionflash import cli
from onionflash.comments import (INPUT_CHARS, NOTE_WINDOW, CommentError, _compose, _source_key, analysis_context,
                                enrich_comments, fetch_comments, merge_cached_comments, status)
from onionflash.config import DEFAULTS, load_config
from onionflash.store import Store
from onionflash.transport import FetchError, HttpClient, Response
from onionflash.util import after, digest, now_iso
from test_core import DATE, FakeClient, analysis, config, item, source


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
            "internal": False, "system": False, "createdAt": DATE,
            "url": URL + "#note_" + ident, "author": {"username": "operator"}, **kw}


def payload(notes=None, **project_changes):
    project = {"id": "gid://gitlab/Project/426", "fullPath": PROJECT, "visibility": "public",
               "webUrl": ORIGIN + "/" + PROJECT, "issue": {
                   "iid": "41473", "confidential": False, "webUrl": URL,
                   "notes": {"nodes": notes if notes is not None else [note()]}}}
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


def enrich(cfg, store, observed, client, **kw):
    """Run enrich_comments with a scripted client in place of its own anonymous one."""
    client.close = lambda: None
    with mock.patch("onionflash.comments.HttpClient", lambda settings: client):
        return enrich_comments(cfg, store, observed, **kw)


def published_issues(store, *iids):
    """Issues already tied to a published story, as (id, url) rows in id order."""
    for iid in iids:
        store.ingest(issue(url=URL.replace("41473", str(iid))), DATE)
    with store.db:
        store.db.execute("UPDATE items SET status='published',story_id='accepted'")
    return store.db.execute("SELECT id,url FROM items ORDER BY id").fetchall()


PROJECT_IDS = {PROJECT: "426", "tpo/core/arti": "647"}


class Issues:
    """Answer every requested issue with no notes; failing iids raise, missing iids answer null."""

    def __init__(self, fail=(), missing=()):
        self.fail, self.missing, self.seen = fail, missing, []

    def request(self, method, endpoint, **kwargs):
        project, iid = (kwargs["json_body"]["variables"][key] for key in ("project", "iid"))
        self.seen.append((project, iid))
        if iid in self.fail:
            raise FetchError("HTTP 503")
        data = payload([], id="gid://gitlab/Project/" + PROJECT_IDS[project], fullPath=project, webUrl=ORIGIN + "/" + project)
        data["data"]["project"]["issue"].update(iid=iid, webUrl=f"{ORIGIN}/{project}/-/work_items/{iid}")
        if iid in self.missing:
            data["data"]["project"]["issue"] = None
        return response(data)


def two_projects(tmp_path, **kw):
    """Comment settings and a store with two new issues in each of two projects."""
    cfg = comments_config(tmp_path, **kw)
    cfg["sources"].append(source(id="arti-issues", kind="gitlab_issue", gitlab_project="tpo/core/arti",
                                 url=ORIGIN + "/api/v4/projects/647/issues"))
    store = Store(cfg["storage"]["database"])
    for iid in ["1", "2"]:
        store.ingest(issue(url=URL.replace("41473", iid)), DATE)
        store.ingest(issue(source_id="arti-issues", url=f"{ORIGIN}/tpo/core/arti/-/work_items/{iid}"), DATE)
    return cfg, store


@pytest.mark.parametrize("kind", ["Note", "DiscussionNote"])
def test_supported_public_note_types_preserve_provenance(kind):
    ident = f"gid://gitlab/{kind}/123"
    notes = fetch_comments(FakeClient([response(payload([note("123", id=ident)]))]), issue_source(), issue(), settings())
    assert len(notes) == 1 and notes[0]["id"] == ident
    assert notes[0]["url"] == URL + "#note_123"


@pytest.mark.parametrize("ident", [None, 123, "gid://gitlab/OtherNote/123", "gid://gitlab/Issue/123",
                                  "gid://other/DiscussionNote/123", "gid://gitlab/DiscussionNote/123/extra",
                                  "gid://gitlab/DiscussionNote/١٢٣", "gid://gitlab/Note/123\n"])
def test_unknown_or_malformed_note_gid_types_are_rejected(ident):
    with pytest.raises(CommentError, match="identity"):
        fetch_comments(FakeClient([response(payload([note("123", id=ident)]))]), issue_source(), issue(), settings())


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
        result = enrich(cfg, store, DATE, FakeClient([response(data)]))
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
        report = enrich(cfg, store, DATE, FakeClient([response(data)]))
        assert report["failed"] == 1 and report["changed"] == 0
        assert dict(store.db.execute("SELECT * FROM items").fetchone()) == before
        assert "SECRET" not in "\n".join(store.db.iterdump())


def test_one_request_reads_the_newest_note_window():
    older, newer = note("1", createdAt="2026-11-08T11:00:00Z"), note("2", body="A later public report.")
    client = FakeClient([response(payload([older, newer])), FetchError("HTTP 503")])
    notes = fetch_comments(client, issue_source(), issue(), settings())
    assert [n["id"] for n in notes] == ["gid://gitlab/Note/2", "gid://gitlab/Note/1"]  # newest first
    [(method, endpoint, request)] = client.calls
    assert (method, endpoint) == ("POST", ENDPOINT)
    assert request["json_body"]["variables"] == {"project": PROJECT, "iid": "41473", "size": NOTE_WINDOW}
    with pytest.raises(FetchError):
        fetch_comments(client, issue_source(), issue(), settings())


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(errors=[{"message": "SECRET upstream text"}]),
    lambda d: d["data"].update(project=None),
    lambda d: d["data"]["project"]["issue"].update(notes=None),
    lambda d: d["data"]["project"]["issue"]["notes"]["nodes"][0].update(url="https://evil.example/note"),
    lambda d: d["data"]["project"]["issue"]["notes"]["nodes"][0].update(author={"username": " "}),
])
def test_malformed_and_partial_graphql_responses_fail_closed(mutate):
    data = payload()
    mutate(data)
    with pytest.raises((CommentError, ValueError)) as error:
        fetch_comments(FakeClient([response(data)]), issue_source(), issue(), settings())
    assert "SECRET" not in str(error.value)


def test_anonymous_transport_never_reuses_set_cookie_or_auth():
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(200, json=payload(), headers={"Set-Cookie": "_gitlab_session=secret; Path=/"})
    resolver = lambda *args: [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))]
    with HttpClient(DEFAULTS["http"], transport=httpx.MockTransport(handler), resolver=resolver) as client:
        for _ in range(2):
            fetch_comments(client, issue_source(), issue(), settings())
    assert len(requests) == 2
    for request in requests:
        assert not any(key in request.headers for key in ["cookie", "authorization", "private-token"])


def test_cache_backoff_edits_deletion_and_refresh(tmp_path):
    cfg = comments_config(tmp_path, interval_seconds=30)
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(issue(), DATE)
        assert enrich(cfg, store, DATE, FakeClient([response(payload())]))["changed"] == 1
        original_id = store.db.execute("SELECT id FROM items").fetchone()[0]
        assert enrich(cfg, store, DATE, FakeClient([]))["checked"] == 0
        fresh = issue(content="The original issue description was corrected.", updated_at="2026-11-08T12:00:10Z")
        merged = merge_cached_comments(store, fresh, issue_source())
        assert merged["content"] == fresh["content"] and len(merged["public_comments"]) == 1
        store.ingest(merged, "2026-11-08T12:00:10Z")
        assert not store.ingest(merge_cached_comments(store, issue(), issue_source()), "2026-11-08T12:00:20Z")
        edited = payload([note(body="The operator reports a mitigation, without confirming its effectiveness.")])
        assert enrich(cfg, store, "2026-11-08T12:01:00Z", FakeClient([response(edited)]))["changed"] == 1
        assert enrich(cfg, store, "2026-11-08T12:02:00Z", FakeClient([response(payload([]))]))["changed"] == 1
        row = store.db.execute("SELECT * FROM items").fetchone()
        assert row["id"] == original_id
        saved = json.loads(row["payload"])
        assert saved["public_comments"] == [] and saved["content"] == fresh["content"]
        assert saved["updated_at"] == fresh["updated_at"]
        failed = enrich(cfg, store, "2026-11-08T12:03:00Z", FakeClient([FetchError("HTTP 503")]))
        assert failed["failed"] == 1
        assert enrich(cfg, store, "2026-11-08T12:04:00Z", FakeClient([]))["checked"] == 0
        enrich(cfg, store, "2026-11-08T12:08:00Z", FakeClient([FetchError("HTTP 503")]))
        assert store.db.execute("SELECT failures FROM comment_sources").fetchone()[0] == 2


def test_old_published_issues_rotate_with_bounded_cache(tmp_path):
    cfg = comments_config(tmp_path, max_issues_per_run=1, max_issues_per_source=1, max_cache_entries=1)
    with Store(cfg["storage"]["database"]) as store:
        published_issues(store, 41473, 41474)
        client = Issues()
        enrich(cfg, store, DATE, client)
        enrich(cfg, store, DATE, client)
        assert sorted(iid for _, iid in client.seen) == ["41473", "41474"]
        assert store.db.execute("SELECT COUNT(*) FROM comment_cache").fetchone()[0] == 1


@pytest.mark.parametrize("status_value", ["pending", "ignored", "rejected", "dismissed"])
def test_rest_activity_requests_a_comment_check_whatever_the_status(tmp_path, status_value):
    cfg = comments_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(issue(), DATE)
        enrich(cfg, store, DATE, FakeClient([response(payload([]))]))
        with store.db:
            store.db.execute("UPDATE items SET status=?", (status_value,))
        later = after(1200, DATE)  # before the regular interval
        # An overlapping REST page repeats a checked revision and requests nothing;
        # a new note only advances updated_at, which leaves the content unchanged.
        for updated_at, notes in [(DATE, None), (after(600, DATE), payload()), (after(600, DATE), None)]:
            assert not store.ingest(merge_cached_comments(store, issue(updated_at=updated_at), issue_source(), later), later)
            client = FakeClient([response(notes)] if notes else [])
            assert enrich(cfg, store, later, client)["changed"] == bool(notes)
        assert store.db.execute("SELECT status FROM items").fetchone()[0] == "pending"


def test_rest_activity_requests_a_first_check_of_an_ignored_issue(tmp_path):
    cfg = comments_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(issue(), DATE)
        with store.db:
            store.db.execute("UPDATE items SET status='ignored'")
        assert enrich(cfg, store, DATE, FakeClient([]))["checked"] == 0  # only pending issues are new
        later = after(600, DATE)
        merge_cached_comments(store, issue(), issue_source(comments_enabled=False), later)  # an excluded source
        assert enrich(cfg, store, later, FakeClient([]))["checked"] == 0
        assert not store.ingest(merge_cached_comments(store, issue(), issue_source(), later), later)
        assert enrich(cfg, store, later, FakeClient([response(payload())]))["changed"] == 1


def test_collection_requests_comment_checks_only_while_comments_are_enabled(tmp_path, monkeypatch):
    cfg = comments_config(tmp_path)
    client = FakeClient([response(payload())])
    monkeypatch.setattr(cli, "source_due", lambda *args: True)
    monkeypatch.setattr(cli, "collect_source", lambda *args: {"items": [issue(updated_at=after(600, DATE))]})
    monkeypatch.setattr(cli, "enrich_comments", lambda *args, **kw: enrich(*args, client, **kw))
    monkeypatch.setattr(cli, "build", lambda *args: {})
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(issue(), DATE)
        with store.db:
            store.db.execute("UPDATE items SET status='ignored'")
        enrich(cfg, store, DATE, FakeClient([]))  # nothing to check yet
        cfg["comments"]["enabled"] = False
        cli.run(cfg, store)
        assert status(store)["watched_issues"] == 0
        cfg["comments"]["enabled"] = True
        assert cli.run(cfg, store)["comments"]["changed"] == 1


def test_requested_checks_go_first_pending_ones_before_others(tmp_path):
    cfg = comments_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        urls = {iid: URL.replace("41473", iid) for iid in ["1", "2", "3", "4"]}
        for url in urls.values():
            store.ingest(issue(url=url), DATE)
        client = Issues()
        enrich(cfg, store, DATE, client)
        with store.db:
            store.db.execute("UPDATE items SET status='published',story_id='story' WHERE url=?", (urls["1"],))
            store.db.execute("UPDATE items SET status='ignored' WHERE url IN (?,?)", (urls["2"], urls["4"]))
        # REST activity on ignored 2, ignored 4 and pending 3; an overlapping page then repeats 2.
        for iid, updated, seen in [("2", 600, 600), ("4", 900, 900), ("3", 1200, 1200), ("2", 600, 1500)]:
            merge_cached_comments(store, issue(url=urls[iid], updated_at=after(updated, DATE)), issue_source(), after(seen, DATE))
        cfg["comments"]["max_issues_per_source"] = 1
        for _ in range(4):  # the published issue's timer is overdue as well
            assert enrich(cfg, store, after(3600, DATE), client)["checked"] == 1
        assert [iid for _, iid in client.seen[4:]] == ["3", "2", "4", "1"]


def test_locked_story_comments_wait_for_unlock(tmp_path):
    cfg = comments_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(issue(), DATE)  # a requeued revision of a published story
        with store.db:
            store.db.execute("UPDATE items SET story_id='story'")
            store.db.execute("""INSERT INTO editorial_controls(story_id,revision,locked,retracted,notice_action,
                notice_reason,notice_at) VALUES('story',1,1,0,'correct','Reviewed.',?)""", (DATE,))
        assert enrich(cfg, store, DATE, FakeClient([]))["checked"] == 0
        merge_cached_comments(store, issue(), issue_source(), DATE)  # REST activity during the lock
        assert enrich(cfg, store, DATE, FakeClient([]))["checked"] == 0
        with store.db:
            store.db.execute("UPDATE editorial_controls SET locked=0")
        assert enrich(cfg, store, DATE, FakeClient([response(payload())]))["changed"] == 1


def test_writer_sees_fetched_notes_verbatim_beside_a_long_description():
    # Four notes at the default fetch bounds: 2,000 characters each, 8,000 in all.
    bodies = [(f"Note {n} reports a detail" + "." * 2000)[:2000] for n in range(4)]
    authors = ["operator", "maintainer"] * 2
    raw = [note(str(n), body=bodies[n], author={"username": authors[n]}, createdAt=f"2026-11-08T1{n}:00:00Z") for n in range(4)]
    notes = fetch_comments(FakeClient([response(payload(raw))]), issue_source(), issue(), settings())
    enriched = _compose(issue(content="Long description. " * 3000), notes, DATE, source_key="k")
    description, seen = analysis_context(enriched)
    assert seen == [{"author": authors[n], "created_at": f"2026-11-08T1{n}:00:00Z", "body": bodies[n]} for n in (3, 2, 1, 0)]
    assert description == enriched["content"][:INPUT_CHARS - 8000]


def test_note_limits_apply_before_any_persistence():
    notes = fetch_comments(FakeClient([response(payload([note(str(i), body="a" * 1000) for i in range(8)]))]),
                           issue_source(), issue(), settings(max_comments=3, comment_chars=200, total_chars=450))
    assert len(notes) == 3 and sum(len(n["body"]) for n in notes) == 450


def test_notes_are_dated_against_the_response_not_the_phase_start(tmp_path):
    cfg = comments_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(issue(), DATE)
        # Written after the phase began, before its request; a future note must not date a story.
        data = payload([note("1", createdAt=now_iso()), note("2", createdAt="2099-01-01T00:00:00Z")])
        assert enrich(cfg, store, DATE, FakeClient([response(data)]))["changed"] == 1
        saved = json.loads(store.db.execute("SELECT payload FROM items").fetchone()[0])
        assert [n["id"] for n in saved["public_comments"]] == ["gid://gitlab/Note/1"]


def test_a_reaction_that_moves_only_a_note_update_time_does_not_requeue(tmp_path):
    cfg = comments_config(tmp_path, interval_seconds=30)
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(issue(), DATE)
        enrich(cfg, store, DATE, FakeClient([response(payload())]))
        with store.db:
            store.db.execute("UPDATE items SET status='published',story_id='story',attempts=2,rejections=2")
        columns = "status,attempts,rejections,next_attempt_at,content_hash"
        before = tuple(store.db.execute(f"SELECT {columns} FROM items").fetchone())
        touched = payload([note(updatedAt=after(60, DATE))])
        assert enrich(cfg, store, after(120, DATE), FakeClient([response(touched)]))["changed"] == 0
        assert tuple(store.db.execute(f"SELECT {columns} FROM items").fetchone()) == before


def test_rows_written_by_earlier_releases_read_as_before_and_change_format_once(tmp_path):
    """Earlier releases kept the description in source_content, wrote note text into content and hashed only content."""
    def stored(store, value):
        store.ingest(value, DATE)
        earlier = digest({key: value.get(key) for key in ("title", "content", "kind", "product", "labels", "authority", "upstream_state")})
        with store.db:
            store.db.execute("UPDATE items SET content_hash=? WHERE url=?", (earlier, value["url"]))
        return dict(store.db.execute("SELECT * FROM items WHERE url=?", (value["url"],)).fetchone())

    description = "The operator reported a plausible compromise and said its keys must no longer be trusted. " * 4
    snapshot = {"comments_checked_at": DATE, "comments_truncated": False, "comments_source_key": _source_key(issue_source())}
    old_note = {"id": "gid://gitlab/Note/1", "url": URL + "#note_1", "title": "Public comment by @operator",
                "author": "operator", "created_at": DATE, "updated_at": DATE, "body": note()["body"]}
    composed = (description + "\n\nPublic issue comments (untrusted attributed reports, not independent verification):\n"
                f"@operator — {DATE} (edited {DATE})\n{old_note['url']}\n{old_note['body']}")
    cfg = comments_config(tmp_path, interval_seconds=30)
    with Store(cfg["storage"]["database"]) as store:
        row = stored(store, issue(content=composed, source_content=description, public_comments=[old_note], **snapshot))
        # The writer and review read the description and the note list, never the composed comment text.
        assert analysis_context(json.loads(row["payload"])) == (
            description, [{"author": "operator", "created_at": DATE, "body": old_note["body"]}])
        assert "Public issue comments" not in json.dumps(store.prepare_candidate(row, analysis(), DATE)["packet"])
        # The first verified check stores the new format and analyzes the issue once more; a repeat does not.
        assert enrich(cfg, store, after(60, DATE), FakeClient([response(payload())]))["changed"] == 1
        migrated = json.loads(store.db.execute("SELECT payload FROM items").fetchone()[0])
        assert "source_content" not in migrated and migrated["content"] == description
        assert enrich(cfg, store, after(120, DATE), FakeClient([response(payload())]))["changed"] == 0
        # An empty snapshot and an item without notes keep the hash an earlier release stored.
        empty = stored(store, issue(url=URL.replace("41473", "41474"), content=description, source_content=description,
                                    public_comments=[], **snapshot))
        assert not store.ingest(merge_cached_comments(store, issue(url=empty["url"], content=description), issue_source()), DATE)
        stored(store, item(kind="feed", url="https://example.org/news/2"))
        assert not store.ingest(item(kind="feed", url="https://example.org/news/2"), DATE)


def test_status_is_read_only_and_contains_only_scheduling_metadata(tmp_path):
    cfg = comments_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        assert status(store) == {"watched_issues": 0, "sources": []}
        assert not store.db.execute("SELECT name FROM sqlite_master WHERE name='comment_cache'").fetchone()
        store.ingest(issue(), DATE)
        enrich(cfg, store, DATE, FakeClient([response(payload())]))
        other = issue(url=URL.replace("41473", "41474"))
        store.ingest(other, DATE)
        merge_cached_comments(store, other, issue_source(), after(60, DATE))  # a requested check has not run
        result = status(store)
        assert result["watched_issues"] == 2 and result["sources"][0]["cached_issues"] == 2
        assert result["sources"][0]["last_checked_at"] == DATE
        assert "body" not in json.dumps(result) and "operator" not in json.dumps(result)


@pytest.mark.parametrize("answer", [response(payload(visibility="private")),
                                    response({**payload(), "errors": [{"message": "unavailable"}]})],
                         ids=["private", "errors"])
def test_project_failure_preserves_only_previously_verified_context(tmp_path, answer):
    cfg = comments_config(tmp_path, interval_seconds=30)
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(issue(), DATE)
        enrich(cfg, store, DATE, FakeClient([response(payload())]))
        original = store.db.execute("SELECT payload FROM items").fetchone()[0]
        assert json.loads(original)["public_comments"]
        enrich(cfg, store, "2026-11-08T12:01:00Z", FakeClient([answer]))
        assert status(store)["sources"][0]["failures"] == 1  # the whole project backs off
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
        enrich(cfg, store, DATE, FakeClient([response(payload())]))
        store.db.execute("UPDATE items SET status=?,story_id='accepted-story'", (status_value,))
        store.db.commit()
        before = dict(store.db.execute("SELECT * FROM items").fetchone())
        failed = enrich(cfg, store, "2026-11-08T12:01:00Z", FakeClient([FetchError("HTTP 503")]))
        assert failed["failed"] == 1 and failed["changed"] == 0
        assert dict(store.db.execute("SELECT * FROM items").fetchone()) == before
        merged = merge_cached_comments(store, issue(), issue_source())
        assert merged["public_comments"] == json.loads(before["payload"])["public_comments"]
        assert merged["comments_checked_at"] == DATE
        assert not store.ingest(merged, "2026-11-08T12:02:00Z")
        recovered = enrich(cfg, store, "2026-11-08T12:07:00Z", FakeClient([response(payload())]))
        assert recovered["failed"] == recovered["changed"] == 0
        after = dict(store.db.execute("SELECT * FROM items").fetchone())
        assert after["status"] == status_value and after["content_hash"] == before["content_hash"]
        assert json.loads(after["payload"])["comments_checked_at"] == "2026-11-08T12:07:00Z"


def test_verified_snapshot_survives_scheduling_cache_eviction_but_not_identity_change(tmp_path):
    cfg = comments_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(issue(), DATE)
        enrich(cfg, store, DATE, FakeClient([response(payload())]))
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
        assert merge_cached_comments(store, issue(), issue_source(), DATE) == issue()  # comments enabled, tables not yet
        assert not store.db.execute("SELECT 1 FROM sqlite_master WHERE name='comment_cache'").fetchone()


@pytest.mark.parametrize("bad_payload", ["broken JSON", '{"kind":"gitlab_issue","title":"Cold item"}',
                                        '{"kind":"gitlab_issue","title":"Missing URL","content":"body"}',
                                        json.dumps(issue(content="invalid\ud800text"))])
def test_bad_local_history_does_not_back_off_other_issues(tmp_path, bad_payload):
    cfg = comments_config(tmp_path, max_issues_per_source=4)
    with Store(cfg["storage"]["database"]) as store:
        first = published_issues(store, 41473, 41474)[0]
        with store.db:
            store.db.execute("UPDATE items SET payload=? WHERE id=?", (bad_payload, first["id"]))
        client = Issues()
        report = enrich(cfg, store, DATE, client)
        assert report["skipped"] == 1 and report["checked"] == 1 and report["failed"] == 0
        assert len(client.seen) == 1
        assert store.db.execute("SELECT failures,next_fetch_at FROM comment_sources").fetchone()[:] == (0, None)


def test_history_cursor_does_not_advance_past_an_unattempted_tail(tmp_path):
    cfg = comments_config(tmp_path, max_issues_per_run=1, max_issues_per_source=4)
    with Store(cfg["storage"]["database"]) as store:
        client = Issues()
        for row in published_issues(store, 41473, 41474, 41475):
            enrich(cfg, store, DATE, client)
            assert store.db.execute("SELECT rotation_cursor FROM comment_sources").fetchone()[0] == row["id"]
        assert len(set(client.seen)) == 3


def test_history_and_recent_issues_share_a_single_slot_over_multiple_runs(tmp_path):
    cfg = comments_config(tmp_path, max_issues_per_run=1, max_issues_per_source=1)
    with Store(cfg["storage"]["database"]) as store:
        published_issues(store, 41473, 41474, 41475, 41476)  # more history than runs, so turns must alternate
        client = Issues()
        for number in range(4):
            observed = f"2026-11-08T12:0{number}:00Z"
            store.ingest(issue(url=URL.replace("41473", str(42000 + number))), observed)
            assert enrich(cfg, store, observed, client)["checked"] == 1
            with store.db:
                store.db.execute("UPDATE items SET status='ignored' WHERE story_id IS NULL")
        assert sum(int(iid) >= 42000 for _, iid in client.seen) == 2


def test_a_requested_check_takes_no_rotation_turn(tmp_path):
    cfg = comments_config(tmp_path, max_issues_per_run=1, max_issues_per_source=1)
    with Store(cfg["storage"]["database"]) as store:
        urls = {iid: URL.replace("41473", iid) for iid in ["1", "2", "3", "4"]}
        for url in urls.values():
            store.ingest(issue(url=url), DATE)
        with store.db:
            store.db.execute("UPDATE items SET status='published',story_id='story' WHERE url IN (?,?)", (urls["1"], urls["4"]))
            store.db.execute("UPDATE items SET status='ignored' WHERE url=?", (urls["2"],))
        client = Issues()
        assert enrich(cfg, store, DATE, client)["checked"] == 1  # a published issue's turn
        merge_cached_comments(store, issue(url=urls["2"], updated_at=after(600, DATE)), issue_source(), after(600, DATE))
        for seconds in (700, 800):  # the request takes run 2; the next rotation turn is still recent 3's
            assert enrich(cfg, store, after(seconds, DATE), client)["checked"] == 1
        fetched = [iid for _, iid in client.seen]
        assert fetched[0] in {"1", "4"} and fetched[1:] == ["2", "3"]


def test_success_on_another_issue_does_not_reset_item_failure_backoff(tmp_path):
    cfg = comments_config(tmp_path, max_issues_per_run=1, max_issues_per_source=1, interval_seconds=3600)
    with Store(cfg["storage"]["database"]) as store:
        rows = published_issues(store, 41473, 41474)
        failed_id = rows[0]["id"]
        client = Issues(fail={rows[0]["url"].rsplit("/", 1)[1]})
        assert enrich(cfg, store, DATE, client)["failed"] == 1
        assert enrich(cfg, store, "2026-11-08T12:05:00Z", client)["failed"] == 0
        assert enrich(cfg, store, "2026-11-08T12:06:00Z", client)["failed"] == 1
        cached = store.db.execute("SELECT failures,next_fetch_at FROM comment_cache WHERE item_id=?", (failed_id,)).fetchone()
        assert tuple(cached) == (2, "2026-11-08T12:16:00Z")
        # REST activity requests a check but keeps the failing issue's backoff.
        merge_cached_comments(store, issue(url=rows[0]["url"], updated_at=after(600, DATE)), issue_source(), after(660, DATE))
        assert enrich(cfg, store, "2026-11-08T12:11:00Z", FakeClient([]))["checked"] == 0


def test_an_issue_that_no_longer_verifies_backs_off_alone(tmp_path):
    cfg = comments_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        for iid in ["1", "2"]:
            store.ingest(issue(url=URL.replace("41473", iid)), DATE)
        with store.db:  # the deleted or hidden issue is checked first
            store.db.execute("UPDATE items SET priority_score=priority_score+1 WHERE url=?", (URL.replace("41473", "1"),))
        client = Issues(missing={"1"})
        assert enrich(cfg, store, DATE, client)["failed"] == 1
        assert [iid for _, iid in client.seen] == ["1", "2"]
        assert status(store)["sources"][0]["failures"] == 0


def test_retries_of_an_issue_that_never_verifies_end_when_its_metadata_expires(tmp_path):
    cfg = comments_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(issue(), DATE)
        with store.db:
            store.db.execute("UPDATE items SET status='ignored'")
        enrich(cfg, store, DATE, FakeClient([]))
        merge_cached_comments(store, issue(), issue_source(), DATE)  # REST activity, then every check fails
        client = Issues(missing={"41473"})
        for seconds in [0, 60, 31 * 86400, 32 * 86400]:  # checked, in backoff, retried, expired
            enrich(cfg, store, after(seconds, DATE), client)
        assert len(client.seen) == 2


def test_an_outage_costs_one_request_per_project(tmp_path):
    cfg, store = two_projects(tmp_path)
    with store:
        client = FakeClient([FetchError("HTTP 503")] * 4)
        assert enrich(cfg, store, DATE, client)["failed"] == len(client.calls) == 2
        assert [s["failures"] for s in status(store)["sources"]] == [1, 1]


def test_projects_take_turns_and_removed_projects_leave_status(tmp_path):
    cfg, store = two_projects(tmp_path, max_issues_per_run=1)
    with store:
        client = Issues()
        for _ in range(3):
            enrich(cfg, store, DATE, client)
        assert [project for project, _ in client.seen] == ["tpo/core/arti", PROJECT, "tpo/core/arti"]
        for kept in [["tor-issues"], []]:
            cfg["sources"] = cfg["sources"][:len(kept)]
            enrich(cfg, store, DATE, client)
            assert [s["id"] for s in status(store)["sources"]] == kept


def test_another_project_does_not_take_a_requested_check(tmp_path):
    cfg, store = two_projects(tmp_path)
    with store:
        with store.db:
            store.db.execute("UPDATE items SET status='ignored'")
        enrich(cfg, store, DATE, FakeClient([]))  # nothing to check yet
        merge_cached_comments(store, issue(url=URL.replace("41473", "1")), issue_source(), DATE)
        client = Issues()
        enrich(cfg, store, DATE, client)  # the other project's turn comes first
        assert client.seen == [(PROJECT, "1")]


def test_spent_deadline_stops_before_any_request(tmp_path):
    cfg = comments_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(issue(), DATE)
        report = enrich(cfg, store, DATE, FakeClient([]), deadline=time.monotonic() - 1)
        assert report["budget_reached"] and report["failed"] == 0


def test_an_issue_outside_its_project_is_never_requested():
    client = FakeClient([])
    with pytest.raises(CommentError):
        fetch_comments(client, issue_source(), issue(url=URL.replace("tpo/core/tor", "other/project")), settings())
    assert not client.calls


def test_comment_config_requires_explicit_clean_identity(tmp_path):
    text = '[comments]\nenabled=true\n[[sources]]\nid="x"\nkind="gitlab_issue"\nurl="https://gitlab.torproject.org/api/v4/projects/426/issues"\ngitlab_project="tpo/core/tor"\n'
    path = tmp_path / "config.toml"
    path.write_text(text)
    assert load_config(path)["comments"]["enabled"]
    for endpoint in ['https://evil.example/api/graphql', ENDPOINT + '?private_token=secret']:
        path.write_text(text + f'comments_graphql_url="{endpoint}"\n')
        with pytest.raises(ValueError, match="anonymous"):
            load_config(path)
