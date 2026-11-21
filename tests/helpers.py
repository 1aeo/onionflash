"""Shared builders, scripted doubles, and receipt helpers for the test suite."""

import copy
from datetime import timedelta
import importlib.util
import json
from pathlib import Path
import socket
from unittest.mock import patch

import pytest

from onionflash import candidate as candidate_mod, cli, comments, editorial, review, review_gate
from onionflash.analyze import AnalysisError, Analyzer, cache_key, tag_notice, tag_update
from onionflash.config import DEFAULTS, load_config
from onionflash.schema import CATEGORIES, STATES
from onionflash.store import Store, item_identity
from onionflash.transport import FetchError, Response
from onionflash.util import MAX_SAVED_DEPTH, digest, format_utc, parse_utc

ROOT = Path(__file__).resolve().parents[1]
DATE = "2026-11-08T12:00:00Z"
LATER = "2026-11-10T12:00:00Z"
REPAIRED = "A revised report describes the source's concerns."
TOR_WORK_ITEM_URL = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41473"
DOCTOR_LIST_URL = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-consensus-health@lists.torproject.org/"
DOCTOR_FEED_URL = DOCTOR_LIST_URL + "feed/"
DOCTOR_OK_LINE = "NOTICE: The following directory authorities are not reporting bandwidth scanner results: faravahar"
NON_TAG_STATES = [value for value in STATES if value != "tagged"]
NON_RELEASE_CATEGORIES = [value for value in CATEGORIES if value != "release"]
DAMAGE = ["invalid-json", "non-object", "invalid-utf8", "deep", "nested",
          "surrogate", "escaped-surrogate", "nan", "bom", "utf-16"]
SITE_CONFIG = {
    "site": {
        "title": "Onion Flash",
        "base_url": "https://example.com/onionflash/",
        "repository_url": "https://github.com/1aeo/onionflash",
    }
}
STORY = {
    "id": "0123456789abcdef01234567",
    "title": "Tor publishes a release",
    "summary": "A new release includes improvements for relay operators.",
    "why_it_matters": "Operators can read the release notes to assess the changes.",
    "category": "release",
    "products": ["tor"],
    "priority": "normal",
    "confidence": "confirmed",
    "state": "released",
    "tags": ["release"],
    "sources": [{"url": "https://blog.torproject.org/example/", "title": "Release announcement"}],
    "published_at": "2026-11-08T12:00:00Z",
    "updated_at": "2026-11-08T14:00:00Z",
}


def public_dns(host, port, *args):
    """Resolve any hostname to a public IPv4 socket tuple for offline tests."""
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", port))]


def raise_once(exc):
    """Return a callable raising `exc` regardless of positional or keyword arguments."""
    def _fail(*_args, **_kwargs):
        raise exc
    return _fail


def source(**kw):
    """Build a synthetic feed source configuration dictionary."""
    return {
        "id": "test", "name": "Test source", "url": "https://example.org/feed.xml",
        "kind": "feed", "fallback_urls": [], "authority": "community", "product": "network",
        "enabled": True, "interval_seconds": 300, "max_pages": 2, "max_items": 100, **kw,
    }


def gitlab_source(**kw):
    """Build the standard Tor GitLab issues source configuration."""
    return source(**{
        "id": "tor-issues", "name": "Tor issues", "kind": "gitlab_issue", "gitlab_project": "tpo/core/tor",
        "url": "https://gitlab.torproject.org/api/v4/projects/426/issues",
        "authority": "development", "product": "tor", **kw,
    })


def item(**kw):
    """Build a normalized source item dictionary with security-issue defaults."""
    return {
        "id": "example", "source_id": "test", "url": "https://example.org/news/1",
        "title": "A reported security incident",
        "content": "The operator reported a plausible compromise and said its keys must no longer be trusted.",
        "published_at": DATE, "updated_at": DATE, "kind": "gitlab_issue",
        "product": "tor", "authority": "development", "labels": ["Security"], **kw,
    }


def tag(**overrides):
    """Build a normalized GitLab tag item dictionary."""
    return {
        "id": "tag-id", "source_id": "tor-tags",
        "url": "https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-0.4.9.16",
        "title": "tor-0.4.9.16", "content": "Tor 0.4.9.16",
        "published_at": "2026-11-04T13:55:43Z", "updated_at": "2026-11-04T13:55:43Z",
        "kind": "tag", "product": "tor", "authority": "official",
        "labels": [], "upstream_state": "", **overrides,
    }


def make_note(
    ident=1,
    body="The operator reports that the keys remain untrusted.",
    *,
    author="operator",
    created_at=DATE,
    url=TOR_WORK_ITEM_URL,
    kind="Note",
    note_id=None,
    title=None,
    **kw,
):
    """Build a public comment dictionary matching GitLab note provenance."""
    full_url = url if "#note_" in url else f"{url}#note_{ident}"
    gid = note_id if note_id is not None else f"gid://gitlab/{kind}/{ident}"
    return {
        "id": gid,
        "url": full_url,
        "title": title if title is not None else f"Public comment by @{author}",
        "author": author,
        "created_at": created_at,
        "body": body,
        **kw,
    }


def gql_note(
    ident="1",
    body="The operator reports that the keys remain untrusted.",
    *,
    author="operator",
    created_at=DATE,
    iid="41473",
    project="tpo/core/tor",
    url=None,
    **kw,
):
    """Build a raw GitLab GraphQL issue-note node."""
    base = url or f"https://gitlab.torproject.org/{project}/-/work_items/{iid}"
    return {
        "id": f"gid://gitlab/Note/{ident}",
        "body": body,
        "internal": False,
        "system": False,
        "createdAt": created_at,
        "url": f"{base}#note_{ident}",
        "author": {"username": author},
        **kw,
    }


def gql_notes_response(
    notes=None,
    *,
    project="tpo/core/tor",
    project_id="426",
    iid="41473",
    issue_url=None,
    confidential=False,
    as_dict=False,
    **project_changes,
):
    """Build a GitLab GraphQL project issue-notes Response (or raw dict when `as_dict=True`)."""
    origin = "https://gitlab.torproject.org"
    web_url = issue_url or f"{origin}/{project}/-/work_items/{iid}"
    proj = {
        "id": f"gid://gitlab/Project/{project_id}",
        "fullPath": project,
        "visibility": "public",
        "webUrl": f"{origin}/{project}",
        "issue": {
            "iid": str(iid),
            "confidential": confidential,
            "webUrl": web_url,
            "notes": {"nodes": [gql_note(iid=iid, project=project, url=web_url)] if notes is None else notes},
        },
        **project_changes,
    }
    data = {"data": {"project": proj}}
    return data if as_dict else Response(200, json.dumps(data).encode(), {}, f"{origin}/api/graphql")


def enrich_with_client(cfg, store, client, now=DATE, **kw):
    """Run `comments.enrich_comments` with `client` patched in as `HttpClient`."""
    with patch("onionflash.comments.HttpClient", lambda _settings: client):
        return comments.enrich_comments(cfg, store, now, **kw)


def list_rss(*entries, list_name="tor-dev"):
    """Build a HyperKitty RSS 2.0 XML payload from author XML fragments or item dicts."""
    items = []
    for n, entry in enumerate(entries, 1):
        if isinstance(entry, str):
            title, link, desc, extra = f"Message {n}", f"https://lists.torproject.org/m/{n}/", "Body", entry
        else:
            title = entry.get("title", f"Message {n}")
            link = entry.get("link", f"https://lists.torproject.org/m/{n}/")
            desc = entry.get("description", "Body")
            extra = f"<author>{entry['author']}</author>" if "author" in entry else entry.get("xml", "")
        items.append(
            f"<item><title>{title}</title><link>{link}</link>"
            f"<description>{desc}</description>{extra}<pubDate>Sun, 08 Nov 2026 12:00:00 GMT</pubDate></item>"
        )
    return (
        '<?xml version="1.0" encoding="utf-8"?><rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/" '
        'xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd"><channel>'
        f"<title>{list_name}</title><link>https://lists.torproject.org/</link><description>List</description>"
        f'{"".join(items)}</channel></rss>'
    ).encode()


def analysis(**kw):
    """Build a valid story-mode writer draft dictionary."""
    return {
        "publish": True,
        "title": "Operator reports possible compromise",
        "summary": "The operator reported a plausible compromise and stopped trusting the affected keys.",
        "why_it_matters": "The report concerns directory authority trust.",
        "category": "security", "priority": "high", "confidence": "reported", "state": "developing",
        "products": ["tor"], "tags": ["security"],
        "evidence": ["The operator reported a plausible compromise"], **kw,
    }


def update_analysis(**overrides):
    """Build a valid update-mode writer draft dictionary."""
    return {
        "publish": True,
        "update": "A material upstream follow-up was posted.",
        "confidence": "reported",
        "state": "developing",
        "evidence": ["The operator reports that old directory-authority keys cannot be trusted"],
        **overrides,
    }


def make_config(tmp_path, **overrides):
    """Build a full configuration dictionary rooted in `tmp_path`."""
    base = Path(tmp_path)
    result = copy.deepcopy(DEFAULTS)
    result["storage"]["database"] = str(base / "state.sqlite3")
    result["storage"]["output_dir"] = str(base / "public")
    result["sources"] = [source()]
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key].update(value)
        else:
            result[key] = value
    return result


def write_toml(tmp_path, extra="", *, name="config.toml", with_source=True):
    """Write a minimal TOML configuration file into `tmp_path` and return its Path."""
    path = Path(tmp_path) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    text = '[storage]\ndatabase = "state.sqlite3"\noutput_dir = "public"\n'
    if extra:
        text += extra.rstrip("\n") + "\n"
    if with_source:
        text += '[[sources]]\nid = "test"\nurl = "https://example.org/feed.xml"\n'
    path.write_text(text, encoding="utf-8")
    return path


def invoke_cli(capsys, *args, expected=0):
    """Run `cli.main` with stringified arguments, assert exit status, and parse JSON output."""
    assert cli.main(list(map(str, args))) == expected
    output = capsys.readouterr()
    return json.loads(output.out) if output.out else {"error": output.err}


def damaged(document, kind):
    """Corrupt a serialized JSON `document` into the requested `DAMAGE` byte sequence."""
    if kind == "surrogate":
        return json.dumps({**json.loads(document), "\ud800": ""}, ensure_ascii=False).encode("utf-8", "surrogatepass")
    if kind == "escaped-surrogate":
        return json.dumps({**json.loads(document), "\ud800": ""}).encode()
    return {
        "invalid-json": b"{", "non-object": b"[1]", "invalid-utf8": b'{"\xff"', "deep": b"[" * 100000,
        "nested": b'{"x":' + b"[" * MAX_SAVED_DEPTH + b"]" * MAX_SAVED_DEPTH + b"}",
        "nan": b'{"x":NaN}', "bom": b"\xef\xbb\xbf" + document.encode(), "utf-16": document.encode("utf-16"),
    }[kind]


def damage_item(db, item_id, kind):
    """Corrupt or strip the stored `payload` column of `item_id` in `items`."""
    expression = {
        "blob": "CAST(payload AS BLOB)",
        "undated": "json_remove(payload,'$.updated_at')",
        "compacted": "json_remove(payload,'$.content')",
    }.get(kind)
    if expression:
        db.execute(f"UPDATE items SET payload={expression} WHERE id=?", (item_id,))
    else:
        document = db.execute("SELECT payload FROM items WHERE id=?", (item_id,)).fetchone()[0]
        db.execute("UPDATE items SET payload=CAST(? AS TEXT) WHERE id=?", (damaged(document, kind), item_id))
    db.commit()


def response(body, headers=None, status=200, url="https://example.org/feed.xml"):
    """Construct a synthetic `Response` object."""
    return Response(status, body, headers or {}, url)


def completion(result, finish_reason: str = "stop") -> Response:
    """Wrap any JSON-serializable `result` in an OpenAI chat-completions `Response`."""
    body = {"choices": [{"finish_reason": finish_reason, "message": {"content": json.dumps(result)}}]}
    return Response(200, json.dumps(body).encode(), {}, "https://llm.example/v1/chat/completions")


class _ClientBase:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def close(self):
        """No-op close hook matching `HttpClient`."""

    @classmethod
    def factory(cls, *responses):
        """Return a factory callable producing a shared client instance."""
        instance = cls(*responses)
        return lambda *_a, **_kw: instance


class FakeClient(_ClientBase):
    """Scripted HTTP client returning canned responses or raising queued exceptions."""

    def __init__(self, values):
        self.values = iter(values)
        self.calls = []

    def request(self, method, url, **kwargs):
        """Record the HTTP call and return or raise the next scripted value."""
        self.calls.append((method, url, kwargs))
        result = next(self.values)
        if isinstance(result, BaseException):
            raise result
        return result


class FakeLLM(_ClientBase):
    """Scripted LLM HTTP client recording `(url, json_body)` requests."""

    def __init__(self, *responses, before=None):
        self.responses, self.requests, self.before = list(responses), [], before

    @property
    def bodies(self):
        """Return recorded request JSON payloads without endpoint URLs."""
        return [body for _, body in self.requests]

    def request(self, method, url, headers=None, json_body=None):
        """Record `(url, json_body)` and return the next Response (auto-wrapping raw JSON values)."""
        if self.before:
            self.before()
        self.requests.append((url, copy.deepcopy(json_body)))
        result = self.responses.pop(0)
        if callable(result) and not isinstance(result, type):
            result = result(method, url, headers=headers, json_body=json_body)
        if isinstance(result, BaseException):
            raise result
        return result if isinstance(result, Response) else completion(result)


def wire_reviewer(cfg, *replies, before=None, monkeypatch=None):
    """Instantiate a real `review.Reviewer` backed by `FakeLLM` replies."""
    if monkeypatch is not None:
        monkeypatch.setenv(cfg["llm"]["api_key_env"], "unit-test-secret")
    result = review.Reviewer(cfg)
    result.client = FakeLLM(*replies, before=before)
    return result


def wire_analyzer(monkeypatch, *replies, cfg=None, fallbacks=()):
    """Instantiate a real `Analyzer` backed by `FakeLLM` replies."""
    settings = copy.deepcopy(cfg or DEFAULTS)
    settings["llm"].update(base_url="https://llm.example/v1", fallback_base_urls=list(fallbacks))
    monkeypatch.setenv(settings["llm"]["api_key_env"], "test-key")
    result = Analyzer(settings)
    result.client = FakeLLM(*replies)
    return result


def verdict(action="approve", *, repair=None, criterion="operational_advice", ref="S1",
            update=False, same_story=None, reason=None, criteria=None):
    """Build a rubric-complete wire review reply dictionary."""
    default_fail = "The source does not support this claim."
    checks = {name: {"reason": "Supported by the supplied source.", "source_refs": [ref], "outcome": "pass"}
              for name in review.CRITERIA}
    if isinstance(criteria, dict) or criteria is None:
        if action != "approve":
            checks[criterion].update(reason=reason or default_fail, outcome="fail")
        elif reason is not None:
            checks[criterion]["reason"] = reason
        for name, patch_val in (criteria or {}).items():
            checks[name].update(patch_val)
    else:
        for index, name in enumerate(criteria):
            checks[name].update(reason=(reason or default_fail) if index == 0 else default_fail, outcome="fail")
    fields = review.UPDATE_EDITABLE if update else review.EDITABLE
    wire = None if repair is None else {key: repair.get(key) for key in fields}
    return {"criteria": checks, "verdict": action, "same_story": same_story, "repair": wire}


def inconsistent(repair=None, *, action="revise", update=False, same_story=None):
    """Build a review reply whose passing criteria contradict its non-approve verdict."""
    reply = verdict(update=update, same_story=same_story)
    reply["verdict"] = action
    reply["criteria"]["source_support"]["reason"] = "UNTRUSTED_PREVIOUS_CRITERIA_SENTINEL"
    if action == "revise":
        edits = ({"update": REPAIRED} if update else {"summary": REPAIRED}) if repair is None else repair
        fields = review.UPDATE_EDITABLE if update else review.EDITABLE
        reply["repair"] = {key: edits.get(key) for key in fields}
    return reply


def approved_result(packet, *, update=False, coverage=None):
    """Validate an approving review verdict against `packet`."""
    return review.validate_review(verdict(update=update), packet, update=update, coverage=coverage)


def _meter_request(on_request, produce=lambda: None):
    if on_request is not None:
        on_request(1)
    result = produce()
    if hasattr(on_request, "response_received"):
        on_request.response_received()
    return result


def _coerce_update_draft(incoming, draft, prior, *, explicit=True):
    if prior is None or "update" in draft:
        return copy.deepcopy(draft)
    if incoming.get("kind") == "tag":
        return tag_update(incoming, prior)
    if not explicit:
        return update_analysis(confidence=prior["confidence"], state=prior["state"], evidence=draft["evidence"])
    return update_analysis(
        update=(draft.get("summary") or draft.get("title"))[:300],
        confidence=draft.get("confidence", prior["confidence"]),
        state=draft.get("state", prior["state"]),
        evidence=draft["evidence"],
    )


class CallLog(list):
    """List recording calls while supporting integer addition on call counts."""

    def __add__(self, other):
        return len(self) + other if isinstance(other, int) else CallLog(super().__add__(other))

    def __radd__(self, other):
        return other + len(self) if isinstance(other, int) else NotImplemented


class Writer(_ClientBase):
    """Configurable double for Analyzer supporting constant drafts or callables."""

    clears = 0

    def __init__(self, response=None):
        self._explicit = response is not None
        self._step = analysis() if response is None else response
        self.calls = CallLog()

    def analyze(self, incoming, prior=None):
        """Record `incoming` and return the scripted story or update draft."""
        self.calls.append(copy.deepcopy(incoming))
        if callable(self._step):
            try:
                return self._step(incoming, prior)
            except TypeError:
                return self._step(incoming)
        return _coerce_update_draft(incoming, self._step, prior, explicit=self._explicit)


class Reviewer(_ClientBase):
    """Returns validated verdicts, recording exact calls, coverages, and issues."""

    def __init__(self, *responses):
        self.responses, self.calls, self.coverages, self.issues = list(responses), CallLog(), [], []
        self._repeat = len(responses) == 1 and callable(responses[0])
        if len(responses) == 1 and isinstance(responses[0], dict) and responses[0].get("verdict") == "approve":
            self.responses.append(verdict())

    def review(self, candidate, packet, *, coverage=None, verification=False, issue=None, update=False, on_request=None):
        """Meter, record, and validate the next scripted review response."""
        def _raw():
            self.calls.append((copy.deepcopy(candidate), copy.deepcopy(packet), verification))
            self.coverages.append(copy.deepcopy(coverage))
            self.issues.append(issue)
            reply = self.responses[0] if self._repeat else self.responses.pop(0)
            if isinstance(reply, Exception):
                raise reply
            if callable(reply):
                return reply(candidate, packet, coverage=coverage, verification=verification, issue=issue, update=update)
            return copy.deepcopy(reply)

        return review.validate_review(_meter_request(on_request, _raw), packet, update=update, coverage=coverage)


class ApprovingReviewer(_ClientBase):
    """Context-manager reviewer approving every call with valid rubric outputs."""

    calls = 0

    def __init__(self, *args, **kwargs):
        pass

    def review(self, candidate, packet, *, coverage=None, verification=False, issue=None, update=False, on_request=None):
        """Approve `candidate` against `packet` after metering one request."""
        _meter_request(on_request)
        return approved_result(packet, update=update, coverage=coverage)


def insert_approval(store, prepared=None, candidate=None, *, key=None, candidate_hash=None, source_hash=None,
                    policy="test-policy", binding_hash=None, result=None, record=None, created_at=None,
                    last_used_at=None):
    """Insert or replace a receipt in review_approvals without 9-column raw SQL boilerplate."""
    if prepared is not None:
        candidate = candidate or prepared["candidate"]
        is_update = prepared.get("mode") == "update"
        result = result or approved_result(prepared["packet"], update=is_update, coverage=prepared.get("coverage"))
        key = key or review_gate._approval_key(candidate, prepared, policy)
        candidate_hash = candidate_hash or digest(candidate)
        source_hash = source_hash or prepared["source_hash"]
        binding_hash = binding_hash or prepared["binding_hash"]
        created_at = created_at or prepared["observed"]
        last_used_at = last_used_at or created_at
        if record is None:
            ctx = {"source_hash": source_hash, "coverage_hash": prepared["coverage_hash"],
                   "binding_hash": binding_hash, "policy_hash": policy}
            if result["verdict"] == "skip":
                reviews = [{"stage": "review", "candidate_hash": candidate_hash, "request": 1, "result": result, **ctx}]
            else:
                if is_update:
                    changes = {k: candidate[k] for k in review.UPDATE_EDITABLE if k != "update"
                               and candidate[k] != prepared["candidate"][k]}
                    if candidate["updates"][-1]["text"] != prepared["candidate"]["updates"][-1]["text"]:
                        changes["update"] = candidate["updates"][-1]["text"]
                else:
                    changes = {k: candidate[k] for k in review.EDITABLE if candidate[k] != prepared["candidate"][k]}
                first = review.validate_review(verdict("revise", repair=changes, update=is_update) if changes else verdict(update=is_update),
                                               prepared["packet"], update=is_update, coverage=prepared.get("coverage"))
                reviews = [{"stage": "review", "candidate_hash": digest(prepared["candidate"]), "request": 1, "result": first, **ctx},
                           {"stage": "verification", "candidate_hash": candidate_hash, "request": 2, "result": result, **ctx}]
            state = review_gate.initial_review_state()
            state["request_budget"]["reserved"] = len(reviews)
            record = {"candidate": candidate, "packet": prepared["packet"], "coverage": prepared["coverage"], "reviews": reviews,
                      "policy_hash": policy, "approval_key": key, **state,
                      "outcome": "skipped" if result.get("verdict") == "skip" else "approved"}
    stamp = created_at or DATE
    with store.db:
        store.db.execute(
            """INSERT OR REPLACE INTO review_approvals (key,candidate_hash,source_hash,policy_hash,
               binding_hash,result_json,review_record_json,created_at,last_used_at) VALUES(?,?,?,?,?,?,?,?,?)""",
            (key, candidate_hash or "", source_hash or "", policy, binding_hash or "",
             json.dumps(result if result is not None else verdict()),
             json.dumps(record if record is not None else {}), stamp, last_used_at or stamp),
        )
    return {"approval_key": key, "policy_hash": policy}


def finish_reviewed(store, row, result, key, observed, *, decision="approve"):
    """Prepare, approve, and commit `row` through the store boundary."""
    parsed = json.loads(row["payload"])
    if (existing := candidate_mod.existing_story(store.db, row)) is not None:
        if candidate_mod.relation(json.loads(existing["payload"]), parsed, store.db) == "citation" and decision == "approve":
            return store.add_citation(row, existing["id"], observed)
    result = _coerce_update_draft(parsed, result, candidate_mod.update_target(store.db, row))
    prepared = store.prepare_candidate(row, result, observed)
    is_update = prepared.get("mode") == "update"
    reply = verdict("skip", criterion="news_value", update=is_update) if decision == "skip" else None
    receipt = {} if prepared["locked"] else insert_approval(store, prepared, result=reply)
    return store.commit_candidate(prepared, prepared["candidate"], key, observed, decision=decision, **receipt)


def item_row(store, item_or_id):
    """Return the stored `items` row dictionary for `item_or_id`."""
    target = item_or_id["id"] if isinstance(item_or_id, dict) else item_or_id
    row = store.db.execute("SELECT * FROM items WHERE id=?", (target,)).fetchone()
    return dict(row) if row else None


def story_payload(store, story_id):
    """Return the decoded `stories.payload` dictionary for `story_id`."""
    return json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (story_id,)).fetchone()[0])


def queued_row(store, item_or_id, ready=LATER):
    """Look up a pending queue row by item dictionary, item ID, or URL without re-ingesting."""
    if isinstance(item_or_id, dict):
        target_id = item_or_id["id"] if "content_hash" in item_or_id else digest(item_identity(item_or_id))[:24]
        target_url = item_or_id.get("url")
    else:
        target_id = target_url = item_or_id
    for row in store.pending(500, ready):
        if row["id"] == target_id or (target_url and row.get("url") == target_url):
            return row
    raise AssertionError(f"Expected item {target_id} is not pending")


def mapped_item(store, row, story_id):
    """Associate a pending `items` row with `story_id` after same-story routing."""
    with store.db:
        store.db.execute("UPDATE items SET story_id=? WHERE id=?", (story_id, row["id"]))
    return {**row, "story_id": story_id}


def pending(store, incoming=None, at=DATE, *, ready=None, target=None):
    """Ingest `incoming` at `at` and return its pending queue row."""
    target_item = incoming or item()
    store.ingest(target_item, at)
    row = queued_row(store, target_item, ready or max(at, LATER))
    return mapped_item(store, row, target) if target is not None else row


def seed_story(store, incoming=None, draft=None, *, key=None, at=DATE, target=None):
    """Ingest, review, and commit `incoming`, returning the stored story dictionary."""
    row = pending(store, incoming, at=at, ready=at, target=target)
    outcome = finish_reviewed(store, row, draft or analysis(), key or cache_key(row, DEFAULTS["llm"]), at)
    return story_payload(store, outcome["story_id"])


def seed_source_story(store, incoming, draft=None, *, at=DATE):
    """Seed a source-shaped published story (including literal tag notices) at `at`."""
    if draft is None:
        if incoming.get("kind") == "tag":
            draft = tag_notice(incoming)
        else:
            text = incoming["content"]
            draft = analysis(title=incoming["title"][:120], summary=text[:220] or incoming["title"],
                             evidence=[text[:80] or incoming["title"]])
    return seed_story(store, incoming, draft, at=at)


def seed_legacy(store, incoming=None, result=None):
    """Insert a legacy story row directly into `stories` without an `analyses` audit."""
    incoming = incoming or item(content=item()["content"] * 3)
    row = pending(store, incoming, at=incoming["updated_at"], ready=LATER)
    prepared = store.prepare_candidate(row, result or analysis(), DATE)
    data = prepared["payload"]
    with store.db:
        store.db.execute("INSERT INTO stories VALUES(?,?,?,?,?)", (data["id"], prepared["cluster_key"],
                         json.dumps(data), data["published_at"], data["updated_at"]))
        store.db.execute("UPDATE items SET status='published',story_id=? WHERE id=?", (data["id"], row["id"]))
    return incoming, data["id"]


def seed_rejected(store, number=0, **changes):
    """Ingest and strike-reject an item after three terminal failures."""
    src = item(url=f"https://example.org/news/{number}", **changes)
    store.ingest(src, DATE)
    for _ in range(3):
        store.defer(src["id"], "Model evidence is not present in source", DEFAULTS["llm"], DATE, terminal=True)
    return src, item_row(store, src["id"])


def seed_ignored(store, number=0):
    """Ingest and editorially skip an item so its status becomes `ignored`."""
    src = item(url=f"https://example.org/ignored/{number}")
    row = pending(store, src, at=DATE, ready=DATE)
    finish_reviewed(store, row, analysis(), cache_key(row, DEFAULTS["llm"]), DATE, decision="skip")
    return src, item_row(store, src["id"])


def add_coverage(store, identity="other-story", **changes):
    """Insert a background story row directly into `stories`."""
    public = {"id": identity, "title": "A previous report", "summary": "The source reported an event.",
              "why_it_matters": "", "category": "network", "priority": "normal", "confidence": "reported",
              "state": "developing", "products": ["tor"], "tags": ["network"],
              "sources": [{"url": "https://example.org/" + identity, "title": "Original source"}],
              "published_at": DATE, "updated_at": DATE, "added_at": DATE, **changes}
    with store.db:
        store.db.execute("INSERT INTO stories VALUES(?,?,?,?,?)",
                         (identity, identity, json.dumps(public), public["published_at"], public["updated_at"]))
    return public


def run_gate(cfg, store, row, writer=None, checker=None, observed=LATER, **kwargs):
    """Run `review_gate.process_item` with scripted defaults."""
    return review_gate.process_item(cfg, store, row, writer or Writer(), checker or Reviewer(verdict()),
                                    observed, **kwargs)


def job(store, item_id=None):
    """Return a saved `review_jobs` row dictionary (or `None`)."""
    target = item_id["id"] if isinstance(item_id, dict) else item_id
    query = "SELECT * FROM review_jobs WHERE item_id=?" if target else "SELECT * FROM review_jobs"
    row = store.db.execute(query, (target,) if target else ()).fetchone()
    return dict(row) if row else None


def job_record(store, item_id=None):
    """Return the parsed `record_json` dictionary from `review_jobs`."""
    return json.loads(job(store, item_id)["record_json"])


def patch_job(store, item_id=None, *, record=None, envelope=None, policy_hash=None, stage=None):
    """Patch selected columns of a saved `review_jobs` row and return the updated row."""
    target = (item_id["id"] if isinstance(item_id, dict) else item_id) or job(store)["item_id"]
    updates = {}
    if record is not None:
        updates["record_json"] = record if isinstance(record, (str, bytes)) else json.dumps(record)
    if envelope is not None:
        updates["envelope_json"] = envelope if isinstance(envelope, (str, bytes)) else json.dumps(envelope)
    if policy_hash is not None:
        updates["policy_hash"] = policy_hash
    if stage is not None:
        updates["stage"] = stage
    columns = ",".join(f"{col}=?" for col in updates)
    with store.db:
        store.db.execute(f"UPDATE review_jobs SET {columns} WHERE item_id=?", (*updates.values(), target))
    return job(store, target)


def downgrade_job_v1(store, item_id=None, *, policy_hash="a" * 64, full=False):
    """Downgrade a saved `review_jobs` row to schema version 1 for legacy migration tests."""
    saved = job(store, item_id)
    legacy = json.loads(saved["record_json"])
    for field in ("input_proof", "input_row", "request_budget", "untrusted_proposals"):
        legacy.pop(field, None)
    if full:
        legacy["input_row"] = json.loads(saved["envelope_json"])["row"]
        legacy.pop("input_hash", None)
    legacy["schema_version"] = 1
    if "policy_hash" in legacy:
        legacy["policy_hash"] = policy_hash
    return patch_job(store, saved["item_id"], record=legacy, policy_hash=policy_hash)


def assert_damaged_job(cfg, store, row, *, draft=None, replies=(), allow_network=True, match=None):
    """Assert `run_gate` fails closed with `app.damaged_job` without calling models or mutating `review_jobs`."""
    target = row["id"] if isinstance(row, dict) else row
    before = job(store, target)
    writer = Writer(draft)
    checker = wire_reviewer(cfg, *replies)
    with pytest.raises(AnalysisError, match=match) as error:
        run_gate(cfg, store, row, writer, checker, allow_network=allow_network)
    assert error.value.code == "app.damaged_job"
    assert not writer.calls and checker.calls == 0 and job(store, target) == before


def saved_audit(store, item_id=None):
    """Return the latest parsed `review_record` audit from `analyses`."""
    if item_id is not None:
        row = store.db.execute(
            "SELECT review_record FROM analyses WHERE source_item_id=? ORDER BY rowid DESC LIMIT 1",
            (item_id,),
        ).fetchone()
    else:
        row = store.db.execute("SELECT review_record FROM analyses ORDER BY rowid DESC LIMIT 1").fetchone()
    return json.loads(row[0])


def decision_rows(store):
    """Return ordered `decision_log` rows with parsed `detail` dictionaries."""
    return [{**dict(row), "detail": json.loads(row["detail_json"])}
            for row in store.db.execute("SELECT * FROM decision_log ORDER BY id")]


def decision_codes(store, item_or_id=None):
    """Return ordered `decision_log` codes, optionally filtered to one item."""
    if item_or_id is None:
        return [row[0] for row in store.db.execute("SELECT code FROM decision_log ORDER BY id")]
    target = item_or_id["id"] if isinstance(item_or_id, dict) else item_or_id
    return [row[0] for row in store.db.execute("SELECT code FROM decision_log WHERE item_id=? ORDER BY id", (target,))]


def editorial_act(fn, store, story_id, *args, reason="Reviewed.", observed=LATER, **kw):
    """Call an `editorial` write helper supplying the current story `expect_hash`."""
    return fn(store.db, story_id, *args, expect_hash=editorial.show(store.db, story_id)["hash"], reason=reason, observed=observed, **kw)


def pause_cached_after_reset(cfg, store, row, monkeypatch, *, replies=None):
    """Crash on commit, reset review work, and crash again on the cached-receipt hit."""
    used = (verdict(), verdict()) if replies is None else replies
    with monkeypatch.context() as scoped:
        scoped.setattr(store, "commit_candidate", raise_once(RuntimeError("before commit")))
        with pytest.raises(RuntimeError, match="before commit"):
            run_gate(cfg, store, row, Writer(), wire_reviewer(cfg, *used))
        with store.db:
            review_gate.reset_review_work(store, row["id"])
        idle = wire_reviewer(cfg)
        with pytest.raises(RuntimeError, match="before commit"):
            run_gate(cfg, store, row, Writer(), idle, allow_network=False)
        assert idle.calls == 0
    audit = job_record(store)
    assert audit["reviews"] == [] and audit["request_budget"]["reserved"] == 0
    assert job(store)["stage"] == "approved" and audit["approval"]["reviews"]
    return audit


def seed_routed_followup(cfg, store, *, target=None, fallbacks=0, replies=None, before=None):
    """Seed an authority-overload story and route an official follow-up item onto it."""
    if target is None:
        target = seed_source_story(
            store,
            item(url="https://example.org/incident", title="Directory authority overload",
                 content="Operators report a directory authority overload."),
        )
    incoming = item(url="https://example.org/followup", authority="official", title="An overload mitigation",
                    content="A new consensus method mitigates the authority overload.")
    row = pending(store, incoming)
    draft = analysis(title=incoming["title"], summary=incoming["content"], why_it_matters="",
                     evidence=[incoming["content"]])
    if fallbacks:
        cfg["llm"]["fallback_base_urls"] = [f"https://fallback{n}.example/v1" for n in range(fallbacks)]
        with pytest.raises(AnalysisError):
            run_gate(cfg, store, row, Writer(draft),
                     wire_reviewer(cfg, *(FetchError("unavailable", status=500) for _ in range(fallbacks + 1))))
    seq = [verdict(same_story=target["id"])] if replies is None else [
        verdict(same_story=target["id"]) if r == "route" else r for r in replies
    ]
    checker = wire_reviewer(cfg, *seq, before=before)
    assert run_gate(cfg, store, row, Writer(draft), checker)["status"] == "routed"
    return target, incoming, row, update_analysis(update=incoming["content"], evidence=[incoming["content"]])


def seed_citation_job(cfg, store):
    """Seed a merged MR story, attach a failing tag job to it, and lock the story as released."""
    target = seed_source_story(
        store,
        item(kind="gitlab_mr", upstream_state="merged", title="Add a guard scheduling option"),
        draft=analysis(state="merged"),
    )
    tag_item = item(kind="tag", authority="official", url="https://example.org/tags/tor-0.4.9.99",
                    title="tor-0.4.9.99", content="")
    row = pending(store, tag_item)
    with store.db:
        store.db.execute("UPDATE items SET story_id=? WHERE id=?", (target["id"], row["id"]))
    row = queued_row(store, row)
    with pytest.raises(AnalysisError):
        run_gate(cfg, store, row, Writer(), wire_reviewer(cfg, FetchError("unavailable", status=500)))
    assert job_record(store)["request_budget"]["reserved"] == 1
    editorial_act(editorial.correct, store, target["id"],
                  {"state": "released", "category": "release", "tags": ["release"]},
                  reason="Record release status.")
    return target, row


def patch_cli_pipeline(monkeypatch, *, now=DATE, analyzer=None, reviewer=ApprovingReviewer, collect=None, no_build=True, build=None):
    """Monkeypatch `cli` pipeline entrypoints for isolated run tests."""
    if now is not None:
        monkeypatch.setattr(cli, "now_iso", now if callable(now) else (lambda: now))
    if analyzer is not None:
        monkeypatch.setattr(cli, "Analyzer", analyzer)
    if reviewer is not None:
        monkeypatch.setattr(cli, "Reviewer", reviewer)
    if collect is not None:
        monkeypatch.setattr(cli, "collect_source", collect)
    if build is not None:
        monkeypatch.setattr(cli, "build", build)
    elif no_build:
        monkeypatch.setattr(cli, "build", lambda *a, **kw: {"published_stories": 0, "stories_skipped": 0})


def pub_settings(tmp_path, **storage):
    """Build publication settings rooted in `tmp_path`."""
    return make_config(
        tmp_path,
        storage={"database": str(Path(tmp_path) / "db.sqlite3"), **storage},
        site={"base_url": "https://example.org/onionflash/"},
        sources=[],
    )


def make_story(number, **changes):
    """Build a numbered public story dictionary."""
    return {**copy.deepcopy(STORY), "id": f"{number:024x}", "title": f"News {number}", **changes}


def put_story(db, value):
    """Insert or update a story row directly in `stories`."""
    db.execute(
        """INSERT INTO stories(id,cluster_key,payload,published_at,updated_at)
           VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,
           published_at=excluded.published_at,updated_at=excluded.updated_at""",
        (value["id"], "test:" + value["id"], json.dumps(value), value["published_at"], value["updated_at"]),
    )
    db.commit()


def publish_stories(stories, output, *, health=(), **site):
    """Seed `stories` into a fresh database, build into `output`, and return `stories_skipped`."""
    cfg = make_config(
        output,
        site={**SITE_CONFIG["site"], **site},
        storage={"database": f"{output}.sqlite3", "output_dir": str(output)},
        sources=[],
    )
    with Store(cfg["storage"]["database"]) as store, patch.object(Store, "health", return_value=list(health)):
        for number, entry in enumerate(stories):
            store.db.execute("INSERT INTO stories(id,cluster_key,payload,published_at,updated_at) VALUES(?,?,?,'','')",
                             (entry["id"], f"test:{number}", json.dumps(entry)))
        store.db.commit()
        return cli.build(cfg, store)["stories_skipped"]


class FakeLinker(_ClientBase):
    """Scripted DocTor host-attachment linker double."""

    def __init__(self, *answers):
        self.answers, self.calls = list(answers), 0

    def confirm(self, *_args) -> bool:
        """Count the call and return or raise the next scripted answer."""
        self.calls += 1
        if not self.answers:
            return False
        nxt = self.answers.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return bool(nxt)


def make_doctor_config(tmp_path: Path, *, publish: bool = True, enabled: bool = True) -> tuple[Path, dict]:
    """Write and load a DocTor consensus-alert TOML configuration in `tmp_path`."""
    path = write_toml(
        tmp_path,
        '[llm]\nbase_url = "https://llm.example/v1"\nmodel = "test-model"\n'
        f'[[sources]]\nid = "tor-consensus-health"\nname = "Tor Project Consensus Health Alerts"\n'
        f'website_url = "{DOCTOR_LIST_URL}"\nurl = "{DOCTOR_FEED_URL}"\n'
        f'kind = "feed"\nproduct = "network"\nauthority = "telemetry"\nalert_format = "consensus"\n'
        f'publish = {"true" if publish else "false"}\nenabled = {"true" if enabled else "false"}\n',
        with_source=False,
    )
    return path, load_config(path)


def doctor_report_item(slug: str, stamp: str, lines: list[str], *, url: str | None = None) -> dict:
    """Build a synthetic DocTor mailing-list report item."""
    return {"source_id": "tor-consensus-health", "url": url or f"{DOCTOR_LIST_URL}message/{slug}/",
            "title": "[tor-consensus-health] Consensus issues", "content": "\n".join(lines),
            "published_at": stamp, "updated_at": stamp, "kind": "feed", "product": "network",
            "authority": "telemetry", "labels": [], "upstream_state": ""}


def bastet_incident_items(start_iso: str = "2024-01-15T00:05:00Z", *, close: bool = False) -> list[dict]:
    """Build a 48h+ Rule A missing-bastet DocTor report sequence."""
    t0 = parse_utc(start_iso)
    missing = ["WARNING: The following authorities are missing from the consensus: bastet", DOCTOR_OK_LINE]
    items = [doctor_report_item(f"JAN24_ATTACH_BAS_{i}", format_utc(t0 + timedelta(hours=i * 12)), missing) for i in range(5)]
    if close:
        items += [doctor_report_item(f"JAN24_ATTACH_BAS_CLOSE_{i}", format_utc(t0 + timedelta(hours=60 + i * 16)), [DOCTOR_OK_LINE]) for i in range(2)]
    return items


def load_evaluator(tools_dir=None, module_name="review_eval_tool"):
    """Dynamically load `tools/evaluate_review.py` as an isolated module."""
    base = Path(tools_dir) if tools_dir else ROOT / "tools"
    spec = importlib.util.spec_from_file_location(module_name, base / "evaluate_review.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
