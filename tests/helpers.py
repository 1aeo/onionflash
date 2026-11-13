"""Shared builders, scripted doubles, and receipt helpers for the test suite."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
from unittest.mock import patch

from onionflash import candidate as candidate_mod, cli, review, review_gate
from onionflash.analyze import cache_key, tag_update
from onionflash.config import DEFAULTS
from onionflash.store import Store
from onionflash.transport import Response
from onionflash.util import MAX_SAVED_DEPTH, digest

ROOT = Path(__file__).resolve().parents[1]
DATE = "2026-11-08T12:00:00Z"
LATER = "2026-11-10T12:00:00Z"
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


def source(**kw):
    return {
        "id": "test", "name": "Test source", "url": "https://example.org/feed.xml",
        "kind": "feed", "fallback_urls": [], "authority": "community", "product": "network",
        "enabled": True, "interval_seconds": 300, "max_pages": 2, "max_items": 100, **kw,
    }


def make_item(**kw):
    return {
        "id": "example", "source_id": "test", "url": "https://example.org/news/1",
        "title": "A reported security incident",
        "content": "The operator reported a plausible compromise and said its keys must no longer be trusted.",
        "published_at": DATE, "updated_at": DATE, "kind": "gitlab_issue",
        "product": "tor", "authority": "development", "labels": ["Security"], **kw,
    }


item = make_item


def make_tag(**overrides):
    return {
        "id": "tag-id", "source_id": "tor-tags",
        "url": "https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-0.4.9.16",
        "title": "tor-0.4.9.16", "content": "Tor 0.4.9.16",
        "published_at": "2026-11-04T13:55:43Z", "updated_at": "2026-11-04T13:55:43Z",
        "kind": "tag", "product": "tor", "authority": "official",
        "labels": [], "upstream_state": "", **overrides,
    }


tag = make_tag


def analysis(**kw):
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
    return {
        "publish": True,
        "update": "A material upstream follow-up was posted.",
        "confidence": "reported",
        "state": "developing",
        "evidence": ["The operator reports that old directory-authority keys cannot be trusted"],
        **overrides,
    }


def make_config(tmp_path, **overrides):
    result = copy.deepcopy(DEFAULTS)
    result["storage"]["database"] = str(tmp_path / "state.sqlite3")
    result["storage"]["output_dir"] = str(tmp_path / "public")
    result["sources"] = [source()]
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key].update(value)
        else:
            result[key] = value
    return result


config = make_config


def damaged(document, kind):
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
    expression = {"blob": "CAST(payload AS BLOB)", "undated": "json_remove(payload,'$.updated_at')"}.get(kind)
    if expression:
        db.execute(f"UPDATE items SET payload={expression} WHERE id=?", (item_id,))
    else:
        document = db.execute("SELECT payload FROM items WHERE id=?", (item_id,)).fetchone()[0]
        db.execute("UPDATE items SET payload=CAST(? AS TEXT) WHERE id=?", (damaged(document, kind), item_id))
    db.commit()


def response(body, headers=None, status=200, url="https://example.org/feed.xml"):
    return Response(status, body, headers or {}, url)


def completion(result: dict, finish_reason: str = "stop") -> Response:
    body = {"choices": [{"finish_reason": finish_reason, "message": {"content": json.dumps(result)}}]}
    return Response(200, json.dumps(body).encode(), {}, "https://llm.example/v1/chat/completions")


class FakeClient:
    def __init__(self, values):
        self.values = iter(values)
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def close(self):
        pass

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        result = next(self.values)
        if isinstance(result, Exception):
            raise result
        return result


class FakeLLM:
    def __init__(self, *responses):
        self.responses, self.requests = list(responses), []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def close(self):
        pass

    def request(self, method, url, headers=None, json_body=None):
        self.requests.append((url, json_body))
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def verdict(action="approve", *, repair=None, criterion="operational_advice", ref="S1", update=False, same_story=None):
    checks = {name: {"reason": "Supported by the supplied source.", "source_refs": [ref], "outcome": "pass"}
              for name in review.CRITERIA}
    if action != "approve":
        checks[criterion].update(reason="The source does not support this claim.", outcome="fail")
    fields = review.UPDATE_EDITABLE if update else review.EDITABLE
    wire = None if repair is None else {key: repair.get(key) for key in fields}
    return {"criteria": checks, "verdict": action, "same_story": same_story, "repair": wire}


def approved_result(packet, *, update=False, coverage=None):
    return review.validate_review(verdict(update=update), packet, update=update, coverage=coverage)


def scripted_completion(reply):
    """Meter a synthetic completion while retaining the real reply validator."""
    def complete(self, *args, on_request=None, **kwargs):
        if on_request is not None:
            on_request(1)
        result = reply(*args, **kwargs)
        if hasattr(on_request, "response_received"):
            on_request.response_received()
        return result
    return complete


class CallLog(list):
    def __add__(self, other):
        return len(self) + other if isinstance(other, int) else CallLog(super().__add__(other))

    def __radd__(self, other):
        return other + len(self) if isinstance(other, int) else NotImplemented


class ScriptedAnalyzer:
    """Configurable double for Analyzer supporting constant drafts, scripted sequences, or callables."""
    clears = 0

    def __init__(self, *responses):
        self._explicit = bool(responses)
        self._repeat = len(responses) == 1 and not isinstance(responses[0], Exception)
        self._queue = list(responses)
        self.result = responses[0] if len(responses) == 1 and isinstance(responses[0], dict) else analysis()
        self.calls = CallLog()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def analyze(self, incoming, prior=None):
        self.calls.append(copy.deepcopy(incoming))
        if self._queue:
            step = self._queue[0] if self._repeat else self._queue.pop(0)
            if isinstance(step, Exception):
                raise step
            if callable(step):
                try:
                    return step(incoming, prior)
                except TypeError:
                    return step(incoming)
            chosen = step
        else:
            chosen = self.result
        if prior is not None and "update" not in chosen:
            if incoming.get("kind") == "tag":
                return tag_update(incoming, prior)
            if not self._explicit:
                return update_analysis(confidence=prior["confidence"], state=prior["state"],
                                       evidence=chosen["evidence"])
            return update_analysis(update=(chosen.get("summary") or chosen.get("title"))[:300],
                                   confidence=chosen.get("confidence", prior["confidence"]),
                                   state=chosen.get("state", prior["state"]),
                                   evidence=chosen["evidence"])
        return copy.deepcopy(chosen)

    @classmethod
    def factory(cls, *responses):
        instance = cls(*responses)
        instance.factory_instance = instance
        return lambda *a, **kw: instance


Writer = ScriptedAnalyzer


class ScriptedReviewer:
    """Returns validated verdicts, recording exact calls, coverages, and issues."""
    last_decoded = None

    def __init__(self, *responses):
        self.responses, self.calls, self.coverages, self.issues = list(responses), CallLog(), [], []
        if len(responses) == 1 and (callable(responses[0]) or
                isinstance(responses[0], dict) and responses[0].get("verdict") == "approve"):
            self.responses.append(verdict())

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def review(self, candidate, packet, *, coverage=None, verification=False, issue=None, update=False, on_request=None):
        if on_request is not None:
            on_request(1)
        self.calls.append((copy.deepcopy(candidate), copy.deepcopy(packet), verification))
        self.coverages.append(copy.deepcopy(coverage))
        self.issues.append(issue)
        reply = self.responses.pop(0)
        if isinstance(reply, Exception):
            raise reply
        if callable(reply):
            try:
                raw = reply(candidate, packet, coverage=coverage, verification=verification, issue=issue, update=update)
            except TypeError:
                raw = reply()
        else:
            raw = copy.deepcopy(reply)
        return review.validate_review(raw, packet, update=update, coverage=coverage)

    @classmethod
    def factory(cls, *responses):
        instance = cls(*responses)
        return lambda *a, **kw: instance


Reviewer = ScriptedReviewer


class ApprovingReviewer:
    """Context-manager reviewer approving every call with valid rubric outputs."""
    calls = 0
    last_decoded = None

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def review(self, candidate, packet, *, coverage=None, verification=False, issue=None, update=False, on_request=None):
        if on_request is not None:
            on_request(1)
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
            context = {"source_hash": source_hash, "coverage_hash": prepared["coverage_hash"],
                       "binding_hash": binding_hash, "policy_hash": policy}
            if result["verdict"] == "skip":
                reviews = [{"stage": "review", "candidate_hash": candidate_hash, "request": 1, "result": result, **context}]
            else:
                if is_update:
                    changes = {key: candidate[key] for key in review.UPDATE_EDITABLE if key != "update"
                               and candidate[key] != prepared["candidate"][key]}
                    if candidate["updates"][-1]["text"] != prepared["candidate"]["updates"][-1]["text"]:
                        changes["update"] = candidate["updates"][-1]["text"]
                else:
                    changes = {key: candidate[key] for key in review.EDITABLE if candidate[key] != prepared["candidate"][key]}
                first = review.validate_review(verdict("revise", repair=changes, update=is_update) if changes else verdict(update=is_update),
                                               prepared["packet"], update=is_update, coverage=prepared.get("coverage"))
                reviews = [{"stage": "review", "candidate_hash": digest(prepared["candidate"]), "request": 1, "result": first, **context},
                           {"stage": "verification", "candidate_hash": candidate_hash, "request": 2, "result": result, **context}]
            state = review_gate.initial_review_state()
            state["request_budget"]["reserved"] = len(reviews)
            record = {"candidate": candidate, "packet": prepared["packet"], "coverage": prepared["coverage"], "reviews": reviews,
                      "policy_hash": policy, "approval_key": key, **state,
                      "outcome": "skipped" if result.get("verdict") == "skip" else "approved"}
    result_text = result if isinstance(result, str) else json.dumps(result if result is not None else verdict())
    record_text = record if isinstance(record, str) else json.dumps(record if record is not None else {})
    stamp = created_at or DATE
    with store.db:
        store.db.execute(
            """INSERT OR REPLACE INTO review_approvals (key,candidate_hash,source_hash,policy_hash,
               binding_hash,result_json,review_record_json,created_at,last_used_at) VALUES(?,?,?,?,?,?,?,?,?)""",
            (key, candidate_hash or "", source_hash or "", policy, binding_hash or "",
             result_text, record_text, stamp, last_used_at or stamp),
        )
    return {"approval_key": key, "policy_hash": policy}


def approve(store, prepared, candidate=None, *, policy="test-policy", result=None):
    return insert_approval(store, prepared, candidate, policy=policy, result=result)


def finish_reviewed(store, row, result, key, observed, *, decision="approve"):
    parsed = json.loads(row["payload"])
    if (existing := candidate_mod.existing_story(store.db, row)) is not None:
        if candidate_mod.relation(json.loads(existing["payload"]), parsed, store.db) == "citation" and decision == "approve":
            return store.add_citation(row, existing["id"], observed)
    if "update" not in result and (prior := candidate_mod.update_target(store.db, row)) is not None:
        if parsed.get("kind") == "tag":
            result = tag_update(parsed, prior)
        else:
            result = update_analysis(update=(result.get("summary") or result.get("title"))[:300],
                                     confidence=result["confidence"], state=result["state"],
                                     evidence=result["evidence"])
    prepared = store.prepare_candidate(row, result, observed)
    is_update = prepared.get("mode") == "update"
    reply = verdict("skip", criterion="news_value", update=is_update) if decision == "skip" else None
    receipt = {} if prepared["locked"] else approve(store, prepared, result=reply)
    return store.commit_candidate(prepared, prepared["candidate"], key, observed, decision=decision, **receipt)


def pending(store, incoming=None, *, at=DATE, ready=LATER):
    target = incoming or make_item()
    store.ingest(target, at)
    rows = store.pending(500, ready)
    found = next((r for r in rows if r["id"] == target["id"]), None)
    if found is None:
        raise AssertionError(f"Expected item {target['id']} is not pending")
    return found


def seed_story(store, incoming=None, draft=None, *, key=None, at=DATE, decision="approve"):
    row = pending(store, incoming, at=at, ready=at)
    used_key = key or cache_key(row, DEFAULTS["llm"])
    outcome = finish_reviewed(store, row, draft or analysis(), used_key, at, decision=decision)
    if decision != "approve" or not outcome.get("story_id"):
        return outcome
    return next(s for s in store.stories(100) if s["id"] == outcome["story_id"])


def seed_source_story(store, incoming, draft=None, *, at=DATE):
    """Seed a source-shaped account when an association test needs its actual topic."""
    text = incoming["content"]
    used = draft or analysis(title=incoming["title"][:120], summary=text[:220] or incoming["title"],
                             evidence=[text[:80] or incoming["title"]])
    return seed_story(store, incoming, used, at=at)


def seed_legacy(store, incoming=None, result=None, *, at=DATE):
    incoming = incoming or make_item(content=make_item()["content"] * 3)
    row = pending(store, incoming, at=incoming["updated_at"], ready=LATER)
    prepared = store.prepare_candidate(row, result or analysis(), at)
    data = prepared["payload"]
    with store.db:
        store.db.execute("INSERT INTO stories VALUES(?,?,?,?,?)", (data["id"], prepared["cluster_key"],
                         json.dumps(data), data["published_at"], data["updated_at"]))
        store.db.execute("UPDATE items SET status='published',story_id=? WHERE id=?", (data["id"], row["id"]))
    return incoming, data["id"]


def seed_rejected(store, number=0, **changes):
    src = make_item(url=f"https://example.org/news/{number}", **changes)
    store.ingest(src, DATE)
    for _ in range(3):
        store.defer(src["id"], "Model evidence is not present in source", DEFAULTS["llm"], DATE, terminal=True)
    return src, dict(store.db.execute("SELECT * FROM items WHERE id=?", (src["id"],)).fetchone())


def seed_ignored(store, number=0):
    src = make_item(url=f"https://example.org/ignored/{number}")
    store.ingest(src, DATE)
    row = store.pending(1, DATE)[0]
    finish_reviewed(store, row, analysis(), cache_key(row, DEFAULTS["llm"]), DATE, decision="skip")
    return src, dict(store.db.execute("SELECT * FROM items WHERE id=?", (src["id"],)).fetchone())


def run_gate(cfg, store, row, writer=None, checker=None, observed=LATER, **kwargs):
    return review_gate.process_item(cfg, store, row, writer or ScriptedAnalyzer(), checker or ScriptedReviewer(verdict()),
                                    observed, **kwargs)


def job(store, item_id=None):
    query = "SELECT * FROM review_jobs WHERE item_id=?" if item_id else "SELECT * FROM review_jobs"
    row = store.db.execute(query, (item_id,) if item_id else ()).fetchone()
    return dict(row) if row else None


def patch_cli_pipeline(monkeypatch, *, now=DATE, analyzer=None, reviewer=ApprovingReviewer, collect=None, no_build=True):
    if now is not None:
        monkeypatch.setattr(cli, "now_iso", now if callable(now) else (lambda: now))
    if analyzer is not None:
        monkeypatch.setattr(cli, "Analyzer", analyzer)
    if reviewer is not None:
        monkeypatch.setattr(cli, "Reviewer", reviewer)
    if collect is not None:
        monkeypatch.setattr(cli, "collect_source", collect)
    if no_build:
        monkeypatch.setattr(cli, "build", lambda *a, **kw: {"published_stories": 0, "stories_skipped": 0})


def pub_settings(tmp_path, **storage):
    cfg = copy.deepcopy(DEFAULTS)
    cfg["storage"].update(database=str(tmp_path / "db.sqlite3"), output_dir=str(tmp_path / "public"), **storage)
    cfg["site"]["base_url"] = "https://example.org/onionflash/"
    cfg["sources"] = []
    return cfg


def make_story(number, **changes):
    return {**copy.deepcopy(STORY), "id": f"{number:024x}", "title": f"News {number}", **changes}


def put_story(db, value):
    db.execute(
        """INSERT INTO stories(id,cluster_key,payload,published_at,updated_at)
           VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,
           published_at=excluded.published_at,updated_at=excluded.updated_at""",
        (value["id"], "test:" + value["id"], json.dumps(value), value["published_at"], value["updated_at"]),
    )
    db.commit()


def pub_meta(db, key):
    return db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()[0]


def upgrade_template(db):
    db.execute("UPDATE public_catalog SET template_hash='old-template'")
    db.execute("UPDATE metadata SET value='old-template' WHERE key='publication_template'")
    db.commit()


def publish_stories(stories, output, *, health=(), **site):
    cfg = copy.deepcopy(DEFAULTS)
    cfg["site"].update(SITE_CONFIG["site"], **site)
    cfg["storage"].update(database=f"{output}.sqlite3", output_dir=str(output))
    with Store(cfg["storage"]["database"]) as store, patch.object(Store, "health", return_value=list(health)):
        for number, entry in enumerate(stories):
            store.db.execute("INSERT INTO stories(id,cluster_key,payload,published_at,updated_at) VALUES(?,?,?,'','')",
                             (entry["id"], f"test:{number}", json.dumps(entry)))
        store.db.commit()
        return cli.build(cfg, store)["stories_skipped"]


def load_evaluator(tools_dir=None, module_name="review_eval_tool"):
    base = Path(tools_dir) if tools_dir else ROOT / "tools"
    spec = importlib.util.spec_from_file_location(module_name, base / "evaluate_review.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
