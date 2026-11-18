"""Direct publication reuses actual durable exact-text verification proofs."""

import copy
import json

import httpx
import pytest

from helpers import DATE, LATER, analysis, item, job, pending, seed_story, verdict
from onionflash import review, review_gate, source_quote
from onionflash.analyze import Analyzer
from onionflash.candidate import ReviewRequired
from onionflash.transport import HttpClient
from test_transport import public_dns


FIRST = "Users can inspect the result when the optional setting is enabled."
SECOND = "Operators can inspect the documented result when the feature is enabled."
BODY = "Introduction.\n\n" + FIRST + "\n\n" + SECOND + "\n\nFollowing context."


@pytest.fixture
def native(context, monkeypatch):
    config, store = context
    monkeypatch.setenv("COMMIT_PROOF_TEST_KEY", "synthetic-fixture-value")
    config["llm"].update(base_url="https://model.example/v1", fallback_base_urls=[],
                         api_key_env="COMMIT_PROOF_TEST_KEY")
    clients = []

    def produce(*, held=False, pause=False, clear_before_hold=False):
        row = pending(store, item(title="A report describes an optional setting", content=BODY,
                                  labels=[], authority="community", kind="feed"))
        requests = []

        def reply(request):
            body = json.loads(request.content)
            requests.append(body)
            schema = body["response_format"]["json_schema"]
            if schema["name"] == "onionflash_news":
                result = analysis(title="A report describes an optional setting", summary=FIRST,
                                  why_it_matters="Every user can inspect all results by default.",
                                  category="network", priority="normal", confidence="reported",
                                  state="developing", tags=["network"],
                                  evidence=[schema["schema"]["properties"]["evidence"]["items"]["enum"][0]])
            else:
                payload = json.loads(body["messages"][1]["content"])
                choices = payload["evidence_context"].get("source_quote_choices")
                result = (verdict("revise", criterion="source_support",
                                  repair={"why_it_matters": choices[0]["rendered"]}) if choices
                          else verdict("revise", criterion="source_support", repair={"why_it_matters": ""})
                          if clear_before_hold and payload["candidate"]["why_it_matters"]
                          else verdict("hold", criterion="news_value") if held else verdict())
            return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {
                "content": json.dumps(result)}}]})

        writer, checker = Analyzer(config), review.Reviewer(config)
        for client in (writer, checker):
            client.client = HttpClient(client.http_settings, transport=httpx.MockTransport(reply), resolver=public_dns)
            clients.append(client)
        if pause:
            def interrupted(*args, **kwargs):
                raise RuntimeError("Interrupted before candidate commit")
            with monkeypatch.context() as patch:
                patch.setattr(store, "commit_candidate", interrupted)
                with pytest.raises(RuntimeError, match="Interrupted before"):
                    review_gate.process_item(config, store, row, writer, checker, LATER)
        else:
            result = review_gate.process_item(config, store, row, writer, checker, LATER)
            assert result["status"] == ("held" if held else "published")
        assert writer.calls == 1 and checker.calls == (3 if clear_before_hold else 2)
        return row, requests

    yield config, store, produce
    for client in clients:
        client.close()


def saved_commit(store):
    saved = job(store)
    prepared = json.loads(saved["envelope_json"])
    record = json.loads(saved["record_json"])
    return prepared, record["candidate"], saved["writer_key"], record, {
        "approval_key": saved["approval_key"], "policy_hash": saved["policy_hash"],
    }


def operator_commit(config, store, row):
    info, handle = review_gate._check_approval(config, store, row["id"])
    assert info["eligible"], info
    prepared, candidate, key, record = handle
    audit = {**copy.deepcopy(record), "outcome": "operator_approved", "operator_approval": {
        "reason": "The reported development is relevant.", "approved_at": LATER,
        "approval_hash": info["hash"], "new_coverage": info["new_coverage"],
    }}
    return prepared, candidate, key, audit, {"operator": True, "review_record": audit,
        "policy_hash": review.policy_hash(config), "review_config": config}


def test_normal_quote_commit_uses_actual_durable_audit(native):
    config, store, produce = native
    row, requests = produce(pause=True)
    prepared, candidate, key, record, receipt = saved_commit(store)
    assert record["schema_version"] == 2
    assert record["request_budget"]["reserved"] == 2
    assert [entry["stage"] for entry in record["reviews"]] == ["review", "verification"]
    assert isinstance(record["reviews"][0]["result"]["repair"]["why_it_matters"], str)
    assert json.loads(requests[-1]["messages"][1]["content"])["candidate"] == candidate
    committed = store.commit_candidate(prepared, candidate, key, LATER, **receipt,
                                       review_config=config, review_record={"outcome": "invented"})
    assert committed["status"] == "published"
    actual = json.loads(store.db.execute("SELECT review_record FROM analyses WHERE source_item_id=?", (row["id"],)).fetchone()[0])
    assert actual == record
    assert store.stories()[0]["why_it_matters"] == candidate["why_it_matters"]


@pytest.mark.parametrize("damage", ["missing-proof", "missing-verification", "altered-path", "wrong-source"])
def test_normal_quote_commit_rejects_stored_damage_despite_valid_caller_proof(native, damage):
    config, store, produce = native
    produce(pause=True)
    prepared, candidate, key, good_record, receipt = saved_commit(store)
    damaged = copy.deepcopy(good_record)
    if damage == "missing-proof":
        damaged = {}
    elif damage == "missing-verification":
        damaged["reviews"].pop()
    elif damage == "altered-path":
        damaged["reviews"][0]["result"]["repair"]["why_it_matters"] = ""
    else:
        damaged["prepared"]["packet"]["sources"][0]["passages"][1]["text"] = "Different supplied prose."
    with store.db:
        store.db.execute("UPDATE review_approvals SET review_record_json=? WHERE key=?",
                         (json.dumps(damaged), receipt["approval_key"]))
    before = list(store.db.iterdump())
    with pytest.raises(ReviewRequired, match="stored exact-text review proof"):
        store.commit_candidate(prepared, candidate, key, LATER, **receipt,
                               review_config=config, review_record=good_record)
    assert list(store.db.iterdump()) == before


@pytest.mark.parametrize("context_change", ["absent-config", "changed-policy", "forged-origin"])
def test_normal_quote_commit_requires_current_policy_and_original_binding(native, context_change):
    config, store, produce = native
    produce(pause=True)
    prepared, candidate, key, record, receipt = saved_commit(store)
    current = copy.deepcopy(config)
    if context_change == "changed-policy":
        current["review"]["model"] = "changed-model"
    if context_change == "forged-origin":
        prepared["candidate"] = copy.deepcopy(candidate)
    with pytest.raises(ReviewRequired):
        store.commit_candidate(prepared, candidate, key, LATER, **receipt,
                               review_config=None if context_change == "absent-config" else current,
                               review_record=record)
    assert not store.stories()


def test_operator_quote_commit_reuses_actual_held_target_and_audit(native):
    config, store, produce = native
    row, _ = produce(held=True)
    prepared, candidate, key, audit, arguments = operator_commit(config, store, row)
    actual_reviews = copy.deepcopy(audit["reviews"])
    audit["reviews"] = []
    assert store.commit_candidate(prepared, candidate, key, LATER, **arguments)["status"] == "published"
    saved = json.loads(store.db.execute("SELECT review_record FROM analyses ORDER BY rowid DESC LIMIT 1").fetchone()[0])
    assert saved["reviews"] == actual_reviews
    assert saved["operator_approval"] == audit["operator_approval"]


def test_operator_cannot_choose_a_different_valid_quote_without_verification(native):
    config, store, produce = native
    row, _ = produce(held=True)
    prepared, candidate, key, audit, arguments = operator_commit(config, store, row)
    available = source_quote.available(prepared["candidate"], prepared["packet"])
    candidate["why_it_matters"] = available[1]["rendered"]
    before = list(store.db.iterdump())
    with pytest.raises(ReviewRequired, match="held candidate and its proof"):
        store.commit_candidate(prepared, candidate, key, LATER, **arguments)
    assert list(store.db.iterdump()) == before


@pytest.mark.parametrize("missing", ["config", "policy"])
def test_operator_quote_requires_explicit_current_policy(native, missing):
    config, store, produce = native
    row, _ = produce(held=True)
    prepared, candidate, key, _, arguments = operator_commit(config, store, row)
    arguments.pop("review_config" if missing == "config" else "policy_hash")
    with pytest.raises(ReviewRequired, match="current review policy"):
        store.commit_candidate(prepared, candidate, key, LATER, **arguments)
    assert not store.stories()


@pytest.mark.parametrize("damage", ["missing-verification", "failed-facts", "empty-then-quote", "changed-envelope"])
def test_operator_uses_held_path_and_fresh_facts_despite_forged_caller_audit(native, damage):
    config, store, produce = native
    row, _ = produce(held=True)
    prepared, candidate, key, audit, arguments = operator_commit(config, store, row)
    saved = job(store)
    record, envelope = json.loads(saved["record_json"]), json.loads(saved["envelope_json"])
    if damage == "missing-verification":
        record["reviews"].pop()
    elif damage == "failed-facts":
        record["reviews"][-1]["result"]["criteria"]["source_support"]["outcome"] = "fail"
    elif damage == "empty-then-quote":
        record["reviews"][0]["result"]["repair"]["why_it_matters"] = ""
    else:
        envelope["candidate"]["why_it_matters"] = ""
    with store.db:
        store.db.execute("UPDATE review_jobs SET record_json=?,envelope_json=? WHERE item_id=?",
                         (json.dumps(record), json.dumps(envelope), row["id"]))
    before = list(store.db.iterdump())
    with pytest.raises(ReviewRequired):
        store.commit_candidate(prepared, candidate, key, LATER, **arguments)
    assert list(store.db.iterdump()) == before


def test_operator_quote_preserves_new_coverage_eligibility(native):
    config, store, produce = native
    row, _ = produce(held=True)
    original = review_gate.approval(config, store, row["id"])
    seed_story(store, item(id="separate", url="https://example.org/separate", title="Separate development",
                           content="A separate report documents another development.", labels=[]),
               analysis(title="Separate development", summary="A separate report documents another development.",
                        why_it_matters="", evidence=["A separate report documents another development."]), at=DATE)
    current = review_gate.approval(config, store, row["id"])
    assert current["eligible"] and current["new_coverage"] and current["hash"] != original["hash"]
    result = review_gate.approve(config, store, row["id"], current["hash"], "Reviewed the additional coverage.", LATER)
    assert result["status"] == "published"
    actual = json.loads(store.db.execute("SELECT review_record FROM analyses WHERE source_item_id=? ORDER BY rowid DESC LIMIT 1", (row["id"],)).fetchone()[0])
    assert actual["operator_approval"]["new_coverage"] == current["new_coverage"]


@pytest.mark.parametrize("forged_mode", [False, True])
def test_operator_cannot_rebase_the_prepared_original_and_draft_to_an_unreviewed_quote(native, forged_mode):
    config, store, produce = native
    row, _ = produce(held=True)
    prepared, held, key, audit, arguments = operator_commit(config, store, row)
    other = source_quote.available(prepared["candidate"], prepared["packet"])[1]["rendered"]
    forged_draft = {**prepared["result"], "why_it_matters": other}
    current_row = dict(store.db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone())
    forged = store.prepare_candidate(current_row, forged_draft, prepared["observed"])
    assert forged["candidate"]["why_it_matters"] == other != held["why_it_matters"]
    if forged_mode:
        forged["mode"] = "update"
    before = list(store.db.iterdump())
    with pytest.raises(ReviewRequired):
        store.commit_candidate(forged, forged["candidate"], key, LATER, **arguments)
    assert list(store.db.iterdump()) == before


@pytest.mark.parametrize("mode", ["normal", "operator"])
@pytest.mark.parametrize("field", ["payload-source", "payload-date", "story-id", "cluster-key", "draft-result"])
def test_direct_quote_commit_requires_the_actual_publication_envelope(native, mode, field):
    config, store, produce = native
    row, _ = produce(held=mode == "operator", pause=mode == "normal")
    if mode == "normal":
        prepared, candidate, key, audit, arguments = saved_commit(store)
        arguments.update(review_config=config, review_record=audit)
    else:
        prepared, candidate, key, audit, arguments = operator_commit(config, store, row)
    if field == "payload-source":
        prepared["payload"]["sources"][0]["url"] = "https://example.org/unreviewed-source"
    elif field == "payload-date":
        prepared["payload"]["updated_at"] = "2026-01-01T12:00:00Z"
    elif field == "story-id":
        prepared["story_id"] = "f" * 24
    elif field == "cluster-key":
        prepared["cluster_key"] = "unreviewed-destination"
    else:
        prepared["result"]["evidence"] = ["Unreviewed source evidence"]
    before = list(store.db.iterdump())
    with pytest.raises(ReviewRequired):
        store.commit_candidate(prepared, candidate, key, LATER, **arguments)
    assert list(store.db.iterdump()) == before


@pytest.mark.parametrize("cleared", [False, True])
def test_operator_cannot_restore_the_original_impact_after_a_quote_path(native, cleared):
    config, store, produce = native
    row, _ = produce(held=True, clear_before_hold=cleared)
    prepared, candidate, key, audit, arguments = operator_commit(config, store, row)
    original = prepared["candidate"]
    assert original["why_it_matters"] != candidate["why_it_matters"]
    assert candidate["why_it_matters"] == "" if cleared else candidate["why_it_matters"].startswith(source_quote.PREFIX)
    before = list(store.db.iterdump())
    with pytest.raises(ReviewRequired):
        store.commit_candidate(prepared, original, key, LATER, **arguments)
    assert list(store.db.iterdump()) == before


def test_operator_cleared_quote_path_still_uses_actual_stored_fresh_proof(native):
    config, store, produce = native
    row, _ = produce(held=True, clear_before_hold=True)
    prepared, candidate, key, audit, arguments = operator_commit(config, store, row)
    assert candidate["why_it_matters"] == ""
    damaged = copy.deepcopy(audit)
    damaged["outcome"] = "held"
    damaged["reviews"].pop()
    with store.db:
        store.db.execute("UPDATE review_jobs SET record_json=? WHERE item_id=?", (json.dumps(damaged), row["id"]))
    with pytest.raises(ReviewRequired):
        store.commit_candidate(prepared, candidate, key, LATER, **arguments)
    assert not store.stories()


def test_operator_may_approve_the_exact_verified_clear_after_a_quote(native):
    config, store, produce = native
    row, _ = produce(held=True, clear_before_hold=True)
    info = review_gate.approval(config, store, row["id"])
    assert info["eligible"]
    result = review_gate.approve(config, store, row["id"], info["hash"], "Reviewed the final cleared impact.", LATER)
    assert result["status"] == "published" and store.stories()[0]["why_it_matters"] == ""


@pytest.mark.parametrize("damage", ["empty-record", "removed-path"])
def test_operator_cannot_restore_plain_impact_when_stored_quote_history_is_lost(native, damage):
    config, store, produce = native
    row, _ = produce(held=True)
    prepared, candidate, key, audit, arguments = operator_commit(config, store, row)
    damaged = {} if damage == "empty-record" else copy.deepcopy(audit)
    if damage == "removed-path":
        damaged.pop("candidate", None)
        damaged["reviews"] = []
        damaged["outcome"] = "held"
    with store.db:
        store.db.execute("UPDATE review_jobs SET record_json=? WHERE item_id=?", (json.dumps(damaged), row["id"]))
    before = list(store.db.iterdump())
    with pytest.raises(ReviewRequired):
        store.commit_candidate(prepared, prepared["candidate"], key, LATER, **arguments)
    assert list(store.db.iterdump()) == before
