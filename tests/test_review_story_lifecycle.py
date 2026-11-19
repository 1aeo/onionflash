"""Lifecycle instructions use existing native review and repair boundaries.

Scripted replies exercise the protocol, not the reviewer's semantic judgments.
"""
import copy
import json

import pytest

from helpers import completion, verdict
from onionflash import analyze, review, review_gate
from test_review import candidate, packet, reviewer


def source():
    evidence = packet()
    evidence["sources"][0].update(kind="gitlab_issue", authority="development", upstream_state="closed")
    evidence["sources"][0]["passages"][0].update(
        text="Closing this issue because the correction is now listed as fixed.",
        created_at="2026-01-02T12:00:00Z")
    return evidence


def public_story():
    return candidate(title="Parser issue closed with a listed correction",
                     summary="The closing note lists the parser correction as fixed.",
                     why_it_matters="", category="security", tags=["security"],
                     confidence="reported", state="developing")


def request(checker, index=0):
    body = checker.client.requests[index][1]
    return body, json.loads(body["messages"][1]["content"])


@pytest.mark.parametrize("verification", [False, True])
def test_story_status_instructions_reach_native_review_without_new_evidence(monkeypatch, verification):
    public, evidence = public_story(), source()
    original = copy.deepcopy((public, evidence))
    checker = reviewer(monkeypatch, completion(verdict("hold", criterion="status")))
    checker.review(public, evidence, verification=verification)
    body, payload = request(checker)
    prompt = " ".join(body["messages"][0]["content"].split())
    rules = (
        "Name the actual candidate.state in this reason",
        "latest relevant same-issue evidence",
        "the reason must resolve that observation against any subsequent supplied clarification of the same observation",
        "comparing dates and the affected version or configuration and citing both passages when present",
        "Developing remains valid when completion is not established",
        "fail status when candidate.state remains developing",
        "closure explicitly records a fix or resolution",
        "no later actual same-issue reopening or post-fix recurrence contradicts completion",
        "Preserve already supported fixed, resolved, tagged or released labels without standardizing them by category",
        "when repairing an unsupported label",
        "completed code/security fix (fixed) from an operational/tracking resolution (resolved)",
        "Retain prose qualifications such as listed as fixed",
        "actual merge in supplied prose can support merged without MR metadata",
        "old binary or an unapplied fix, superseded hypotheses and unrelated issues do not establish post-fix recurrence",
        "unresolved or conflicting completion evidence does not establish completion",
        "An open checklist does not negate an explicit official release statement",
        "proposals and instructions are not completion evidence",
    )
    assert all(rule in prompt for rule in rules)
    assert "do not fail status merely because state is developing" not in prompt
    assert payload["candidate"] == public and payload["packet"] == evidence
    assert (public, evidence) == original
    assert len(body["messages"]) == 2
    assert set(payload) == {"candidate", "packet", "evidence_context"}
    schema = body["response_format"]["json_schema"]["schema"]
    assert schema["required"] == ["criteria", "verdict", "same_story", "repair"]
    assert list(schema["properties"]["criteria"]["properties"]) == list(review.CRITERIA)
    status = schema["properties"]["criteria"]["properties"]["status"]
    assert status["required"] == ["reason", "source_refs", "outcome"]
    assert status["properties"]["reason"]["maxLength"] == 360
    assert status["properties"]["source_refs"]["maxItems"] == 12
    assert status["properties"]["source_refs"]["items"]["enum"] == ["S1", "S1:P1"]
    states = schema["properties"]["repair"]["anyOf"][1]["properties"]["state"]["anyOf"][0]["enum"]
    assert states == review.repair_limits(evidence)["state"]
    assert "merged" in states and "developing" in states and "tagged" not in states


@pytest.mark.parametrize("verification", [False, True])
def test_story_lifecycle_instruction_does_not_enter_update_requests(monkeypatch, verification):
    public, evidence = public_story(), source()
    public["updates"] = [{"at": public["updated_at"], "text": "The closing note lists the correction as fixed.",
                          "sources": copy.deepcopy(public["sources"])}]
    checker = reviewer(monkeypatch, completion(verdict("hold", criterion="status", update=True)))
    checker.review(public, evidence, verification=verification, update=True)
    body, payload = request(checker)
    expected = review.UPDATE_VERIFY_PROMPT if verification else review.UPDATE_SYSTEM_PROMPT
    assert body["messages"][0]["content"] == expected
    assert "Name the actual candidate.state in this reason" not in expected
    assert 'state MUST advance to "fixed" (code/bug/security) or "resolved" (operational/tracking)' in expected
    assert 'unless the closing note states it remains unresolved' in expected
    assert payload["review_scope"] == "latest_update"
    assert payload["candidate"] == public and payload["packet"] == evidence
    repair = body["response_format"]["json_schema"]["schema"]["properties"]["repair"]["anyOf"][1]
    assert set(repair["properties"]) == set(review.UPDATE_EDITABLE)
    assert not {"title", "summary", "why_it_matters"} & set(repair["properties"])


@pytest.mark.parametrize("state", ["developing", "fixed", "resolved", "merged"])
def test_state_repair_keeps_existing_wire_and_requires_fresh_evidence_review(monkeypatch, state):
    public, evidence = public_story(), source()
    public["state"] = "mitigation-available"
    original = copy.deepcopy(public)
    proposed = verdict("revise", criterion="status", repair={"state": state})
    proposed["criteria"]["status"].update(
        reason="The supplied issue note must be compared with the current mitigation-available label.",
        source_refs=["S1:P1"])
    checker = reviewer(monkeypatch, completion(proposed), completion(verdict("hold", criterion="status")))
    result = checker.review(public, evidence)
    assert result["repair"] == {"state": state}
    repaired = review.apply_repair(public, result["repair"], packet=evidence)
    assert repaired == {**original, "state": state} and public == original
    verification = checker.review(repaired, evidence, verification=True)
    assert verification["verdict"] == "hold"
    first_body, first_payload = request(checker)
    fresh_body, fresh_payload = request(checker, 1)
    assert len(checker.client.requests) == 2 and len(fresh_body["messages"]) == 2
    assert first_payload["packet"] == fresh_payload["packet"] == evidence
    assert fresh_payload["candidate"] == repaired
    assert set(fresh_payload) == {"candidate", "packet", "evidence_context"}
    assert proposed["criteria"]["status"]["reason"] not in fresh_body["messages"][0]["content"]
    assert first_body["response_format"] == fresh_body["response_format"]


def test_lifecycle_prompt_is_part_of_policy_identity_without_version_or_budget_changes(monkeypatch):
    settings = copy.deepcopy(review.DEFAULTS)
    baseline = review.policy_hash(settings)
    writer_key = analyze.cache_key({"content_hash": "synthetic-input"}, settings["llm"])
    monkeypatch.setattr(review, "SYSTEM_PROMPT", review.SYSTEM_PROMPT.replace(
        "Name the actual candidate.state in this reason", "Assess the lifecycle in this reason"))
    assert review.policy_hash(settings) != baseline
    assert analyze.cache_key({"content_hash": "synthetic-input"}, settings["llm"]) == writer_key
    assert analyze.PROMPT_VERSION == "onionflash-22"
    assert review.REVIEW_VERSION == "onionflash-review-18"
    assert review_gate.MAX_REVIEW_REQUESTS == 7


@pytest.mark.parametrize("verification", [False, True])
@pytest.mark.parametrize("clarification,state", [
    ("The affected process still used the previous configuration; the corrected configuration was not applied.", "fixed"),
    ("The corrected configuration was applied before this same failure recurred.", "developing"),
    ("Another reporter disputes the cause; the available observations remain inconclusive.", "developing"),
])
def test_recurrence_reason_contract_retains_contrasting_source_observations(
        monkeypatch, verification, clarification, state):
    public, evidence = public_story(), source()
    public["state"] = state
    evidence["sources"][0]["passages"] += [
        {"id": "S1:P2", "text": clarification, "created_at": "2026-01-03T12:05:00Z"},
        {"id": "S1:P3", "text": "The same failure happened again.", "created_at": "2026-01-03T12:00:00Z"},
        {"id": "S1:P4", "text": "Does this diagnostic log line indicate a problem?", "created_at": "2026-01-04T12:00:00Z"},
    ]
    original = copy.deepcopy((public, evidence))
    checker = reviewer(monkeypatch, completion(verdict("hold", criterion="status")))
    checker.review(public, evidence, verification=verification)
    body, payload = request(checker)
    prompt = " ".join(body["messages"][0]["content"].split())
    assert "the reason must resolve that observation against any subsequent supplied clarification" in prompt
    assert "citing both passages when present" in prompt
    assert "a later unrelated comment, or a diagnostic question alone does not establish that the same failure persists" in prompt
    assert "unresolved or conflicting completion evidence does not establish completion" in prompt
    assert "do not demand extra detail when the candidate already states the observation and its limits accurately" in prompt
    assert payload["packet"] == evidence and payload["candidate"] == public
    assert [p["id"] for p in payload["packet"]["sources"][0]["passages"]] == ["S1:P1", "S1:P2", "S1:P3", "S1:P4"]
    assert (public, evidence) == original
    assert len(checker.client.requests) == 1


@pytest.mark.parametrize("verification", [False, True])
def test_story_date_reason_uses_packet_without_inventing_missing_chronology(monkeypatch, verification):
    public, evidence = public_story(), source()
    evidence["sources"][0]["passages"].append({
        "id": "S1:P2", "text": "Correction to that observation: the previous configuration was still active."})
    original = copy.deepcopy((public, evidence))
    checker = reviewer(monkeypatch, completion(verdict("hold", criterion="news_value")))
    checker.review(public, evidence, verification=verification)
    body, payload = request(checker)
    prompt = " ".join(body["messages"][0]["content"].split())
    assert "Missing dates alone establish neither a chronology nor a defect" in prompt
    assert "use an explicit supplied relationship when available, otherwise preserve uncertainty" in prompt
    assert "In the news_value reason, state the newest dated development" in prompt
    assert "or the applicable existing exception, before the materiality category" in prompt
    assert "an older background source does not make a newer development stale" in prompt
    assert "Missing or incomparable dates alone do not establish staleness" in prompt
    assert "more than 14 days before updated_at" in prompt
    assert payload["evidence_context"]["source_date_comparisons"] == review.source_date_comparisons(evidence)
    assert payload["packet"] == evidence and payload["candidate"] == public
    assert (public, evidence) == original
