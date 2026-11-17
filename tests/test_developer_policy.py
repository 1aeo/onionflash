"""Contributor policy delivery and controlled cases, not simulated model accuracy."""

import copy
import json
from pathlib import Path

import pytest

from helpers import FakeLLM, analysis, completion, load_evaluator, update_analysis, verdict
from onionflash import analyze, review
from onionflash.config import DEFAULTS
from onionflash.transport import FetchError


CORPUS = json.loads((Path(__file__).parents[1] / "tools/review_cases_roles.json").read_text())
EVALUATOR = load_evaluator()
CASES = {case["id"]: case for case in EVALUATOR.expand(CORPUS)}
CROSS = ("ctor-on-arti", "arti-on-ctor")


def assert_role_contract(prompt):
    text = " ".join(prompt.split())
    assert "authored by that same person and committed into C Tor or Arti" in text
    assert "Either contribution supports the generic role" in text
    assert "in news about either project" in text
    assert "project-specific label" in text
    assert "in the named project, not just the other one" in text
    assert "Quoting or attributing a developer self-description does not waive this requirement." in text
    for limit in ("self-description", "proposed/unmerged code", "unrelated project", "official authority"):
        assert limit in text
    assert "committed into C Tor's codebase" not in text


def config(fallback):
    value = copy.deepcopy(DEFAULTS)
    value["llm"].update(base_url="https://model.example/v1",
                         fallback_base_urls=["https://fallback.example/v1"] if fallback else [])
    return value


@pytest.mark.parametrize("direction", CROSS)
@pytest.mark.parametrize("update", [False, True])
@pytest.mark.parametrize("reasoning", [False, True])
@pytest.mark.parametrize("fallback", [False, True])
def test_writer_delivers_cross_project_role_rule_in_both_modes_and_fallbacks(
        monkeypatch, direction, update, reasoning, fallback):
    case = CASES[f"role-cross-{direction}-{'update-generic' if update else 'generic'}"]
    source = case["packet"]["sources"][0]
    item = EVALUATOR.writer_item(source)
    evidence = [passage["text"] for passage in source["passages"][1:]]
    if update:
        answer = update_analysis(update=case["candidate"]["updates"][-1]["text"], evidence=evidence)
    else:
        answer = analysis(**{field: case["candidate"][field] for field in (
            "title", "summary", "why_it_matters", "category", "priority", "confidence", "state", "products", "tags")},
                          evidence=evidence)
    cfg = config(fallback)
    cfg["llm"]["writer_reasoning"] = reasoning
    original = copy.deepcopy(cfg)
    monkeypatch.setenv("ONIONFLASH_LLM_API_KEY", "synthetic-policy-key")
    responses = [FetchError("Unavailable", status=503)] if fallback else []
    with analyze.Analyzer(cfg) as writer:
        writer.client = FakeLLM(*responses, completion(answer))
        prior = case["existing_coverage"]["prior_story"] if update else None
        writer.analyze(item, prior)
        requests = [body for _, body in writer.client.requests]
    assert len(requests) == (2 if fallback else 1)
    assert all(request == requests[0] for request in requests)
    for request in requests:
        assert_role_contract(request["messages"][0]["content"])
        payload = json.loads(request["messages"][-1]["content"])
        assert payload["authority"] == "community"
        assert all(text in payload["content"] for text in evidence)
        assert not {"is_developer", "contributor_verified", "role_evidence"} & payload.keys()
    assert cfg == original


@pytest.mark.parametrize("direction", CROSS)
@pytest.mark.parametrize("update,verification", [(False, False), (False, True), (True, False), (True, True)])
@pytest.mark.parametrize("correction,fallback", [(False, False), (True, True)])
def test_review_modes_and_corrections_deliver_role_and_substantive_eligibility_rules(
        monkeypatch, direction, update, verification, correction, fallback):
    case = CASES[f"role-cross-{direction}-{'update-generic' if update else 'generic'}"]
    coverage = copy.deepcopy(case["existing_coverage"])
    if not update:
        coverage = {"prior_story": None, "recent": [{"id": "related-story", "title": "Earlier separate report"}], "truncated": False}
    monkeypatch.setenv("ONIONFLASH_LLM_API_KEY", "synthetic-policy-key")
    responses = [FetchError("Unavailable", status=503)] if fallback else []
    with review.Reviewer(config(fallback)) as checker:
        checker.client = FakeLLM(*responses, completion(verdict(update=update)))
        checker.review(case["candidate"], case["packet"], coverage=coverage, update=update,
                       verification=verification,
                       validation_error=review.INCONSISTENT_VERDICT if correction else None)
        requests = [body for _, body in checker.client.requests]
    assert len(requests) == (2 if fallback else 1)
    assert all(request == requests[0] for request in requests)
    for request in requests:
        prompt = request["messages"][0]["content"]
        assert_role_contract(prompt)
        assert prompt.count(review._PERSONAL_ROLE_RULE) == 1
        assert "Discussion and sender authority alone" in prompt
        assert "reported activity" not in review._PERSONAL_ROLE_RULE
        if update:
            assert "contributor meeting the commit-evidence rule" in prompt
            assert "contributor status alone" in prompt
        else:
            assert "including with authority=community" in prompt
            assert "case (5) does not apply" in prompt
            assert "all significance, staleness and factual checks remain" in prompt
            assert "proposed/unmerged code do not qualify by themselves" in prompt
            assert "Contributor status does not corroborate" in prompt
        payload = json.loads(request["messages"][-1]["content"])
        assert payload["packet"] == case["packet"]
        assert payload["packet"]["sources"][0]["authority"] == "community"


@pytest.mark.parametrize("direction", CROSS)
def test_cross_project_controls_separate_generic_and_named_project_labels(direction):
    prefix = "role-cross-" + direction
    positive = CASES[prefix + "-generic"]
    matched = CASES[prefix + "-specific-matched"]
    wrong = CASES[prefix + "-specific-wrong"]
    assert positive["packet"] == matched["packet"] == wrong["packet"]
    assert positive["expected"] == matched["expected"] == "approve"
    assert wrong["expected"] == "not_approve" and wrong["unsupported"]
    assert CASES[prefix + "-update-generic"]["expected"] == "approve"
    assert CASES[prefix + "-update-specific-wrong"]["expected"] == "not_approve"
    assert positive["candidate"]["confidence"] == "reported"
    prepared = {"packet": positive["packet"], "payload": {"editorial_kind": "feed"}}
    assert review.final_holds(review.personal_attribution.normalize(positive["candidate"]), prepared) == []
    confirmed = {**positive["candidate"], "confidence": "confirmed"}
    assert "confirmed_source" in review.final_holds(confirmed, prepared)


@pytest.mark.parametrize("kind", ["self-claimed", "unmerged", "other-author", "unrelated-project", "contributor-routine"])
def test_community_comment_controls_gain_no_blanket_news_exception(kind):
    case = CASES["role-community-" + kind]
    assert case["expected"] == "skip"
    assert case["packet"]["sources"][0]["authority"] == "community"
    assert case["candidate"]["confidence"] == "reported"


@pytest.mark.parametrize("direction", CROSS)
def test_prior_committed_code_can_support_substantive_review_of_a_current_unmerged_patch(direction):
    base = CASES[f"role-cross-{direction}-generic"]
    with_patch = CASES[f"role-cross-{direction}-current-unmerged"]
    assert with_patch["expected"] == base["expected"] == "approve"
    assert with_patch["packet"]["sources"][0]["passages"][:3] == base["packet"]["sources"][0]["passages"]
    assert "is still unmerged" in with_patch["packet"]["sources"][0]["passages"][-1]["text"]
    assert with_patch["candidate"]["state"] == "developing"
    assert with_patch["candidate"]["confidence"] == "reported"
    assert with_patch["packet"]["sources"][0]["authority"] == "community"
    assert CASES["role-community-unmerged"]["expected"] == "skip"
    assert review.final_holds(review.personal_attribution.normalize(with_patch["candidate"]), {
        "packet": with_patch["packet"], "payload": {"editorial_kind": "feed"}}) == []


def test_contributor_proof_does_not_bypass_uncorroborated_incident_guard():
    case = CASES["role-community-contributor-unconfirmed-attack"]
    assert case["expected"] == "skip"
    assert "committed and merged into Arti" in case["packet"]["sources"][0]["passages"][-1]["text"]
    assert "untrusted_operator_claim" in review.final_holds(
        case["candidate"], {"packet": case["packet"], "payload": {"editorial_kind": "feed"}})


def test_role_policy_versions_and_prompt_hashes_change_without_new_authority_values(monkeypatch):
    assert analyze.PROMPT_VERSION == "onionflash-22"
    assert review.REVIEW_VERSION == "onionflash-review-18"
    cfg = config(False)
    before = review.policy_hash(cfg)
    monkeypatch.setattr(review, "SYSTEM_PROMPT", review.SYSTEM_PROMPT + "Changed role contract.")
    assert review.policy_hash(cfg) != before
    packet = CASES["role-cross-ctor-on-arti-generic"]["packet"]
    assert "confirmed" not in review.repair_limits(packet)["confidence"]
