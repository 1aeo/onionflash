"""Exact-candidate review protocol, immutable repairs and fresh verification."""

import copy
import json

import pytest

from approval_helpers import verdict
from onionflash import analyze, review
from onionflash.analyze import AnalysisError
from onionflash.config import DEFAULTS
from onionflash.render import _prepare_story
from onionflash.transport import FetchError, Response
from test_analyze import FakeLLM, completion
from test_render import STORY


def config():
    result = copy.deepcopy(DEFAULTS)
    result["llm"]["base_url"] = "https://llm.example/v1"
    return result


def candidate(**changes):
    return _prepare_story({**copy.deepcopy(STORY), **changes})


def packet():
    return {"sources": [{"id": "S1", "url": STORY["sources"][0]["url"], "title": "Release notes",
                         "kind": "rss", "authority": "official", "product": "tor",
                         "published_at": STORY["published_at"], "updated_at": STORY["updated_at"],
                         "passages": [{"id": "S1:P1", "text": "The release includes improvements for relay operators."}]}],
            "missing_sources": [], "truncated": False}


def reviewer(monkeypatch, *responses, settings=None):
    monkeypatch.setenv("ONIONFLASH_LLM_API_KEY", "unit-test-secret")
    result = review.Reviewer(settings or config())
    result.client = FakeLLM(*responses)
    return result


def test_review_and_its_fresh_verification_send_only_the_exact_candidate_and_packet(monkeypatch):
    public = candidate(why_it_matters="Operators must edit their configuration to exclude the compromised node.")
    checker = reviewer(monkeypatch, completion(verdict("revise", repair={"why_it_matters": ""})), completion(verdict()))
    result = checker.review(public, packet())
    assert result["repair"] == {"why_it_matters": ""}  # The reply's null fields are not edits.
    repaired = review.apply_repair(public, result["repair"])
    assert checker.review(repaired, packet(), verification=True)["verdict"] == "approve"
    first, second = (body for _, body in checker.client.requests)
    for check in first["response_format"]["json_schema"]["schema"]["properties"]["criteria"]["properties"].values():
        assert check["properties"]["source_refs"]["items"]["enum"] == sorted(review._packet_refs(packet()))
    assert "enum" not in review.REFS["items"]  # A request cannot contaminate another packet's schema.
    assert json.loads(first["messages"][1]["content"]) == {"candidate": public, "packet": packet()}
    # Verification starts afresh: its own prompt and the repaired text, never the earlier reply.
    assert len(second["messages"]) == 2 and second["messages"][0]["content"] == review.VERIFY_PROMPT
    assert json.loads(second["messages"][1]["content"]) == {"candidate": repaired, "packet": packet()}


@pytest.mark.parametrize("bad", ["source-ref", "pass-with-issues", "failed-criterion", "changed-text", "missing-criterion", "missing-refs", "score", "unknown-verdict"])
def test_malformed_or_ambiguous_approval_is_rejected(monkeypatch, bad):
    response = verdict()
    if bad == "source-ref":
        response["criteria"]["source_support"]["source_refs"] = ["S2:P99"]
    elif bad == "pass-with-issues":
        response["issues"] = [{"criterion": "source_support", "explanation": "Unsupported", "source_refs": ["S1:P1"]}]
    elif bad == "failed-criterion":
        response["criteria"]["source_support"]["outcome"] = "fail"
    elif bad == "changed-text":
        response["repair"] = {key: None for key in review.EDITABLE}
    elif bad == "missing-criterion":
        del response["criteria"]["technical_details"]
    elif bad == "missing-refs":
        response["criteria"]["source_support"]["source_refs"] = []
    elif bad == "score":
        response["score"] = 10
    else:
        response["verdict"] = "probably"
    checker = reviewer(monkeypatch, completion(response))
    with pytest.raises(review.ReviewError):
        checker.review(candidate(), packet())
    assert len(checker.client.requests) == 1


def test_approval_is_not_rewritten_or_reclassified(monkeypatch):
    public = candidate(confidence="suspected", state="developing", why_it_matters="")
    before = copy.deepcopy(public)
    response = reviewer(monkeypatch, completion(verdict())).review(public, packet())
    assert response["verdict"] == "approve" and public == before


@pytest.mark.parametrize("action", ["revise", "hold", "skip"])
@pytest.mark.parametrize("long_reason", [False, True])
def test_refusal_issues_conservatively_override_pass_checks_without_mutating_input(action, long_reason):
    """A stated problem may downgrade a refusal's check, never authorize publication."""
    criterion = "news_value" if action == "skip" else "technical_details"
    response = verdict(action, criterion=criterion, repair={"tags": ["release"]} if action == "revise" else None)
    response["criteria"][criterion]["outcome"] = "pass"
    issue = response["issues"][0]
    issue["source_refs"] = ["S1:P1"]
    issue["explanation"] = "Security classification is unsupported." if not long_reason else "Unsupported classification. " * 8
    original = copy.deepcopy(response)
    normalized = review.validate_review(response, packet())
    check = normalized["criteria"][criterion]
    assert normalized["verdict"] == action and check["outcome"] == "fail"
    assert check["source_refs"] == issue["source_refs"]
    assert 0 < len(check["reason"]) <= review.CHECK["properties"]["reason"]["maxLength"]
    if not long_reason:
        assert check["reason"] == issue["explanation"]
    if action == "revise":
        assert normalized["repair"] == {"tags": ["release"]}
    assert response == original
    normalized["issues"][0]["source_refs"].clear()
    normalized["criteria"][criterion]["source_refs"].clear()
    assert response == original


@pytest.mark.parametrize("problem", ["approve", "bad-reference", "unexplained-failure", "unknown-criterion"])
def test_issue_reconciliation_preserves_fail_closed_review_rules(problem):
    """Contradictory critiques cannot bypass approval, reference or completeness checks."""
    response = verdict("revise", criterion="technical_details", repair={"tags": ["release"]})
    response["criteria"]["technical_details"]["outcome"] = "pass"
    if problem == "approve":
        response.update(verdict="approve", repair=None)
    elif problem == "bad-reference":
        response["issues"][0]["source_refs"] = ["S9:P99"]
    elif problem == "unexplained-failure":
        response["criteria"]["source_support"]["outcome"] = "fail"
    else:
        response["issues"][0]["criterion"] = "invented"
    original = copy.deepcopy(response)
    with pytest.raises(review.ReviewError):
        review.validate_review(response, packet())
    assert response == original


def test_issue_reconciliation_never_upgrades_existing_failed_or_insufficient_checks():
    """Existing refusal reasons retain their outcomes and evidence during normalization."""
    for outcome in ("fail", "insufficient"):
        response = verdict("hold", criterion="technical_details")
        response["criteria"]["technical_details"]["outcome"] = outcome
        prior = copy.deepcopy(response["criteria"]["technical_details"])
        normalized = review.validate_review(response, packet())
        assert normalized["criteria"]["technical_details"] == prior


def test_repairs_can_clear_but_cannot_generate_an_impact_paragraph(monkeypatch):
    """Model repairs may remove legacy commentary without creating new advice."""
    public = candidate(why_it_matters="Existing commentary")
    assert review.apply_repair(public, {"why_it_matters": ""})["why_it_matters"] == ""
    with pytest.raises(review.ReviewError):
        review.apply_repair(public, {"why_it_matters": "Operators must upgrade immediately."})
    checker = reviewer(monkeypatch, completion(verdict()))
    checker.review(public, packet())
    schema = checker.client.requests[0][1]["response_format"]["json_schema"]["schema"]
    field = schema["properties"]["repair"]["anyOf"][1]["properties"]["why_it_matters"]
    assert field["anyOf"][0]["enum"] == [""] and field["anyOf"][1] == {"type": "null"}


def test_editorial_coverage_is_background_and_never_an_evidence_reference(monkeypatch):
    """Keep coverage separate from the packet IDs allowed as factual evidence."""
    public = candidate()
    background = {"prior_story": None, "recent": [{"id": "B1", "title": "Earlier coverage"}], "truncated": False}
    checker = reviewer(monkeypatch, completion(verdict()), completion(verdict()))
    checker.review(public, packet(), coverage=background)
    checker.review(public, packet(), coverage=background, verification=True)
    for _, request in checker.client.requests:
        assert json.loads(request["messages"][1]["content"]) == {
            "candidate": public, "packet": packet(), "coverage_background": background}
        fields = request["response_format"]["json_schema"]["schema"]["properties"]["criteria"]["properties"]
        assert set(fields) == set(review.CRITERIA)
        assert "news_value" in fields and "new_information" in fields
        for check in fields.values():
            assert check["properties"]["source_refs"]["items"]["enum"] == ["S1", "S1:P1"]
    forged = verdict("skip", criterion="new_information", ref="B1")
    with pytest.raises(review.ReviewError, match="source reference"):
        reviewer(monkeypatch, completion(forged)).review(public, packet(), coverage=background)


@pytest.mark.parametrize("criterion", ["news_value", "new_information"])
@pytest.mark.parametrize("outcome", ["fail", "insufficient"])
def test_editorial_skip_requires_a_recorded_editorial_failure(criterion, outcome):
    """Require a failed selection criterion before accepting a skip verdict."""
    response = verdict("skip", criterion=criterion)
    response["criteria"][criterion]["outcome"] = outcome
    result = review.validate_review(response, packet())
    assert result["verdict"] == "skip" and result["repair"] is None


def test_skip_can_record_factual_defects_without_polishing_non_news():
    response = verdict("skip", criterion="new_information")
    response["criteria"]["source_support"]["outcome"] = "fail"
    response["issues"].append({"criterion": "source_support", "explanation": "The draft overstates a repeated report.", "source_refs": ["S1:P1"]})
    assert review.validate_review(response, packet())["verdict"] == "skip"


def test_factual_failure_alone_is_not_an_editorial_skip():
    with pytest.raises(review.ReviewError, match="editorial criterion"):
        review.validate_review(verdict("skip", criterion="source_support"), packet())


def test_skip_cannot_repair_text_or_omit_its_issues():
    response = verdict("skip", criterion="news_value", repair={"summary": "Different text"})
    with pytest.raises(review.ReviewError, match="Only a revise"):
        review.validate_review(response, packet())
    response = verdict("skip", criterion="news_value")
    response["issues"] = []
    with pytest.raises(review.ReviewError, match="every failed criterion"):
        review.validate_review(response, packet())


@pytest.mark.parametrize("criterion", ["news_value", "new_information"])
def test_all_nine_criteria_are_required_for_approval(criterion):
    response = verdict()
    del response["criteria"][criterion]
    with pytest.raises(review.ReviewError, match="fields do not match"):
        review.validate_review(response, packet())
    response = verdict("skip", criterion=criterion)
    response["verdict"] = "approve"
    with pytest.raises(review.ReviewError, match="all criteria"):
        review.validate_review(response, packet())


def test_fresh_verification_can_skip_a_duplicate_without_proposing_a_repair(monkeypatch):
    """Permit final duplicate rejection while forbidding an accompanying rewrite."""
    response = verdict("skip", criterion="new_information")
    checker = reviewer(monkeypatch, completion(response))
    result = checker.review(candidate(), packet(), coverage={"prior_story": candidate(), "recent": [], "truncated": False}, verification=True)
    assert result["verdict"] == "skip" and result["repair"] is None
    assert checker.client.requests[0][1]["messages"][0]["content"] == review.VERIFY_PROMPT


def test_repairs_cannot_modify_immutable_or_private_fields():
    with pytest.raises(review.ReviewError, match="immutable"):
        review.apply_repair(candidate(), {"sources": "changed"})


def test_repair_is_normalized_before_verification_and_preserves_public_metadata():
    public = candidate()
    repaired = review.apply_repair(public, {"summary": "  More   precise source wording.  ", "why_it_matters": ""})
    assert repaired["summary"] == "More precise source wording." and repaired["why_it_matters"] == ""
    assert all(repaired[key] == value for key, value in public.items() if key not in review.EDITABLE)
    with pytest.raises(review.ReviewError, match="does not change"):
        review.apply_repair(public, {"title": public["title"]})


@pytest.mark.parametrize("patch", [{"title": ""}, {"summary": 1}, {"products": ["unknown"]}, {"state": "approved"}])
def test_invalid_semantic_repairs_fail_closed(patch):
    with pytest.raises(review.ReviewError):
        review.apply_repair(candidate(), patch)


def test_final_verification_nonapproval_is_an_explicit_verdict_for_the_gate(monkeypatch):
    checker = reviewer(monkeypatch, completion(verdict("revise", repair={"why_it_matters": ""})))
    public = candidate()
    revised = checker.review(public, packet(), verification=True)
    assert revised["verdict"] == "revise" and public == candidate()
    # The durable gate holds this verdict and never applies a second repair.
    held = reviewer(monkeypatch, completion(verdict("hold"))).review(candidate(), packet(), verification=True)
    assert held["verdict"] == "hold" and held["repair"] is None


def test_cached_api_response_validation_checks_refs_and_sparse_repairs():
    response = verdict("revise", repair={"why_it_matters": ""})
    response["repair"] = {"why_it_matters": ""}
    assert review.validate_review(response, packet())["repair"] == {"why_it_matters": ""}
    response["issues"][0]["source_refs"] = ["S9"]
    with pytest.raises(review.ReviewError, match="source reference"):
        review.validate_review(response, packet())


def test_reviewer_sends_app_built_packet_text_without_rechecking_it(monkeypatch):
    # Rows stored before line endings were normalized can still carry a carriage return.
    evidence = packet()
    evidence["sources"][0]["passages"][0]["text"] += "\r\nA second line."
    assert reviewer(monkeypatch, completion(verdict())).review(candidate(), evidence)["verdict"] == "approve"
    evidence["sources"][0]["passages"][0]["text"] = "\ud800"
    checker = reviewer(monkeypatch)
    with pytest.raises(AnalysisError, match="UTF-8"):  # the request's own check still applies
        checker.review(candidate(), evidence)
    assert checker.client.requests == []


def test_duplicate_verdict_and_truncated_review_are_never_approved(monkeypatch):
    encoded = json.dumps(verdict()).replace('{"verdict":', '{"verdict":"hold","verdict":', 1)
    raw = {"choices": [{"finish_reason": "stop", "message": {"content": encoded}}]}
    checker = reviewer(monkeypatch, Response(200, json.dumps(raw).encode(), {}, "https://llm.example/v1"))
    with pytest.raises(AnalysisError, match="invalid JSON") as caught:
        checker.review(candidate(), packet())
    assert not caught.value.retryable  # a strike against the item, as for the writer
    checker = reviewer(monkeypatch, completion(verdict(), finish_reason="length"))
    with pytest.raises(AnalysisError, match="truncated") as caught:
        checker.review(candidate(), packet())
    assert not caught.value.retryable


def test_review_reuses_endpoint_fallback_and_effective_timeout_policy(monkeypatch):
    cfg = config()
    cfg["llm"]["fallback_base_urls"] = ["https://fallback.example/v1"]
    cfg["review"].update(model="review-model", timeout_seconds=180)
    checker = reviewer(monkeypatch, FetchError("unavailable", status=503), completion(verdict()), settings=cfg)
    assert checker.review(candidate(), packet())["verdict"] == "approve"
    assert [url for url, _ in checker.client.requests] == ["https://llm.example/v1/chat/completions", "https://fallback.example/v1/chat/completions"]
    assert checker.client.requests[-1][1]["model"] == "review-model"
    assert checker.http_settings["total_timeout_seconds"] == 120
    assert checker.http_settings["retry_attempts"] == 1


def test_review_client_receives_shared_absolute_deadline(monkeypatch):
    monkeypatch.setenv("ONIONFLASH_LLM_API_KEY", "unit-test-secret")
    fake = FakeLLM(completion(verdict()))
    monkeypatch.setattr(analyze, "HttpClient", lambda *args, **kwargs: fake)
    with review.Reviewer(config(), deadline=123.5) as checker:
        checker.review(candidate(), packet())
        assert fake.deadline == 123.5


def test_policy_hash_binds_effective_model_endpoint_sources_but_not_credentials(monkeypatch):
    cfg = config()
    initial = review.policy_hash(cfg)
    monkeypatch.setenv("ONIONFLASH_LLM_API_KEY", "a-different-secret")
    assert review.policy_hash(cfg) == initial
    for section, key, value in [("llm", "model", "another-model"), ("llm", "base_url", "https://other.example/v1"),
                                ("review", "max_source_chars", 12000), ("review", "model", "review-only")]:
        changed = copy.deepcopy(cfg)
        changed[section][key] = value
        assert review.policy_hash(changed) != initial


@pytest.mark.parametrize("name", ["COVERAGE_ROWS", "COVERAGE_CHARS", "COVERAGE_SUMMARY_CHARS"])
def test_policy_hash_binds_coverage_limits(monkeypatch, name):
    cfg = config()
    initial = review.policy_hash(cfg)
    monkeypatch.setattr(review.candidate_policy, name, getattr(review.candidate_policy, name) + 1)
    assert review.policy_hash(cfg) != initial
