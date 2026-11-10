"""Exact-candidate review protocol, immutable repairs and fresh verification."""

import copy
import json

import pytest

from onionflash import analyze, review
from onionflash.analyze import Analyzer, AnalysisError
from onionflash.config import DEFAULTS
from onionflash.render import _prepare_story
from onionflash.transport import FetchError, Response
from test_analyze import FakeLLM, completion
from test_core import analysis, item
from test_render import STORY


def config():
    result = copy.deepcopy(DEFAULTS)
    result["llm"]["base_url"] = "https://llm.example/v1"
    result["review"] = {"model": "", "timeout_seconds": 90, "connect_timeout_seconds": 10,
                        "total_timeout_seconds": 120, "max_output_tokens": 2200,
                        "max_source_chars": 24000, "max_sources": 8, "max_passages": 64,
                        "passage_chars": 1800, "max_repairs": 1, "max_cache_entries": 2000}
    return result


def candidate(**changes):
    return _prepare_story({**copy.deepcopy(STORY), **changes})


def packet():
    return {"sources": [{"id": "S1", "url": STORY["sources"][0]["url"], "title": "Release notes",
                         "kind": "rss", "authority": "official", "product": "tor",
                         "published_at": STORY["published_at"], "updated_at": STORY["updated_at"],
                         "passages": [{"id": "S1:P1", "text": "The release includes improvements for relay operators."}]}],
            "missing_sources": [], "truncated": False}


def verdict(kind="approve", *, repair=None, criterion="source_support"):
    checks = {name: {"outcome": "pass", "source_refs": ["S1:P1"], "reason": "Supported by the source."}
              for name in review.CRITERIA}
    issues = []
    if kind != "approve":
        checks[criterion]["outcome"] = "fail"
        issues = [{"criterion": criterion, "source_refs": ["S1:P1"], "explanation": "The source does not state this claim."}]
    wire_repair = None if repair is None else {key: repair.get(key) for key in review.EDITABLE}
    return {"verdict": kind, "criteria": checks, "issues": issues, "repair": wire_repair}


def reviewer(monkeypatch, *responses, settings=None):
    monkeypatch.setenv("ONIONFLASH_LLM_API_KEY", "unit-test-secret")
    result = review.Reviewer(settings or config())
    result.client = FakeLLM(*responses)
    return result


def test_normal_path_has_one_draft_and_one_exact_candidate_review(monkeypatch):
    monkeypatch.setenv("ONIONFLASH_LLM_API_KEY", "unit-test-secret")
    client = FakeLLM(completion(analysis()), completion(verdict()))
    writer, checker = Analyzer(config()), review.Reviewer(config())
    writer.client = checker.client = client
    draft = writer.analyze(item())
    public = candidate(**{key: draft[key] for key in review.EDITABLE})
    assert checker.review(public, packet())["verdict"] == "approve"
    assert len(client.requests) == 2
    request = client.requests[1][1]
    schema = request["response_format"]["json_schema"]["schema"]
    allowed = sorted(review._packet_refs(packet()))
    for check in schema["properties"]["criteria"]["properties"].values():
        assert check["properties"]["source_refs"]["items"]["enum"] == allowed
    assert "enum" not in review.REFS["items"]  # A request cannot contaminate another packet's schema.
    assert json.loads(request["messages"][1]["content"]) == {"candidate": public, "packet": packet()}


def test_repaired_path_has_three_calls_and_independent_verification(monkeypatch):
    monkeypatch.setenv("ONIONFLASH_LLM_API_KEY", "unit-test-secret")
    claim = "Operators must edit their configuration to exclude the compromised node."
    client = FakeLLM(completion(analysis(why_it_matters=claim)),
                     completion(verdict("revise", repair={"why_it_matters": ""}, criterion="operational_advice")),
                     completion(verdict()))
    writer, checker = Analyzer(config()), review.Reviewer(config())
    writer.client = checker.client = client
    draft = writer.analyze(item())
    public = candidate(**{key: draft[key] for key in review.EDITABLE})
    result = checker.review(public, packet())
    assert result["repair"] == {"why_it_matters": ""}
    repaired = review.apply_repair(public, result["repair"])
    assert checker.review(repaired, packet(), verification=True)["verdict"] == "approve"
    assert len(client.requests) == 3 and public["why_it_matters"] == claim
    request = client.requests[-1][1]
    assert len(request["messages"]) == 2
    assert request["messages"][0]["content"] == review.VERIFY_PROMPT
    assert json.loads(request["messages"][1]["content"]) == {"candidate": repaired, "packet": packet()}
    assert claim not in request["messages"][1]["content"]


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


@pytest.mark.parametrize("field", ["id", "sources", "published_at", "updated_at", "added_at", "editorial", "evidence"])
def test_repairs_cannot_modify_immutable_or_private_fields(field):
    with pytest.raises(review.ReviewError, match="immutable"):
        review.apply_repair(candidate(), {field: "changed"})


def test_repair_is_normalized_before_verification_and_preserves_public_metadata():
    public = candidate()
    repaired = review.apply_repair(public, {"summary": "  More   precise source wording.  ", "why_it_matters": ""})
    assert repaired["summary"] == "More precise source wording." and repaired["why_it_matters"] == ""
    assert all(repaired[key] == value for key, value in public.items() if key not in review.EDITABLE)
    with pytest.raises(review.ReviewError, match="does not change"):
        review.apply_repair(public, {"title": public["title"]})


@pytest.mark.parametrize("patch", [{"title": ""}, {"summary": 1}, {"products": ["unknown"]}, {"state": "approved"}, {"why_it_matters": "\ud800"}])
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
    assert review.validate_review(response, candidate(), packet())["repair"] == {"why_it_matters": ""}
    response["issues"][0]["source_refs"] = ["S9"]
    with pytest.raises(review.ReviewError, match="source reference"):
        review.validate_review(response, candidate(), packet())


@pytest.mark.parametrize("change", ["duplicate-id", "wrong-parent", "max-text", "max-passages", "invalid-utf8"])
def test_source_packet_bounds_fail_before_model_request(monkeypatch, change):
    cfg, evidence = config(), packet()
    if change == "duplicate-id":
        evidence["sources"].append(copy.deepcopy(evidence["sources"][0]))
    elif change == "wrong-parent":
        evidence["sources"][0]["passages"][0]["id"] = "S2:P1"
    elif change == "max-text":
        cfg["review"]["max_source_chars"] = 1
    elif change == "max-passages":
        cfg["review"]["max_passages"] = 1
        evidence["sources"][0]["passages"].append({"id": "S1:P2", "text": "More source text."})
    else:
        evidence["sources"][0]["passages"][0]["text"] = "\ud800"
    checker = reviewer(monkeypatch, settings=cfg)
    with pytest.raises(review.ReviewError):
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
