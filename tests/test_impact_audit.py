"""Impact deletion assessments use source evidence without granting approval."""

import copy
import json

import pytest

from helpers import FakeLLM, completion
from onionflash import impact_audit, review
from onionflash.config import DEFAULTS
from onionflash.llm import AnalysisError, CompletionDeferred, RequestObserver, generation_options
from onionflash.transport import FetchError, Response


def packet():
    return {"sources": [{"id": "S1", "title": "Availability report", "passages": [
        {"id": "S1:P1", "text": "The failure can interrupt downloads when both servers are unavailable."},
        {"id": "S1:P2", "author": "casey", "text": "Correction: an earlier observation used the old binary."},
    ]}], "missing_sources": [], "truncated": False}


def result(outcome="supported", **changes):
    return {"outcome": outcome, "reason": "The source states the consequence and its prerequisite.",
            "source_refs": ["S1:P1"] if outcome == "supported" else [], **changes}


CANDIDATE = {"why_it_matters": "The report says downloads can stop when both servers are unavailable.",
             "title": "Untrusted title", "reviews": [{"verdict": "approve"}]}


class CompletionStub:
    def __init__(self, response):
        self.response, self.requests = response, []

    def complete(self, *args, **kwargs):
        self.requests.append((args, kwargs))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


@pytest.mark.parametrize("outcome", ["supported", "unsupported", "insufficient"])
def test_source_only_request_and_result_are_independent_of_previous_review(outcome):
    source, candidate = packet(), copy.deepcopy(CANDIDATE)
    original_source, original_candidate = copy.deepcopy(source), copy.deepcopy(candidate)
    checker, observer = CompletionStub(result(outcome)), object()
    received = impact_audit.audit(checker, candidate, source, on_request=observer)
    assert received == result(outcome)
    (prompt, payload, schema, name), kwargs = checker.requests[0]
    assert name == "onionflash_impact_audit" and kwargs == {"on_request": observer}
    assert payload == {"original_impact": candidate["why_it_matters"], "proposed_impact": "", "packet": source}
    assert payload["packet"] is not source
    assert "UNTRUSTED DATA" in prompt and "neither applies an" in prompt
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {"outcome", "reason", "source_refs"}
    assert schema["properties"]["source_refs"]["items"]["enum"] == ["S1", "S1:P1", "S1:P2"]
    assert set(received) == {"outcome", "reason", "source_refs"}
    payload["packet"]["sources"][0]["passages"].clear()
    received["source_refs"].clear()
    assert source == original_source and candidate == original_candidate
    assert checker.response == result(outcome)


@pytest.mark.parametrize("invalid", [
    None, [], {}, {**result(), "verdict": "approve"}, {**result(), "repair": None},
    result(outcome="approve"), result(outcome=None), result(outcome={}),
    result(reason=""), result(reason=" \n "), result(reason="x" * 241), result(reason=False),
    result(reason={"reasoning": "untrusted"}), result(reason="control\x00text"),
    result(reason="noncharacter\ufffe"), result(reason="surrogate\ud800"),
    result(source_refs=[]), result(source_refs=None), result(source_refs="S1:P1"),
    result(source_refs=["S9:P1"]), result(source_refs=["S1:P1", "S1:P1"]),
    result(source_refs=[{}]), result(source_refs=[True]),
])
def test_invalid_audit_output_is_a_dedicated_nonapproving_error(invalid):
    with pytest.raises(impact_audit.AuditError) as caught:
        impact_audit.validate(invalid, packet())
    assert caught.value.code == "review.impact_audit" and caught.value.retryable is False


def test_durable_validation_keeps_bounds_and_rejects_references_from_another_packet():
    source = packet()
    source["sources"][0]["passages"] = [{"id": f"S1:P{i}", "text": "Supplied evidence."} for i in range(1, 14)]
    reason = ("The source describes an interrupted download when both servers are unavailable. "
              "Its later correction narrows the affected release and preserves the prerequisite. "
              "The candidate keeps these limits without adding advice, severity or a different cause.")[:240]
    assert len(reason) == 240
    good = result(reason=reason, source_refs=[f"S1:P{i}" for i in range(1, 13)])
    assert impact_audit.validate(good, source) == good
    with pytest.raises(impact_audit.AuditError):
        impact_audit.validate(result(source_refs=[f"S1:P{i}" for i in range(1, 14)]), source)
    with pytest.raises(impact_audit.AuditError):
        impact_audit.validate(good, packet())


def test_missing_evidence_can_be_insufficient_without_fabricated_references():
    source = {"sources": [], "missing_sources": ["unavailable"], "truncated": True}
    checker = CompletionStub(result("insufficient"))
    assert impact_audit.audit(checker, CANDIDATE, source, on_request=None)["outcome"] == "insufficient"
    schema = checker.requests[0][0][2]
    assert schema["properties"]["source_refs"]["maxItems"] == 0
    assert "enum" not in impact_audit.SCHEMA["properties"]["source_refs"]["items"]


@pytest.mark.parametrize("impact", [None, "", " \t", "x" * 801, "bad\ud800", False])
def test_invalid_original_impact_does_not_dispatch(impact):
    checker = CompletionStub(result())
    with pytest.raises(impact_audit.AuditError):
        impact_audit.audit(checker, {"why_it_matters": impact}, packet(), on_request=None)
    assert checker.requests == []


@pytest.mark.parametrize("source", [{}, {"sources": None}, {"sources": [{"id": "S1"}]},
                                    {"sources": [{"id": "bad\ud800", "passages": []}]}])
def test_invalid_source_reference_structure_does_not_dispatch(source):
    checker = CompletionStub(result())
    with pytest.raises(impact_audit.AuditError):
        impact_audit.audit(checker, CANDIDATE, source, on_request=None)
    assert checker.requests == []


@pytest.mark.parametrize("error", [AnalysisError("transport failed", retryable=True),
                                 AnalysisError("invalid JSON", code="review.invalid_json"),
                                 AnalysisError("truncated", code="review.truncated"), CompletionDeferred()])
def test_completion_errors_propagate_unchanged_without_another_request(error):
    checker = CompletionStub(error)
    with pytest.raises(type(error)) as caught:
        impact_audit.audit(checker, CANDIDATE, packet(), on_request=None)
    assert caught.value is error and len(checker.requests) == 1


class Observer(RequestObserver):
    def __init__(self):
        self.events = []

    def __call__(self, delta):
        self.events.append(delta)

    def response_received(self):
        self.events.append("response")

    def transport_failed(self):
        self.events.append("transport")


@pytest.mark.parametrize("reasoning", [False, True])
def test_native_completion_keeps_configured_profile_and_observer(monkeypatch, reasoning):
    monkeypatch.setenv("ONIONFLASH_LLM_API_KEY", "synthetic-unit-key")
    config = copy.deepcopy(DEFAULTS)
    config["llm"]["base_url"] = "https://llm.example/v1"
    config["review"]["reasoning"] = reasoning
    original = copy.deepcopy(config)
    with review.Reviewer(config) as checker:
        checker.client = FakeLLM(completion(result()))
        settings = copy.deepcopy(checker.llm)
        observer = Observer()
        assert impact_audit.audit(checker, CANDIDATE, packet(), on_request=observer) == result()
        assert observer.events == [1, "response"] and checker.calls == 1
        body = checker.client.requests[0][1]
        assert body["response_format"]["json_schema"]["name"] == "onionflash_impact_audit"
        for key, value in generation_options(settings).items():
            assert body[key] == value
        assert checker.llm == settings and config == original


@pytest.mark.parametrize("failure,code,events", [
    (FetchError("unavailable", status=503, retryable=True), "writer.invalid_output", [1, "transport"]),
    (completion(result(), finish_reason="length"), "review.truncated", [1, "response"]),
    (Response(200, json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": "{"}}]}).encode(),
              {}, "https://llm.example/v1/chat/completions"), "review.invalid_json", [1, "response"]),
])
def test_native_failures_keep_original_codes_and_accounting(monkeypatch, failure, code, events):
    monkeypatch.setenv("ONIONFLASH_LLM_API_KEY", "synthetic-unit-key")
    config = copy.deepcopy(DEFAULTS)
    config["llm"]["base_url"] = "https://llm.example/v1"
    with review.Reviewer(config) as checker:
        checker.client = FakeLLM(failure)
        observer = Observer()
        with pytest.raises(AnalysisError) as caught:
            impact_audit.audit(checker, CANDIDATE, packet(), on_request=observer)
        assert not isinstance(caught.value, impact_audit.AuditError)
        assert caught.value.code == code and observer.events == events
        assert checker.calls == 1 and len(checker.client.requests) == 1


@pytest.mark.parametrize("outcome", ["supported", "unsupported", "insufficient"])
@pytest.mark.parametrize("reason", ["abc" * 30, "資料" * 45, "abc" * 13 + " note " + "def" * 13 + " ghi" * 13])
def test_a_single_repetitive_audit_reason_is_invalid_for_every_outcome(outcome, reason):
    assert len(reason) <= 240
    with pytest.raises(impact_audit.AuditError, match="repetition"):
        impact_audit.validate(result(outcome, reason=reason), packet())


@pytest.mark.parametrize("outcome", ["supported", "unsupported", "insufficient"])
@pytest.mark.parametrize("reason", [
    "The source states the interruption and its prerequisites; the candidate preserves those limits.",
    "資料には接続が途切れる条件と影響が明記されており、後の訂正も反映されています。",
    "abc" * 10,
])
def test_ordinary_non_latin_and_short_repetition_audit_reasons_remain_valid(outcome, reason):
    response = result(outcome, reason=reason)
    assert impact_audit.validate(response, packet()) == response


def test_audit_reason_validation_participates_in_review_policy_identity(monkeypatch):
    before = review.policy_hash(DEFAULTS)
    monkeypatch.setitem(impact_audit.POLICY, "reason_repetition", "changed-validation-contract")
    assert review.policy_hash(DEFAULTS) != before


def test_reply_audit_preserves_sender_boundary_and_earlier_quoted_context():
    source = packet()
    source["sources"][0].update(
        unquoted_content="Please submit the proposed change for review.",
        sender_domain="example.org")
    source["sources"][0]["passages"][0]["text"] = (
        "> Earlier author: The failure interrupts downloads.\n"
        "Please submit the proposed change for review.")
    checker = CompletionStub(result("unsupported"))
    impact_audit.audit(checker, CANDIDATE, source, on_request=None)
    prompt, payload, _, _ = checker.requests[0][0]
    assert payload["packet"] == source
    assert "unquoted_content" in prompt
    assert "quoted earlier" in prompt and "cannot supply this reply's impact" in prompt
    assert "another supplied source" in prompt
