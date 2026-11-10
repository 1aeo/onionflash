"""Model output validation, endpoint failure handling, grounding pass and the rejected state."""

from __future__ import annotations

import copy
import json

import pytest

from onionflash.analyze import AnalysisError, Analyzer, validate_analysis
from onionflash.config import DEFAULTS
from onionflash.store import Store
from onionflash.transport import FetchError, Response
from test_core import DATE, analysis, item


def completion(result: dict, finish_reason: str = "stop") -> Response:
    body = {"choices": [{"finish_reason": finish_reason, "message": {"content": json.dumps(result)}}]}
    return Response(200, json.dumps(body).encode(), {}, "https://llm.example/v1/chat/completions")


class FakeLLM:
    def __init__(self, *responses):
        self.responses, self.requests = list(responses), []

    def request(self, method, url, headers=None, json_body=None):
        self.requests.append((url, json_body))
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    def close(self):
        pass


def analyzer(monkeypatch, *responses, fallbacks=()):
    monkeypatch.setenv("ONIONFLASH_LLM_API_KEY", "test-key")
    config = copy.deepcopy(DEFAULTS)
    config["llm"].update(base_url="https://llm.example/v1", fallback_base_urls=list(fallbacks))
    result = Analyzer(config)
    result.client = FakeLLM(*responses)
    return result


def grounded(**changes):
    text = {key: analysis()[key] for key in ("title", "summary", "why_it_matters")}
    return {"unsupported": [], **text, **changes}


def test_grounding_pass_replaces_unsupported_text(monkeypatch):
    claim = "Operators must update their configurations to exclude the node."
    revised = "Scope and consequences remain subject to the linked upstream discussion."
    llm = analyzer(monkeypatch, completion(analysis(why_it_matters=claim)),
                   completion(grounded(unsupported=[claim], why_it_matters=revised)))
    result = llm.analyze(item())
    assert result["why_it_matters"] == revised
    draft, check = (body for _, body in llm.client.requests)
    assert check["response_format"]["json_schema"]["name"] == "onionflash_grounding"
    sent = json.loads(check["messages"][1]["content"])
    assert sent["draft"]["why_it_matters"] == claim and sent["source"]["content"] == item()["content"]


def test_grounding_rewrite_must_still_pass_validation(monkeypatch):
    # The failed check gets one repair round; a repair that still fails is rejected.
    llm = analyzer(monkeypatch, completion(analysis()), completion(grounded(why_it_matters="")),
                   completion(grounded(why_it_matters="")))
    with pytest.raises(AnalysisError, match="needs text") as caught:
        llm.analyze(item())
    assert not caught.value.retryable
    assert len(llm.client.requests) == 3
    assert "needs text" in json.loads(llm.client.requests[2][1]["messages"][1]["content"])["problem"]
    # A repair call that itself returns garbage keeps the original reason.
    llm = analyzer(monkeypatch, completion(analysis()), completion(grounded(why_it_matters="")),
                   completion({"verdict": "fine"}))
    with pytest.raises(AnalysisError, match="needs text"):
        llm.analyze(item())
    llm = analyzer(monkeypatch, completion(analysis()), completion({"verdict": "fine"}))
    with pytest.raises(AnalysisError, match="grounding check") as caught:
        llm.analyze(item())
    assert not caught.value.retryable


def test_a_statement_the_check_flags_but_keeps_is_rejected(monkeypatch):
    claim = "Operators must update their configurations to exclude the node."
    kept = grounded(unsupported=[claim], why_it_matters=claim)
    llm = analyzer(monkeypatch, completion(analysis(why_it_matters=claim)), completion(kept),
                   completion(grounded(why_it_matters=claim)))
    with pytest.raises(AnalysisError, match="left this flagged statement unchanged") as caught:
        llm.analyze(item())
    assert not caught.value.retryable
    # The repair round was told which statement it kept.
    assert claim in json.loads(llm.client.requests[2][1]["messages"][1]["content"])["problem"]
    # Editing a different sentence of the same field does not fix the flagged one.
    partly = grounded(unsupported=[claim], why_it_matters="The report concerns trust. " + claim)
    llm = analyzer(monkeypatch, completion(analysis(why_it_matters="It matters. " + claim)), completion(partly),
                   completion(partly))
    with pytest.raises(AnalysisError, match="left this flagged statement unchanged"):
        llm.analyze(item())


def test_one_repair_round_fixes_exactly_the_failed_check(monkeypatch):
    draft = analysis(title="Operator removed the affected keys after reported compromise")
    fixed = "Operator reports possible compromise and stops trusting its keys"
    llm = analyzer(monkeypatch, completion(draft), completion(grounded(title=draft["title"])),
                   completion(grounded(title=fixed)))
    assert llm.analyze(item())["title"] == fixed
    problem = json.loads(llm.client.requests[2][1]["messages"][1]["content"])["problem"]
    assert problem == "The title says 'removed', a completed action the source does not state"


def test_attributing_a_flagged_statement_to_the_source_does_not_fix_it(monkeypatch):
    claim = "Operators must update their configurations to exclude the node."
    attributed = "According to the report, operators must update their configurations to exclude the node."
    llm = analyzer(monkeypatch, completion(analysis(why_it_matters=claim)),
                   completion(grounded(unsupported=[claim], why_it_matters=attributed)),
                   completion(grounded(why_it_matters=attributed)))
    with pytest.raises(AnalysisError, match="left this flagged statement unchanged"):
        llm.analyze(item())


def test_a_qualifier_inside_the_flagged_claim_does_not_excuse_it():
    from onionflash.analyze import _kept_claim
    claim = "Operators may need to rotate keys."
    draft = {"title": "t", "summary": claim, "why_it_matters": "w"}
    copied = {**draft, "title": "New title"}
    attributed = {**draft, "summary": "According to the report, operators may need to rotate keys."}
    assert _kept_claim([claim], [draft], copied) == claim
    assert _kept_claim([claim], [draft], attributed) == claim  # the claim's own "may" is not a hedge
    hedged = {**draft, "summary": "It is unclear whether operators may need to rotate keys."}
    assert _kept_claim([claim], [draft], hedged) is None


def test_a_short_flagged_statement_removed_once_may_not_come_back():
    from onionflash.analyze import _kept_claim
    draft = {"title": "t", "summary": "The issue reports a crash. No fix.", "why_it_matters": "w"}
    first = {**draft, "summary": "The issue reports a crash."}
    assert _kept_claim(["No fix."], [draft], first) is None
    assert _kept_claim(["No fix."], [draft, first], draft) == "No fix."
    hedged = {**draft, "summary": "The issue reports a crash. It is unclear whether there is no fix."}
    assert _kept_claim(["No fix."], [draft, first], hedged) is None
    # Whole words only: "confirmed" inside "unconfirmed" is not the flagged word.
    assert _kept_claim(["confirmed compromise"], [draft], {**draft, "summary": "An unconfirmed compromise."}) is None


def test_a_flagged_statement_may_be_reworded_with_the_same_words(monkeypatch):
    claim = "plausible compromise of all relays"
    for rewrite in ("The report does not say whether this is a plausible compromise of all relays.",
                    "It is unclear whether this is a plausible compromise of all relays."):
        draft = analysis(summary="The operator reported a plausible compromise of all relays.")
        llm = analyzer(monkeypatch, completion(draft), completion(grounded(unsupported=[claim], summary=rewrite)))
        assert llm.analyze(item())["summary"] == rewrite


def test_ignore_decision_makes_one_call_and_skips_field_checks(monkeypatch):
    ignore = analysis(publish=False, title="x" * 150, evidence=["not in the source at all"])
    llm = analyzer(monkeypatch, completion(ignore))
    assert llm.analyze(item())["publish"] is False
    assert len(llm.client.requests) == 1


def test_endpoint_failures_are_retryable_and_validation_is_not_resent(monkeypatch):
    llm = analyzer(monkeypatch, FetchError("HTTP 401", status=401))
    with pytest.raises(AnalysisError, match="HTTP 401") as caught:
        llm.analyze(item())
    assert caught.value.retryable  # a rejected credential stops the run, not the item
    bad = analysis(evidence=["words the source never says"])
    llm = analyzer(monkeypatch, completion(bad), fallbacks=["https://fallback.example/v1"])
    with pytest.raises(AnalysisError, match="evidence") as caught:
        llm.analyze(item())
    assert not caught.value.retryable and len(llm.client.requests) == 1
    llm = analyzer(monkeypatch, FetchError("network request failed", retryable=True),
                   completion(analysis()), completion(grounded()), fallbacks=["https://fallback.example/v1"])
    assert llm.analyze(item())["title"] == analysis()["title"]
    assert [url for url, _ in llm.client.requests][0].startswith("https://llm.example")


def test_truncated_and_malformed_completions(monkeypatch):
    llm = analyzer(monkeypatch, completion(analysis(), finish_reason="length"))
    with pytest.raises(AnalysisError, match="truncated") as caught:
        llm.analyze(item())
    assert not caught.value.retryable
    llm = analyzer(monkeypatch, Response(200, b'{"error": "busy"}', {}, "https://llm.example/v1"))
    with pytest.raises(AnalysisError, match="unexpected response") as caught:
        llm.analyze(item())
    assert caught.value.retryable


def test_evidence_matching_ignores_typography_and_case_but_not_emptiness():
    source = item(content="It’s a security release — operators should upgrade.")
    for quote in ["It's a security release", "it’s A SECURITY release", "release - operators should"]:
        validate_analysis(analysis(evidence=[quote]), source)
    for quote in [" " * 8, "release", "not a quote from the source"]:
        with pytest.raises(AnalysisError, match="evidence"):
            validate_analysis(analysis(evidence=[quote]), source)


def test_hedged_issue_wording_is_not_a_completed_action():
    source = item(title="Remove bastet", content="Bastet should be removed from the authority list.")
    for summary in ["The issue asks that bastet be removed.", "Bastet has not been removed yet.",
                    "The key has not been rotated."]:
        validate_analysis(analysis(summary=summary, evidence=["Bastet should be removed"]), source)
    with pytest.raises(AnalysisError, match="completed action"):
        validate_analysis(analysis(summary="Tor has removed bastet.", evidence=["Bastet should be removed"]), source)


def test_items_are_rejected_after_three_failures_and_requeued_when_content_changes(tmp_path):
    llm = DEFAULTS["llm"]
    with Store(tmp_path / "state.db") as store:
        store.ingest(item(), DATE)
        row_id = store.pending(1, DATE)[0]["id"]
        for _ in range(4):  # endpoint failures (retryable) never count toward rejection
            store.defer(row_id, "LLM request failed (HTTP 503)", llm, DATE, terminal=False)
        for _ in range(2):
            store.defer(row_id, "Model evidence is not present in source", llm, DATE, terminal=True)
        assert store.db.execute("SELECT status FROM items WHERE id=?", (row_id,)).fetchone()[0] == "pending"
        store.defer(row_id, "Model evidence is not present in source", llm, DATE, terminal=True)
        status = store.db.execute("SELECT status, attempts, rejections FROM items WHERE id=?", (row_id,)).fetchone()
        assert tuple(status) == ("rejected", 7, 3) and store.rejected_count() == 1 and store.pending_count() == 0
        store.ingest(item(content="Edited: the operator now confirms the compromise."), DATE)
        status = store.db.execute("SELECT status, attempts, rejections FROM items WHERE id=?", (row_id,)).fetchone()
        assert tuple(status) == ("pending", 0, 0) and store.rejected_count() == 0


def test_one_failing_item_does_not_stop_the_run_but_two_endpoint_failures_do(tmp_path, monkeypatch):
    from onionflash import cli
    calls = []

    class FlakyAnalyzer:
        def __init__(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def analyze(self, payload):
            calls.append(payload["url"])
            if payload["url"].endswith("/bad") or failing_endpoint:
                raise AnalysisError("LLM request failed (HTTP 400)", retryable=True)
            return analysis()

    monkeypatch.setattr(cli, "Analyzer", FlakyAnalyzer)
    monkeypatch.setattr(cli, "build", lambda *args: {})
    config = copy.deepcopy(DEFAULTS)
    config["sources"] = []
    for failing_endpoint, expected in [(False, 3), (True, 2)]:
        calls.clear()
        with Store(tmp_path / f"state-{failing_endpoint}.db") as store:
            for url in ["https://example.org/bad", "https://example.org/a", "https://example.org/b"]:
                store.ingest(item(url=url, content=url, labels=["Security"] if url.endswith("bad") else []), DATE)
            cli.run(config, store)
        assert len(calls) == expected
