"""Draft schema/evidence, shared transport, retained baseline checks and rejection."""

from __future__ import annotations

from approval_helpers import ApprovingReviewer
import copy
import json

import pytest

from onionflash.analyze import AnalysisError, Analyzer, MIN_EVIDENCE_CHARS, _writer_schema, tag_notice, validate_analysis
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


def test_a_qualifier_must_belong_to_the_claims_own_clause():
    from onionflash.analyze import _kept_claim
    claim = "Operators must update their configurations to exclude the node."
    draft = {"title": "t", "summary": claim, "why_it_matters": "w"}
    elsewhere = {**draft, "summary": "It is unclear whether the node is compromised, but operators must "
                                      "update their configurations to exclude the node."}
    assert _kept_claim([claim], [draft], elsewhere) == claim
    after = {**draft, "summary": "The report says operators must update their configurations to exclude "
                                  "the node is unconfirmed."}
    assert _kept_claim([claim.rstrip(".")], [draft], after) is None


def test_a_short_flagged_statement_left_unchanged_is_kept():
    from onionflash.analyze import _kept_claim
    draft = {"title": "t", "summary": "The patch is merged. Safe.", "why_it_matters": "w"}
    assert _kept_claim(["Safe."], [draft], {**draft, "title": "New title"}) == "Safe."






def test_non_finite_numbers_are_invalid_model_json():
    from onionflash.analyze import _json_object
    for text in ('{"publish": false, "priority": NaN}', '{"publish": false, "x": 1e999}'):
        with pytest.raises(AnalysisError, match="invalid JSON"):
            _json_object(text)


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
                   completion(analysis()), fallbacks=["https://fallback.example/v1"])
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


@pytest.mark.parametrize("noncharacter", ["\ufffe", "\uffff"])
def test_draft_text_that_publishing_would_drop_is_a_strike_before_review(noncharacter):
    # Rendering removes U+FFFE and U+FFFF, so this headline would publish empty.
    with pytest.raises(AnalysisError, match="Invalid model title") as caught:
        validate_analysis(analysis(title=f" {noncharacter} "), item(), editorial=False)
    assert not caught.value.retryable


def test_evidence_matching_ignores_typography_and_case_but_not_emptiness():
    source = item(content="It’s a security release — operators should upgrade.")
    for quote in ["It's a security release", "it’s A SECURITY release", "release - operators should"]:
        validate_analysis(analysis(evidence=[quote]), source)
    for quote in [" " * 8, "release", "not a quote from the source"]:
        with pytest.raises(AnalysisError, match="evidence"):
            validate_analysis(analysis(evidence=[quote]), source)


@pytest.mark.parametrize("body,quote", [
    ('The result is **available** under "policy beta".', 'The result is **available** under "policy beta".'),
    ('> An earlier report spans\n> two quoted source lines.', 'An earlier report spans\n> two quoted source lines.'),
    ('The `sample_metric` counter remains unchanged.', 'The `sample_metric` counter remains unchanged.'),
])
def test_literal_evidence_preserves_source_formatting(body, quote):
    result = validate_analysis(analysis(evidence=[quote]), item(content=body), editorial=False)
    assert result["evidence"] == [quote]


@pytest.mark.parametrize("body,quote", [
    ('The result is **available** under the policy.', 'The result is available under the policy.'),
    ('The result uses "policy beta".', "The result uses 'policy beta'."),
    ('> An earlier report spans\n> two quoted source lines.', 'An earlier report spans two quoted source lines.'),
    ('The `sample_metric` counter remains unchanged.', 'The sample_metric counter remains unchanged.'),
    ('The old keys are not trusted.', 'The old keys are trusted.'),
])
def test_model_reformatting_or_changed_words_are_still_not_literal_evidence(body, quote):
    with pytest.raises(AnalysisError, match="not an exact excerpt"):
        validate_analysis(analysis(evidence=[quote]), item(content=body), editorial=False)


def test_evidence_diagnostics_distinguish_short_quotes_from_absent_quotes():
    with pytest.raises(AnalysisError, match="quote 1 is shorter"):
        validate_analysis(analysis(evidence=["ACK"]), item(content="The reply was ACK."), editorial=False)
    with pytest.raises(AnalysisError, match="quote 2 is not an exact excerpt"):
        validate_analysis(analysis(evidence=["The reply was", "An invented quotation"]),
                          item(content="The reply was acknowledged."), editorial=False)
    tag = item(kind="tag", title="v1")
    assert validate_analysis(tag_notice(tag), tag)["evidence"] == ["v1"]


def test_writer_request_advertises_the_existing_evidence_length_floor(monkeypatch):
    llm = analyzer(monkeypatch, completion(analysis()))
    llm.analyze(item())
    request = llm.client.requests[0][1]
    rule = request["response_format"]["json_schema"]["schema"]["properties"]["evidence"]["items"]
    assert rule["minLength"] == MIN_EVIDENCE_CHARS


def test_evidence_enum_is_derived_from_the_exact_supplied_context():
    supplied = {"title": "An example source", "content": '> A quoted **status** uses "policy alpha".\nA second literal line.'}
    choices = _writer_schema(supplied)["properties"]["evidence"]["items"]["enum"]
    assert '> A quoted **status** uses "policy alpha".' in choices
    assert all(choice in supplied["title"] or choice in supplied["content"] for choice in choices)
    assert all(MIN_EVIDENCE_CHARS <= len(choice) <= 500 for choice in choices)


def test_writer_excerpt_options_retain_later_supplied_comments(monkeypatch):
    source = item(content="Original description", source_content="Original description", public_comments=[{
        "id": "gid://gitlab/DiscussionNote/1", "url": "https://example.org/issue#note_1", "author": "operator",
        "created_at": DATE, "updated_at": DATE, "body": 'The later **clarification** retains "quoted text".',
    }])
    llm = analyzer(monkeypatch, completion(analysis(evidence=["Original description"])))
    llm.analyze(source)
    request = llm.client.requests[0][1]
    supplied = json.loads(request["messages"][1]["content"])
    choices = request["response_format"]["json_schema"]["schema"]["properties"]["evidence"]["items"]["enum"]
    assert 'The later **clarification** retains "quoted text".' in choices
    assert all(choice in supplied["title"] or choice in supplied["content"] for choice in choices)


def test_oversized_literal_lines_have_bounded_choices_including_their_tail():
    line = "x" * 1500 + "END"
    choices = _writer_schema({"title": "A source title", "content": line})["properties"]["evidence"]["items"]["enum"]
    assert all(len(choice) <= 500 for choice in choices)
    assert any(choice.endswith("END") for choice in choices)
    assert all(choice in line or choice == "A source title" for choice in choices)


def test_adjacent_short_lines_remain_a_literal_evidence_option():
    supplied = {"title": "Ack", "content": "one\ntwo\nthree\nend"}
    choices = _writer_schema(supplied)["properties"]["evidence"]["items"]["enum"]
    assert choices and any(choice.endswith("end") for choice in choices)
    assert all(choice in supplied["content"] for choice in choices)


def test_no_qualifying_literal_excerpt_fails_closed_without_a_request(monkeypatch):
    llm = analyzer(monkeypatch)
    with pytest.raises(AnalysisError, match="no qualifying literal evidence"):
        llm.analyze(item(title="Ack", content="OK"))
    assert llm.client.requests == []


@pytest.mark.parametrize("text", ["Straße!", "ßßßß", "ﬃﬃﬃ"])
def test_casefold_expansion_cannot_create_an_impossible_enum_choice(text):
    with pytest.raises(AnalysisError, match="no qualifying literal evidence"):
        _writer_schema({"title": text, "content": ""})


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
    monkeypatch.setattr(cli, "Reviewer", ApprovingReviewer)
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


def test_writer_produces_one_draft_without_premerge_grounding(monkeypatch):
    claim = "Operators must update their configurations to exclude the node."
    draft = analysis(why_it_matters=claim, confidence="confirmed", state="released")
    llm = analyzer(monkeypatch, completion(draft))
    assert llm.analyze(item()) == draft
    assert len(llm.client.requests) == 1
    # The separate exact-candidate reviewer, not a hidden pre-merge rewrite,
    # now owns semantic approval and correction of the unsupported claim.


def test_empty_optional_context_is_a_valid_draft(monkeypatch):
    draft = analysis(why_it_matters="")
    llm = analyzer(monkeypatch, completion(draft))
    assert llm.analyze(item())["why_it_matters"] == ""
    assert len(llm.client.requests) == 1


def test_duplicate_model_json_fields_are_rejected():
    from onionflash.analyze import _json_object
    for text in ('{"publish":false,"publish":true}', '{"nested":{"verdict":"hold","verdict":"approve"}}'):
        with pytest.raises(AnalysisError, match="invalid JSON"):
            _json_object(text)
