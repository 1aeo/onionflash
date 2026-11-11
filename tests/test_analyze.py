"""Draft schema/evidence, shared transport, retained baseline checks and rejection."""

from __future__ import annotations

from approval_helpers import ApprovingReviewer
import copy
import json

import pytest

from onionflash.analyze import (AnalysisError, Analyzer, MAX_EVIDENCE_CHOICES, MIN_EVIDENCE_CHARS, SCHEMA, _writer_schema,
                                validate_analysis)
from onionflash.comments import INPUT_CHARS
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


def test_non_finite_numbers_are_invalid_model_json():
    from onionflash.analyze import _json_object
    for text in ('{"publish": false, "priority": NaN}', '{"publish": false, "x": 1e999}'):
        with pytest.raises(AnalysisError, match="invalid JSON"):
            _json_object(text)


def test_historical_impact_text_remains_readable():
    saved = analysis(why_it_matters="The report concerns directory authority trust.")
    assert validate_analysis(saved, item()) == saved


def test_writer_cannot_silently_skip_a_source_before_editorial_review(monkeypatch):
    ignore = analysis(publish=False, title="", summary="", why_it_matters="", evidence=[], products=[], tags=[])
    llm = analyzer(monkeypatch, completion(ignore))
    with pytest.raises(AnalysisError, match="draft for publication review") as caught:
        llm.analyze(item())
    assert not caught.value.retryable
    assert len(llm.client.requests) == 1


@pytest.mark.parametrize("use_fallback", [False, True])
def test_writer_rejects_separate_impact_text_even_when_endpoint_ignores_schema(monkeypatch, use_fallback):
    """Reject impact text from either endpoint without another validation retry."""
    responses = [FetchError("network request failed", retryable=True)] if use_fallback else []
    responses.append(completion(analysis(why_it_matters="Operators must update to prevent consensus generation issues.")))
    llm = analyzer(monkeypatch, *responses, fallbacks=["https://fallback.example/v1"])
    with pytest.raises(AnalysisError, match="leave why_it_matters empty") as caught:
        llm.analyze(item())
    assert not caught.value.retryable
    assert len(llm.client.requests) == llm.calls == 1 + use_fallback  # the run report counts each endpoint request
    assert all(request[1]["response_format"]["json_schema"]["schema"]["properties"]["why_it_matters"]["enum"] == [""]
               for request in llm.client.requests)


@pytest.mark.parametrize("sent", [0, 1])
def test_endpoint_attempts_refused_at_the_deadline_are_not_counted(monkeypatch, sent):
    from onionflash.transport import DeadlineReached
    responses = [FetchError("network request failed", retryable=True)] * sent + [DeadlineReached()] * (3 - sent)
    llm = analyzer(monkeypatch, *responses, fallbacks=["https://fallback.example/v1", "https://third.example/v1"])
    with pytest.raises(AnalysisError, match="LLM request failed") as caught:
        llm.analyze(item())
    assert caught.value.retryable and llm.calls == sent and len(llm.client.requests) == sent + 1


def test_endpoint_failures_are_retryable_and_validation_is_not_resent(monkeypatch):
    """Retry transport failures while keeping malformed content failures item-local."""
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
                   completion(analysis(why_it_matters="")), fallbacks=["https://fallback.example/v1"])
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
        validate_analysis(analysis(title=f" {noncharacter} "), item())
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
    result = validate_analysis(analysis(evidence=[quote]), item(content=body))
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
        validate_analysis(analysis(evidence=[quote]), item(content=body))


def test_evidence_diagnostics_distinguish_short_quotes_from_absent_quotes():
    with pytest.raises(AnalysisError, match="quote 1 is shorter"):
        validate_analysis(analysis(evidence=["ACK"]), item(content="The reply was ACK."))
    with pytest.raises(AnalysisError, match="quote 2 is not an exact excerpt"):
        validate_analysis(analysis(evidence=["The reply was", "An invented quotation"]),
                          item(content="The reply was acknowledged."))
    with pytest.raises(AnalysisError, match="needs text and source evidence"):
        validate_analysis(analysis(evidence=[]), item())


def test_writer_request_requires_a_draft_and_the_existing_evidence_length_floor(monkeypatch):
    llm = analyzer(monkeypatch, completion(analysis(why_it_matters="")))
    llm.analyze(item())
    request = llm.client.requests[0][1]
    fields = request["response_format"]["json_schema"]["schema"]["properties"]
    assert fields["publish"]["enum"] == [True]
    assert fields["why_it_matters"]["enum"] == [""]
    assert fields["evidence"]["items"]["minLength"] == MIN_EVIDENCE_CHARS
    assert fields["title"]["minLength"] == fields["summary"]["minLength"] == fields["evidence"]["minItems"] == 1
    assert "minLength" not in SCHEMA["properties"]["title"] | SCHEMA["properties"]["summary"]  # review repairs copy these rules


def test_evidence_enum_is_derived_from_the_exact_supplied_context():
    supplied = {"title": "An example source", "content": '> A quoted **status** uses "policy alpha".\nA second literal line.'}
    choices = _writer_schema(supplied)["properties"]["evidence"]["items"]["enum"]
    assert '> A quoted **status** uses "policy alpha".' in choices
    assert all(choice in supplied["title"] or choice in supplied["content"] for choice in choices)
    assert all(MIN_EVIDENCE_CHARS <= len(choice) <= 500 for choice in choices)


def test_writer_excerpt_options_retain_later_supplied_comments(monkeypatch):
    """Keep literal comment evidence within the same context sent to the writer."""
    body = 'The later **clarification** retains "quoted text".'
    source = item(content="Original description", public_comments=[{
        "id": "gid://gitlab/DiscussionNote/1", "url": "https://example.org/issue#note_1",
        "title": "Public comment by @operator", "author": "operator", "created_at": DATE, "body": body,
    }])
    llm = analyzer(monkeypatch, completion(analysis(why_it_matters="", evidence=[body])))
    assert llm.analyze(source)["evidence"] == [body]  # a note body the writer saw is literal evidence
    request = llm.client.requests[0][1]
    supplied = json.loads(request["messages"][1]["content"])
    choices = request["response_format"]["json_schema"]["schema"]["properties"]["evidence"]["items"]["enum"]
    assert body in choices
    texts = [supplied["title"], supplied["content"], *(note["body"] for note in supplied["public_comments"])]
    assert all(any(choice in text for text in texts) for choice in choices)


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


def test_evidence_grammar_is_bounded_across_a_full_many_line_input():
    content = "".join(f"row-{index:04d}\n" for index in range(1550)) + "Final comment"
    assert len(content) <= INPUT_CHARS
    choices = _writer_schema({"title": "Source title", "content": content})["properties"]["evidence"]["items"]["enum"]
    assert len(choices) == MAX_EVIDENCE_CHOICES
    assert choices[0] == "Source title" and choices[-1] == "Final comment"
    assert all(choice == "Source title" or choice in content for choice in choices)
    assert any("row-07" in choice for choice in choices)
    assert sum(map(len, choices)) <= MAX_EVIDENCE_CHOICES * 500


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
        calls = 0
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
    draft = analysis(summary=claim, why_it_matters="", confidence="confirmed", state="released")
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
