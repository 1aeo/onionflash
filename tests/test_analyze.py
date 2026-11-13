"""Draft schema/evidence, shared transport, retained baseline checks and rejection."""

from __future__ import annotations

from approval_helpers import ApprovingReviewer, verdict
import copy
import json

import pytest

from onionflash import decisions
from onionflash.analyze import (AnalysisError, Analyzer, MAX_EVIDENCE_CHOICES, MIN_EVIDENCE_CHARS, SCHEMA, _writer_schema,
                                validate_analysis)
from onionflash.comments import INPUT_CHARS
from onionflash.config import DEFAULTS
from onionflash.schema import CONFIDENCES, STATES
from onionflash.store import Store
from onionflash.transport import FetchError, Response
from test_core import DATE, analysis, item
from test_review_gate import Reviewer, context, pending, run  # noqa: F401 (fixture)


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
def test_writer_keeps_a_source_stated_impact_sentence(monkeypatch, use_fallback):
    """An impact sentence from either endpoint stays in the draft, with no other request."""
    responses = [FetchError("network request failed", retryable=True)] if use_fallback else []
    sentence = "The report says the keys must no longer be trusted."
    responses.append(completion(analysis(why_it_matters=f" {sentence} ")))  # stripped spaces are not a clear
    llm = analyzer(monkeypatch, *responses, fallbacks=["https://fallback.example/v1"])
    assert llm.analyze(item())["why_it_matters"] == sentence and llm.clears == 0
    assert len(llm.client.requests) == llm.calls == 1 + use_fallback  # the run report counts each endpoint request
    assert all("enum" not in request[1]["response_format"]["json_schema"]["schema"]["properties"]["why_it_matters"]
               for request in llm.client.requests)


NUMBERED = item(title="Tor 0.4.8.20 and 0.4.9.16 are released",
                content="Upgrade to 0.4.9.16 now. Tor Browser 15.0a3 is affected. 3 authorities voted. "
                        "Release 2026-11-09. " + "7" * 5000)  # int() refuses a digit run this long


@pytest.mark.parametrize("sentence,kept", [
    ("The announcement asks operators to upgrade to 0.4.9.16.", True),
    ("The announcement says 0.4.8.20 is released.", True),  # only in the title
    ("The announcement says three authorities voted.", True),
    ("The announcement says it ships on Nov 9.", True),  # 09 in the source
    ("The announcement often matters to one canine.", True),  # number words count only as whole words, excluding "one"
    ("The announcement asks operators to upgrade.", True),
    ("The announcement asks operators to upgrade to 0.4.8.15.", False),
    ("The announcement asks operators to upgrade to 0.4.9.", False),  # only a prefix of 0.4.9.16
    ("The announcement says Tor Browser 15.0 is affected.", False),  # the source says 15.0a3
    ("The announcement says four authorities voted.", False),
])
def test_impact_sentence_numbers_and_versions_must_appear_in_the_source(sentence, kept):
    draft = analysis(why_it_matters=sentence, evidence=["Upgrade to 0.4.9.16 now."])
    assert validate_analysis(copy.deepcopy(draft), NUMBERED) == {**draft, "why_it_matters": sentence if kept else ""}


def test_impact_sentence_may_cite_numbers_from_a_comment_the_writer_saw(monkeypatch):
    note = {"id": "gid://gitlab/DiscussionNote/1", "url": "https://example.org/issue#note_1",
            "title": "Public comment by @operator", "author": "operator", "created_at": DATE,
            "body": "Relays running 0.4.8.17 must upgrade."}
    kept, dated = "A comment says relays running 0.4.8.17 must upgrade.", "The report was filed in 2026."
    llm = analyzer(monkeypatch, completion(analysis(why_it_matters=kept)), completion(analysis(why_it_matters=dated)))
    assert llm.analyze(item(public_comments=[note]))["why_it_matters"] == kept and llm.clears == 0
    # Its year appears only in the item's and the comment's dates, which are metadata.
    assert llm.analyze(item(public_comments=[note]))["why_it_matters"] == "" and llm.clears == 1
    assert llm.analyze(item(kind="tag", title="tor-0.4.9.16", content=""))["why_it_matters"] == "" and llm.clears == 0
    assert len(llm.client.requests) == 2  # one request per draft, and none for the tag


def test_a_cleared_impact_sentence_is_counted_with_its_decision(context, monkeypatch):
    cfg, store = context
    for url, sentence in (("https://example.org/news/1", "The report says relays running 0.4.8.17 must upgrade."),
                          ("https://example.org/news/2", "The report says the keys must no longer be trusted.")):
        writer = analyzer(monkeypatch, completion(analysis(why_it_matters=sentence)))
        assert run(cfg, store, pending(store, item(url=url)), writer, Reviewer(verdict()))["status"] == "published"
    details = [json.loads(row[0]) for row in store.db.execute("SELECT detail_json FROM decision_log ORDER BY id")]
    assert [detail.get("writer_clears") for detail in details] == [1, None]
    assert decisions.summary(store.db, DATE)["writer_clears"] == 1


def test_writer_clears_on_repeat_hold_operator_retry_and_operator_approve(context, monkeypatch):
    from onionflash import rejection

    cfg, store = context
    cleared = "The report says relays running 0.4.8.17 must upgrade."
    # 1. Held news dispute -> repeat hold keeps writer_clears -> operator retry resets it -> post-retry publish has None.
    writer = analyzer(monkeypatch, completion(analysis(why_it_matters=cleared)))
    row = pending(store, item(url="https://example.org/news/retry-clear"))
    assert run(cfg, store, row, writer, Reviewer(verdict(), verdict("hold", criterion="news_value")))["status"] == "held"
    with store.db:
        store.db.execute("UPDATE items SET status='pending' WHERE id=?", (row["id"],))
    row = store.pending(1, DATE)[0]
    assert run(cfg, store, row, writer, Reviewer())["status"] == "held"  # repeat_hold without reset_review_work
    rejection.retry_item(store, row["id"], row["content_hash"], "Retry kept draft", observed=DATE)
    row = store.pending(1, DATE)[0]
    assert run(cfg, store, row, writer, Reviewer(verdict()))["status"] == "published"

    # 2. Held news dispute -> operator approve logs operator.approved without repeating writer_clears.
    writer2 = analyzer(monkeypatch, completion(analysis(why_it_matters=cleared, evidence=["Second distinct report body."])))
    row2 = pending(store, item(url="https://example.org/news/approve-clear", content="Second distinct report body. " * 5))
    assert run(cfg, store, row2, writer2, Reviewer(verdict(), verdict("hold", criterion="news_value")))["status"] == "held"
    shown = rejection.show_item(store, row2["id"], config=cfg)
    rejection.approve_item(cfg, store, row2["id"], shown["final_review"]["approval"]["hash"], "Worth publishing", observed=DATE)

    # 3. Skipped cleared draft keeps writer_clears; failure row does not.
    writer3 = analyzer(monkeypatch, completion(analysis(why_it_matters=cleared, evidence=["Third distinct report body."])))
    row3 = pending(store, item(url="https://example.org/news/skip-clear", content="Third distinct report body. " * 5))
    assert run(cfg, store, row3, writer3, Reviewer(verdict("skip", criterion="news_value")))["status"] == "ignored"
    writer4 = analyzer(monkeypatch, completion(analysis(why_it_matters=cleared, evidence=["Fourth distinct report body."])))
    row4 = pending(store, item(url="https://example.org/news/fail-clear", content="Fourth distinct report body. " * 5))
    store.reject(row4["id"], "Invalid review reply", "failed.review.invalid_reply", DATE)

    rows = [
        (code, json.loads(detail).get("writer_clears"))
        for code, detail in store.db.execute("SELECT code, detail_json FROM decision_log ORDER BY id")
    ]
    assert rows == [
        ("held.verification.disagreed_news", 1),
        ("held.gate.repeat_hold", 1),
        ("operator.retried", None),
        ("published.new", None),
        ("held.verification.disagreed_news", 1),
        ("operator.approved", None),
        ("skipped.review.news_value", 1),
        ("failed.review.invalid_reply", None),
    ]
    assert decisions.summary(store.db, DATE)["writer_clears"] == 4


@pytest.mark.parametrize("source,confidence,state", [
    (item(), ["reported", "suspected", "observed-anomaly"], STATES),
    (item(kind="gitlab_mr", upstream_state="merged"), CONFIDENCES, ["merged"]),
    (item(kind="feed", authority="official"), CONFIDENCES, STATES)], ids=["issue", "merged-request", "official-feed"])
def test_writer_schema_limits_labels_by_source(monkeypatch, source, confidence, state):
    llm = analyzer(monkeypatch, completion(analysis(why_it_matters="", state=state[0])))
    llm.analyze(source)
    fields = llm.client.requests[0][1]["response_format"]["json_schema"]["schema"]["properties"]
    assert (fields["confidence"]["enum"], fields["state"]["enum"]) == (confidence, state)
    assert SCHEMA["properties"]["confidence"]["enum"] == CONFIDENCES  # review repairs copy the full rules


@pytest.mark.parametrize("use_fallback", [False, True])
@pytest.mark.parametrize("source,labels", [(item(), {"confidence": "confirmed"}),
                                           (item(kind="gitlab_mr", upstream_state="merged"), {"state": "released"})],
                         ids=["confirmed-issue", "released-merge-request"])
def test_writer_rejects_labels_outside_the_source_limits_even_when_endpoint_ignores_schema(monkeypatch, use_fallback,
                                                                                         source, labels):
    responses = [FetchError("network request failed", retryable=True)] if use_fallback else []
    responses.append(completion(analysis(why_it_matters="", **labels)))
    llm = analyzer(monkeypatch, *responses, fallbacks=["https://fallback.example/v1"])
    with pytest.raises(AnalysisError, match="labels exceed") as caught:
        llm.analyze(source)
    assert not caught.value.retryable
    assert len(llm.client.requests) == llm.calls == 1 + use_fallback


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
    assert "enum" not in fields["why_it_matters"]
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
    draft = analysis(summary=claim, why_it_matters="", confidence="reported", state="fixed")
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


def test_update_mode_sends_prior_context_narrows_schema_and_validates(monkeypatch):
    from approval_helpers import update_analysis
    from onionflash.analyze import UPDATE_PROMPT, UPDATE_SCHEMA, cache_key, tag_update

    prior = {
        "id": "a" * 24,
        "title": "Distinct prior headline",
        "summary": "Distinct prior summary that must never enter evidence choices.",
        "why_it_matters": "Distinct prior consequence.",
        "category": "release",
        "priority": "normal",
        "confidence": "confirmed",
        "state": "released",
        "products": ["tor"],
        "tags": ["release"],
        "published_at": DATE,
        "updated_at": DATE,
        "added_at": DATE,
        "sources": [{"url": "https://example.org/release", "title": "Release"}],
        "updates": [{"at": f"2026-11-08T12:{n:02d}:00Z", "text": f"Update {n}.",
                     "sources": [{"url": "https://example.org/release", "title": "Release"}]} for n in range(12)],
    }
    src_item = item(authority="community", kind="feed")
    draft = update_analysis(update="Packages for Debian are now published.", confidence="confirmed",
                            state="released", evidence=[src_item["title"]])
    llm = analyzer(monkeypatch, completion(draft))
    assert llm.analyze(src_item, prior=prior) == draft
    _, body = llm.client.requests[0]
    assert body["messages"][0]["content"] == UPDATE_PROMPT
    assert body["response_format"]["json_schema"]["name"] == "onionflash_update"
    schema = body["response_format"]["json_schema"]["schema"]
    assert set(schema["properties"]) == {"publish", "update", "confidence", "state", "evidence"}
    assert schema["properties"]["state"]["enum"] == ["released", "tagged"]
    assert schema["properties"]["confidence"]["enum"] == ["confirmed"]
    for choice in schema["properties"]["evidence"]["items"]["enum"]:
        assert "Distinct prior" not in choice
    sent = json.loads(body["messages"][1]["content"])
    assert len(sent["prior_story"]["updates"]) == 10
    assert sent["prior_story"]["updates"][0]["text"] == "Update 2."

    for bad in (
        {**draft, "title": "Forbidden"},
        {**draft, "update": "   "},
        {**draft, "update": "x" * 301},
        {**draft, "update": "Truncated mid-word without punctuation"},
        {**draft, "evidence": ["Distinct prior summary that must never enter evidence choices."]},
    ):
        with pytest.raises(AnalysisError):
            validate_analysis(copy.deepcopy(bad), item(), UPDATE_SCHEMA)

    tag = item(kind="tag", title="tor-0.4.9.16", content="")
    tag_llm = analyzer(monkeypatch)
    literal = tag_llm.analyze(tag, prior=prior)
    assert literal == tag_update(tag, prior)
    assert literal["update"] == "The upstream feed lists the tag “tor-0.4.9.16”."
    assert (literal["confidence"], literal["state"]) == ("confirmed", "released")
    assert tag_llm.client.requests == []

    row = {"content_hash": "h1"}
    base_key = cache_key(row, DEFAULTS["llm"], prior)
    assert base_key != cache_key(row, DEFAULTS["llm"])
    assert base_key != cache_key(row, DEFAULTS["llm"], {**prior, "state": "tagged"})
    assert base_key != cache_key(row, DEFAULTS["llm"], {**prior, "updates": prior["updates"][:-1]})
