"""Draft schema/evidence, writer cache identity, reasoning profile, and update input checks."""

import copy
import json

import httpx
import pytest

from helpers import (
    DATE, LATER, NON_RELEASE_CATEGORIES, NON_TAG_STATES, ApprovingReviewer, FakeClient, FakeLLM,
    Reviewer, Writer, analysis, completion, decision_rows, finish_reviewed, item, list_rss,
    make_note, patch_cli_pipeline, pending, public_dns, response, run_gate, seed_story, source,
    update_analysis, verdict, wire_analyzer, write_toml,
)
from onionflash import analyze, candidate, cli, collect, decisions, rejection, source_packet
from onionflash.analyze import (
    MAX_EVIDENCE_CHOICES, MIN_EVIDENCE_CHARS, SCHEMA, UPDATE_PROMPT, UPDATE_SCHEMA,
    AnalysisError, Analyzer, _writer_schema, cache_key, tag_update, validate_analysis,
)
from onionflash.comments import INPUT_CHARS, analysis_context
from onionflash.config import DEFAULTS, load_config
from onionflash.doctor import LinkChecker
from onionflash.llm import (
    has_malformed_tor_version, has_shouting_caps, json_object, unquoted_mail_text, validate_schema_field,
)
from onionflash.review import Reviewer as RealReviewer
from onionflash.schema import CATEGORIES, CONFIDENCES, STATES
from onionflash.store import Store, item_hash
from onionflash.transport import DeadlineReached, FetchError, HttpClient, Response
from onionflash.util import digest, plain_text

NUMBERED = item(
    title="Tor 0.4.8.20 and 0.4.9.16 are released",
    content="Upgrade to 0.4.9.16 now. Tor Browser 15.0a3 is affected. 3 authorities voted. Release 2026-11-09. " + "7" * 5000,
)
REASONING_PROMPT = "Summarize only supplied evidence."
REASONING_PAYLOAD = {"source": "The report states a bounded effect."}
REASONING_SCHEMA = {"type": "object"}


def _prior_story(**overrides):
    base = {
        "id": "a" * 24,
        "title": "Distinct prior headline",
        "summary": "Distinct prior summary that must never enter evidence choices.",
        "why_it_matters": "Distinct prior consequence.",
        "category": "network",
        "priority": "normal",
        "confidence": "reported",
        "state": "released",
        "products": ["tor"],
        "tags": ["network"],
        "published_at": DATE,
        "updated_at": DATE,
        "added_at": DATE,
        "sources": [{"url": "https://source.example/project/-/merge_requests/1", "title": "Source"}],
        "updates": [{"at": DATE, "text": "Earlier update."}],
    }
    return {**base, **overrides}


def _cache_source(**overrides):
    defaults = {
        "title": "A concrete source report",
        "content": "A source describes a supported change.",
        "labels": [],
        "upstream_state": "opened",
        "published_at": "2020-01-01T00:00:00Z",
        "updated_at": "2020-01-02T00:00:00Z",
    }
    return item(**{**defaults, **overrides})


def _cache_key_for(incoming=None, previous=None, **llm_overrides):
    settings = {**copy.deepcopy(DEFAULTS["llm"]), "model": "writer-model", **llm_overrides}
    return cache_key({"content_hash": item_hash(incoming or _cache_source())}, settings, previous)


def _reasoning_settings(enabled=False):
    cfg = copy.deepcopy(DEFAULTS)
    cfg["llm"].update(base_url="https://model.example/v1", model="writer-model",
                      api_key_env="NATIVE_WRITER_TEST_KEY", writer_reasoning=enabled, timeout_seconds=3600)
    cfg["review"]["model"] = "review-model"
    return cfg


def _saved_item(description, *, legacy, notes, updated_at):
    value = item(content=description, public_comments=notes, updated_at=updated_at)
    if legacy:
        value["source_content"] = description
        value["content"] = "Previously composed description and comment text."
    return value


@pytest.fixture
def capture(monkeypatch):
    """Yield a runner capturing wire HTTP requests and effective LLM settings for a stage class."""
    monkeypatch.setenv("NATIVE_WRITER_TEST_KEY", "synthetic-fixture-value")

    def _run(cls, settings):
        observed = []
        client = cls(settings)

        def _reply(request):
            observed.append(request)
            return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {"content": "{}"}}]})

        client.client = HttpClient(client.http_settings, transport=httpx.MockTransport(_reply), resolver=public_dns)
        try:
            assert client.complete(REASONING_PROMPT, REASONING_PAYLOAD, REASONING_SCHEMA, "profile_probe") == {}
            assert len(observed) == client.calls == 1
            return observed[0], copy.deepcopy(client.llm), copy.deepcopy(client.http_settings)
        finally:
            client.close()

    return _run


@pytest.mark.parametrize("text", ['{"publish": false, "priority": NaN}', '{"publish": false, "x": 1e999}', "[" * 10000 + "]" * 10000])
def test_json_object_rejects_nonstandard_and_deep_json(text):
    """Reject NaN, overflowing floats, and deeply nested JSON payloads."""
    with pytest.raises(AnalysisError, match="invalid JSON"):
        json_object(text)


def test_historical_impact_and_mandatory_draft(monkeypatch):
    """Accept source-grounded drafts and reject publish=false responses."""
    saved = analysis(why_it_matters="The report concerns directory authority trust.")
    assert validate_analysis(saved, item()) == saved
    assert wire_analyzer(monkeypatch, analysis(why_it_matters="")).analyze(item())["why_it_matters"] == ""

    claim = "Operators must update their configurations to exclude the node."
    draft = analysis(summary=claim, why_it_matters="", confidence="reported", state="fixed")
    llm = wire_analyzer(monkeypatch, draft)
    assert llm.analyze(item()) == draft and len(llm.client.requests) == 1

    ignore = analysis(publish=False, title="", summary="", why_it_matters="", evidence=[], products=[], tags=[])
    llm_ig = wire_analyzer(monkeypatch, ignore)
    with pytest.raises(AnalysisError, match="draft for publication review") as caught:
        llm_ig.analyze(item())
    assert not caught.value.retryable and len(llm_ig.client.requests) == 1


@pytest.mark.parametrize("use_fallback", [False, True])
def test_writer_keeps_a_source_stated_impact_sentence(monkeypatch, use_fallback):
    """Retain a source-supported why_it_matters sentence across primary and fallback endpoints."""
    responses = [FetchError("network request failed", retryable=True)] if use_fallback else []
    sentence = "The report says the keys must no longer be trusted."
    responses.append(analysis(why_it_matters=f" {sentence} "))
    llm = wire_analyzer(monkeypatch, *responses, fallbacks=["https://fallback.example/v1"])
    assert llm.analyze(item())["why_it_matters"] == sentence and llm.clears == 0
    assert len(llm.client.requests) == llm.calls == 1 + use_fallback
    assert all("enum" not in req[1]["response_format"]["json_schema"]["schema"]["properties"]["why_it_matters"]
               for req in llm.client.requests)


@pytest.mark.parametrize("sentence,kept", [
    ("The announcement asks operators to upgrade to 0.4.9.16.", True),
    ("The announcement says 0.4.8.20 is released.", True),
    ("The announcement says three authorities voted.", True),
    ("The announcement says it ships on Nov 9.", True),
    ("The announcement often matters to one canine.", True),
    ("The announcement asks operators to upgrade.", True),
    ("The announcement asks operators to upgrade to 0.4.8.15.", False),
    ("The announcement asks operators to upgrade to 0.4.9.", False),
    ("The announcement says Tor Browser 15.0 is affected.", False),
    ("The announcement says four authorities voted.", False),
])
def test_impact_sentence_numbers_and_versions_must_appear_in_the_source(sentence, kept):
    """Clear why_it_matters when numbers or versions do not match source text."""
    draft = analysis(why_it_matters=sentence, evidence=["Upgrade to 0.4.9.16 now."])
    assert validate_analysis(copy.deepcopy(draft), NUMBERED) == {**draft, "why_it_matters": sentence if kept else ""}


@pytest.mark.parametrize("source_version, sentence_version, kept", [
    ("1.2.3-rc1", "1.2.3-rc1", True),
    ("1.2.3-rc.1", "1.2.3-rc.1", True),
    ("1.2.3-rc-1", "1.2.3-rc-1", True),
    ("1.2.3-alpha", "1.2.3-alpha", True),
    ("1.2.3-beta2", "1.2.3-beta2", True),
    ("1.2.3-pre.2", "1.2.3-pre.2", True),
    ("1.2.3-dev4", "1.2.3-dev4", True),
    ("1.2-rc1a", "1.2-rc1a", True),
    ("1.2.3-rc1", "1.2.3", False),
    ("1.2.3-rc.1", "1.2.3", False),
    ("1.2.3-alpha", "1.2.3", False),
    ("1.2.3-beta2", "1.2.3", False),
    ("1.2.3-pre.2", "1.2.3", False),
    ("1.2.3-dev4", "1.2.3", False),
    ("1.2.3-rc1", "1.2.3-rc2", False),
    ("1.2.3-rc1", "1.2.3-beta1", False),
    ("1.2.3", "1.2.3-rc1", False),
])
def test_impact_versions_keep_their_prerelease_qualifier(source_version, sentence_version, kept):
    """Require prerelease suffixes in why_it_matters versions to match the source."""
    src_text = f"Version {source_version} includes the reported correction."
    sentence = f"The report says version {sentence_version} includes the correction."
    draft = analysis(why_it_matters=sentence, evidence=[src_text])
    assert validate_analysis(copy.deepcopy(draft), item(title="Software correction", content=src_text)) == {
        **draft, "why_it_matters": sentence if kept else ""}


def test_prerelease_words_in_prose_do_not_change_a_count():
    """Keep spelled-out prose counts distinct from prerelease version tokens."""
    src_text = "The developers corrected 3 connection failures. A separate release candidate is under review."
    sentence = "The report says developers corrected three connection failures."
    draft = analysis(why_it_matters=sentence, evidence=[src_text])
    assert validate_analysis(copy.deepcopy(draft), item(title="Connection correction", content=src_text)) == draft


def test_impact_clears_across_comments_decisions_retries_and_approvals(context, monkeypatch):
    """Track writer_clears across comment bodies, retries, operator approvals, and decision summaries."""
    note = make_note(1, "Relays running 0.4.8.17 must upgrade.", url="https://example.org/issue", kind="DiscussionNote")
    kept, dated = "A comment says relays running 0.4.8.17 must upgrade.", "The report was filed in 2026."
    llm = wire_analyzer(monkeypatch, analysis(why_it_matters=kept), analysis(why_it_matters=dated))
    assert llm.analyze(item(public_comments=[note]))["why_it_matters"] == kept and llm.clears == 0
    assert llm.analyze(item(public_comments=[note]))["why_it_matters"] == "" and llm.clears == 1
    assert llm.analyze(item(kind="tag", title="tor-0.4.9.16", content=""))["why_it_matters"] == "" and llm.clears == 0
    assert len(llm.client.requests) == 2

    cfg, store = context
    cleared = "The report says relays running 0.4.8.17 must upgrade."
    for url, sentence in (("https://example.org/news/1", cleared), ("https://example.org/news/2", "The report says the keys must no longer be trusted.")):
        w = wire_analyzer(monkeypatch, analysis(why_it_matters=sentence))
        assert run_gate(cfg, store, pending(store, item(url=url)), w, Reviewer(verdict()))["status"] == "published"
    assert [r["detail"].get("writer_clears") for r in decision_rows(store)] == [1, None]
    assert decisions.summary(store.db, DATE)["writer_clears"] == 1

    store.db.execute("DELETE FROM decision_log")
    w1 = wire_analyzer(monkeypatch, analysis(why_it_matters=cleared))
    r1 = pending(store, item(url="https://example.org/news/retry-clear"))
    assert run_gate(cfg, store, r1, w1, Reviewer(verdict(), verdict("hold", criterion="news_value")))["status"] == "held"
    with store.db:
        store.db.execute("UPDATE items SET status='pending' WHERE id=?", (r1["id"],))
    r1 = store.pending(1, DATE)[0]
    assert run_gate(cfg, store, r1, w1, Reviewer())["status"] == "held"
    rejection.retry_item(store, r1["id"], r1["content_hash"], "Retry kept draft", observed=DATE)
    assert run_gate(cfg, store, store.pending(1, DATE)[0], w1, Reviewer(verdict()))["status"] == "published"

    w2 = wire_analyzer(monkeypatch, analysis(why_it_matters=cleared, evidence=["Second distinct report body."]))
    r2 = pending(store, item(url="https://example.org/news/approve-clear", content="Second distinct report body. " * 5))
    assert run_gate(cfg, store, r2, w2, Reviewer(verdict(), verdict("hold", criterion="news_value")))["status"] == "held"
    shown = rejection.show_item(store, r2["id"], config=cfg)
    rejection.approve_item(cfg, store, r2["id"], shown["final_review"]["approval"]["hash"], "Worth publishing", observed=DATE)

    w3 = wire_analyzer(monkeypatch, analysis(why_it_matters=cleared, evidence=["Third distinct report body."]))
    r3 = pending(store, item(url="https://example.org/news/skip-clear", content="Third distinct report body. " * 5))
    assert run_gate(cfg, store, r3, w3, Reviewer(verdict("skip", criterion="news_value")))["status"] == "ignored"
    store.reject(pending(store, item(url="https://example.org/news/fail-clear", content="Fourth distinct report body. " * 5))["id"],
                 "Invalid review reply", "failed.review.invalid_reply", DATE)

    rows = [(r["code"], r["detail"].get("writer_clears")) for r in decision_rows(store)]
    assert rows == [
        ("held.verification.disagreed_news", 1), ("held.gate.repeat_hold", 1), ("operator.retried", None),
        ("published.new", None), ("held.verification.disagreed_news", 1), ("operator.approved", None),
        ("skipped.review.news_value", 1), ("failed.review.invalid_reply", None),
    ]
    assert decisions.summary(store.db, DATE)["writer_clears"] == 4


@pytest.mark.parametrize("src_item,confidence,state,categories", [
    (item(), ["reported", "suspected", "observed-anomaly"], NON_TAG_STATES, CATEGORIES),
    (item(kind="gitlab_mr", upstream_state="merged"), CONFIDENCES, ["merged"], NON_RELEASE_CATEGORIES),
    (item(kind="feed", authority="official"), CONFIDENCES, NON_TAG_STATES, CATEGORIES),
], ids=["issue", "merged-request", "official-feed"])
def test_writer_schema_limits_labels_by_source(monkeypatch, src_item, confidence, state, categories):
    """Restrict writer schema label enums according to source kind and authority."""
    llm = wire_analyzer(monkeypatch, analysis(why_it_matters="", state=state[0]))
    llm.analyze(src_item)
    fields = llm.client.requests[0][1]["response_format"]["json_schema"]["schema"]["properties"]
    assert (fields["confidence"]["enum"], fields["state"]["enum"]) == (confidence, state)
    assert fields["category"]["enum"] == fields["tags"]["items"]["enum"] == categories
    assert (SCHEMA["properties"]["confidence"]["enum"], SCHEMA["properties"]["state"]["enum"],
            SCHEMA["properties"]["category"]["enum"]) == (CONFIDENCES, STATES, CATEGORIES)


@pytest.mark.parametrize("use_fallback", [False, True])
@pytest.mark.parametrize("src_item,labels", [
    (item(), {"confidence": "confirmed"}),
    (item(), {"state": "tagged"}),
    (item(kind="gitlab_mr", upstream_state="merged"), {"state": "released"}),
    (item(kind="gitlab_mr", upstream_state="merged"), {"state": "merged", "category": "release"}),
], ids=["confirmed-issue", "tagged-issue", "released-mr", "release-category-mr"])
def test_writer_rejects_labels_outside_source_limits(monkeypatch, use_fallback, src_item, labels):
    """Refuse writer responses whose labels exceed source-derived limits."""
    responses = [FetchError("network request failed", retryable=True)] if use_fallback else []
    responses.append(analysis(why_it_matters="", **labels))
    llm = wire_analyzer(monkeypatch, *responses, fallbacks=["https://fallback.example/v1"])
    with pytest.raises(AnalysisError, match="labels exceed") as caught:
        llm.analyze(src_item)
    assert not caught.value.retryable and len(llm.client.requests) == llm.calls == 1 + use_fallback


@pytest.mark.parametrize("overrides,match", [
    ({"tags": ["release", "unknown-label"]}, "Invalid model tags"),
    ({"priority": []}, "Invalid model priority"),
    ({"priority": {}}, "Invalid model priority"),
    ({"priority": 1}, "Invalid model priority"),
    ({"priority": None}, "Invalid model priority"),
    ({"title": " \ufffe "}, "Invalid model title"),
    ({"title": " \uffff "}, "Invalid model title"),
])
def test_validate_analysis_rejects_malformed_scalars_and_noncharacters(overrides, match):
    """Reject invalid enum values, non-string scalars, and XML noncharacters."""
    with pytest.raises(AnalysisError, match=match) as caught:
        validate_analysis(analysis(**overrides), item())
    assert not caught.value.retryable


def test_label_normalization_schema_limits_and_release_tag_stripping(monkeypatch):
    """Deduplicate array labels, enforce length caps, and strip unannounced release tags."""
    merged_mr = item(kind="gitlab_mr", upstream_state="merged")
    draft = analysis(why_it_matters="", state="merged", category="feature", tags=["feature", "release"])
    assert wire_analyzer(monkeypatch, draft).analyze(merged_mr)["tags"] == ["feature"]
    released = analysis(why_it_matters="", state="released", category="feature", tags=["feature", "release"])
    assert wire_analyzer(monkeypatch, released).analyze(item(kind="feed", authority="official"))["tags"] == ["feature", "release"]
    misclassified = analysis(why_it_matters="", state="developing", category="release", tags=["release"])
    assert wire_analyzer(monkeypatch, misclassified).analyze(item())["tags"] == ["release"]
    assert validate_analysis(draft, merged_mr)["tags"] == ["feature", "release"]

    quote = "The operator\nreported a plausible\tcompromise"
    accepted = validate_analysis(analysis(products=["tor", "tor"], tags=["security", "security"], evidence=[quote]), item())
    assert accepted["products"] == ["tor"] and accepted["tags"] == ["security"] and accepted["evidence"] == [quote]

    with monkeypatch.context() as mp:
        mp.setitem(SCHEMA["properties"]["title"], "maxLength", 10)
        with pytest.raises(AnalysisError, match="Invalid model title"):
            validate_analysis(analysis(title="       short       "), item())
        mp.setitem(SCHEMA["properties"]["products"], "maxItems", 1)
        with pytest.raises(AnalysisError, match="Invalid model products"):
            validate_analysis(analysis(title="Short", products=["tor", "tor"]), item())
        mp.setitem(SCHEMA["properties"]["evidence"]["items"], "maxLength", 10)
        with pytest.raises(AnalysisError, match="Invalid model evidence"):
            validate_analysis(analysis(title="Short"), item())


@pytest.mark.parametrize("sent", [0, 1])
def test_endpoint_deadlines_bound_retries(monkeypatch, sent):
    """Stop retrying across fallback endpoints once `DeadlineReached` fires."""
    responses = [FetchError("network request failed", retryable=True)] * sent + [DeadlineReached()] * (3 - sent)
    llm = wire_analyzer(monkeypatch, *responses, fallbacks=["https://fallback.example/v1", "https://third.example/v1"])
    with pytest.raises(AnalysisError, match="LLM request failed") as caught:
        llm.analyze(item())
    assert caught.value.retryable and llm.calls == sent and len(llm.client.requests) == sent + 1


def test_endpoint_failover_and_malformed_completions(monkeypatch):
    """Distinguish retryable transport/auth failures from terminal truncation and evidence errors."""
    llm_ok = wire_analyzer(monkeypatch, FetchError("network request failed", retryable=True),
                           analysis(why_it_matters=""), fallbacks=["https://fallback.example/v1"])
    assert llm_ok.analyze(item())["title"] == analysis()["title"] and llm_ok.client.requests[0][0].startswith("https://llm.example")

    for reply, fallbacks, match, retryable in (
        (FetchError("HTTP 401", status=401), (), "HTTP 401", True),
        (analysis(evidence=["words the source never says"]), ("https://fallback.example/v1",), "evidence", False),
        (completion(analysis(), finish_reason="length"), (), "truncated", False),
        (Response(200, b'{"error": "busy"}', {}, "https://llm.example/v1"), (), "unexpected response", True),
    ):
        client = wire_analyzer(monkeypatch, reply, fallbacks=fallbacks)
        with pytest.raises(AnalysisError, match=match) as caught:
            client.analyze(item())
        assert caught.value.retryable is retryable and len(client.client.requests) == 1


@pytest.mark.parametrize("body,quotes,match", [
    ('The result is **available** under "policy beta".', ['The result is **available** under "policy beta".'], None),
    ("> An earlier report spans\n> two quoted source lines.", ["An earlier report spans\n> two quoted source lines."], None),
    ("The `sample_metric` counter remains unchanged.", ["The `sample_metric` counter remains unchanged."], None),
    ("It’s a security release — operators should upgrade.", ["It's a security release"], None),
    ("It’s a security release — operators should upgrade.", ["it’s A SECURITY release"], None),
    ("It’s a security release — operators should upgrade.", ["release - operators should"], None),
    ("The result is **available** under the policy.", ["The result is available under the policy."], "not an exact excerpt"),
    ('The result uses "policy beta".', ["The result uses 'policy beta'."], "not an exact excerpt"),
    ("> An earlier report spans\n> two quoted source lines.", ["An earlier report spans two quoted source lines."], "not an exact excerpt"),
    ("The `sample_metric` counter remains unchanged.", ["The sample_metric counter remains unchanged."], "not an exact excerpt"),
    ("The old keys are not trusted.", ["The old keys are trusted."], "not an exact excerpt"),
    ("It’s a security release — operators should upgrade.", [" " * 8], "evidence"),
    ("It’s a security release — operators should upgrade.", ["release"], "evidence"),
    ("It’s a security release — operators should upgrade.", ["not a quote from the source"], "evidence"),
    ("The reply was ACK.", ["ACK"], "quote 1 is shorter"),
    ("The reply was acknowledged.", ["The reply was", "An invented quotation"], "quote 2 is not an exact excerpt"),
    ("The reply was acknowledged.", [], "needs text and source evidence"),
])
def test_literal_evidence_formatting_and_reformatting_guards(body, quotes, match):
    """Require exact normalized source excerpts while preserving Markdown, quotes, and > markers."""
    if match is None:
        assert validate_analysis(analysis(evidence=quotes), item(content=body))["evidence"] == quotes
    else:
        with pytest.raises(AnalysisError, match=match):
            validate_analysis(analysis(evidence=quotes), item(content=body))


@pytest.mark.parametrize("text", ["Straße!", "ßßßß", "ﬃﬃﬃ"])
def test_writer_schema_rejects_short_nfkc_titles(text):
    """Refuse inputs whose normalized literal excerpts fall below MIN_EVIDENCE_CHARS."""
    with pytest.raises(AnalysisError, match="no qualifying literal evidence"):
        _writer_schema({"title": text, "content": ""})


def test_evidence_matching_diagnostics_and_grammar_bounds(monkeypatch):
    """Bound evidence enum choices to MAX_EVIDENCE_CHOICES across descriptions and comments."""
    llm = wire_analyzer(monkeypatch, analysis(why_it_matters=""))
    llm.analyze(item())
    fields = llm.client.requests[0][1]["response_format"]["json_schema"]["schema"]["properties"]
    assert fields["publish"]["enum"] == [True] and "enum" not in fields["why_it_matters"]
    assert fields["evidence"]["items"]["minLength"] == MIN_EVIDENCE_CHARS
    assert fields["title"]["minLength"] == fields["summary"]["minLength"] == fields["evidence"]["minItems"] == 1
    assert "minLength" not in SCHEMA["properties"]["title"] | SCHEMA["properties"]["summary"]

    supplied = {"title": "An example source", "content": '> A quoted **status** uses "policy alpha".\nA second literal line.'}
    choices = _writer_schema(supplied)["properties"]["evidence"]["items"]["enum"]
    assert '> A quoted **status** uses "policy alpha".' in choices
    assert all((c in supplied["title"] or c in supplied["content"]) and MIN_EVIDENCE_CHARS <= len(c) <= 500 for c in choices)

    note_body = 'The later **clarification** retains "quoted text".'
    with_note = item(content="Original description",
                     public_comments=[make_note(1, note_body, url="https://example.org/issue", kind="DiscussionNote")])
    llm_n = wire_analyzer(monkeypatch, analysis(why_it_matters="", evidence=[note_body]))
    assert llm_n.analyze(with_note)["evidence"] == [note_body]
    req_n = llm_n.client.requests[0][1]
    sent_n = json.loads(req_n["messages"][1]["content"])
    n_choices = req_n["response_format"]["json_schema"]["schema"]["properties"]["evidence"]["items"]["enum"]
    texts = [sent_n["title"], sent_n["content"], *(n["body"] for n in sent_n["public_comments"])]
    assert note_body in n_choices and all(any(c in t for t in texts) for c in n_choices)

    long_line = "x" * 1500 + "END"
    tail_choices = _writer_schema({"title": "A source title", "content": long_line})["properties"]["evidence"]["items"]["enum"]
    assert all(len(c) <= 500 and (c in long_line or c == "A source title") for c in tail_choices) and any(c.endswith("END") for c in tail_choices)
    short_choices = _writer_schema({"title": "Ack", "content": "one\ntwo\nthree\nend"})["properties"]["evidence"]["items"]["enum"]
    assert short_choices and any(c.endswith("end") for c in short_choices)

    llm_empty = wire_analyzer(monkeypatch)
    with pytest.raises(AnalysisError, match="no qualifying literal evidence"):
        llm_empty.analyze(item(title="Ack", content="OK"))
    assert llm_empty.client.requests == []

    many = "".join(f"row-{idx:04d}\n" for idx in range(1550)) + "Final comment"
    assert len(many) <= INPUT_CHARS
    m_choices = _writer_schema({"title": "Source title", "content": many})["properties"]["evidence"]["items"]["enum"]
    assert len(m_choices) == MAX_EVIDENCE_CHOICES and m_choices[0] == "Source title" and m_choices[-1] == "Final comment"
    assert any("row-07" in c for c in m_choices) and sum(map(len, m_choices)) <= MAX_EVIDENCE_CHOICES * 500


def test_rejection_strikes_run_endpoint_circuit_breaker_and_source_snapshot(tmp_path, monkeypatch):
    """Stop retrying after three terminal strikes and trip the run circuit breaker on endpoint errors."""
    llm_cfg = DEFAULTS["llm"]
    with Store(tmp_path / "state.db") as store:
        src = item()
        row = pending(store, src, at=DATE, ready=DATE)
        finish_reviewed(store, row, analysis(), "first-analysis", DATE)
        src["content"] += " A later source correction."
        store.ingest(src, DATE)
        saved = store.db.execute("SELECT source_payload,source_item_id FROM analyses WHERE cache_key='first-analysis'").fetchone()
        assert json.loads(saved[0])["content"] == json.loads(row["payload"])["content"] and saved[1] == row["id"]

        row_id = row["id"]
        for _ in range(4):
            store.defer(row_id, "LLM request failed (HTTP 503)", llm_cfg, DATE, terminal=False)
        for _ in range(2):
            store.defer(row_id, "Model evidence is not present in source", llm_cfg, DATE, terminal=True)
        assert store.db.execute("SELECT status FROM items WHERE id=?", (row_id,)).fetchone()[0] == "pending"
        store.defer(row_id, "Model evidence is not present in source", llm_cfg, DATE, terminal=True)
        assert tuple(store.db.execute("SELECT status, attempts, rejections FROM items WHERE id=?", (row_id,)).fetchone()) == ("rejected", 7, 3)
        store.ingest(item(content="Edited: the operator now confirms the compromise."), DATE)
        assert tuple(store.db.execute("SELECT status, attempts, rejections FROM items WHERE id=?", (row_id,)).fetchone()) == ("pending", 0, 0)

    calls = []
    failing_endpoint = False

    def _step(payload):
        calls.append(payload["url"])
        if payload["url"].endswith("/bad") or failing_endpoint:
            raise AnalysisError("LLM request failed (HTTP 400)", retryable=True)
        return analysis()

    patch_cli_pipeline(monkeypatch, analyzer=Writer.factory(_step), reviewer=ApprovingReviewer)
    cfg = {**copy.deepcopy(DEFAULTS), "sources": []}
    for failing_endpoint, expected in [(False, 3), (True, 2)]:
        calls.clear()
        with Store(tmp_path / f"state-{failing_endpoint}.db") as store:
            for url in ("https://example.org/bad", "https://example.org/a", "https://example.org/b"):
                store.ingest(item(id=url, url=url, content=f"{url} the operator reported a plausible compromise.",
                                  labels=["Security"] if url.endswith("bad") else []), DATE)
            cli.run(cfg, store)
        assert len(calls) == expected


@pytest.mark.parametrize("bad_update", [
    {"title": "Forbidden"},
    {"update": "   "},
    {"update": "x" * 301},
    {"update": "Truncated mid-word without punctuation"},
    {"update": "."},
    {"evidence": ["Distinct prior summary that must never enter evidence choices."]},
])
def test_validate_update_analysis_rejects_invalid_payloads(bad_update):
    """Reject malformed, empty, unpunctuated, or prior-story-quoting update drafts."""
    base = update_analysis(update="Packages for Debian are now published.", confidence="confirmed",
                           state="released", evidence=[item()["title"]])
    with pytest.raises(AnalysisError):
        validate_analysis({**base, **bad_update}, item(), UPDATE_SCHEMA)


def test_update_mode_sends_prior_context_narrows_schema_and_validates(monkeypatch):
    """Bound prior_story updates, narrow update state/confidence enums, and bind cache keys."""
    prior = _prior_story(
        category="release",
        confidence="confirmed",
        tags=["release"],
        sources=[{"url": "https://example.org/release", "title": "Release"}],
        updates=[{"at": f"2026-11-08T12:{n:02d}:00Z", "text": f"Update {n}.",
                  "sources": [{"url": "https://example.org/release", "title": "Release"}]} for n in range(12)],
    )
    src_item = item(authority="community", kind="feed")
    draft = update_analysis(update="Packages for Debian are now published.", confidence="confirmed",
                            state="released", evidence=[src_item["title"]])
    llm = wire_analyzer(monkeypatch, draft)
    assert llm.analyze(src_item, prior=prior) == draft
    _, body = llm.client.requests[0]
    assert body["messages"][0]["content"] == UPDATE_PROMPT and body["response_format"]["json_schema"]["name"] == "onionflash_update"
    schema = body["response_format"]["json_schema"]["schema"]
    assert set(schema["properties"]) == {"publish", "update", "confidence", "state", "evidence"}
    assert (schema["properties"]["state"]["enum"], schema["properties"]["confidence"]["enum"]) == (["released"], ["confirmed"])

    tagged_llm = wire_analyzer(monkeypatch, draft)
    tagged_llm.analyze(src_item, prior={**prior, "state": "tagged"})
    assert tagged_llm.client.requests[0][1]["response_format"]["json_schema"]["schema"]["properties"]["state"]["enum"] == ["released", "tagged"]

    dev_prior = {**prior, "category": "security", "confidence": "reported", "state": "developing", "tags": ["security"]}
    dev_llm = wire_analyzer(monkeypatch, {**draft, "confidence": "reported", "state": "developing"})
    dev_llm.analyze(src_item, prior=dev_prior)
    assert dev_llm.client.requests[0][1]["response_format"]["json_schema"]["schema"]["properties"]["state"]["enum"] == NON_TAG_STATES
    with pytest.raises(AnalysisError, match="limits"):
        wire_analyzer(monkeypatch, {**draft, "confidence": "reported", "state": "tagged"}).analyze(src_item, prior=dev_prior)
    assert all("Distinct prior" not in c for c in schema["properties"]["evidence"]["items"]["enum"])
    sent = json.loads(body["messages"][1]["content"])
    assert len(sent["prior_story"]["updates"]) == 10 and sent["prior_story"]["updates"][0]["text"] == "Update 2."

    tag = item(kind="tag", title="tor-0.4.9.16", content="")
    tag_llm = wire_analyzer(monkeypatch)
    literal = tag_llm.analyze(tag, prior=prior)
    assert literal == tag_update(tag, prior) and literal["update"] == "The upstream feed lists the tag “tor-0.4.9.16”."
    assert (literal["confidence"], literal["state"]) == ("confirmed", "released")
    assert tag_update(tag, {**prior, "state": "merged"})["state"] == "tagged" and tag_llm.client.requests == []

    row = {"content_hash": "h1"}
    base_key = cache_key(row, DEFAULTS["llm"], prior)
    assert base_key != cache_key(row, DEFAULTS["llm"])
    assert base_key != cache_key(row, DEFAULTS["llm"], {**prior, "state": "tagged"})
    assert base_key != cache_key(row, DEFAULTS["llm"], {**prior, "updates": prior["updates"][:-1]})


def test_shouting_caps_and_malformed_tor_version_helpers_and_validation(monkeypatch):
    """Detect ALL-CAPS shouting and three-part C-Tor version typos across writer validation."""
    for clean in (
        "TCP SYN flood on relays", "HTTP CONNECT proxy", "CVE-2026-1234",
        "BSD PF firewall", "TLS SNI ALPN", "IPV4 IPV6 NAT64", "HSDir and DoS on macOS",
        "CELL_STATS_EXTEND counter",
    ):
        assert not has_shouting_caps(clean)
    for shouted in (
        "AT RISK FOR DEANONYMIZATION AND CONNECTION TRACKING",
        "ROOT CAUSE & BULLETPROOF FIX",
        "DO NOT UPGRADE NOW",
        "THIS IS A CRITICAL WARNING",
    ):
        assert has_shouting_caps(shouted)

    for bad_ver in (
        "Tor 0.4.17 relays", "post-0.4.17 upgrade", "0.4.15 relays",
        "upgrading to v0.4.17", "basic Tor 0.4.17 daemon",
        "Tor 0.4.17 release notes were written today.",
        "The post written yesterday cites Tor 0.4.17.",
        "A sic transit provider upgraded to Tor 0.4.17.",
    ):
        assert has_malformed_tor_version(bad_ver)
        assert has_malformed_tor_version(bad_ver, ["tor"])
        assert has_malformed_tor_version(bad_ver, ["network"])
        assert not has_malformed_tor_version(bad_ver, ["arti"])
    for valid_ver in (
        "Tor 0.4.9.17 is released", "Tor 0.4.9 branch", "Tor 0.4.10.1 alpha",
        "Tor 0.4.17 [sic]", "Tor 0.4.17 (sic)", 'written as "Tor 0.4.17"',
        "written as Tor 0.4.17 in the message", "the 0.4.17 release typo",
        "a 0.4.17 upgrade (version typo in subject)", "10.0.4.17 release",
    ):
        assert not has_malformed_tor_version(valid_ver, ["tor"])

    src = item(content="Operators reported a relay issue on 0.4.17 and 0.4.9.17.")
    ev = ["Operators reported a relay issue"]
    for draft, schema in (
        (analysis(title="DO NOT UPGRADE NOW", evidence=ev), SCHEMA),
        (analysis(summary="Relays are AT RISK FOR DEANONYMIZATION.", evidence=ev), SCHEMA),
        (update_analysis(update="OPERATORS MUST UPGRADE NOW.", evidence=ev), UPDATE_SCHEMA),
    ):
        with pytest.raises(AnalysisError, match="all-caps shouting"):
            validate_analysis(draft, src, schema)

    list_url = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/abc/"
    impact = "The post says operators should monitor relay load."
    for auth, expected in (("community", ""), ("trusted-operator", impact), ("project-sender", impact)):
        mail_item = item(url=list_url, authority=auth, content="Operators should monitor relay load.")
        assert validate_analysis(analysis(why_it_matters=impact, evidence=["Operators should monitor relay load."]), mail_item)["why_it_matters"] == expected

    llm_clear = wire_analyzer(
        monkeypatch,
        analysis(why_it_matters="The report warns DO NOT UPGRADE NOW.", evidence=ev),
        analysis(why_it_matters="The report warns about a post-0.4.17 upgrade.", evidence=ev),
    )
    assert llm_clear.analyze(src)["why_it_matters"] == "" and llm_clear.clears == 1
    assert llm_clear.analyze(src)["why_it_matters"] == "" and llm_clear.clears == 1


def test_mailing_list_blockquote_unquoted_mail_text_and_sender_domain_guards(monkeypatch, tmp_path):
    """Preserve blockquote breaks and isolate unquoted mail text, sender_domain, and reply evidence."""
    html_reply = (
        "<p>Hi Adam,</p><p>Three corrections follow.</p>"
        "<blockquote>&gt; Please create a merge request.<br>&gt; Many relays are falling.</blockquote>"
    )
    assert "\n> Please create a merge request.\n> Many relays are falling." in plain_text(html_reply, 2000, html=True)

    sample_reply = (
        "Hi Adam,\n\n"
        "Three corrections:\n"
        "buf_new() allocates an empty buffer structure.\n\n"
        "[1] Our measurements:\n"
        "https://1aeo.com/blog/tor-begindir-hsdir-mitigation-pressure.html\n\n"
        "On Friday, November 13th, 2026 at 11:02 AM, forest via tor-dev wrote:\n\n"
        "> On 2026-11-11 15:13, keevesadam98--- via tor-dev wrote:\n"
        "> > We are happy to submit this logic as a formal merge request.\n"
        "> Please do. Many of our 42 relays are falling due to this continued attack.\n"
        ">\n"
        "> Regards,\n"
        "> forest"
    )
    stripped = unquoted_mail_text(sample_reply)
    assert "[1] Our measurements:\nhttps://1aeo.com/blog/tor-begindir-hsdir-mitigation-pressure.html" in stripped
    assert all(tok not in stripped for tok in ("On Friday, November 13th", "forest", "keevesadam98"))
    assert unquoted_mail_text("Top reply text.\n\n-----Original Message-----\nFrom: someone@example.org\n\n> Quoted line") == "Top reply text."

    msg_base = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-dev@lists.torproject.org/message"
    rss_xml = list_rss(
        {"title": "[tor-dev] Re: BEGIN_DIR buffer behavior", "link": f"{msg_base}/MSG1/",
         "author": "tor\uff201aeo.com (Tor at 1AEO)", "description": "Unquoted operator clarification."},
        {"title": "[tor-dev] Core update", "link": f"{msg_base}/MSG2/",
         "author": "nickm\uff20torproject.org (Nick Mathewson)", "description": "Project sender note."},
        {"title": "[tor-dev] Community question", "link": f"{msg_base}/MSG3/",
         "author": "forest\uff20example.net (forest)", "description": "Community note."},
    )
    feed_url = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-dev@lists.torproject.org/feed/"
    list_src = source(id="tor-dev", url=feed_url, kind="feed", authority="community", product="tor")
    settings = {**DEFAULTS["collection"], "trusted_operator_domains": ["1aeo.com"]}
    collected = collect.collect_source(FakeClient([response(rss_xml, url=feed_url)]), list_src, {}, settings, "2026-11-15T12:05:00Z")
    by_msg = {entry["url"].rstrip("/").rsplit("/", 1)[-1]: entry for entry in collected["items"]}
    assert by_msg["MSG1"]["authority"] == "trusted-operator" and by_msg["MSG1"]["sender_domain"] == "1aeo.com"
    assert by_msg["MSG2"]["authority"] == "project-sender" and by_msg["MSG2"]["sender_domain"] == "torproject.org"
    assert by_msg["MSG3"]["authority"] == "community" and "sender_domain" not in by_msg["MSG3"]

    without_domain = {k: v for k, v in by_msg["MSG1"].items() if k != "sender_domain"}
    assert item_hash(by_msg["MSG1"]) != item_hash(without_domain)
    assert source_packet.source_fingerprint(by_msg["MSG1"]) != source_packet.source_fingerprint(without_domain)

    reply_item = {**by_msg["MSG1"], "content": sample_reply}
    valid_draft = analysis(
        title="Relay operator clarifies BEGIN_DIR buffer allocation on tor-dev",
        summary="A relay operator at 1aeo.com clarifies that buf_new() allocates an empty buffer structure.",
        why_it_matters="", confidence="reported", evidence=["buf_new() allocates an empty buffer structure."],
    )
    with Store(tmp_path / "reply.sqlite3") as store:
        row = pending(store, dict(reply_item), at="2026-11-15T12:05:00Z", ready="2026-11-15T12:05:00Z")
        pkt_src = store.prepare_candidate(row, valid_draft, "2026-11-15T12:05:00Z")["packet"]["sources"][0]
        assert pkt_src["sender_domain"] == "1aeo.com"
        assert "buf_new() allocates an empty buffer structure." in pkt_src["unquoted_content"]
        assert "forest" not in pkt_src["unquoted_content"]

    writer = wire_analyzer(monkeypatch, valid_draft)
    writer.analyze(dict(reply_item))
    sent_payload = json.loads(writer.client.requests[0][1]["messages"][1]["content"])
    assert sent_payload["sender_domain"] == "1aeo.com" and "forest" not in sent_payload["unquoted_content"]

    short_reply = {**reply_item, "content": "ACK.\n> Our 42 relays are failing right now."}
    subject_reply = {**reply_item, "title": "Re: 42 relays are failing right now",
                     "content": "That count is incorrect and should not be cited.\n> 42 relays are failing right now."}
    assert "failed.writer.quoted_only_evidence" in decisions.CODES
    for target_item, quote in (
        (reply_item, "> Please do. Many of our 42 relays are falling due to this continued attack."),
        (short_reply, "> Our 42 relays are failing right now."),
        (subject_reply, "Re: 42 relays are failing right now"),
    ):
        with pytest.raises(AnalysisError, match="unquoted author text") as err:
            validate_analysis(analysis(title="Relay operator replies on tor-dev",
                                       summary="A relay operator replied to the thread.", evidence=[quote]), target_item)
        assert err.value.code == "writer.quoted_only_evidence"

    for target_item, impact, quote, expected in (
        (reply_item, "The post notes 42 relays are falling.", "buf_new() allocates an empty buffer structure.", ""),
        (reply_item, "The post gives three corrections on buffer allocation.", "buf_new() allocates an empty buffer structure.",
         "The post gives three corrections on buffer allocation."),
        (subject_reply, "The post says 42 relays are failing.", "That count is incorrect and should not be cited.", ""),
    ):
        checked = validate_analysis(analysis(title="Relay operator clarifies BEGIN_DIR buffer allocation",
                                             summary="A relay operator clarifies buf_new() behavior.",
                                             why_it_matters=impact, evidence=[quote]), target_item)
        assert checked["why_it_matters"] == expected


@pytest.mark.parametrize("update", [False, True])
def test_active_prompt_and_base_schema_changes_invalidate_writer_cache(monkeypatch, update):
    """Invalidate `cache_key` whenever the active prompt text or schema bounds change."""
    previous = _prior_story() if update else None
    before = _cache_key_for(previous=previous)
    prompt = "UPDATE_PROMPT" if update else "SYSTEM_PROMPT"
    schema = analyze.UPDATE_SCHEMA if update else analyze.SCHEMA
    with monkeypatch.context() as changed:
        changed.setattr(analyze, prompt, getattr(analyze, prompt) + "\nA changed writer instruction.")
        assert _cache_key_for(previous=previous) != before
    field = "update" if update else "title"
    with monkeypatch.context() as changed:
        changed.setitem(schema["properties"][field], "maxLength", schema["properties"][field]["maxLength"] - 1)
        assert _cache_key_for(previous=previous) != before
    assert _cache_key_for(previous=previous) == before


@pytest.mark.parametrize("update", [False, True])
def test_schema_property_order_is_part_of_writer_identity(monkeypatch, update):
    """Include JSON-schema property order in `cache_key` even when canonical `digest` matches."""
    previous = _prior_story() if update else None
    schema = analyze.UPDATE_SCHEMA if update else analyze.SCHEMA
    before, canonical = _cache_key_for(previous=previous), digest(schema)
    monkeypatch.setitem(schema, "properties", dict(reversed(list(schema["properties"].items()))))
    assert digest(schema) == canonical and _cache_key_for(previous=previous) != before


def test_update_input_policy_invalidates_only_update_drafts(monkeypatch):
    """Invalidate update-mode `cache_key` values without affecting story-mode keys."""
    ordinary, update = _cache_key_for(), _cache_key_for(previous=_prior_story())
    monkeypatch.setattr(analyze, "UPDATE_INPUT_VERSION", analyze.UPDATE_INPUT_VERSION + 1)
    assert _cache_key_for() == ordinary and _cache_key_for(previous=_prior_story()) != update


def test_unchanged_inputs_hit_and_existing_content_model_version_components_remain(monkeypatch):
    """Hit on identical inputs while invalidating on content, model, or `PROMPT_VERSION` changes."""
    original = _cache_key_for()
    assert _cache_key_for(_cache_source()) == original
    assert _cache_key_for(_cache_source(content="A different supported source change.")) != original
    assert _cache_key_for(model="another-writer-model") != original
    monkeypatch.setattr(analyze, "PROMPT_VERSION", analyze.PROMPT_VERSION + "-next")
    assert _cache_key_for() != original


@pytest.mark.parametrize("field,value", [
    ("title", "Changed title"), ("summary", "Changed summary."), ("why_it_matters", "Changed impact."),
    ("confidence", "confirmed"), ("state", "fixed"), ("updated_at", "2020-01-03T00:00:00Z"),
    ("updates", [{"at": "2020-01-02T00:00:00Z", "text": "Another prior update."}]),
])
def test_prior_prompt_context_remains_in_cache_identity(field, value):
    """Bind every writer-visible `prior_story` field into update `cache_key` identity."""
    before = _prior_story()
    after = {**copy.deepcopy(before), field: value}
    assert _cache_key_for(previous=before) != _cache_key_for(previous=after)
    assert _cache_key_for(previous=before) != _cache_key_for()


@pytest.mark.parametrize("incoming,before,after", [
    (_cache_source(), _prior_story(), {**_prior_story(), "category": "release"}),
    (_cache_source(kind="gitlab_mr", upstream_state="merged"), _prior_story(state="merged"),
     {**_prior_story(state="merged"), "sources": [{"url": "https://source.example/project/-/issues/1", "title": "Source"}]}),
])
def test_prior_grammar_dependencies_are_bound_without_changing_prompt_context(incoming, before, after):
    """Bind grammar-driving `prior_story` category and merge-source predicates into `cache_key`."""
    assert analyze.prior_context(before) == analyze.prior_context(after)
    assert _writer_schema(incoming, analyze.UPDATE_SCHEMA, prior=before) != _writer_schema(incoming, analyze.UPDATE_SCHEMA, prior=after)
    assert _cache_key_for(incoming, before) != _cache_key_for(incoming, after)


def test_closed_at_and_prior_source_metadata_do_not_invalidate_writer_cache():
    """Ignore `closed_at` and non-grammar source metadata in `item_hash` and `cache_key`."""
    incoming, before = _cache_source(), _prior_story()
    after = copy.deepcopy(before)
    after["closed_at"] = "2020-02-01T00:00:00Z"
    after["sources"][0].update(closed_at="2020-02-01T00:00:00Z", title="Changed caption", id="extra-metadata")
    changed = {**incoming, "closed_at": "2020-02-01T00:00:00Z"}
    assert item_hash(incoming) == item_hash(changed)
    assert _cache_key_for(changed) == _cache_key_for(incoming)
    assert _cache_key_for(changed, after) == _cache_key_for(incoming, before)
    after["sources"][0]["url"] = "https://source.example/project/-/merge_requests/99"
    assert _cache_key_for(changed, after) == _cache_key_for(incoming, before)


@pytest.mark.parametrize("mutate,invalidates", [
    (lambda d: d["public_comments"][0].update(author="other-author"), True),
    (lambda d: d["public_comments"][0].update(created_at="2020-01-03T00:00:00Z"), True),
    (lambda d: d["public_comments"][0].update(body="A changed public observation."), True),
    (lambda d: (d.update(comments_checked_at="2020-01-04T00:00:00Z", comments_source_key="poll-marker"),
                d["public_comments"][0].update(id="another-id", url="https://source.example/other", edited_at="2020-01-04T00:00:00Z")), False),
])
def test_writer_comment_cache_invalidation_and_polling_exclusions(mutate, invalidates):
    """Invalidate `cache_key` on writer-visible comment changes while ignoring polling metadata."""
    note = make_note(1, "A public source observation.", author="author", created_at="2020-01-02T00:00:00Z",
                     url="https://source.example/note#note_1", note_id="note-1")
    incoming = _cache_source(public_comments=[note])
    changed = copy.deepcopy(incoming)
    mutate(changed)
    assert (_cache_key_for(incoming) != _cache_key_for(changed)) is invalidates


@pytest.mark.parametrize("field,value", [
    ("model", "another-model"), ("base_url", "https://another.example/v1"),
    ("fallback_base_urls", ["https://fallback.example/v1"]),
    ("temperature", 0.4), ("top_p", 0.9), ("top_k", 15), ("min_p", 0.2),
    ("presence_penalty", 0.2), ("repetition_penalty", 1.2), ("reasoning_effort", "medium"),
    ("max_output_tokens", 4096), ("max_response_bytes", 131072),
    ("enable_thinking", True), ("send_chat_template_kwargs", False), ("writer_reasoning", True),
])
@pytest.mark.parametrize("update", [False, True])
def test_effective_generation_contract_changes_invalidate_writer_cache(field, value, update):
    """Invalidate `cache_key` whenever any effective LLM generation parameter changes."""
    previous = _prior_story() if update else None
    assert _cache_key_for(previous=previous, **{field: value}) != _cache_key_for(previous=previous)


def test_writer_cache_uses_effective_options_and_excludes_credentials(monkeypatch):
    """Hash effective reasoning-profile options while ignoring overridden scalars and API keys."""
    previous = _prior_story()
    before = _cache_key_for(writer_reasoning=True)
    before_update = _cache_key_for(previous=previous, writer_reasoning=True)
    overrides = dict(writer_reasoning=True, temperature=0, max_output_tokens=7, enable_thinking=False,
                     api_key_env="ANOTHER_PRIVATE_KEY_NAME", credential="not-part-of-generation")
    monkeypatch.setenv("ANOTHER_PRIVATE_KEY_NAME", "synthetic-private-value")
    assert _cache_key_for(**overrides) == before
    assert _cache_key_for(previous=previous, **overrides) == before_update
    assert before_update != before


def test_fallback_order_is_part_of_writer_identity():
    """Treat `fallback_base_urls` ordering as part of `cache_key` identity."""
    urls = ["https://first.example/v1", "https://second.example/v1"]
    assert _cache_key_for(fallback_base_urls=urls) != _cache_key_for(fallback_base_urls=list(reversed(urls)))


def test_enabled_writer_sends_the_declared_profile_exactly(capture):
    """Send the exact `writer_reasoning` sampling and thinking wire payload without mutating config."""
    config = _reasoning_settings(True)
    before = copy.deepcopy(config)
    sent, effective, transport = capture(Analyzer, config)
    expected = {
        "model": "writer-model",
        "messages": [{"role": "system", "content": REASONING_PROMPT},
                     {"role": "user", "content": json.dumps(REASONING_PAYLOAD, ensure_ascii=False, allow_nan=False)}],
        "temperature": 1.0, "max_tokens": 32768,
        "response_format": {"type": "json_schema", "json_schema": {"name": "profile_probe", "strict": True, "schema": REASONING_SCHEMA}},
        "top_p": 0.95, "top_k": 20, "min_p": 0.0,
        "presence_penalty": 0.0, "repetition_penalty": 1.0, "reasoning_effort": "xhigh",
        "chat_template_kwargs": {"enable_thinking": True},
        "stream": True,
    }
    assert json.loads(sent.content) == expected
    assert transport["max_response_bytes"] == 2097152
    assert transport["timeout_seconds"] == effective["timeout_seconds"] == 3600
    assert transport["total_timeout_seconds"] == 3610
    assert config == before


@pytest.mark.parametrize("cls", [RealReviewer, LinkChecker])
def test_writer_option_does_not_change_other_stages(capture, cls):
    """Keep `Reviewer` and `LinkChecker` wire profiles isolated from `writer_reasoning`."""
    off = _reasoning_settings(False)
    before, effective_before, transport_before = capture(cls, off)
    enabled = _reasoning_settings(True)
    original = copy.deepcopy(enabled)
    capture(Analyzer, enabled)
    after, effective_after, transport_after = capture(cls, enabled)
    before_body, after_body = json.loads(before.content), json.loads(after.content)
    assert before_body == after_body and transport_before == transport_after and enabled == original
    assert after_body["chat_template_kwargs"] == {"enable_thinking": False}
    assert "reasoning_effort" not in after_body
    assert effective_before["max_output_tokens"] == effective_after["max_output_tokens"]


@pytest.mark.parametrize("template", [False, True])
def test_disabled_writer_keeps_existing_wire_semantics(capture, template):
    """Preserve non-reasoning `Analyzer` wire defaults when `writer_reasoning` is disabled."""
    config = _reasoning_settings(False)
    config["llm"]["send_chat_template_kwargs"] = template
    sent, effective, transport = capture(Analyzer, config)
    body = json.loads(sent.content)
    assert body["temperature"] == 0 and body["max_tokens"] == 1200
    assert transport["max_response_bytes"] == 65536 and not effective["enable_thinking"]
    assert ("chat_template_kwargs" in body) is template
    assert not {"top_p", "top_k", "min_p", "presence_penalty", "repetition_penalty", "reasoning_effort"} & body.keys()


def test_profile_does_not_override_the_configured_timeout(capture):
    """Honor custom `llm.timeout_seconds` values when `writer_reasoning` is enabled."""
    config = _reasoning_settings(True)
    config["llm"]["timeout_seconds"] = 45
    _, effective, transport = capture(Analyzer, config)
    assert effective["timeout_seconds"] == transport["timeout_seconds"] == 45


@pytest.mark.parametrize("enabled", [False, True])
def test_writer_reasoning_is_a_validated_operator_setting(tmp_path, enabled):
    """Load boolean `llm.writer_reasoning` values cleanly from TOML."""
    path = write_toml(tmp_path, f"[llm]\nwriter_reasoning = {str(enabled).lower()}", name="app.toml")
    assert load_config(path)["llm"]["writer_reasoning"] is enabled


def test_reasoning_requires_the_declared_chat_template_contract():
    """Reject `writer_reasoning = true` when `send_chat_template_kwargs` is disabled in `Analyzer`."""
    config = _reasoning_settings(True)
    config["llm"]["send_chat_template_kwargs"] = False
    with pytest.raises(ValueError, match="writer_reasoning requires"):
        Analyzer(config)


@pytest.mark.parametrize("toml_body,match", [
    ("[llm]\nwriter_reasoning=true\nsend_chat_template_kwargs=false", "writer_reasoning requires"),
    *[(f"[llm]\nwriter_reasoning={v}", "writer_reasoning must be a boolean") for v in ('"true"', "1", "[]")],
])
def test_writer_reasoning_rejects_invalid_toml_settings(tmp_path, toml_body, match):
    """Reject incompatible or non-boolean `llm.writer_reasoning` TOML configurations."""
    with pytest.raises(ValueError, match=match):
        load_config(write_toml(tmp_path, toml_body, name="app.toml"))


@pytest.mark.parametrize("prior_legacy", [False, True])
@pytest.mark.parametrize("current_legacy", [False, True])
@pytest.mark.parametrize("body_changed", [False, True])
def test_update_writer_receives_only_effective_new_description_and_notes(
        store, monkeypatch, prior_legacy, current_legacy, body_changed):
    """Filter unchanged/quoted descriptions and old notes across legacy and modern item formats."""
    description = "The original report describes a circuit allocation defect."
    old_note = make_note("1", "The original reporter is investigating the defect.", author="reporter",
                         created_at=DATE, url="https://example.org/news/1", note_id="1")
    original = _saved_item(description, legacy=prior_legacy, notes=[old_note], updated_at=DATE)
    seed_story(store, original, analysis(summary=description, evidence=[description]), key="first")
    added = "The reporter has prepared a patch for the allocation defect."
    new_note = make_note("2", added, author="reporter", created_at=LATER, url="https://example.org/news/1", note_id="2")
    changed = "The updated description identifies the affected allocation path."
    latest_body = changed + "\n> An old quoted claim must not be new evidence." if body_changed else description
    incoming = _saved_item(latest_body, legacy=current_legacy, notes=[new_note, old_note], updated_at=LATER)
    row = pending(store, incoming, at=LATER, ready=LATER)
    original_payload = json.loads(row["payload"])
    untouched = copy.deepcopy(original_payload)
    mode, filtered = candidate.own_update_input(store.db, row, original_payload)
    assert mode == "update" and original_payload == untouched
    assert "source_content" not in filtered
    assert filtered["content"] == (changed if body_changed else "")
    assert filtered["public_comments"] == [new_note]
    captured = {}

    def _complete(self, _prompt, payload, schema, schema_name):
        captured.update(payload=payload, schema=schema, name=schema_name)
        return update_analysis(update=added, evidence=[added])

    monkeypatch.setattr(Analyzer, "complete", _complete)
    with Analyzer(DEFAULTS) as writer:
        writer.analyze(filtered, candidate.update_target(store.db, row))
    assert captured["name"] == "onionflash_update"
    assert captured["payload"]["content"] == (changed if body_changed else "")
    assert captured["payload"]["public_comments"] == [{key: new_note[key] for key in ("author", "created_at", "body")}]
    choices = captured["schema"]["properties"]["evidence"]["items"]["enum"]
    assert added in choices and description not in choices
    assert not any("old quoted claim" in choice for choice in choices)


def test_legacy_reply_description_cannot_restore_quoted_history(store):
    """Strip quoted reply history from legacy `source_content` during `own_update_input`."""
    seed_story(store, item(), analysis(), key="first")
    existing = dict(store.db.execute("SELECT * FROM stories").fetchone())
    reply = item(id="reply", kind="feed", url="https://example.org/reply", title="Re: Allocation defect",
                 content="An obsolete composed body.", source_content="A new patch was proposed.\n> Old quoted history.",
                 updated_at=LATER)
    mode, filtered = candidate.own_update_input(store.db, {"id": "reply"}, reply, existing=existing)
    assert mode == "update" and filtered["content"] == "A new patch was proposed."
    assert analysis_context(filtered)[0] == "A new patch was proposed."
    assert "source_content" not in filtered and reply["source_content"].endswith("Old quoted history.")


def test_description_format_does_not_change_identity_but_effective_body_does():
    """Compute identical `item_hash` values across legacy and modern description representations."""
    description = "The original report describes a circuit allocation defect."
    modern = _saved_item(description, legacy=False, notes=[], updated_at=DATE)
    legacy = _saved_item(description, legacy=True, notes=[], updated_at=DATE)
    assert item_hash(legacy) == item_hash(modern)
    assert item_hash({**legacy, "content": "Different obsolete composed text."}) == item_hash(legacy)
    changed = {**legacy, "source_content": "The updated report describes a second affected allocation path."}
    assert item_hash(changed) != item_hash(legacy)


def test_legacy_description_edit_alone_is_queued_and_reaches_update_writer(store):
    """Queue a legacy `source_content` edit and pass its updated text into update mode."""
    original = _saved_item("The original report describes a circuit allocation defect.",
                           legacy=True, notes=[], updated_at=DATE)
    seed_story(store, original, analysis(evidence=[original["source_content"]]), key="first")
    changed = "The updated report identifies another affected allocation path."
    incoming = {**original, "source_content": changed, "updated_at": LATER}
    row = pending(store, incoming, at=LATER, ready=LATER)
    mode, filtered = candidate.own_update_input(store.db, row, json.loads(row["payload"]))
    assert mode == "update" and analysis_context(filtered) == (changed, [])


def test_unquoted_mail_text_preserves_dated_headings_eof_from_and_strips_wrapped_on_wrote():
    """Preserve dated author timelines and EOF `From:` prose while stripping wrapped `On ... wrote:` headers."""
    assert unquoted_mail_text("2026-11-15 status update:\nOn 2026-11-14, Bob wrote:\n> Any update on CPU load?") == "2026-11-15 status update:"
    multi_dated = "2026-11-14 rollout started:\n2026-11-15 CPU load stabilized:\nOn 2026-11-13, Bob wrote:\n> Status?"
    assert unquoted_mail_text(multi_dated) == "2026-11-14 rollout started:\n2026-11-15 CPU load stabilized:"
    assert unquoted_mail_text("On Wednesday,\n2026-11-16 at 10:00 UTC, Alice wrote:\n> Any update on CPU load?") == ""
    eof_from = "We tested the patch on 3 relays.\nFrom: our Prometheus metrics, CPU dropped 40%."
    assert unquoted_mail_text(eof_from) == eof_from
    assert unquoted_mail_text("From: Alice\n> Any update on CPU load?") == ""

    author_on = (
        "On Tor 0.4.8.19, our relay crashed at startup.\n"
        "On Mon, Nov 16, 2026 at 10:00 AM Alice wrote:\n"
        "> Did anyone else see this?"
    )
    assert unquoted_mail_text(author_on) == "On Tor 0.4.8.19, our relay crashed at startup."
    list_item = item(
        url="https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/M1/",
        kind="feed",
        authority="community",
        title="[tor-relays] Re: Relay startup crash",
        content=author_on,
    )
    valid_draft = analysis(
        title="Relay operator reports startup crash on Tor 0.4.8.19",
        summary="A relay operator reports a startup crash on Tor 0.4.8.19.",
        why_it_matters="",
        category="relay",
        tags=["relay"],
        confidence="reported",
        state="developing",
        evidence=["On Tor 0.4.8.19, our relay crashed at startup."],
    )
    assert validate_analysis(copy.deepcopy(valid_draft), list_item)["evidence"] == [
        "On Tor 0.4.8.19, our relay crashed at startup."
    ]
    for wrapped in (
        "Am 16.11.2026 um 10:00 schrieb Alice Example\n<alice@torproject.org>:\n> Quote",
        "Le 16/11/2026 à 10:00, Alice Example\n<alice@torproject.org> a écrit :\n> Quote",
        "On Mon, Nov 16, 2026 at 10:00 AM Alice wrote :\n> Quote",
        "On Mon, Nov 16, 2026 at 10:00 AM\nAlice Example <alice@torproject.org>\nwrote:\n> Quote",
    ):
        assert unquoted_mail_text(wrapped) == ""


def test_writer_schema_separates_short_quoted_lines_and_fails_fast_on_ack_only_replies(monkeypatch):
    """Prevent short `>`-quoted lines from poisoning unquoted excerpts and fail fast before HTTP on ack-only replies."""
    list_url = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/M2/"
    short_quote_body = "> Hi,\nWe saw the exact same relay crash on Tor 0.4.8.19 today."
    post = item(
        url=list_url,
        kind="feed",
        authority="community",
        title="[tor-relays] Relay crash",
        content=short_quote_body,
    )
    schema = _writer_schema(post)
    expected_exc = "We saw the exact same relay crash on Tor 0.4.8.19 today."
    assert expected_exc in schema["properties"]["evidence"]["items"]["enum"]

    reply_draft = analysis(
        title="Operator reports relay crash on Tor 0.4.8.19",
        summary="An operator reports seeing the same relay crash on Tor 0.4.8.19.",
        why_it_matters="",
        category="relay",
        tags=["relay"],
        confidence="reported",
        state="developing",
        evidence=[expected_exc],
    )
    writer = wire_analyzer(monkeypatch, reply_draft)
    out = writer.analyze(post)
    assert out["evidence"] == [expected_exc] and writer.calls == 1

    for ack_body in (
        "On Mon, Nov 16, 2026 at 10:00 AM Alice wrote:\n> Our relay crashed on Tor 0.4.8.19.\n\n+1",
        "On Mon, Nov 16, 2026 at 10:00 AM Alice wrote:\n> Our relay crashed on Tor 0.4.8.19.",
    ):
        ack_writer = wire_analyzer(monkeypatch, reply_draft)
        with pytest.raises(AnalysisError) as err:
            ack_writer.analyze({**post, "content": ack_body})
        assert err.value.code == "writer.quoted_only_evidence" and ack_writer.calls == 0


def test_validate_schema_field_enforces_booleans_unsupported_types_and_clean_evidence():
    """Validate boolean types, reject unknown schema rule types, and reject control/noncharacter evidence."""
    assert validate_schema_field(True, {"type": "boolean"}, error=AnalysisError) is True
    assert validate_schema_field(False, {"type": "boolean"}, error=AnalysisError) is False
    for bad_bool in (1, 0, "true", None):
        with pytest.raises(AnalysisError):
            validate_schema_field(bad_bool, {"type": "boolean"}, error=AnalysisError)
    with pytest.raises(ValueError, match="Unsupported schema rule type"):
        validate_schema_field(1, {"type": "integer"}, error=AnalysisError)

    src = item(content="Tor 0.4.8.13 fixes relay bug now.")
    for bad_char in ("\x00", "\x1f", "\ufffe"):
        bad_draft = analysis(
            title="Tor 0.4.8.13 fixes relay bug",
            summary="Tor 0.4.8.13 fixes relay bug now.",
            evidence=[f"Tor 0.4.8.13 fixes relay bug{bad_char} now."],
        )
        with pytest.raises(AnalysisError, match="evidence"):
            validate_analysis(bad_draft, src)


def test_unquoted_mail_text_preserves_on_prose_before_wrapped_and_dated_quote_intros(monkeypatch):
    """Preserve unquoted 'On ...' author prose above wrapped multi-line or dated quote headers."""
    list_url = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/M3/"
    wrapped_intro = (
        "On Tor 0.4.8.19, our relay crashed at startup\n"
        "On Mon, Nov 16, 2026 Alice Example\n"
        "wrote:\n"
        "> Did anyone else see this?"
    )
    assert unquoted_mail_text(wrapped_intro) == "On Tor 0.4.8.19, our relay crashed at startup"

    dated_intro = (
        "On Tor 0.4.8.19 we saw a regression\n"
        "2026-11-16 10:00 Alice wrote:\n"
        "> Did anyone else see this?"
    )
    assert unquoted_mail_text(dated_intro) == "On Tor 0.4.8.19 we saw a regression"
    assert unquoted_mail_text("On Wednesday,\n2026-11-16 at 10:00 UTC,\nAlice wrote:\n> Any update on CPU load?") == ""

    for body, quote in (
        (wrapped_intro, "On Tor 0.4.8.19, our relay crashed at startup"),
        (dated_intro, "On Tor 0.4.8.19 we saw a regression"),
    ):
        post = item(url=list_url, kind="feed", authority="community", title="[tor-relays] Re: Crash", content=body)
        draft = analysis(
            title="Relay operator reports crash on Tor 0.4.8.19",
            summary=f"{quote}.",
            why_it_matters="",
            category="relay",
            tags=["relay"],
            confidence="reported",
            state="developing",
            evidence=[quote],
        )
        writer = wire_analyzer(monkeypatch, draft)
        assert writer.analyze(post)["evidence"] == [quote] and writer.calls == 1


def test_unquoted_mail_text_strips_time_colon_initial_abbrev_and_nfd_headers_and_fails_fast(monkeypatch):
    """Strip wrapped HH:MM:, initial/month-abbreviation, and NFD quote headers while keeping author prose."""
    list_url = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/M4/"
    headers = (
        "On Mon, Nov 16, 2026 at 10:00:\nAlice Example wrote:\n> Our relay crashed on Tor 0.4.8.19.",
        "On Mon, 16 Nov. 2026, J.\nDoe wrote:\n> Our relay crashed on Tor 0.4.8.19.",
        "Am 16.11.2026 um 10:00\nUhr schrieb J.\nDoe:\n> Our relay crashed on Tor 0.4.8.19.",
        "Le 16/11/2026 à 10:00, Alice a e\u0301crit :\n> Our relay crashed on Tor 0.4.8.19.",
        "Le 16 nov.\n2026 à 10:00, Alice a e\u0301crit :\n> Our relay crashed on Tor 0.4.8.19.",
    )
    for body in headers:
        assert unquoted_mail_text(body) == ""
        ack_post = item(
            url=list_url,
            kind="feed",
            authority="community",
            title="[tor-relays] Re: Crash",
            content=f"{body}\n\n+1",
        )
        writer = wire_analyzer(monkeypatch, analysis())
        with pytest.raises(AnalysisError) as err:
            writer.analyze(ack_post)
        assert err.value.code == "writer.quoted_only_evidence" and writer.calls == 0

    for prose_body, expected in (
        ("On Tor 0.4.8.19, our relay crashed.\nOn 2026-11-16 Alice wrote:\n> Quote", "On Tor 0.4.8.19, our relay crashed."),
        ("On Tor 0.4.8.19, status update:\nOn 2026-11-16 Alice wrote:\n> Quote", "On Tor 0.4.8.19, status update:"),
        ("On Tor 0.4.8.19, we tested Tor.\nOn 2026-11-16 Alice wrote:\n> Quote", "On Tor 0.4.8.19, we tested Tor."),
        ("On Tor 0.4.8.19, our relay crashed.\nwrote:\n> Quote", "On Tor 0.4.8.19, our relay crashed.\nwrote:"),
    ):
        assert unquoted_mail_text(prose_body) == expected


def test_unquoted_mail_text_keeps_from_prose_and_dated_headings_before_quotes(store):
    """Keep `From:` prose above attributions and dated author headings directly above quotes."""
    from_prose = "From: our metrics, CPU dropped 40%.\nOn Tuesday, Alice wrote:\n> Any update?"
    assert unquoted_mail_text(from_prose) == "From: our metrics, CPU dropped 40%."
    assert unquoted_mail_text(
        "From: our metrics, CPU dropped 40%.\n-----Original Message-----\nFrom: someone@example.org\n> Any update?"
    ) == "From: our metrics, CPU dropped 40%."
    assert unquoted_mail_text("From: Alice\n> Any update on CPU load?") == ""
    assert unquoted_mail_text(
        "Top reply.\n\n-----Original Message-----\nFrom: Alice <alice@example.org>\n"
        "Sent: Tuesday, Nov 16, 2026 10:00 AM\nTo: tor-relays@lists.torproject.org\n"
        "Subject: Re: CPU load\n\n> Quoted line"
    ) == "Top reply."
    assert unquoted_mail_text(
        "Top reply.\n\nFrom: Alice <alice@example.org>\nDate: Tue, 16 Nov 2026 10:00:00 +0000\n"
        "Subject: Re: CPU load\n\n> Quoted line"
    ) == "Top reply."

    dated_heading = "2026-11-15 CPU load returned to baseline:\n> Did CPU load recover?"
    assert unquoted_mail_text(dated_heading) == "2026-11-15 CPU load returned to baseline:"
    assert unquoted_mail_text("2026-11-15 Alice wrote:\n> Did CPU load recover?") == ""
    assert unquoted_mail_text("2026-11-15 10:00 schrieb Alice:\n> Did CPU load recover?") == ""

    base_url = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message"
    original = item(
        url=f"{base_url}/CPU1/",
        kind="feed",
        authority="community",
        title="[tor-relays] Relay CPU load spike",
        content="Relays observed elevated CPU load after deployment.",
        published_at=DATE,
        updated_at=DATE,
    )
    seeded = seed_story(store, original, analysis(summary=original["content"], evidence=[original["content"]]), key="cpu-1")
    for idx, (reply_body, expected_kept) in enumerate((
        (from_prose, "From: our metrics, CPU dropped 40%."),
        (dated_heading, "2026-11-15 CPU load returned to baseline:"),
    ), 2):
        reply = item(
            url=f"{base_url}/CPU{idx}/",
            kind="feed",
            authority="community",
            title="[tor-relays] Re: Relay CPU load spike",
            content=reply_body,
            published_at=LATER,
            updated_at=LATER,
        )
        row = pending(store, reply, at=LATER, ready=LATER)
        with store.db:
            store.db.execute("UPDATE items SET story_id=? WHERE id=?", (seeded["id"], row["id"]))
        row = {**row, "story_id": seeded["id"]}
        mode, filtered = candidate.own_update_input(store.db, row, json.loads(row["payload"]))
        assert mode == "update" and filtered["content"] == expected_kept


def test_editorial_polish_pass_thread_root_label_normalization_and_fallback(monkeypatch):
    """Run two-stage polish when enabled, forward thread_root safely, normalize labels, and fall back on invalid polish."""
    from onionflash.llm import CompletionDeferred

    # 1. Story polish (2 calls), headline refinement, why_it_matters preservation, and label retention.
    src_item = item(
        title="tor#41500: Consensus votes exceeding 16 MB fail serialization",
        content="Consensus votes larger than 16 MB are truncated before signing on Tor 0.4.9.16.",
        labels=[],
    )
    initial_draft = analysis(
        title="Tor issue reports consensus vote truncation over 16 MB",
        summary="A GitLab issue says consensus votes larger than 16 MB are truncated before signing on Tor 0.4.9.16.",
        why_it_matters="Large directory votes exceeding 16 MB can be truncated before signing.",
        category="network",
        priority="normal",
        confidence="reported",
        state="developing",
        products=["tor"],
        tags=["network"],
        evidence=["Consensus votes larger than 16 MB are truncated before signing on Tor 0.4.9.16."],
    )
    polished_reply = {
        "title": "Tor consensus votes over 16 MB truncated before signing",
        "summary": "Votes larger than 16 MB are truncated before signing on Tor 0.4.9.16.",
        "why_it_matters": "Directory authority votes exceeding 16 MB on Tor 0.4.9.16 can be truncated before signing.",
    }
    cfg = copy.deepcopy(DEFAULTS)
    cfg["llm"].update(base_url="https://llm.example/v1")
    monkeypatch.setenv(cfg["llm"]["api_key_env"], "test-key")
    polished_writer = Analyzer(cfg, editorial_polish=True)
    polished_writer.client = FakeLLM(initial_draft, polished_reply)
    out = polished_writer.analyze(src_item)
    assert len(polished_writer.client.requests) == 2 and polished_writer.calls == 2
    assert out["title"] == polished_reply["title"]
    assert out["summary"] == polished_reply["summary"]
    assert out["why_it_matters"] == polished_reply["why_it_matters"]
    assert out["evidence"] == initial_draft["evidence"]
    assert out["category"] == "network" and out["state"] == "developing"
    polish_req = polished_writer.client.requests[1][1]
    assert polish_req["messages"][0]["content"] == analyze.POLISH_PROMPT
    assert polish_req["response_format"]["json_schema"]["name"] == "onionflash_polish"
    assert polish_req["response_format"]["json_schema"]["schema"] == analyze.POLISH_SCHEMA
    polish_payload = json.loads(polish_req["messages"][1]["content"])
    assert polish_payload["draft"]["why_it_matters"] == initial_draft["why_it_matters"]

    # 2. Partial polish reply retains omitted why_it_matters and validated fields; ungrounded polish clears why_it_matters.
    omitted_wim_writer = Analyzer(cfg, editorial_polish=True)
    omitted_wim_writer.client = FakeLLM(initial_draft, {"title": "Polished headline", "summary": "Polished summary."})
    out_omitted = omitted_wim_writer.analyze(src_item)
    assert out_omitted["title"] == "Polished headline"
    assert out_omitted["why_it_matters"] == initial_draft["why_it_matters"] and omitted_wim_writer.clears == 0

    bad_num_writer = Analyzer(cfg, editorial_polish=True)
    bad_num_writer.client = FakeLLM(initial_draft, {**polished_reply, "why_it_matters": "Votes over 64 MB fail."})
    out_cleared = bad_num_writer.analyze(src_item)
    assert out_cleared["why_it_matters"] == "" and bad_num_writer.clears == 1

    # 3. Fallback on non-retryable AnalysisError (invalid schema keys, shouting caps, truncated), while propagating retryable / Deadline.
    for bad_reply in (
        {"unexpected": "field"},
        {**polished_reply, "title": "RELAYS AT RISK FOR DEANONYMIZATION"},
        completion(polished_reply, finish_reason="length"),
        {**polished_reply, "title": ""},
    ):
        fb_writer = Analyzer(cfg, editorial_polish=True)
        fb_writer.client = FakeLLM(initial_draft, bad_reply)
        fallback_out = fb_writer.analyze(src_item)
        assert fallback_out == initial_draft and len(fb_writer.client.requests) == 2

    retry_writer = Analyzer(cfg, editorial_polish=True)
    retry_writer.client = FakeLLM(initial_draft, FetchError("unavailable", status=503))
    with pytest.raises(AnalysisError) as retry_err:
        retry_writer.analyze(src_item)
    assert retry_err.value.retryable is True

    defer_writer = Analyzer(cfg, editorial_polish=True)
    defer_writer.client = FakeLLM(initial_draft, CompletionDeferred("deadline"))
    with pytest.raises(CompletionDeferred):
        defer_writer.analyze(src_item)

    # 4. Polish skipped on tag items and update mode (prior is not None), and default editorial_polish=False makes 1 call.
    default_writer = wire_analyzer(monkeypatch, initial_draft)
    assert default_writer.analyze(src_item) == initial_draft and len(default_writer.client.requests) == 1

    tag_writer = Analyzer(cfg, editorial_polish=True)
    tag_writer.client = FakeLLM()
    assert tag_writer.analyze(item(kind="tag", title="tor-0.4.9.16", content=""))["state"] == "tagged"
    assert tag_writer.client.requests == []

    upd_draft = update_analysis(update="A follow-up patch landed.", evidence=[src_item["content"]])
    upd_writer = Analyzer(cfg, editorial_polish=True)
    upd_writer.client = FakeLLM(upd_draft)
    assert upd_writer.analyze(src_item, prior=_prior_story())["update"] == upd_draft["update"]
    assert len(upd_writer.client.requests) == 1

    # 5. thread_root forwarded into bounded payload (never into evidence or impact_context).
    list_url = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/R2/"
    reply_item = item(
        url=list_url, kind="feed", authority="trusted-operator",
        title="[tor-relays] Re: Guard bandwidth drop",
        content="Our 5 relays saw stable throughput today.\n> Earlier 99 relays dropped.",
        labels=[],
        thread_root={"title": "[tor-relays] Guard bandwidth drop", "published_at": DATE,
                     "url": "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/R1/",
                     "excerpt": "We saw 77 relays drop bandwidth earlier."},
    )
    reply_draft = analysis(
        title="Guard bandwidth steady on 5 observed relays",
        summary="A relay operator reports stable throughput across 5 relays.",
        why_it_matters="5 observed relays maintained stable throughput.",
        category="relay", tags=["relay"], confidence="reported",
        evidence=["Our 5 relays saw stable throughput today."],
    )
    tr_writer = Analyzer(cfg, editorial_polish=True)
    tr_writer.client = FakeLLM(reply_draft, {
        "title": "Guard bandwidth steady on 5 observed relays",
        "summary": "A relay operator reports stable throughput across 5 relays.",
        "why_it_matters": "77 relays dropped bandwidth earlier.",
    })
    tr_out = tr_writer.analyze(reply_item)
    first_sent = json.loads(tr_writer.client.requests[0][1]["messages"][1]["content"])
    first_evidence_enum = tr_writer.client.requests[0][1]["response_format"]["json_schema"]["schema"]["properties"]["evidence"]["items"]["enum"]
    assert first_sent["thread_root"] == reply_item["thread_root"]
    assert all("77 relays" not in exc for exc in first_evidence_enum)
    assert tr_out["why_it_matters"] == "" and tr_writer.clears == 1

    # 6. Merged MR confidence=confirmed & dirauth operational category=directory-authority normalization in polish mode only.
    mr_item = item(kind="gitlab_mr", upstream_state="merged", title="Fix descriptor retry timer", content="Merged fix for descriptor retries.", labels=[])
    mr_draft = analysis(title="Fix descriptor retry timer", summary="Merged fix for descriptor retries.", why_it_matters="",
                        category="network", state="merged", confidence="reported", tags=["network"],
                        evidence=["Merged fix for descriptor retries."])
    mr_polish = {"title": "Tor merges descriptor retry timer fix", "summary": "A merged MR fixes descriptor retry timing.", "why_it_matters": ""}
    mr_writer = Analyzer(cfg, editorial_polish=True)
    mr_writer.client = FakeLLM(mr_draft, mr_polish)
    assert mr_writer.analyze(mr_item)["confidence"] == "confirmed"

    da_item = item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41920",
        kind="gitlab_issue", authority="dirauth-operator", author="linus",
        title="Planned IPv4/IPv6 migration for maatuska",
        content="maatuska will migrate to a new dual-stack subnet.", labels=["Directory Authority (dirauth)"],
    )
    da_draft = analysis(
        title="Maatuska directory authority plans dual-stack migration",
        summary="A ticket plans a dual-stack IP migration for maatuska.",
        why_it_matters="", category="network", tags=["network"],
        evidence=["maatuska will migrate to a new dual-stack subnet."],
    )
    da_polish = {"title": "Maatuska directory authority plans dual-stack IP migration",
                 "summary": "maatuska will migrate to a new dual-stack subnet.", "why_it_matters": ""}
    da_writer = Analyzer(cfg, editorial_polish=True)
    da_writer.client = FakeLLM(da_draft, da_polish)
    da_out = da_writer.analyze(da_item)
    assert da_out["category"] == "directory-authority" and da_out["tags"] == ["directory-authority"]

    with monkeypatch.context() as mp:
        mp.setattr(analyze._util, "should_confirm_merged_mr", lambda srcs: srcs[0].get("kind") == "gitlab_mr", raising=False)
        mp.setattr(analyze._util, "is_dirauth_category_story", lambda srcs: "maatuska" in srcs[0].get("title", ""), raising=False)
        mr_hook = Analyzer(cfg, editorial_polish=True)
        mr_hook.client = FakeLLM(mr_draft, mr_polish)
        assert mr_hook.analyze(mr_item)["confidence"] == "confirmed"
        da_hook = Analyzer(cfg, editorial_polish=True)
        da_hook.client = FakeLLM(da_draft, da_polish)
        assert da_hook.analyze(da_item)["category"] == "directory-authority"

    direct_writer = Analyzer(cfg)
    direct_writer.client = FakeLLM(polished_reply)
    assert direct_writer.polish_draft(initial_draft, src_item, src_item)["title"] == polished_reply["title"]

    # 7. cache_key invalidates on POLISH_PROMPT / POLISH_SCHEMA for story mode, not update mode.
    story_key = _cache_key_for()
    upd_key = _cache_key_for(previous=_prior_story())
    with monkeypatch.context() as mp:
        mp.setattr(analyze, "POLISH_PROMPT", analyze.POLISH_PROMPT + "\nExtra polish note.")
        assert _cache_key_for() != story_key and _cache_key_for(previous=_prior_story()) == upd_key
    with monkeypatch.context() as mp:
        mp.setitem(analyze.POLISH_SCHEMA["properties"]["title"], "maxLength", 139)
        assert _cache_key_for() != story_key and _cache_key_for(previous=_prior_story()) == upd_key
