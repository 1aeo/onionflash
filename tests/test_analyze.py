"""Draft schema/evidence, shared transport, retained baseline checks and rejection."""

from __future__ import annotations

import copy
import json

import pytest

from helpers import (
    DATE, ApprovingReviewer, FakeLLM, Reviewer, ScriptedAnalyzer, analysis, completion,
    finish_reviewed, item, patch_cli_pipeline, pending, run_gate, update_analysis, verdict,
)
from onionflash import cli, decisions, rejection
from onionflash.analyze import (
    MAX_EVIDENCE_CHOICES, MIN_EVIDENCE_CHARS, SCHEMA, UPDATE_PROMPT, UPDATE_SCHEMA,
    AnalysisError, Analyzer, _writer_schema, cache_key, tag_update, validate_analysis,
)
from onionflash.comments import INPUT_CHARS
from onionflash.config import DEFAULTS
from onionflash.llm import json_object
from onionflash.schema import CATEGORIES, CONFIDENCES, STATES
from onionflash.store import Store
from onionflash.transport import DeadlineReached, FetchError, Response

NON_TAG_STATES = [value for value in STATES if value != "tagged"]
NON_RELEASE_CATEGORIES = [value for value in CATEGORIES if value != "release"]
NUMBERED = item(
    title="Tor 0.4.8.20 and 0.4.9.16 are released",
    content="Upgrade to 0.4.9.16 now. Tor Browser 15.0a3 is affected. 3 authorities voted. Release 2026-11-09. " + "7" * 5000,
)


def analyzer(monkeypatch, *responses, fallbacks=()):
    monkeypatch.setenv("ONIONFLASH_LLM_API_KEY", "test-key")
    cfg = copy.deepcopy(DEFAULTS)
    cfg["llm"].update(base_url="https://llm.example/v1", fallback_base_urls=list(fallbacks))
    result = Analyzer(cfg)
    result.client = FakeLLM(*responses)
    return result


@pytest.mark.parametrize("text", ['{"publish": false, "priority": NaN}', '{"publish": false, "x": 1e999}', "[" * 10000 + "]" * 10000])
def test_json_object_rejects_nonstandard_and_deep_json(text):
    with pytest.raises(AnalysisError, match="invalid JSON"):
        json_object(text)


def test_historical_impact_and_mandatory_draft(monkeypatch):
    saved = analysis(why_it_matters="The report concerns directory authority trust.")
    assert validate_analysis(saved, item()) == saved
    assert analyzer(monkeypatch, completion(analysis(why_it_matters=""))).analyze(item())["why_it_matters"] == ""

    claim = "Operators must update their configurations to exclude the node."
    draft = analysis(summary=claim, why_it_matters="", confidence="reported", state="fixed")
    llm = analyzer(monkeypatch, completion(draft))
    assert llm.analyze(item()) == draft and len(llm.client.requests) == 1

    ignore = analysis(publish=False, title="", summary="", why_it_matters="", evidence=[], products=[], tags=[])
    llm_ig = analyzer(monkeypatch, completion(ignore))
    with pytest.raises(AnalysisError, match="draft for publication review") as caught:
        llm_ig.analyze(item())
    assert not caught.value.retryable and len(llm_ig.client.requests) == 1


@pytest.mark.parametrize("use_fallback", [False, True])
def test_writer_keeps_a_source_stated_impact_sentence(monkeypatch, use_fallback):
    responses = [FetchError("network request failed", retryable=True)] if use_fallback else []
    sentence = "The report says the keys must no longer be trusted."
    responses.append(completion(analysis(why_it_matters=f" {sentence} ")))
    llm = analyzer(monkeypatch, *responses, fallbacks=["https://fallback.example/v1"])
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
    source = f"Version {source_version} includes the reported correction."
    sentence = f"The report says version {sentence_version} includes the correction."
    draft = analysis(why_it_matters=sentence, evidence=[source])
    assert validate_analysis(copy.deepcopy(draft), item(title="Software correction", content=source)) == {
        **draft, "why_it_matters": sentence if kept else ""}


def test_prerelease_words_in_prose_do_not_change_a_count():
    source = "The developers corrected 3 connection failures. A separate release candidate is under review."
    sentence = "The report says developers corrected three connection failures."
    draft = analysis(why_it_matters=sentence, evidence=[source])
    assert validate_analysis(copy.deepcopy(draft), item(title="Connection correction", content=source)) == draft


def test_impact_clears_across_comments_decisions_retries_and_approvals(context, monkeypatch):
    note = {"id": "gid://gitlab/DiscussionNote/1", "url": "https://example.org/issue#note_1",
            "title": "Public comment by @operator", "author": "operator", "created_at": DATE,
            "body": "Relays running 0.4.8.17 must upgrade."}
    kept, dated = "A comment says relays running 0.4.8.17 must upgrade.", "The report was filed in 2026."
    llm = analyzer(monkeypatch, completion(analysis(why_it_matters=kept)), completion(analysis(why_it_matters=dated)))
    assert llm.analyze(item(public_comments=[note]))["why_it_matters"] == kept and llm.clears == 0
    assert llm.analyze(item(public_comments=[note]))["why_it_matters"] == "" and llm.clears == 1
    assert llm.analyze(item(kind="tag", title="tor-0.4.9.16", content=""))["why_it_matters"] == "" and llm.clears == 0
    assert len(llm.client.requests) == 2

    cfg, store = context
    cleared = "The report says relays running 0.4.8.17 must upgrade."
    for url, sentence in (("https://example.org/news/1", cleared), ("https://example.org/news/2", "The report says the keys must no longer be trusted.")):
        w = analyzer(monkeypatch, completion(analysis(why_it_matters=sentence)))
        assert run_gate(cfg, store, pending(store, item(url=url)), w, Reviewer(verdict()))["status"] == "published"
    assert [json.loads(r[0]).get("writer_clears") for r in store.db.execute("SELECT detail_json FROM decision_log ORDER BY id")] == [1, None]
    assert decisions.summary(store.db, DATE)["writer_clears"] == 1

    store.db.execute("DELETE FROM decision_log")
    w1 = analyzer(monkeypatch, completion(analysis(why_it_matters=cleared)))
    r1 = pending(store, item(url="https://example.org/news/retry-clear"))
    assert run_gate(cfg, store, r1, w1, Reviewer(verdict(), verdict("hold", criterion="news_value")))["status"] == "held"
    with store.db:
        store.db.execute("UPDATE items SET status='pending' WHERE id=?", (r1["id"],))
    r1 = store.pending(1, DATE)[0]
    assert run_gate(cfg, store, r1, w1, Reviewer())["status"] == "held"
    rejection.retry_item(store, r1["id"], r1["content_hash"], "Retry kept draft", observed=DATE)
    assert run_gate(cfg, store, store.pending(1, DATE)[0], w1, Reviewer(verdict()))["status"] == "published"

    w2 = analyzer(monkeypatch, completion(analysis(why_it_matters=cleared, evidence=["Second distinct report body."])))
    r2 = pending(store, item(url="https://example.org/news/approve-clear", content="Second distinct report body. " * 5))
    assert run_gate(cfg, store, r2, w2, Reviewer(verdict(), verdict("hold", criterion="news_value")))["status"] == "held"
    shown = rejection.show_item(store, r2["id"], config=cfg)
    rejection.approve_item(cfg, store, r2["id"], shown["final_review"]["approval"]["hash"], "Worth publishing", observed=DATE)

    w3 = analyzer(monkeypatch, completion(analysis(why_it_matters=cleared, evidence=["Third distinct report body."])))
    r3 = pending(store, item(url="https://example.org/news/skip-clear", content="Third distinct report body. " * 5))
    assert run_gate(cfg, store, r3, w3, Reviewer(verdict("skip", criterion="news_value")))["status"] == "ignored"
    store.reject(pending(store, item(url="https://example.org/news/fail-clear", content="Fourth distinct report body. " * 5))["id"],
                 "Invalid review reply", "failed.review.invalid_reply", DATE)

    rows = [(code, json.loads(d).get("writer_clears")) for code, d in store.db.execute("SELECT code, detail_json FROM decision_log ORDER BY id")]
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
    llm = analyzer(monkeypatch, completion(analysis(why_it_matters="", state=state[0])))
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
    responses = [FetchError("network request failed", retryable=True)] if use_fallback else []
    responses.append(completion(analysis(why_it_matters="", **labels)))
    llm = analyzer(monkeypatch, *responses, fallbacks=["https://fallback.example/v1"])
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
    with pytest.raises(AnalysisError, match=match) as caught:
        validate_analysis(analysis(**overrides), item())
    assert not caught.value.retryable


def test_label_normalization_schema_limits_and_release_tag_stripping(monkeypatch):
    merged_mr = item(kind="gitlab_mr", upstream_state="merged")
    draft = analysis(why_it_matters="", state="merged", category="feature", tags=["feature", "release"])
    assert analyzer(monkeypatch, completion(draft)).analyze(merged_mr)["tags"] == ["feature"]
    released = analysis(why_it_matters="", state="released", category="feature", tags=["feature", "release"])
    assert analyzer(monkeypatch, completion(released)).analyze(item(kind="feed", authority="official"))["tags"] == ["feature", "release"]
    misclassified = analysis(why_it_matters="", state="developing", category="release", tags=["release"])
    assert analyzer(monkeypatch, completion(misclassified)).analyze(item())["tags"] == ["release"]
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
def test_endpoint_deadlines_retries_and_malformed_completions(monkeypatch, sent):
    responses = [FetchError("network request failed", retryable=True)] * sent + [DeadlineReached()] * (3 - sent)
    llm = analyzer(monkeypatch, *responses, fallbacks=["https://fallback.example/v1", "https://third.example/v1"])
    with pytest.raises(AnalysisError, match="LLM request failed") as caught:
        llm.analyze(item())
    assert caught.value.retryable and llm.calls == sent and len(llm.client.requests) == sent + 1

    llm401 = analyzer(monkeypatch, FetchError("HTTP 401", status=401))
    with pytest.raises(AnalysisError, match="HTTP 401") as c401:
        llm401.analyze(item())
    assert c401.value.retryable

    llm_ev = analyzer(monkeypatch, completion(analysis(evidence=["words the source never says"])), fallbacks=["https://fallback.example/v1"])
    with pytest.raises(AnalysisError, match="evidence") as cev:
        llm_ev.analyze(item())
    assert not cev.value.retryable and len(llm_ev.client.requests) == 1

    llm_ok = analyzer(monkeypatch, FetchError("network request failed", retryable=True),
                      completion(analysis(why_it_matters="")), fallbacks=["https://fallback.example/v1"])
    assert llm_ok.analyze(item())["title"] == analysis()["title"] and llm_ok.client.requests[0][0].startswith("https://llm.example")

    with pytest.raises(AnalysisError, match="truncated") as ctr:
        analyzer(monkeypatch, completion(analysis(), finish_reason="length")).analyze(item())
    assert not ctr.value.retryable

    with pytest.raises(AnalysisError, match="unexpected response") as cun:
        analyzer(monkeypatch, Response(200, b'{"error": "busy"}', {}, "https://llm.example/v1")).analyze(item())
    assert cun.value.retryable


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
    if match is None:
        assert validate_analysis(analysis(evidence=quotes), item(content=body))["evidence"] == quotes
    else:
        with pytest.raises(AnalysisError, match=match):
            validate_analysis(analysis(evidence=quotes), item(content=body))


@pytest.mark.parametrize("text", ["Straße!", "ßßßß", "ﬃﬃﬃ"])
def test_writer_schema_rejects_short_nfkc_titles(text):
    with pytest.raises(AnalysisError, match="no qualifying literal evidence"):
        _writer_schema({"title": text, "content": ""})


def test_evidence_matching_diagnostics_and_grammar_bounds(monkeypatch):
    llm = analyzer(monkeypatch, completion(analysis(why_it_matters="")))
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
    with_note = item(content="Original description", public_comments=[{
        "id": "gid://gitlab/DiscussionNote/1", "url": "https://example.org/issue#note_1",
        "title": "Public comment by @operator", "author": "operator", "created_at": DATE, "body": note_body,
    }])
    llm_n = analyzer(monkeypatch, completion(analysis(why_it_matters="", evidence=[note_body])))
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

    llm_empty = analyzer(monkeypatch)
    with pytest.raises(AnalysisError, match="no qualifying literal evidence"):
        llm_empty.analyze(item(title="Ack", content="OK"))
    assert llm_empty.client.requests == []

    many = "".join(f"row-{idx:04d}\n" for idx in range(1550)) + "Final comment"
    assert len(many) <= INPUT_CHARS
    m_choices = _writer_schema({"title": "Source title", "content": many})["properties"]["evidence"]["items"]["enum"]
    assert len(m_choices) == MAX_EVIDENCE_CHOICES and m_choices[0] == "Source title" and m_choices[-1] == "Final comment"
    assert any("row-07" in c for c in m_choices) and sum(map(len, m_choices)) <= MAX_EVIDENCE_CHOICES * 500


def test_rejection_strikes_run_endpoint_circuit_breaker_and_source_snapshot(tmp_path, monkeypatch):
    llm_cfg = DEFAULTS["llm"]
    with Store(tmp_path / "state.db") as store:
        src = item()
        store.ingest(src, DATE)
        row = store.pending(1, DATE)[0]
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

    def step(payload):
        calls.append(payload["url"])
        if payload["url"].endswith("/bad") or failing_endpoint:
            raise AnalysisError("LLM request failed (HTTP 400)", retryable=True)
        return analysis()

    patch_cli_pipeline(monkeypatch, analyzer=lambda *a, **kw: ScriptedAnalyzer(step), reviewer=ApprovingReviewer)
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
    base = update_analysis(update="Packages for Debian are now published.", confidence="confirmed",
                           state="released", evidence=[item()["title"]])
    with pytest.raises(AnalysisError):
        validate_analysis({**base, **bad_update}, item(), UPDATE_SCHEMA)


def test_update_mode_sends_prior_context_narrows_schema_and_validates(monkeypatch):
    prior = {
        "id": "a" * 24, "title": "Distinct prior headline",
        "summary": "Distinct prior summary that must never enter evidence choices.",
        "why_it_matters": "Distinct prior consequence.", "category": "release", "priority": "normal",
        "confidence": "confirmed", "state": "released", "products": ["tor"], "tags": ["release"],
        "published_at": DATE, "updated_at": DATE, "added_at": DATE,
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
    assert body["messages"][0]["content"] == UPDATE_PROMPT and body["response_format"]["json_schema"]["name"] == "onionflash_update"
    schema = body["response_format"]["json_schema"]["schema"]
    assert set(schema["properties"]) == {"publish", "update", "confidence", "state", "evidence"}
    assert (schema["properties"]["state"]["enum"], schema["properties"]["confidence"]["enum"]) == (["released"], ["confirmed"])

    tagged_llm = analyzer(monkeypatch, completion(draft))
    tagged_llm.analyze(src_item, prior={**prior, "state": "tagged"})
    assert tagged_llm.client.requests[0][1]["response_format"]["json_schema"]["schema"]["properties"]["state"]["enum"] == ["released", "tagged"]

    dev_prior = {**prior, "category": "security", "confidence": "reported", "state": "developing", "tags": ["security"]}
    dev_llm = analyzer(monkeypatch, completion({**draft, "confidence": "reported", "state": "developing"}))
    dev_llm.analyze(src_item, prior=dev_prior)
    assert dev_llm.client.requests[0][1]["response_format"]["json_schema"]["schema"]["properties"]["state"]["enum"] == NON_TAG_STATES
    with pytest.raises(AnalysisError, match="limits"):
        analyzer(monkeypatch, completion({**draft, "confidence": "reported", "state": "tagged"})).analyze(src_item, prior=dev_prior)
    assert all("Distinct prior" not in c for c in schema["properties"]["evidence"]["items"]["enum"])
    sent = json.loads(body["messages"][1]["content"])
    assert len(sent["prior_story"]["updates"]) == 10 and sent["prior_story"]["updates"][0]["text"] == "Update 2."

    tag = item(kind="tag", title="tor-0.4.9.16", content="")
    tag_llm = analyzer(monkeypatch)
    literal = tag_llm.analyze(tag, prior=prior)
    assert literal == tag_update(tag, prior) and literal["update"] == "The upstream feed lists the tag “tor-0.4.9.16”."
    assert (literal["confidence"], literal["state"]) == ("confirmed", "released")
    assert tag_update(tag, {**prior, "state": "merged"})["state"] == "tagged" and tag_llm.client.requests == []

    row = {"content_hash": "h1"}
    base_key = cache_key(row, DEFAULTS["llm"], prior)
    assert base_key != cache_key(row, DEFAULTS["llm"])
    assert base_key != cache_key(row, DEFAULTS["llm"], {**prior, "state": "tagged"})
    assert base_key != cache_key(row, DEFAULTS["llm"], {**prior, "updates": prior["updates"][:-1]})
