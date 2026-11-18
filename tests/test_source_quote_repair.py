"""Source quotation repairs retain native validation, replay and verification."""
import copy
import json

import httpx
import pytest

from helpers import LATER, Writer, analysis, item, job, pending, run_gate as run, verdict
from onionflash import candidate as candidate_mod, personal_attribution, review, review_gate, source_quote
from onionflash.llm import AnalysisError
from onionflash.transport import HttpClient
from onionflash.util import digest
from test_review import candidate, packet
from test_review_request_budget import context, record, saved_audit
from test_transport import public_dns


SENTENCE = "Users can inspect the result when the optional setting is enabled."
SECOND = "Operators may inspect the separate report when the feature is available."
QUOTE = source_quote.PREFIX + SENTENCE + "”"
SECOND_QUOTE = source_quote.PREFIX + SECOND + "”"
BODY = "Introduction.\n\n" + SENTENCE + "\n\n" + SECOND + "\n\nFollowing context."


def source():
    result = packet()
    result["sources"][0]["passages"] = [
        {"id": "S1:P1", "text": "Source report"}, {"id": "S1:P2", "text": BODY}]
    return result


def quote_item(**changes):
    return item(title="A source report", content=BODY, **changes)


def draft(**changes):
    return analysis(title="A source report describes the optional setting",
                    summary="The report describes an optional setting.",
                    why_it_matters="The setting always prevents every failure.", **changes)


@pytest.fixture
def native():
    clients = []

    def make(cfg, *responses):
        sent = []
        replies = iter(responses)

        def handle(request):
            sent.append(json.loads(request.content))
            reply = next(replies)
            if isinstance(reply, BaseException):
                raise reply
            if isinstance(reply, int):
                return httpx.Response(reply, text="Synthetic transport failure")
            return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {
                "content": json.dumps(reply)}}]})

        checker = review.Reviewer(cfg)
        checker.client = HttpClient(checker.http_settings, transport=httpx.MockTransport(handle), resolver=public_dns)
        clients.append(checker)
        checker.sent = sent
        return checker

    yield make
    for checker in clients:
        checker.client.close()


def payload(request):
    return json.loads(request["messages"][1]["content"])


def quote_enum(request):
    return request["response_format"]["json_schema"]["schema"]["properties"]["repair"]["anyOf"][1]["properties"]["why_it_matters"]["anyOf"][0]["enum"]


def test_native_wire_selects_exact_quote_and_retains_real_origins(context, native):
    cfg, _ = context
    public, evidence = candidate(), source()
    checker = native(cfg, verdict("revise", criterion="source_support", repair={"why_it_matters": QUOTE}))
    result = checker.review(public, evidence)
    assert result["repair"] == {"why_it_matters": QUOTE}
    assert quote_enum(checker.sent[0]) == ["", QUOTE, SECOND_QUOTE]
    choice = payload(checker.sent[0])["evidence_context"]["source_quote_choices"][0]
    assert choice["origins"][0]["ref"] == "S1:P2"
    passage = payload(checker.sent[0])["evidence_context"]["source_quote_passages"]["S1:P2"]
    origin = choice["origins"][0]
    assert passage["text"] == BODY
    assert passage["source_ref"] == "S1" and passage["source_url"] == evidence["sources"][0]["url"]
    assert passage["text"][origin["start"]:origin["end"]] == SENTENCE
    assert result["criteria"]["source_support"]["source_refs"] == ["S1"]
    assert 'The only allowed why_it_matters edit is ""' not in checker.sent[0]["messages"][0]["content"]
    assert "literal provenance only" in checker.sent[0]["messages"][0]["content"]
    assert review.FIELDS["why_it_matters"]["enum"] == [""]


@pytest.mark.parametrize("bad", ["An invented consequence.", QUOTE.lower(), QUOTE.replace("optional", "mandatory"),
                                  QUOTE.replace(".", "!"), QUOTE.replace("Users can", "Users  can")])
def test_nonmembers_fail_wire_apply_and_final_candidate(context, native, bad):
    cfg, _ = context
    public, evidence = candidate(), source()
    checker = native(cfg, verdict("revise", criterion="source_support", repair={"why_it_matters": bad}))
    with pytest.raises(review.ReviewError):
        checker.review(public, evidence)
    with pytest.raises(review.ReviewError):
        review.apply_repair(public, {"why_it_matters": bad}, packet=evidence)
    with pytest.raises(candidate_mod.ReviewRequired):
        candidate_mod.validate_approved(public, {**public, "why_it_matters": bad}, packet=evidence)


@pytest.mark.parametrize("change", ["empty", "quoted", "uncited", "changed_source", "missing_packet"])
def test_quote_cannot_cross_an_invalid_origin_or_source_boundary(change):
    public, evidence = candidate(), source()
    value = QUOTE
    if change == "empty":
        public["why_it_matters"] = ""
    elif change == "quoted":
        public["why_it_matters"] = SECOND_QUOTE
    elif change == "uncited":
        evidence["sources"][0]["url"] = "https://example.org/uncited"
    elif change == "changed_source":
        evidence["sources"][0]["passages"][1]["text"] = BODY.replace("optional", "mandatory")
    else:
        evidence = None
    with pytest.raises(review.ReviewError):
        review.apply_repair(public, {"why_it_matters": value}, packet=evidence)
    with pytest.raises(candidate_mod.ReviewRequired):
        candidate_mod.validate_approved(public, {**public, "why_it_matters": value}, packet=evidence)


def test_unchanged_writer_why_and_null_clear_remain_valid():
    public, evidence = candidate(), source()
    assert candidate_mod.validate_approved(public, public)
    assert review.validate_review(verdict(), evidence, candidate=public)["verdict"] == "approve"
    changed = review.apply_repair(public, {"summary": "Another source-supported observation."}, packet=evidence)
    assert changed["why_it_matters"] == public["why_it_matters"]
    quoted = review.apply_repair(public, {"why_it_matters": QUOTE}, packet=evidence)
    cleared = review.apply_repair(quoted, {"why_it_matters": ""}, packet=evidence)
    assert cleared["why_it_matters"] == ""
    for value in (QUOTE, SECOND_QUOTE, public["why_it_matters"]):
        with pytest.raises(review.ReviewError):
            review.apply_repair(cleared, {"why_it_matters": value}, packet=evidence)
    with pytest.raises(review.ReviewError):
        review.apply_repair(quoted, {"why_it_matters": SECOND_QUOTE}, packet=evidence)


def test_normalization_cannot_mutate_an_offered_quote(monkeypatch):
    public, evidence = candidate(), source()
    normalize = personal_attribution.normalize

    def drift(value, **kwargs):
        result = normalize(value, **kwargs)
        result["why_it_matters"] = result["why_it_matters"].replace("optional", "mandatory")
        return result

    monkeypatch.setattr(personal_attribution, "normalize", drift)
    with pytest.raises(review.ReviewError, match="Normalization changed"):
        review.apply_repair(public, {"why_it_matters": QUOTE}, packet=evidence)


def test_quote_needs_fresh_native_verification_and_resumes_without_writer(context, native):
    cfg, store = context
    row = pending(store, quote_item())
    first = native(cfg, verdict("revise", criterion="source_support", repair={"why_it_matters": QUOTE}), 500)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(draft()), first)
    assert not store.stories() and job(store)["stage"] == "verify"
    assert record(store)["candidate"]["why_it_matters"] == QUOTE
    assert record(store)["schema_version"] == 2 and record(store)["request_budget"]["reserved"] == 2
    assert quote_enum(first.sent[1]) == [""]
    writer, checker = Writer(), native(cfg, verdict())
    result = run(cfg, store, row, writer, checker)
    assert result["status"] == "published" and result["writer_calls"] == 0 and result["review_calls"] == 1
    assert not writer.calls and store.stories()[0]["why_it_matters"] == QUOTE
    assert payload(checker.sent[0])["candidate"]["why_it_matters"] == QUOTE
    assert "fresh verification request" in checker.sent[0]["messages"][0]["content"]
    assert saved_audit(store)["request_budget"]["reserved"] == 3
    assert [entry["stage"] for entry in saved_audit(store)["reviews"]] == ["review", "verification"]


def pause_approved(cfg, store, row, native, monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(store, "commit_candidate", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("paused commit")))
        with pytest.raises(RuntimeError, match="paused commit"):
            run(cfg, store, row, Writer(draft()), native(cfg,
                verdict("revise", criterion="source_support", repair={"why_it_matters": QUOTE}), verdict()))
    return json.loads(job(store)["envelope_json"]), record(store)


def test_approved_quote_cache_replays_actual_path_without_new_call(context, native, monkeypatch):
    cfg, store = context
    row = pending(store, quote_item())
    prepared, proof = pause_approved(cfg, store, row, native, monkeypatch)
    assert proof["candidate"]["why_it_matters"] == QUOTE
    review_gate.validate_review_state(proof, "approved", proof["candidate"], prepared)
    writer, checker = Writer(), native(cfg)
    result = run(cfg, store, row, writer, checker)
    assert result["status"] == "published" and result["cache_hit"]
    assert not writer.calls and not checker.sent
    assert store.stories()[0]["why_it_matters"] == QUOTE


@pytest.mark.parametrize("bad_origin", ["", SECOND_QUOTE])
def test_saved_replay_rejects_quote_after_clear_or_an_earlier_quote(context, native, monkeypatch, bad_origin):
    cfg, store = context
    row = pending(store, quote_item())
    prepared, proof = pause_approved(cfg, store, row, native, monkeypatch)
    # Keep every transition hash internally consistent; origin permission must reject it.
    original = copy.deepcopy(prepared["candidate"])
    original["why_it_matters"] = bad_origin
    prepared["candidate"] = original
    prepared["candidate_hash"] = digest(original)
    proof["prepared"]["candidate"] = original
    proof["prepared"]["candidate_hash"] = digest(original)
    proof["reviews"][0]["candidate_hash"] = digest(original)
    with pytest.raises(AnalysisError):
        review_gate.validate_review_state(proof, "approved", proof["candidate"], prepared)


def test_quote_repair_keeps_new_absent_name_in_history(context, native):
    cfg, store = context
    first = verdict("revise", criterion="actor_and_action", repair={
        "why_it_matters": QUOTE, "title": "Juno reports that the setting is available."})
    escaped = verdict("revise", criterion="actor_and_action", repair={
        "title": "The report describes an optional setting.", "summary": "juno’s account describes the original observations."})
    checker = native(cfg, first, escaped, verdict(), verdict())
    row = pending(store, quote_item())
    with pytest.raises(review.UnsupportedAttributionReview):
        run(cfg, store, row, Writer(draft()), checker)
    saved = record(store)
    prepared = json.loads(job(store)["envelope_json"])
    assert review.attribution_names(prepared, saved) == ["Juno"]
    assert not store.stories()
    assert any(flag["name"] == "Juno" and flag["field"] == "summary"
               for flag in payload(checker.sent[-1])["application_attribution_checks"])


def test_invalid_quote_reply_is_discarded_before_uniform_correction(context, native):
    cfg, store = context
    row = pending(store, quote_item())
    invalid = verdict("revise", criterion="source_support", repair={"why_it_matters": QUOTE + "Extra."})
    checker = native(cfg, invalid, verdict(), verdict())
    assert run(cfg, store, row, Writer(draft()), checker)["status"] == "published"
    assert payload(checker.sent[0])["candidate"] == payload(checker.sent[1])["candidate"]
    assert store.stories()[0]["why_it_matters"] == draft()["why_it_matters"]
    assert saved_audit(store)["untrusted_proposals"][0]["repair"] is None


def test_quote_never_increases_the_seven_physical_request_cap(context, native):
    cfg, store = context
    row = pending(store, quote_item())
    first = native(cfg, verdict("revise", criterion="source_support", repair={"why_it_matters": QUOTE}), 500)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(draft()), first)
    replies = [verdict("revise", repair={"summary": f"The source describes observation number {number}."})
               for number in range(5)]
    checker = native(cfg, *replies, verdict())
    with pytest.raises(review.ReviewLimitReached):
        run(cfg, store, row, Writer(), checker)
    assert len(first.sent) + len(checker.sent) == 7 and record(store)["request_budget"]["reserved"] == 7
    assert not store.stories()


@pytest.mark.parametrize("why", ["", QUOTE])
def test_empty_or_already_quoted_current_why_offers_only_clear(context, native, why):
    cfg, _ = context
    checker = native(cfg, verdict())
    checker.review(candidate(why_it_matters=why), source())
    assert quote_enum(checker.sent[0]) == [""]
    assert "source_quote_choices" not in payload(checker.sent[0])["evidence_context"]


def test_update_wire_and_immutable_why_stay_outside_quote_permissions(context, native):
    from test_review_scope_budget import update_case
    cfg, _ = context
    case, prepared = update_case()
    checker = native(cfg, verdict(update=True))
    checker.review(case["candidate"], prepared["packet"], update=True, coverage=prepared["coverage"])
    request = checker.sent[0]
    repair = request["response_format"]["json_schema"]["schema"]["properties"]["repair"]["anyOf"][1]["properties"]
    assert "why_it_matters" not in repair and set(repair) == set(review.UPDATE_EDITABLE)
    assert "source_quote_choices" not in payload(request)["evidence_context"]
    assert review.SOURCE_QUOTE_REPAIR_RULE not in request["messages"][0]["content"]
    with pytest.raises(review.ReviewError):
        review.apply_repair(case["candidate"], {"why_it_matters": QUOTE}, packet=prepared["packet"], update=True)


def test_nonprinting_source_character_cannot_be_silently_removed_from_quote():
    evidence = source()
    evidence["sources"][0]["passages"][1]["text"] = (
        "Introduction.\n\nUsers can inspect the optional setting when it is en\x00abled.\n\nFollowing context.")
    assert not source_quote.available(candidate(), evidence)


def test_packet_only_prepass_does_not_apply_uncited_source_caps():
    evidence = source()
    extra = copy.deepcopy(evidence["sources"][0])
    extra.update(id="S0", url="https://example.org/uncited")
    extra["passages"] = [{"id": "S0:P1", "text": "Another source"}, {"id": "S0:P2", "text": (
        "Introduction.\n\n" + "\n\n".join(f"Users can inspect numbered option {n} when enabled." for n in range(9))
        + "\n\nFollowing context.")}]
    evidence["sources"].insert(0, extra)
    repair = verdict("revise", criterion="source_support", repair={"why_it_matters": QUOTE})
    assert review.validate_review(repair, evidence)["repair"]["why_it_matters"] == QUOTE
    assert review.apply_repair(candidate(), {"why_it_matters": QUOTE}, packet=evidence)["why_it_matters"] == QUOTE


def test_second_quote_attempt_is_discarded_then_current_quote_can_be_cleared(context, native):
    cfg, store = context
    row = pending(store, quote_item())
    checker = native(cfg,
        verdict("revise", criterion="source_support", repair={"why_it_matters": QUOTE}),
        verdict("revise", criterion="source_support", repair={"why_it_matters": SECOND_QUOTE}),
        verdict("revise", criterion="source_support", repair={"why_it_matters": ""}), verdict())
    result = run(cfg, store, row, Writer(draft()), checker)
    assert result["status"] == "published" and store.stories()[0]["why_it_matters"] == ""
    assert payload(checker.sent[1])["candidate"] == payload(checker.sent[2])["candidate"]
    assert payload(checker.sent[2])["candidate"]["why_it_matters"] == QUOTE
    assert saved_audit(store)["untrusted_proposals"][0]["repair"] is None
    assert quote_enum(checker.sent[-1]) == [""]


def test_exact_quote_can_fail_fresh_factual_verification(context, native):
    cfg, store = context
    row = pending(store, quote_item())
    checker = native(cfg, verdict("revise", criterion="source_support", repair={"why_it_matters": QUOTE}),
                     verdict("hold", criterion="scope_timing"))
    assert run(cfg, store, row, Writer(draft()), checker)["status"] == "held"
    assert len(checker.sent) == 2 and not store.stories()
    assert record(store)["candidate"]["why_it_matters"] == QUOTE
    assert not review_gate.approval(cfg, store, row["id"])["eligible"]


def test_quote_and_other_field_repair_are_verified_together(context, native):
    cfg, store = context
    row = pending(store, quote_item())
    edits = {"why_it_matters": QUOTE, "title": "A report describes the conditional optional setting",
             "summary": "The setting is optional and the report describes its condition."}
    checker = native(cfg, verdict("revise", criterion="source_support", repair=edits), verdict())
    assert run(cfg, store, row, Writer(draft()), checker)["status"] == "published"
    verified = payload(checker.sent[-1])["candidate"]
    assert all(verified[key] == value for key, value in edits.items())
    assert all(store.stories()[0][key] == value for key, value in edits.items())


def test_repeated_quote_origins_do_not_duplicate_full_passage_context(context, native):
    cfg, _ = context
    evidence = source()
    evidence["sources"][0]["url"] = "https://example.org/" + "long-source-path" * 50
    public = candidate(sources=[{"url": evidence["sources"][0]["url"], "title": "Source report"}])
    repeated = "Introduction.\n\n" + "\n\n".join([SENTENCE] * 20) + "\n\nFollowing context."
    evidence["sources"][0]["passages"] = [{"id": "S1:P1", "text": "Source report"}] + [
        {"id": f"S1:P{number}", "text": repeated} for number in range(2, 16)]
    checker = native(cfg, verdict())
    checker.review(public, evidence)
    context = payload(checker.sent[0])["evidence_context"]
    choices, passages = context["source_quote_choices"], context["source_quote_passages"]
    assert len(choices) == 1 and len(choices[0]["origins"]) == 280
    assert len(passages) == 14
    assert all(passages[origin["ref"]]["text"][origin["start"]:origin["end"]] == SENTENCE
               for origin in choices[0]["origins"])
    assert all(set(origin) == {"ref", "start", "end"} for origin in choices[0]["origins"])
    assert len(json.dumps(choices, ensure_ascii=False).encode()) < 5 * len(json.dumps(evidence).encode())
