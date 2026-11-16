"""Literal-name absence is a bounded check, never permission to publish."""
import copy
import json

import pytest

from helpers import DATE, LATER, Writer, analysis, insert_approval, pending, run_gate as run, verdict
from onionflash import review, review_gate
from onionflash.analyze import AnalysisError
from onionflash.candidate import ReviewRequired
from onionflash.named_attribution import NAMED_ATTRIBUTION_POLICY, missing_named_attributions
from onionflash.transport import FetchError
from test_review_request_budget import context, record, reviewer, saved_audit


def packet(text="The source describes a parser defect.", *, author="mira"):
    return {"sources": [{"id": "S1", "url": "https://example.org/report", "title": "A source report", "author": author,
                        "passages": [{"id": "S1:P1", "text": "A source report"},
                                     {"id": "S1:P2", "text": text}]}], "missing_sources": []}


def candidate(text, field="title"):
    return {"title": "A source report", "summary": "The report describes the issue.", "why_it_matters": "", field: text}


@pytest.mark.parametrize("text,name", [
    ("Juno reports that clients fail.", "Juno"),
    ("According to Juno, clients fail.", "Juno"),
    ('"Juno" reports that clients fail.', "Juno"),
    ("‘Juno’ reports that clients fail.", "Juno"),
    ("`Juno` reports that clients fail.", "Juno"),
    ("@juno says that clients fail.", "@juno"),
    ("@operator says that clients fail.", "@operator"),
    ("@123juno says that clients fail.", "@123juno"),
    ("Juno Vale says: clients fail.", "Juno Vale"),
    ("Juno Labs states that clients fail.", "Juno Labs"),
    ("According to the Juno Project, clients fail.", "Juno Project"),
    ("Ирина says that clients fail.", "Ирина"),
    ("李雷 reports that clients fail.", "李雷"),
])
@pytest.mark.parametrize("field", ["title", "summary", "why_it_matters"])
def test_absent_explicit_name_is_flagged_in_each_current_field(text, name, field):
    assert missing_named_attributions(candidate(text, field), packet()) == [
        {"field": field, "name": name, "finding": "literal_name_absent_from_source"}]


@pytest.mark.parametrize("text", [
    "The report says that clients fail.", "A public issue reports that clients fail.",
    "The website says that clients fail.", "The notice says that clients fail.",
    "The application reports that clients fail.", "Earlier the source said that clients fail.",
    "A public security report: the parser rejects the input.",
    "According to the merge request, the parser rejects the input.",
    "The development team reported that the parser rejects the input.",
    "The coordinator says that the parser rejects the input.",
    "According to the monitoring daemon, clients fail.",
    "According to the original report, clients fail.",
    "According to Juno's post, clients fail.",
    "A maintainer says that clients fail.", "The operator says that clients fail.",
    "They say that clients fail.", "This says that clients fail.",
    "Arti’s announcement says that clients fail.", "The Tor development team reported a defect.",
    "Juno reported unreachable after an outage.", "The example `Juno reports that X` is syntax.",
    "123Juno reports that clients fail.",
    "Alice Beatrice Claire Diana Evans says that clients fail.",
    "According to Alice Beatrice Claire Diana Evans, clients fail.",
    "```text\nJuno reports that clients fail.\n```\nThe report describes the syntax.",
])
def test_generic_passive_and_code_text_is_not_a_named_attribution(text):
    assert missing_named_attributions(candidate(text), packet()) == []


@pytest.mark.parametrize("text,source", [
    ("Mira says that clients fail.", packet()),
    ("@mira reports that clients fail.", packet()),
    ("@123juno reports that clients fail.", packet(author="123juno")),
    ("According to Juno, clients fail.", packet("Mira is explicitly identified in this report as Juno.")),
    ("Juno Labs reports that clients fail.", packet("Juno Labs published the observations.")),
    ("José reports that clients fail.", packet("Jose\u0301 published the observations.")),
    ("李雷 reports that clients fail.", packet("李雷 published the observations.")),
])
def test_only_literal_source_names_or_explicit_alias_text_can_match(text, source):
    assert missing_named_attributions(candidate(text), source) == []


def test_real_note_author_metadata_is_evidence_without_inference_from_other_metadata():
    source = packet(author="other")
    source["sources"][0]["passages"][1]["author"] = "juno"
    assert not missing_named_attributions(candidate("Juno reports that clients fail."), source)
    source["sources"][0]["passages"][1].pop("author")
    source["sources"][0].update(authority="Juno", product="Juno", source_id="Juno", name="Juno", url="https://example.org/Juno")
    source["sources"][0]["passages"][1]["text"] = "See https://example.org/users/Juno for details."
    assert missing_named_attributions(candidate("Juno reports that clients fail."), source)


@pytest.mark.parametrize("name,source", [("Juno", "Junora"), ("Juno Vale", "Mira Vale"), ("Jose", "José"), ("Mira", "Miranda"), ("Strasse", "Straße"), ("Mira", "Mira-Vale"), ("Mira", "Mira.Vale")])
def test_no_substring_typo_surname_or_transliteration_guess(name, source):
    assert missing_named_attributions(candidate(name + " reports that clients fail."), packet(source, author="other"))


def test_author_metadata_requires_whole_username_and_literal_presence_does_not_prove_identity():
    assert missing_named_attributions(candidate("Mira reports that clients fail."), packet(author="mira-v"))
    # An at-sign is presentation, not an identity lookup. This absence check
    # cannot establish whether the source word actually identifies the speaker.
    assert not missing_named_attributions(candidate("@operator reports that clients fail."), packet("The operator reports a defect.", author="other"))
    assert not missing_named_attributions(candidate("@operator reports that clients fail."), packet("@operator published the report.", author="other"))


def test_quoted_prose_does_not_excuse_an_absent_speaker_and_inputs_are_unchanged():
    text = candidate('The report quotes "Juno reports that clients fail."')
    sources = packet()
    saved = copy.deepcopy((text, sources))
    assert missing_named_attributions(text, sources)[0]["name"] == "Juno"
    assert (text, sources) == saved


def test_update_checks_only_latest_text_and_its_cited_source_scope():
    sources = packet("Juno published an earlier observation.", author="juno")
    sources["sources"][0]["passages"].append({"id": "S1:P3", "text": "The new comment describes a fix.",
                                              "author": "mira", "url": "https://example.org/report#note_1"})
    text = {**candidate("Absent reports that old text was published."), "updates": [
        {"text": "Absent reports that old text was published.", "sources": [{"url": "https://example.org/report"}]},
        {"text": "Juno reports that the fix is available.", "sources": [{"url": "https://example.org/report#note_1"}]}]}
    assert missing_named_attributions(text, sources, update=True) == [{
        "field": "updates[-1].text", "name": "Juno", "finding": "literal_name_absent_from_source"}]
    text["updates"][-1]["text"] = "Mira reports that the fix is available."
    assert not missing_named_attributions(text, sources, update=True)
    text["updates"][-1]["sources"] = [{"url": "https://example.org/report"}]
    text["updates"][-1]["text"] = "Juno reports that the fix is available."
    assert not missing_named_attributions(text, sources, update=True)


def named_draft():
    return {**analysis(), "title": "Juno reports that the source describes a problem."}


@pytest.mark.parametrize("action", ["approve", "revise", "skip", "inconsistent_edit"])
def test_actor_pass_with_missing_name_uses_one_correction_then_fresh_verification(context, action):
    cfg, store = context
    bad = verdict("revise" if action == "inconsistent_edit" else action,
                  criterion="news_value" if action == "skip" else "source_support",
                  repair={"summary": "Untrusted replacement text."} if action in {"revise", "inconsistent_edit"} else None)
    if action == "inconsistent_edit":
        for check in bad["criteria"].values():
            check["outcome"] = "pass"
    fixed = verdict("revise", criterion="actor_and_action", repair={"title": "The source reports a problem"})
    checker = reviewer(cfg, bad, fixed, verdict())
    result = run(cfg, store, pending(store), Writer(named_draft()), checker)
    assert result["status"] == "published" and checker.calls == 3
    bodies = [json.loads(r["messages"][1]["content"]) for r in checker.client.requests]
    assert bodies[0]["application_attribution_checks"][0]["name"] == "Juno"
    assert bodies[1] == {**bodies[0], "validation_error": review.UNSUPPORTED_ATTRIBUTION}
    assert "application_attribution_checks" not in bodies[2]
    assert "Untrusted replacement" not in json.dumps(bodies)
    audit = saved_audit(store)
    assert audit["request_budget"]["reserved"] == 3 and audit["request_budget"]["validation_reask"]["attempts"] == [2]
    event = audit["untrusted_proposals"][0]
    assert event["error"] == review.UNSUPPORTED_ATTRIBUTION and not event["accepted"] and event["repair"] is None
    assert [r["request"] for r in audit["reviews"]] == [2, 3]
    status = review_gate.recovery_status(audit)
    assert status["raw_attribution_count"] == 1 and status["raw_inconsistency_count"] == status["raw_degenerate_count"] == 0
    assert not status["unresolved_attribution"]


def test_repeated_actor_pass_fails_without_new_calls_on_resume(context):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, verdict(), verdict())
    with pytest.raises(review.UnsupportedAttributionReview):
        run(cfg, store, row, Writer(named_draft()), checker)
    assert checker.calls == 2 and not store.stories()
    resumed = reviewer(cfg, verdict(), verdict())
    with pytest.raises(review.UnsupportedAttributionReview):
        run(cfg, store, row, Writer(named_draft()), resumed)
    assert resumed.calls == 0 and record(store)["request_budget"]["reserved"] == 2


def test_existing_correction_slot_is_shared_with_inconsistency(context):
    from test_review_request_budget import inconsistent
    cfg, store = context
    row = pending(store)
    fixed = verdict("revise", criterion="actor_and_action", repair={"title": "The source reports a problem"})
    checker = reviewer(cfg, verdict(), fixed, inconsistent({}))
    with pytest.raises(review.InconsistentReview):
        run(cfg, store, row, Writer(named_draft()), checker)
    assert checker.calls == 3 and record(store)["request_budget"]["validation_reask"]["attempts"] == [2]
    status = review_gate.recovery_status(record(store))
    assert status["raw_inconsistency_count"] == status["raw_attribution_count"] == 1


@pytest.mark.parametrize("corrupted_first", [False, True])
def test_attribution_and_corruption_share_the_same_correction_slot(context, corrupted_first):
    from test_degenerate_review import corrupt
    cfg, store = context
    replies = (corrupt(), verdict()) if corrupted_first else (verdict(), corrupt())
    error = review.UnsupportedAttributionReview if corrupted_first else review.DegenerateReview
    checker = reviewer(cfg, *replies)
    with pytest.raises(error):
        run(cfg, store, pending(store), Writer(named_draft()), checker)
    audit = record(store)
    assert checker.calls == 2 and audit["request_budget"]["validation_reask"]["attempts"] == [2]
    status = review_gate.recovery_status(audit)
    assert status["raw_degenerate_count"] == status["raw_attribution_count"] == 1


def test_missing_name_correction_transport_spends_shared_budget_and_keeps_feedback(context):
    cfg, store = context
    row = pending(store)
    first = reviewer(cfg, verdict(), FetchError("temporary", status=500))
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(named_draft()), first)
    assert record(store)["request_budget"]["reserved"] == 2
    second = reviewer(cfg, verdict("revise", criterion="actor_and_action", repair={"title": "The source reports a problem"}), verdict())
    assert run(cfg, store, row, Writer(named_draft()), second)["status"] == "published"
    assert saved_audit(store)["request_budget"]["reserved"] == 4
    assert json.loads(second.client.requests[0]["messages"][1]["content"])["validation_error"] == review.UNSUPPORTED_ATTRIBUTION


def test_last_slot_name_repair_cannot_publish_without_fresh_verification(context):
    cfg, store = context
    cfg["llm"]["fallback_base_urls"] = [f"https://fallback-{n}.example/v1" for n in range(5)]
    fixed = verdict("revise", criterion="actor_and_action", repair={"title": "The source reports a problem"})
    checker = reviewer(cfg, *[FetchError("temporary", status=500) for _ in range(5)], verdict(), fixed)
    with pytest.raises(review.ReviewLimitReached):
        run(cfg, store, pending(store), Writer(named_draft()), checker)
    audit = record(store)
    assert checker.calls == audit["request_budget"]["reserved"] == 7
    assert audit["request_budget"]["validation_reask"]["response"] == 7
    assert not store.stories()


def test_literal_name_presence_does_not_override_other_failed_criteria(context):
    cfg, store = context
    from helpers import make_item
    row = pending(store, make_item(content="Juno describes a parser defect and asks for investigation."))
    checker = reviewer(cfg, verdict("hold", criterion="source_support"))
    assert run(cfg, store, row, Writer(named_draft()), checker)["status"] == "held"
    assert checker.calls == 1 and not store.stories()


def test_missing_name_cache_receipt_is_not_approval(context):
    cfg, store = context
    row = pending(store);draft = named_draft();prepared = store.prepare_candidate(row, draft, LATER)
    insert_approval(store, prepared, policy=review.policy_hash(cfg))
    checker = reviewer(cfg, verdict("revise", criterion="actor_and_action", repair={"title": "The source reports a problem"}), verdict())
    result = run(cfg, store, row, Writer(draft), checker)
    assert result["status"] == "published" and not result["cache_hit"] and checker.calls == 2
    assert store.stories()[0]["title"] == "The source reports a problem"


def test_commit_boundary_cannot_publish_missing_name_through_operator_or_receipt(context):
    cfg, store = context
    row = pending(store);draft = named_draft()
    assert run(cfg, store, row, Writer(draft), reviewer(cfg, verdict("hold", criterion="actor_and_action")))["status"] == "held"
    row = dict(store.db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone())
    prepared = store.prepare_candidate(row, draft, LATER)
    assert "named_attribution" in review.final_holds(prepared["candidate"], prepared)
    audit = {"outcome": "operator_approved", "operator_approval": {"reason": "Synthetic approval attempt"}}
    with pytest.raises(ReviewRequired, match="Named attribution needs literal source evidence"):
        store.commit_candidate(prepared, prepared["candidate"], "writer-key", LATER, operator=True, review_record=audit)
    assert not store.stories()


def test_named_attribution_policy_changes_review_identity(context, monkeypatch):
    cfg, _ = context
    before = review.policy_hash(cfg)
    monkeypatch.setitem(NAMED_ATTRIBUTION_POLICY, "version", NAMED_ATTRIBUTION_POLICY["version"] + 1)
    assert review.policy_hash(cfg) != before


@pytest.mark.parametrize("replacement", [
    "juno reports that the source describes a problem.",
    "Juno’s account describes the original observations.",
    "The report includes `Juno` in its description.",
])
@pytest.mark.parametrize("field", ["title", "summary", "why_it_matters"])
def test_known_absent_name_cannot_escape_through_grammar_case_style_or_field(context, replacement, field):
    cfg, store = context
    row = pending(store)
    draft = named_draft()
    repair = {"title": "The report describes the problem"}
    if field == "why_it_matters":
        # Reviewers can only clear this field; exercise a pre-existing writer
        # sentence left behind after its headline attribution is corrected.
        draft[field] = replacement
    else:
        repair[field] = replacement
    checker = reviewer(cfg, verdict(), verdict("revise", criterion="actor_and_action", repair=repair), verdict())
    with pytest.raises(review.UnsupportedAttributionReview):
        run(cfg, store, row, Writer(draft), checker)
    assert checker.calls == 3 and not store.stories()
    last = json.loads(checker.client.requests[-1]["messages"][1]["content"])
    assert any(flag["field"] == field and flag["name"] == "Juno" for flag in last["application_attribution_checks"])
    resumed = reviewer(cfg, verdict())
    with pytest.raises(review.UnsupportedAttributionReview):
        run(cfg, store, row, Writer(draft), resumed)
    assert resumed.calls == 0


@pytest.mark.parametrize("untrusted_first", [False, True])
def test_name_introduced_by_applied_edit_is_remembered_across_later_repairs(context, untrusted_first):
    from test_review_request_budget import inconsistent
    cfg, store = context
    introduced = {"title": "Juno reports that the source describes a problem."}
    first = inconsistent(introduced) if untrusted_first else verdict("revise", criterion="actor_and_action", repair=introduced)
    escaped = verdict("revise", criterion="actor_and_action", repair={"title": "Juno’s account describes the original observations."})
    checker = reviewer(cfg, first, verdict(), escaped, verdict())
    with pytest.raises(review.UnsupportedAttributionReview):
        run(cfg, store, pending(store), Writer(), checker)
    audit = record(store)
    assert checker.calls == 4 and audit["request_budget"]["validation_reask"]["trigger"] == 2
    assert not store.stories()


def test_update_rematerialization_ignores_prior_published_fields():
    from test_review_scope_budget import update_case
    case, prepared = update_case()
    original = copy.deepcopy(case["candidate"])
    original["title"] = "Oldname reports that prior published text has a claim."
    original["updates"][-1]["text"] = "Juno reports that a workaround is available."
    prepared = {**prepared, "candidate": original}
    known = review.attribution_names(prepared)
    assert known == ["Juno"]
    current = copy.deepcopy(original)
    current["updates"][-1]["text"] = "Juno’s account describes the workaround."
    flags = missing_named_attributions(current, prepared["packet"], update=True, known_names=known)
    assert flags == [{"field": "updates[-1].text", "name": "Juno", "finding": "literal_name_absent_from_source"}]
    current["updates"][-1]["text"] = "The issue describes the supplied workaround."
    assert missing_named_attributions(current, prepared["packet"], update=True, known_names=known) == []


def test_context_name_is_rechecked_against_source_and_does_not_establish_evidence():
    text = candidate("Juno’s account describes the original observations.")
    assert missing_named_attributions(text, packet(), known_names=["Juno"])
    assert not missing_named_attributions(text, packet(author="juno"), known_names=["Juno"])


def test_operator_cannot_strip_actual_held_history_to_hide_a_known_name(context):
    cfg, store = context
    row = pending(store);draft = analysis()
    first = verdict("revise", criterion="actor_and_action", repair={"title": "Juno reports that clients fail."})
    escaped = verdict("revise", criterion="actor_and_action", repair={"title": "Juno’s account describes the original observations."})
    checker = reviewer(cfg, first, escaped, verdict("hold", criterion="actor_and_action"))
    assert run(cfg, store, row, Writer(draft), checker)["status"] == "held"
    current_row = dict(store.db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone())
    prepared = store.prepare_candidate(current_row, draft, LATER)
    held = record(store)["candidate"]
    fake_audit = {"outcome": "operator_approved", "operator_approval": {"reason": "Synthetic history-stripping attempt"}}
    with pytest.raises(ReviewRequired, match="Named attribution needs literal source evidence"):
        store.commit_candidate(prepared, held, "writer-key", LATER, operator=True, review_record=fake_audit)
    assert not store.stories()


def test_current_receipt_cannot_publish_known_name_after_a_possessive_repair(context):
    cfg, store = context
    row = pending(store);prepared = store.prepare_candidate(row, named_draft(), LATER)
    changes = {"title": "Juno’s account describes the original observations."}
    escaped = review.apply_repair(prepared["candidate"], changes)
    receipt = insert_approval(store, prepared, candidate=escaped, policy=review.policy_hash(cfg))
    saved = store.db.execute("SELECT review_record_json FROM review_approvals WHERE key=?", (receipt["approval_key"],)).fetchone()
    proof = json.loads(saved["review_record_json"])
    proof["reviews"][0]["result"] = review.validate_review(
        verdict("revise", criterion="actor_and_action", repair=changes), prepared["packet"],
        coverage=prepared["coverage"], candidate=prepared["candidate"])
    store.db.execute("UPDATE review_approvals SET review_record_json=? WHERE key=?", (json.dumps(proof), receipt["approval_key"]))
    store.db.commit()
    with pytest.raises(review.UnsupportedAttributionReview):
        store.commit_candidate(prepared, escaped, "writer-key", LATER, **receipt)
    assert not store.stories()
    assert store.db.execute("SELECT 1 FROM review_approvals WHERE key=?", (receipt["approval_key"],)).fetchone()


@pytest.mark.parametrize("opening,closing", [('"', '"'), ("'", "'"), ("“", "”"), ("‘", "’")])
@pytest.mark.parametrize("verb", ["says", "reports", "confirms"])
def test_direct_speech_delimiter_survives_quoted_name_normalization(opening, closing, verb):
    text = f'"Juno" {verb} {opening}Clients fail.{closing}'
    assert missing_named_attributions(candidate(text), packet()) == [
        {"field": "title", "name": "Juno", "finding": "literal_name_absent_from_source"}]
    assert not missing_named_attributions(candidate(text), packet(author="juno"))


@pytest.mark.parametrize("name", ["Mira", "@Mira"])
def test_numeric_dotted_handle_cannot_prove_a_shorter_name(name):
    assert missing_named_attributions(candidate(f"{name} says that clients fail."),
                                     packet("The account @Mira.2 reported measurements.", author="other"))
    assert not missing_named_attributions(candidate("@Mira.2 says that clients fail."),
                                         packet("The account @Mira.2 reported measurements.", author="other"))


def test_combining_marks_stay_with_the_whole_name_and_cannot_supply_a_suffix_identity():
    from onionflash.named_attribution import _names
    text = "राहुल reports that clients fail."
    assert _names(text) == ["राहुल"]
    assert missing_named_attributions(candidate(text), packet("सुशील reported the observations.", author="other"))
    assert not missing_named_attributions(candidate(text), packet(author="राहुल"))
    assert missing_named_attributions(candidate("ल reports that clients fail."), packet("सुशील reported the observations.", author="other"))


@pytest.mark.parametrize("separator", ["–", "—", "‑", "−", "\u200d"])
def test_unsupported_joined_name_syntax_is_skipped_whole_without_suffix_guessing(separator):
    from onionflash.named_attribution import _names
    assert _names(f"Juno{separator}Vale reports that clients fail.") == []
    assert missing_named_attributions(candidate("Vale reports that clients fail."),
                                     packet(f"Juno{separator}Vale supplied measurements.", author="other"))


@pytest.mark.parametrize("text", ["The Juno Project says that clients fail.",
                                 "According to the Juno Project, clients fail.",
                                 "Juno Project reports that clients fail."])
def test_organization_article_is_consistent_between_extraction_and_author_metadata(text):
    assert not missing_named_attributions(candidate(text), packet(author="The Juno Project"))
    assert missing_named_attributions(candidate("Juno reports that clients fail."), packet(author="The Juno"))


@pytest.mark.parametrize("reference", ["RFC 9000", "RFC9000", "IETF RFC 9000", "CVE-2026-1234"])
def test_document_references_are_not_people_and_urls_are_not_person_evidence(reference):
    sources = packet("The fetched specification describes a transport protocol.", author="other")
    sources["sources"][0]["url"] = "https://www.rfc-editor.org/rfc/rfc9000"
    assert not missing_named_attributions(candidate(f"According to {reference}, the transport has streams."), sources)
    sources["sources"][0]["url"] = "https://example.org/authors/Juno"
    assert missing_named_attributions(candidate("According to Juno, clients fail."), sources)


@pytest.mark.parametrize("text", ["In 2026 Juno says that clients fail.",
                                 "By 2026 Juno says that clients fail.",
                                 "At 12:00 Juno says that clients fail.",
                                 "According to Juno 2026 measurements show a failure."])
def test_standalone_numbers_bound_names_without_erasing_the_named_speaker(text):
    flags = missing_named_attributions(candidate(text), packet())
    assert flags and flags[0]["name"] == "Juno"


@pytest.mark.parametrize("source", ['Juno—who operates a relay—says that clients fail.',
                                   'Juno—"Clients fail."',
                                   'Juno—“Clients fail.”'])
def test_narrative_em_dash_asides_do_not_hide_literal_source_names(source):
    assert not missing_named_attributions(candidate("Juno says that clients fail."), packet(source, author="other"))
    assert missing_named_attributions(candidate(source), packet(), known_names=["Juno"])


def test_author_handles_and_ambiguous_compounds_do_not_use_prose_aside_normalization():
    assert missing_named_attributions(candidate("@Juno says that clients fail."), packet(author="Juno—who"))
    assert missing_named_attributions(candidate("Vale says that clients fail."), packet("Juno–Vale published measurements.", author="other"))


@pytest.mark.parametrize("domain,missing", [
    ("example.org", False), ("EXAMPLE.ORG", False),
    ("mail.example.org", True), ("example.org.invalid", True),
])
def test_sender_domain_can_support_only_its_exact_literal_attribution(domain, missing):
    packet = {"sources": [{"url": "https://lists.example/thread", "sender_domain": domain,
                           "passages": [{"text": "The sender reports a connection failure."}]}]}
    candidate = {"title": "Example.org reports that a connection fails"}
    assert bool(missing_named_attributions(candidate, packet)) is missing


def test_sender_domain_is_not_inferred_from_url_or_note_metadata():
    packet = {"sources": [{"url": "https://example.org/report", "name": "Example.org",
                           "passages": [{"text": "The sender reports a connection failure.",
                                         "sender_domain": "example.org"}]}]}
    candidate = {"title": "Example.org reports that a connection fails"}
    assert missing_named_attributions(candidate, packet)
