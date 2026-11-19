"""Merge evidence availability guides repair; semantic verification still decides."""
import copy
import json

import pytest

from helpers import Writer, analysis, make_item, pending, run_gate, verdict
from onionflash import merge_evidence, review
from onionflash.config import DEFAULTS
from test_review import candidate
from test_review_request_budget import context, inconsistent, reviewer, saved_audit


URL = "https://example.org/project/issues/1"
IMPACT = "The parser rejects malformed input."


def target(**changes):
    return candidate(title="Parser repair recorded", summary="The issue describes a parser repair.",
                     why_it_matters=IMPACT, confidence="reported", state="merged", category="security",
                     tags=["security"], sources=[{"url": URL, "title": "Parser repair"}], **changes)


def packet(text="Fix in private/project!12. As of a commit it is listed as fixed in the next release.", **source):
    return {"truncated": False, "missing_sources": [], "sources": [{
        "id": "S1", "kind": "gitlab_issue", "authority": "development", "upstream_state": "closed",
        "url": URL, "title": "Parser repair", "passages": [
            {"id": "S1:P1", "text": "Parser repair"},
            {"id": "S1:P2", "url": URL + "#note_1", "text": text}], **source}]}


def prepared(evidence, mode="story"):
    return {"mode": mode, "packet": evidence, "payload": {"editorial_kind": "gitlab_issue"}}


def check(evidence, missing, public=None):
    public = target() if public is None else public
    data = prepared(evidence)
    before = copy.deepcopy((public, data))
    assert review.unsupported_completion_claims(public, data) == (("merged",) if missing else ())
    assert ("completed_action" in review.final_holds(public, data)) is missing
    assert (public, data) == before


@pytest.mark.parametrize("text", [
    "Fix in private/project!12.", "The ticket is closed.", "As of commit abc123, it is listed as fixed.",
    "The patch should be merged.", "The patch was not merged.", "The patch hasn't been merged.",
    "The patch hasn’t been merged.", "The patch will probably have been merged.",
    "If the patch is merged, the tests can run.", "Unless the patch is merged, the tests cannot run.",
    "Was the patch merged?", "Please merge the patch.", "The merge request contains a fix.",
    "> The fix is merged.", "`The fix is merged.`", "```\nThe fix is merged.\n```\n",
    "See https://example.org/merged for the report.", "<div>The fix is listed as fixed.</div>",
])
def test_references_plans_and_non_narrative_material_are_not_completion(text):
    check(packet(text), True)


@pytest.mark.parametrize("text", [
    "The fix is now merged; no release has been announced.", "Merged for the next alpha.",
    "The patch landed in main.", "The change was integrated into the maintenance branch.",
    "The patch was cherry-picked into the branch.", "The fix was backported.",
    "The fix was applied to the stable branch.", "Landed.", "Integrated.",
])
def test_explicit_completion_language_does_not_require_merge_request_metadata(text):
    check(packet(text), False)


@pytest.mark.parametrize("text", [
    "A separate unrelated patch was merged; this issue remains under investigation.",
    "When we merged the fix yesterday, the tests passed.",
    "The patch was not only merged but also tested.",
    "The rocket landed safely at the test field.",
    "The patch we wanted to improve this component is now merged.",
    "We should note that it is merged.",
])
def test_ambiguous_language_stays_with_semantic_review(text):
    # Absence of this additional concern is not a same-object or truth verdict.
    check(packet(text), False)


@pytest.mark.parametrize("text", [
    "The patch was merged into main.<br>", "<p>The fix is now merged.</p>",
    "<blockquote>The fix is now merged.</blockquote>", "<code>The fix is now merged.</code>",
    '<div data-state="merged">The issue is under discussion.</div>',
    '<a href="https://example.org/merged">The issue is under discussion.</a>',
    "<p>The patch landed in main.</p>", "The patch was applied<br>to the branch.",
    "<p>The patch was applied\nto the branch.</p>",
])
def test_unknown_markup_with_completion_language_defers_without_interpreting_it(text):
    # Paragraphs, parent quotations, code and attributes have different meanings.
    # The additional absence check cannot decide them by skipping the markup.
    check(packet(text), False)


@pytest.mark.parametrize("text", [
    "<p>The issue is closed.</p>", "Fix in private/project!12.<br>",
    '<div data-state="closed">Listed as fixed.</div>',
])
def test_markup_without_completion_language_does_not_supply_a_witness(text):
    check(packet(text), True)


def test_markup_deferral_does_not_bypass_the_supplied_own_text_boundary():
    text = "<p>The fix is now merged.</p>"
    check(packet(text, unquoted_content=text), False)
    check(packet(text, unquoted_content="I will inspect the report."), True)


def test_metadata_needs_an_exact_cited_merged_request_and_no_merge_word_in_title():
    evidence = packet("The patch corrects a parser.", kind="gitlab_mr", upstream_state="merged")
    check(evidence, False)
    evidence["sources"][0]["upstream_state"] = "opened"
    check(evidence, True)
    evidence["sources"][0]["upstream_state"] = "merged"
    evidence["sources"][0]["url"] = "https://example.org/uncited"
    check(evidence, True)


def test_fragment_citation_does_not_borrow_another_comment_or_parent_metadata():
    evidence = packet()
    evidence["sources"][0]["passages"].append(
        {"id": "S1:P3", "url": URL + "#note_2", "text": "The fix is now merged."})
    public = target()
    public["sources"][0]["url"] = URL + "#note_1"
    check(evidence, True, public)
    public["sources"][0]["url"] = URL + "#note_2"
    check(evidence, False, public)
    evidence["sources"][0].update(kind="gitlab_mr", upstream_state="merged")
    public["sources"][0]["url"] = URL + "#note_1"
    check(evidence, True, public)


def test_fragment_source_metadata_is_not_a_base_request_record():
    evidence = packet("The parser rejects malformed input.", kind="gitlab_mr", upstream_state="merged")
    evidence["sources"][0]["url"] = URL + "#note_1"
    public = target()
    public["sources"][0]["url"] = URL + "#note_1"
    check(evidence, True, public)
    evidence["sources"][0]["passages"] = [{"id": "S1:P1", "text": "The fix is now merged."}]
    check(evidence, False, public)
    public["sources"][0]["url"] = URL + "#note_2"
    check(evidence, True, public)


@pytest.mark.parametrize("text", [
    "The parser is in `parser.rs`. The fix is now merged.",
    "See https://example.org/details for context. The fix is now merged.",
])
def test_own_text_is_mapped_before_code_or_urls_are_masked(text):
    check(packet(text, unquoted_content=text), False)
    check(packet(text, unquoted_content="I will inspect the report."), True)


def test_code_fences_do_not_leak_across_passage_chunks():
    evidence = packet()
    source = evidence["sources"][0]
    source["passages"] = [
        {"id": "S1:P1", "url": URL + "#note_1", "text": "```\ncode sample\n"},
        {"id": "S1:P2", "url": URL + "#note_1", "text": "The fix is merged.\n```\n"},
    ]
    check(evidence, True)
    source["passages"].append({"id": "S1:P3", "url": URL + "#note_2", "text": "The fix is now merged."})
    check(evidence, False)


def test_uncertain_closing_chunk_boundary_defers_instead_of_asserting_absence():
    evidence = packet()
    evidence["sources"][0]["passages"] = [
        {"id": "S1:P1", "url": URL + "#note_1", "text": "```text\nexample output\n"},
        {"id": "S1:P2", "url": URL + "#note_1", "text": "```\nThe fix is now merged."},
    ]
    check(evidence, False)


@pytest.mark.parametrize("field", ["title", "summary", "why_it_matters"])
def test_affirmative_merge_prose_is_checked_even_without_the_state(field):
    public = target()
    public.update(state="developing", **{field: "The parser fix was merged."})
    check(packet(), True, public)


@pytest.mark.parametrize("text", [
    "The fix will be merged.", "The fix was not merged.", "The fix hasn't merged.",
    "If merged, the fix will affect the parser.", "When merged, the fix will affect the parser.",
    "After the fix merged, the tests passed.", "Was the fix merged?", "The `merged` flag is available.",
    "Read https://example.org/merged for details.",
])
def test_nonaffirmative_or_non_narrative_prose_adds_no_new_concern(text):
    public = target()
    public.update(state="developing", title="Parser repair proposal", summary=text)
    check(packet(), False, public)


def test_update_state_and_text_do_not_enter_the_new_story_check():
    public = target()
    public["updates"] = [{"text": "The fix is merged.", "sources": [{"url": URL}]}]
    assert review.unsupported_completion_claims(public, prepared(packet(), "update")) == ()
    assert not merge_evidence.missing_completion(public, packet(), update=True)


def pending_merge(store, *, evidence=None, prose=False):
    text = evidence or "The issue is closed and listed as fixed. Fix in private/project!12. " + IMPACT
    item = make_item(kind="gitlab_issue", authority="hackerone", upstream_state="closed", title="Parser repair",
                     content=text)
    draft = analysis(title="Parser repair recorded", summary="The issue is closed and listed as fixed.",
                     why_it_matters=IMPACT, state="merged", confidence="reported", evidence=[IMPACT])
    if prose:
        draft.update(state="developing", summary="The parser fix was merged.")
    return pending(store, item), Writer(draft)


@pytest.mark.parametrize("with_correction", [False, True])
def test_native_state_repair_preserves_impact_and_requires_fresh_verification(context, with_correction):
    config, store = context
    row, writer = pending_merge(store)
    replies = ([inconsistent({})] if with_correction else []) + [
        verdict("revise", criterion="status", repair={"state": "resolved"}), verdict()]
    checker = reviewer(config, *replies)
    result = run_gate(config, store, row, writer, checker)
    assert result["status"] == "published" and checker.calls == 2 + int(with_correction)
    wires = [json.loads(body["messages"][1]["content"]) for body in checker.client.requests]
    assert review.MERGE_COMPLETION_ISSUE in wires[0]["application_issue"]
    assert '\n["merged"]' in wires[0]["application_issue"]
    assert wires[0]["candidate"]["state"] == "merged" and wires[-1]["candidate"]["state"] == "resolved"
    assert all(wire["candidate"]["why_it_matters"] == IMPACT for wire in wires)
    assert "application_issue" not in wires[-1]
    assert checker.client.requests[-1]["messages"][0]["content"].startswith(review.VERIFY_PROMPT)
    audit = saved_audit(store)
    assert audit["outcome"] == "approved" and audit["reviews"][-1]["stage"] == "verification"
    assert store.stories()[0]["why_it_matters"] == IMPACT


def test_native_prose_repair_uses_the_same_completion_constraint(context):
    config, store = context
    row, writer = pending_merge(store, prose=True)
    checker = reviewer(config, verdict("revise", criterion="status", repair={
        "summary": "The issue is closed and listed as fixed."}), verdict())
    result = run_gate(config, store, row, writer, checker)
    assert result["status"] == "published" and checker.calls == 2
    assert store.stories()[0]["summary"] == "The issue is closed and listed as fixed."
    assert store.stories()[0]["why_it_matters"] == IMPACT


def test_two_ignored_native_approvals_do_not_publish(context):
    config, store = context
    row, writer = pending_merge(store)
    checker = reviewer(config, verdict(), verdict())
    result = run_gate(config, store, row, writer, checker)
    assert result["status"] == "held" and checker.calls == 2 and store.stories() == []
    assert saved_audit(store)["hold_code"] == "completed_action"
    assert all(review.MERGE_COMPLETION_ISSUE in json.loads(body["messages"][1]["content"])["application_issue"]
               for body in checker.client.requests)


def test_actual_prose_completion_needs_no_repair_or_extra_review(context):
    config, store = context
    row, writer = pending_merge(store, evidence="The fix is now merged and the issue is closed and listed as fixed. " + IMPACT)
    checker = reviewer(config, verdict(), verdict())
    result = run_gate(config, store, row, writer, checker)
    assert result["status"] == "published" and checker.calls == 2
    assert store.stories()[0]["state"] == "merged"
    assert all("application_issue" not in json.loads(body["messages"][1]["content"])
               for body in checker.client.requests)


@pytest.mark.parametrize("body,refused", [
    ("The patch was merged into main.<br>", False),
    ("<p>The fix is now merged.</p>", False),
    ("<blockquote>The fix is now merged.</blockquote>", True),
    ('<div data-state="merged">The fix is under discussion.</div>', True),
])
def test_native_public_comment_markup_reaches_fresh_semantic_review(context, body, refused):
    from helpers import DATE, FakeClient
    from onionflash import comments
    from test_comments import gql_response, issue, issue_source, note, payload

    config, store = context
    incoming = issue(title="Parser repair", authority="hackerone", upstream_state="closed",
                     content="The issue is closed and listed as fixed. " + IMPACT)
    source = issue_source()
    notes = comments.fetch_comments(FakeClient([gql_response(payload([note("123", body=body)]))]),
                                    source, incoming)
    assert notes[0]["body"] == body
    enriched = comments._compose(incoming, notes, DATE, source_key=comments._source_key(source))
    row = pending(store, enriched)
    draft = analysis(title="Parser repair recorded", summary="The issue is closed and listed as fixed.",
                     why_it_matters=IMPACT, state="merged", confidence="reported", evidence=[IMPACT])
    replies = [verdict(), verdict("hold", criterion="status") if refused else verdict()]
    checker = reviewer(config, *replies)
    result = run_gate(config, store, row, Writer(draft), checker)
    wires = [json.loads(request["messages"][1]["content"]) for request in checker.client.requests]
    assert checker.calls == 2
    assert any(body in passage["text"] for source in wires[0]["packet"]["sources"] for passage in source["passages"])
    assert all("application_issue" not in wire for wire in wires)
    assert checker.client.requests[-1]["messages"][0]["content"].startswith(review.VERIFY_PROMPT)
    assert result["status"] == ("held" if refused else "published")
    if refused:
        assert store.stories() == []
    else:
        assert store.stories()[0]["state"] == "merged"
        assert store.stories()[0]["why_it_matters"] == IMPACT


def test_guard_policy_is_fingerprinted(monkeypatch):
    before = review.policy_hash(DEFAULTS)
    monkeypatch.setattr(merge_evidence, "POLICY", {**merge_evidence.POLICY, "version": 0})
    assert review.policy_hash(DEFAULTS) != before


def test_markup_deferral_has_a_new_policy_identity(monkeypatch):
    before = review.policy_hash(DEFAULTS)
    monkeypatch.setattr(merge_evidence, "POLICY", {"version": 1, "scope": "current-story-citations", "update": "unchanged",
        "uncertain_language": "defer-to-semantic-review", "own_text": "raw-mapping-before-nonnarrative-masking"})
    assert review.policy_hash(DEFAULTS) != before
