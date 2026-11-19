"""Opposite controls for the narrow missing-completion evidence check."""

import json

import pytest

from helpers import run_gate, verdict
from onionflash import merge_evidence, review
from test_merge_completion_evidence import IMPACT, check, packet, pending_merge, target
from test_review_request_budget import context, reviewer, saved_audit


@pytest.mark.parametrize("field", ["title", "summary", "why_it_matters"])
@pytest.mark.parametrize("predicate", ["is now", "was", "has been", "had already been", "got"])
def test_purpose_infinitive_does_not_hide_a_later_affirmative_predicate(field, predicate):
    public = target()
    public.update(state="developing", **{field: f"The patch to improve the parser {predicate} merged."})
    assert merge_evidence.claim_fields(public) == [field]
    check(packet(), True, public)
    check(packet("The parser patch has been merged."), False, public)


@pytest.mark.parametrize("field", ["title", "summary", "why_it_matters"])
def test_plural_purpose_clause_keeps_affirmative_completion(field):
    public = target()
    public.update(state="developing", **{field: "The patches to improve parsing have been merged."})
    assert merge_evidence.claim_fields(public) == [field]
    check(packet(), True, public)
    check(packet("The patches have been merged."), False, public)


@pytest.mark.parametrize("field", ["title", "summary", "why_it_matters"])
@pytest.mark.parametrize("text", [
    "We worked to improve parsing and merged the fix.",
    "We worked to improve parsing\nand finally merged the fix.",
    "We worked to improve reviewed code and merged the fix.",
])
def test_coordinated_past_completion_is_outside_a_nonpassive_purpose(field, text):
    public = target()
    public.update(state="developing", **{field: text})
    assert merge_evidence.claim_fields(public) == [field]
    check(packet(), True, public)
    check(packet(text), False, public)


@pytest.mark.parametrize("text", [
    "We want to see the fix reviewed and merged.",
    "We want to see the fix reviewed carefully and merged.",
    "We want to see the fix approved and merged.",
    "We want to see the fix written and merged.",
    "We want to see the fix built and merged.",
    "We want to see the fix done and merged.",
    "We want to see the fix read and merged.",
    "We want to see the fix set and merged.",
])
def test_prospective_object_complements_do_not_receive_the_coordination_exception(text):
    public = target()
    public.update(state="developing", summary=text)
    assert merge_evidence.claim_fields(public) == []
    check(packet(), False, public)


@pytest.mark.parametrize("field", ["title", "why_it_matters"])
def test_prospective_object_complement_remains_nonaffirmative_in_other_fields(field):
    public = target()
    public.update(state="developing", **{field: "We want to see the fix reviewed and merged."})
    assert merge_evidence.claim_fields(public) == []
    check(packet(), False, public)


@pytest.mark.parametrize("text", [
    "The patch is to be merged.", "The patch is to get merged.",
    "The patch is expected to have been merged.", "The patch to improve parsing will be merged.",
    "The patches are expected to have been merged.",
    "The patch to improve parsing was not merged.", "The patch to improve parsing has never been merged.",
    "The patch is to be reviewed and merged.",
    "The patch is to get reviewed and merged.",
    "We might have worked for several days to improve parsing and merged the fix.",
    "We never worked to improve parsing and merged the fix.",
])
def test_future_intent_and_negation_remain_nonaffirmative(text):
    public = target()
    public.update(state="developing", summary=text)
    assert merge_evidence.claim_fields(public) == []
    check(packet(), False, public)


@pytest.mark.parametrize("text", [
    "The patch to improve the parser got merged.",
    "We worked to improve parsing and merged the fix.",
])
@pytest.mark.parametrize("supported", [False, True])
def test_native_purpose_completion_needs_actual_evidence(context, text, supported):
    config, store = context
    evidence = (text if supported else "The parser work remains under discussion.") + "\n\n" + IMPACT
    row, writer = pending_merge(store, evidence=evidence, prose=True)
    writer.result["summary"] = text
    checker = reviewer(config, verdict(), verdict())
    result = run_gate(config, store, row, writer, checker)
    assert checker.calls == 2
    assert result["status"] == ("published" if supported else "held")
    if supported:
        assert store.stories()[0]["why_it_matters"] == IMPACT
    else:
        assert store.stories() == []
        assert saved_audit(store)["hold_code"] == "completed_action"


def test_native_coordinated_future_intent_is_not_an_asserted_merge(context):
    config, store = context
    text = "The patch is to be reviewed and merged."
    row, writer = pending_merge(store, evidence=text + "\n\n" + IMPACT, prose=True)
    writer.result["summary"] = text
    checker = reviewer(config, verdict(), verdict())
    result = run_gate(config, store, row, writer, checker)
    assert checker.calls == 2 and result["status"] == "published"
    assert store.stories()[0]["why_it_matters"] == IMPACT


@pytest.mark.parametrize("text", [
    "We want to see the fix reviewed and merged.",
    "We want to see the fix reviewed carefully and merged.",
])
def test_native_object_complement_does_not_add_a_false_completion_hold(context, text):
    config, store = context
    evidence = "The maintainers request a completed review and integration of the fix.\n\n" + IMPACT
    row, writer = pending_merge(store, evidence=evidence, prose=True)
    writer.result["summary"] = text
    checker = reviewer(config, verdict(), verdict())
    result = run_gate(config, store, row, writer, checker)
    assert checker.calls == 2 and result["status"] == "published"
    assert store.stories()[0]["why_it_matters"] == IMPACT


def test_reported_completion_question_is_not_a_claim_or_witness():
    question = "The note asks us to check whether the patch was merged."
    public = target()
    public.update(state="developing", summary=question)
    assert merge_evidence.claim_fields(public) == []
    check(packet("The maintainer requested confirmation of integration status."), False, public)
    check(packet(question), True)


@pytest.mark.parametrize("text", [
    "The note asks whether the patch was merged, landed, or backported.",
    "We checked whether the patch was merged; the answer was no.",
    "We checked whether the patch was merged; they will confirm later.",
    "We checked whether the patch was merged; they have not confirmed the result.",
])
def test_unanswered_reported_question_does_not_supply_completion(text):
    check(packet(text), True)


@pytest.mark.parametrize("text", [
    "We checked whether the patch was merged and confirmed that it was.",
    "We checked whether the patch was merged; the answer was yes.",
    "The note asks whether the patch was merged; the patch was merged yesterday.",
    "The note asks whether the patch was merged, but the patch was merged yesterday.",
])
def test_possible_answer_or_independent_completion_prevents_false_absence(text):
    check(packet(text), False)


def chunks(*texts):
    evidence = packet()
    evidence["sources"][0]["passages"] = [
        {"id": f"S1:P{index}", "url": "https://example.org/note", "text": text}
        for index, text in enumerate(texts, 1)]
    return evidence


@pytest.mark.parametrize("fence", ["```", "~~~~"])
def test_fence_opened_in_markup_passage_still_excludes_following_code(fence):
    evidence = chunks(fence + "html\n<div>example</div>\n", "The fix is now merged.\n" + fence + "\n")
    check(evidence, True)
    # A different source unit must not inherit the example's fence state.
    evidence["sources"][0]["passages"][1]["url"] = "https://example.org/another-note"
    evidence["sources"][0]["passages"][1]["text"] = "The fix is now merged."
    check(evidence, False)


def test_fence_closes_in_markup_passage_before_subsequent_narrative():
    check(chunks("```html\nexample\n", "<div>example</div>\n```\n", "The fix is now merged."), False)


def test_markup_remains_unparsed_and_its_completion_language_still_defers():
    check(chunks("<div data-state='merged'>example</div>\n"), False)
    check(chunks("<div>example</div>\n", "The fix is now merged."), False)


@pytest.mark.parametrize("text", [
    "```text\nThe patch was merged.\n```\n",
    "```html\n<p>The patch was merged.</p>\n```\n",
    "~~~html\n<p>The patch was merged.</p>\n~~~\n",
    "> <p>The patch was merged.</p>",
    "    <p>The patch was merged.</p>",
    "`<p>The patch was merged.</p>`",
    '<a href="https://example.org/merged">The issue is under discussion.</a>',
    '<a href="https://example.org/details">https://example.org/merged</a>',
])
def test_known_exclusions_precede_unknown_markup_deferral(text):
    check(packet(text), True)
    check(packet(text + "\n\nThe patch was merged."), False)


def test_markup_completion_inside_a_split_fence_is_still_excluded():
    check(chunks("```html\n<div data-state='merged'>example</div>\n", "example\n```\n"), True)
    check(chunks("```html\n<div>example</div>\n", "<p>The patch was merged.</p>\n```\n"), True)


@pytest.mark.parametrize("text", [
    "<p>The patch was merged.</p>", "<blockquote>The patch was merged.</blockquote>",
    '<div data-state="merged">The issue is under discussion.</div>',
    '<a href="https://example.org/details">Merged.</a>',
    "<a href='https://example.org/details'>Merged.</a>",
    '<p>https://example.org/details</p><p>The patch was merged.</p>',
    '<span title="`">The patch was merged into main.</span>',
])
def test_unparsed_own_markup_still_defers(text):
    check(packet(text), False)


@pytest.mark.parametrize("text,missing", [
    ("<p>The patch was merged.</p>", False),
    ("<p>The patch was applied\nto the branch.</p>", False),
    ('<a href="https://example.org/details">Merged.</a>', False),
    ('<span title="`">The patch was merged into main.</span>', False),
    ("> <p>The patch was merged.</p>", True),
    ("`<p>The patch was merged.</p>`", True),
    ('<a href="https://example.org/merged">The issue is under discussion.</a>', True),
])
def test_uncertain_closing_boundary_preserves_only_possible_narrative_completion(text, missing):
    check(chunks("```html\nexample\n", "```\n" + text), missing)


@pytest.mark.parametrize("text,missing", [
    ("```text\nThe patch was merged.\n```\n", True),
    ("```html\n<p>The patch was merged.</p>\n```\n", True),
    ("> <p>The patch was merged.</p>", True),
    ("<p>The patch was merged.</p>", False),
])
def test_native_markup_exclusions_survive_two_unchanged_approvals(context, text, missing):
    config, store = context
    row, writer = pending_merge(store, evidence="The issue is closed and listed as fixed.\n\n" + text + "\n\n" + IMPACT)
    checker = reviewer(config, verdict(), verdict())
    result = run_gate(config, store, row, writer, checker)
    assert checker.calls == 2
    assert result["status"] == ("held" if missing else "published")
    wires = [json.loads(request["messages"][1]["content"]) for request in checker.client.requests]
    assert all((review.MERGE_COMPLETION_ISSUE in wire.get("application_issue", "")) is missing for wire in wires)
    if missing:
        assert store.stories() == []
        assert saved_audit(store)["hold_code"] == "completed_action"
    else:
        assert store.stories()[0]["why_it_matters"] == IMPACT


@pytest.mark.parametrize("text", [
    "The patch was not\nmerged.", "The patch was not\r\nmerged.",
    "The patch has\nnot yet been\nmerged.", "The patch will\nbe merged.",
    "The patch wasn't\nmerged.", "The patch was not `yet` merged.",
])
def test_soft_wraps_preserve_denial_and_future_intent(text):
    check(packet(text), True)
    public = target()
    public.update(state="developing", summary=text)
    check(packet(), False, public)


@pytest.mark.parametrize("separator", [
    "\n\n", "\n \t\n", "\r\n\r\n", "\n```text\nexample\n```\n", "\n    example\n",
])
def test_paragraph_and_code_boundaries_do_not_extend_an_earlier_denial(separator):
    text = "The patch was not" + separator + "Merged."
    check(packet(text), False)
    public = target()
    public.update(state="developing", summary=text)
    check(packet(), True, public)


def test_soft_wrapped_affirmative_completion_remains_available():
    check(packet("The patch has now\nbeen merged."), False)


@pytest.mark.parametrize("text", [
    "The fix was not merged, landed, or backported.",
    "The fix was never landed or merged.",
    "The fix was not merged, integrated, nor even backported.",
    "The fix has not been landed, cherry-picked, or merged.",
    "The fix was not merged or applied to the stable branch.",
    "The fix was not applied to the stable branch or merged.",
    "The fix will be merged, landed, and backported.",
])
def test_completion_lists_share_denial_or_future_intent(text):
    check(packet(text), True)
    public = target()
    public.update(state="developing", summary=text)
    check(packet(), False, public)


@pytest.mark.parametrize("text", [
    "The fix was not merged, but it was backported.",
    "The fix was not backported but it was merged.",
    "The fix was not merged; it was backported.",
    "The fix was not merged. It was backported.",
    "The fix was not merged, and the change was backported.",
    "The fix was merged, landed, and backported.",
])
def test_new_affirmative_predicates_do_not_inherit_denial(text):
    check(packet(text), False)


@pytest.mark.parametrize("predicate", ["is", "is finally", "can be", "will be", "must be", "should be"])
def test_prospective_prerequisites_are_not_completion_evidence(predicate):
    text = f"The patch has not yet been merged. Before the patch {predicate} merged, it must pass CI."
    check(packet(text), True)
    check(packet(text, kind="gitlab_mr", upstream_state="merged"), False)


@pytest.mark.parametrize("text", [
    "Before the patch was merged, it passed CI.",
    "Before we merged the patch, the tests passed.",
    "When the patch is merged, the tests run.",
    "Once merged, the patch changes the parser.",
    "After the patch was merged, the tests passed.",
    "Before the patch is merged, a separate fix was backported.",
])
def test_retrospective_and_ambiguous_temporal_language_still_defers(text):
    check(packet(text), False)
