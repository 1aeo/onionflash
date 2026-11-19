"""Opposite controls for the narrow missing-completion evidence check."""

import pytest

from onionflash import merge_evidence
from test_merge_completion_evidence import check, packet, target


@pytest.mark.parametrize("field", ["title", "summary", "why_it_matters"])
@pytest.mark.parametrize("predicate", ["is now", "was", "has been", "had already been"])
def test_purpose_infinitive_does_not_hide_a_later_affirmative_predicate(field, predicate):
    public = target()
    public.update(state="developing", **{field: f"The patch to improve the parser {predicate} merged."})
    assert merge_evidence.claim_fields(public) == [field]
    check(packet(), True, public)
    check(packet("The parser patch has been merged."), False, public)


@pytest.mark.parametrize("text", [
    "The patch is to be merged.", "The patch is to get merged.",
    "The patch is expected to have been merged.", "The patch to improve parsing will be merged.",
    "The patch to improve parsing was not merged.", "The patch to improve parsing has never been merged.",
])
def test_future_intent_and_negation_remain_nonaffirmative(text):
    public = target()
    public.update(state="developing", summary=text)
    assert merge_evidence.claim_fields(public) == []
    check(packet(), False, public)


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
    check(chunks("```html\n<div data-state='merged'>example</div>\n", "example\n```\n"), False)
    check(chunks("<div>example</div>\n", "The fix is now merged."), False)


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
