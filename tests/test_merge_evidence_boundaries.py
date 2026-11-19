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
