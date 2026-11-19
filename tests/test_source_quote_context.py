"""Conclusion connectors cannot detach a quotation from its stated premises."""
import copy

import pytest

from onionflash import review, source_quote
from onionflash.config import DEFAULTS
from test_source_quote_catalog import fixture


@pytest.mark.parametrize("connector", [
    "therefore", "thus", "hence", "consequently", "accordingly", "as a result",
    "as a consequence", "for this reason", "for that reason", "for these reasons",
    "for those reasons", "ThErEfOrE", "as\na\nresult",
])
def test_conclusion_after_separate_prerequisite_is_not_offered(connector):
    premise = "If an optional export fails, the diagnostic file may contain private records."
    conclusion = f"A diagnostic reader can {connector} obtain private records."
    candidate, packet = fixture("Intro.\n\n" + premise + " " + conclusion + "\n\nEnd.")
    before = copy.deepcopy(packet)
    result = source_quote.build(packet)
    assert [entry["raw"] for entry in result["eligible_spans"]] == [premise]
    assert packet == before
    quote = source_quote.PREFIX + source_quote.flat(conclusion) + "”"
    with pytest.raises(ValueError):
        source_quote.validate_replacement(quote, packet, candidate)


@pytest.mark.parametrize("sentence", [
    "Therefore, diagnostic readers can obtain private records.",
    "If an optional export fails, diagnostic readers can therefore obtain private records.",
])
def test_conclusion_rule_is_conservative_even_with_an_internal_premise(sentence):
    _, packet = fixture("Intro.\n\n" + sentence + "\n\nEnd.")
    assert not source_quote.build(packet)["choices"]


@pytest.mark.parametrize("sentence", [
    "Users can inspect the result when the optional setting is enabled.",
    "This release can repair the documented optional export failure.",
    "Their logs can contain private records when the optional export fails.",
    "We encourage users to upgrade after reviewing the documented compatibility changes.",
    "Users can henceforth inspect the complete result from an optional export.",
    "The optional export has a result for every selected record.",
])
def test_referents_conditions_and_word_boundaries_remain_available(sentence):
    _, packet = fixture("Intro.\n\n" + sentence + "\n\nEnd.")
    result = source_quote.build(packet)
    assert [entry["raw"] for entry in result["eligible_spans"]] == [sentence]
    assert result["semantic_grounding"] == "NOT_DETERMINED"


def test_exclusion_precedes_fixed_choice_budget_and_preserves_source_order():
    sentences = [f"Users can inspect numbered result {index} when the option is enabled."
                 for index in range(9)]
    excluded = "A diagnostic reader can therefore obtain private records."
    _, packet = fixture("Intro.\n\n" + "\n\n".join([excluded, *sentences]) + "\n\nEnd.")
    result = source_quote.build(packet)
    assert [choice["rendered"] for choice in result["choices"]] == [
        source_quote.PREFIX + sentence + "”" for sentence in sentences[:8]]
    assert result["rendered_utf8_bytes"] <= 4096


def test_quote_admission_policy_changes_review_identity(monkeypatch):
    current = review.policy_hash(DEFAULTS)
    monkeypatch.setitem(source_quote.POLICY, "version", 1)
    assert review.policy_hash(DEFAULTS) != current
