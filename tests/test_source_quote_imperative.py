"""A narrow request clause can witness a whole optional source sentence."""
import copy

import pytest

from helpers import Writer, item, job, pending, run_gate, verdict
from onionflash import review, source_quote
from onionflash.llm import AnalysisError
from test_review_request_budget import context, record, saved_audit
from test_source_quote_catalog import fixture
from test_source_quote_repair import draft, native, payload, quote_enum


SENTENCE = "The update reduces queue growth so please restart workers."
QUOTE = source_quote.PREFIX + SENTENCE + "”"


@pytest.mark.parametrize("sentence", [
    SENTENCE,
    "This package changes default permissions so please review local settings.",
    "That service temporarily restricts access so please use the documented fallback.",
    "The patch addresses connection failures so please install the corrected build.",
])
def test_assertion_and_explicit_request_remain_one_exact_sentence(sentence):
    public, packet = fixture("Introduction.\n\n" + sentence + "\n\nFollowing context.")
    original = copy.deepcopy((public, packet))
    catalog = source_quote.build(packet)
    assert [entry["raw"] for entry in catalog["eligible_spans"]] == [sentence]
    choice = source_quote.available(public, packet)[0]
    assert choice["rendered"] == source_quote.PREFIX + sentence + "”"
    assert choice["semantic_grounding"] == "NOT_DETERMINED"
    assert (public, packet) == original


@pytest.mark.parametrize("sentence", [
    "For full details on recent changes, please see the CHANGELOG.",
    "Please consult the documentation before making configuration changes.",
    "The release notes so please read them carefully.",
    "This report on broken workers so please read it carefully.",
    "The release tells operators please upgrade before the deadline.",
    "This release affects workers, so please upgrade promptly.",
    "If this release affects workers so please upgrade promptly.",
    "The update reduces memory use so Please restart workers.",
    "The update reduces memory use so please the operations team.",
    "The update reduces memory use so please restart workers so please retry.",
])
def test_navigation_fragments_and_unrecognized_clause_shapes_stay_excluded(sentence):
    assert source_quote.rejection(sentence) == "no_conservative_finite_clause_witness"
    public, packet = fixture("Introduction.\n\n" + sentence + "\n\nFollowing context.")
    assert source_quote.available(public, packet) == []


@pytest.mark.parametrize("spacing", [" ", "   ", "\t", "\n", "\u00a0", " \t\n\u00a0 "])
@pytest.mark.parametrize("before", ["The release notes", "The update reduces"])
def test_spacing_cannot_supply_the_missing_assertion_object(before, spacing):
    sentence = before + spacing + "so please restart workers."
    assert source_quote.rejection(sentence) == "no_conservative_finite_clause_witness"
    public, packet = fixture("Introduction.\n\n" + sentence + "\n\nFollowing context.")
    assert source_quote.available(public, packet) == []


@pytest.mark.parametrize("object_text", ["\u200b", "\u200c", "\ufeff", "\u0301", "\u200b\u0301\ufeff"])
@pytest.mark.parametrize("before", ["The release notes", "The update reduces"])
def test_invisible_or_mark_only_text_cannot_supply_an_assertion_object(before, object_text):
    sentence = before + " " + object_text + " so please restart workers."
    assert source_quote.rejection(sentence) == "no_conservative_finite_clause_witness"
    public, packet = fixture("Introduction.\n\n" + sentence + "\n\nFollowing context.")
    assert source_quote.available(public, packet) == []


@pytest.mark.parametrize("spacing", [" ", "   ", "\t", "\n", "\u00a0", " \t\n\u00a0 "])
def test_valid_request_spacing_matches_its_rendered_sentence(spacing):
    sentence = SENTENCE.replace(" so please", spacing + "so please")
    public, packet = fixture("Introduction.\n\n" + sentence + "\n\nFollowing context.")
    choices = source_quote.available(public, packet)
    assert [choice["rendered"] for choice in choices] == [QUOTE]
    origin = choices[0]["origins"][0]
    passage = packet["sources"][0]["passages"][1]["text"]
    assert passage[origin["start"]:origin["end"]] == sentence


@pytest.mark.parametrize("transform", [
    lambda text: text[:-1] + "?",
    lambda text: text.replace("workers", "`workers`"),
    lambda text: text.replace("workers", '"workers"'),
    lambda text: text.replace("so please", "therefore so please"),
])
def test_request_witness_does_not_waive_other_sentence_rejections(transform):
    public, packet = fixture("Introduction.\n\n" + transform(SENTENCE) + "\n\nFollowing context.")
    assert source_quote.available(public, packet) == []


@pytest.mark.parametrize("change", ["edge", "parent", "code", "markup", "uncited", "other_reply", "truncated"])
def test_request_witness_does_not_waive_source_boundaries(change):
    public, packet = fixture("Introduction.\n\n" + SENTENCE + "\n\nFollowing context.")
    source = packet["sources"][0]
    if change == "edge":
        source["passages"][1]["text"] = SENTENCE
    elif change == "parent":
        source["passages"][1]["text"] = "Introduction.\n\n> " + SENTENCE + "\n\nEnd."
    elif change == "code":
        source["passages"][1]["text"] = "```text\n\n" + SENTENCE + "\n\n```\n"
    elif change == "markup":
        source["passages"][1]["text"] = "<blockquote>\n\n" + SENTENCE + "\n\n</blockquote>"
    elif change == "uncited":
        public["sources"] = []
    elif change == "other_reply":
        source["unquoted_content"] = "A different reply contributes only this observation."
    else:
        packet["truncated"] = True
    assert source_quote.available(public, packet) == []


def test_request_quote_still_requires_fresh_native_verification(context, native):
    cfg, store = context
    row = pending(store, item(title="A source report", content="Introduction.\n\n" + SENTENCE + "\n\nFollowing context."))
    first = native(cfg, verdict("revise", criterion="source_support", repair={"why_it_matters": QUOTE}), 500)
    with pytest.raises(AnalysisError):
        run_gate(cfg, store, row, Writer(draft()), first)
    assert not store.stories() and job(store)["stage"] == "verify"
    assert record(store)["candidate"]["why_it_matters"] == QUOTE
    assert quote_enum(first.sent[0]) == ["", QUOTE]
    assert quote_enum(first.sent[1]) == [""]
    writer, checker = Writer(), native(cfg, verdict())
    result = run_gate(cfg, store, row, writer, checker)
    assert result["status"] == "published" and result["writer_calls"] == 0
    assert result["review_calls"] == 1 and store.stories()[0]["why_it_matters"] == QUOTE
    assert payload(checker.sent[0])["candidate"]["why_it_matters"] == QUOTE
    assert saved_audit(store)["request_budget"]["reserved"] == 3


def test_witness_policy_change_invalidates_cached_review_identity(context, monkeypatch):
    cfg, _ = context
    current = review.policy_hash(cfg)
    old = {key: value for key, value in source_quote.POLICY.items() if key != "assertion_imperative"}
    old["version"] = 4
    monkeypatch.setattr(source_quote, "POLICY", old)
    assert review.policy_hash(cfg) != current
