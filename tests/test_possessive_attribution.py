"""Possessive reporting phrases require the same literal source names as speech."""
import copy

import pytest

from helpers import Writer, analysis, pending, run_gate, verdict
from onionflash import review
from onionflash.named_attribution import missing_named_attributions
from test_named_attribution import candidate, packet
from test_review_request_budget import context, inconsistent, record, reviewer


@pytest.mark.parametrize("text,name", [
    ("Nora’s account describes the reported observations.", "Nora"),
    ("Nora's account of the reported observations is disputed.", "Nora"),
    ("Nora's report identifies a parser problem.", "Nora"),
    ("Nora’s comment describes the failure.", "Nora"),
    ("Nora's statement: clients were affected.", "Nora"),
    ("Nora’s analysis of the failure remains preliminary.", "Nora"),
    ("Nora Vale's report describes a failure.", "Nora Vale"),
    ("O’Brien’s report describes a failure.", "O’Brien"),
    ("@user's report describes a failure.", "@user"),
    ("@user.2’s statement describes a failure.", "@user.2"),
    ("Jose\u0301's analysis describes a failure.", "José"),
    ("李雷’s report describes a failure.", "李雷"),
    ("The Orion Project's report describes a failure.", "Orion Project"),
    ('The post quotes “Nora’s report describes a failure.”', "Nora"),
    ("**Nora Vale**'s statement describes a failure.", "Nora Vale"),
    ("`Nora`'s report describes a failure.", "Nora"),
    ("'Nora'’s report describes a failure.", "Nora"),
])
@pytest.mark.parametrize("field", ["title", "summary", "why_it_matters"])
def test_new_possessive_reporting_name_needs_literal_evidence(text, name, field):
    assert missing_named_attributions(candidate(text, field), packet(author="other")) == [
        {"field": field, "name": name, "finding": "literal_name_absent_from_source"}]
    assert not missing_named_attributions(candidate(text, field), packet(author=name.lstrip("@")))


@pytest.mark.parametrize("text", [
    "Yesterday’s report describes the outage.",
    "Friday’s report describes the outage.",
    "The report’s account describes the outage.",
    "The operator's report describes the outage.",
    "The source’s analysis describes the outage.",
    "The software's report describes the outage.",
    "Nora's machine stopped responding.",
    "Nora's account was locked after a password reset.",
    "Nora's account balance changed.",
    "Arti’s parser rejects the input.",
    "Rust’s ownership model is unchanged.",
    "Arti’s announcement says that clients fail.",
    "According to Nora's post, clients fail.",
    "A maintainer's statement describes the failure.",
    "Nora Beatrice Claire Diana Evans's report describes the failure.",
    "The example `Nora’s report describes a failure` is code.",
    "The example `Nora’s report\ndescribes a failure` is code.",
    "```text\nNora's report describes a failure.\n```",
])
def test_possession_without_a_bounded_named_reporting_phrase_is_unchanged(text):
    assert not missing_named_attributions(candidate(text), packet(author="other"))


@pytest.mark.parametrize("phrase", ["Nora reports that the event happened.", "Nora’s report describes the event."])
@pytest.mark.parametrize("boundary", ["\n\n", "\n \t\n", "\r\n\r\n", "\r\r",
                                      "\n```text\nA code example.\n```\n"])
def test_unmatched_backticks_cannot_hide_a_name_across_blocks(phrase, boundary):
    text = f"An unfinished `code marker.{boundary}{phrase}{boundary}A closing ` marker."
    assert missing_named_attributions(candidate(text), packet(author="other")) == [
        {"field": "title", "name": "Nora", "finding": "literal_name_absent_from_source"}]


@pytest.mark.parametrize("phrase", ["Nora reports that\nthe event happened.", "Nora’s report\ndescribes the event."])
@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
def test_actual_soft_line_break_code_stays_protected(phrase, newline):
    text = "The example `" + phrase.replace("\n", newline) + "` is code."
    assert not missing_named_attributions(candidate(text), packet(author="other"))
    text += " Nora’s report describes the real event."
    assert missing_named_attributions(candidate(text), packet(author="other")) == [
        {"field": "title", "name": "Nora", "finding": "literal_name_absent_from_source"}]


@pytest.mark.parametrize("handle", ["_Nora_", "__Nora__", "_Nora_Vale_"])
def test_possessive_literal_account_keeps_whole_underscore_identity(handle):
    source = packet(author=handle)
    assert not missing_named_attributions(candidate(f"{handle}'s report describes a failure."), source)
    assert missing_named_attributions(candidate(f"{handle.strip('_')}'s report describes a failure."), source)


def test_possessive_source_matching_uses_only_existing_whole_literal_identity():
    text = candidate("Nora Vale's report describes a failure.")
    assert not missing_named_attributions(text, packet("Nora Vale submitted the observations.", author="other"))
    assert missing_named_attributions(text, packet("Nora Valeri submitted the observations.", author="other"))
    assert missing_named_attributions(text, packet(author="Vale"))
    assert missing_named_attributions(candidate("Jose's report describes a failure."), packet(author="José"))
    assert not missing_named_attributions(candidate("José's report describes a failure."), packet(author="Jose\u0301"))


@pytest.mark.parametrize("prefix", ["Apparently", "Reportedly", "Allegedly", "Presumably", "Possibly",
                                   "Perhaps", "Following", "Regarding", "Concerning", "Despite", "Considering"])
def test_possessive_clause_prefix_is_not_part_of_the_reporting_name(prefix):
    text = candidate(f"{prefix} Nora Vale's report, the issue remains open.")
    assert not missing_named_attributions(text, packet(author="Nora Vale"))
    assert missing_named_attributions(text, packet(author="other")) == [
        {"field": "title", "name": "Nora Vale", "finding": "literal_name_absent_from_source"}]
    assert missing_named_attributions(text, packet(author="Vale"))


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize("previous", ["Earlier speaker: Nora", "The", "Nora Vale"])
def test_possessive_name_cannot_absorb_a_previous_paragraph(previous, newline):
    text = candidate(previous + newline + " \t" + newline + "Sam’s report describes the finding.")
    assert not missing_named_attributions(text, packet(author="Sam"))
    assert missing_named_attributions(text, packet(author="other")) == [
        {"field": "title", "name": "Sam", "finding": "literal_name_absent_from_source"}]


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_possessive_name_can_span_a_soft_line_break(newline):
    text = candidate("Nora" + newline + "Vale’s report describes the finding.")
    assert not missing_named_attributions(text, packet(author="Nora Vale"))
    flags = missing_named_attributions(text, packet(author="other"))
    assert len(flags) == 1 and flags[0]["name"].split() == ["Nora", "Vale"]
    assert missing_named_attributions(text, packet(author="Vale"))


def test_possessive_unquoted_reply_evidence_and_update_citations_keep_their_scope():
    source = packet(author="other")
    source["sources"][0]["unquoted_content"] = "Nora supplied the observations."
    source["sources"][0]["passages"].append({"id": "S1:P3", "text": "A follow-up report.",
                                              "url": "https://example.org/report#note_1", "author": "other"})
    text = candidate("Nora’s report describes a failure.")
    assert not missing_named_attributions(text, source)
    updated = {**candidate("Unrelated’s report is old."), "updates": [
        {"text": "Unrelated’s report is old.", "sources": [{"url": "https://example.org/report"}]},
        {"text": text["title"], "sources": [{"url": "https://example.org/report#note_1"}]}]}
    before = copy.deepcopy((updated, source))
    assert missing_named_attributions(updated, source, update=True) == [
        {"field": "updates[-1].text", "name": "Nora", "finding": "literal_name_absent_from_source"}]
    assert (updated, source) == before
    source["sources"][0]["passages"][-1]["author"] = "nora"
    assert not missing_named_attributions(updated, source, update=True)


@pytest.mark.parametrize("initial", [True, False])
def test_new_possessive_actor_is_rejected_without_prior_name_memory(context, initial):
    cfg, store = context
    row = pending(store)
    named = "Nora’s account describes the original observations."
    draft = analysis(title=named) if initial else analysis()
    first = [] if initial else [verdict("revise", criterion="actor_and_action", repair={"title": named})]
    checker = reviewer(cfg, *first, verdict(), verdict())
    with pytest.raises(review.UnsupportedAttributionReview):
        run_gate(cfg, store, row, Writer(draft), checker)
    assert not store.stories() and checker.calls == len(first) + 2
    assert record(store)["request_budget"]["validation_reask"]["trigger"] == len(first) + 1


def test_later_valid_possessive_repair_needs_no_evidence_from_an_invalid_reply(context):
    cfg, store = context
    introduced = {"title": "Nora reports that the source describes a problem."}
    escaped = verdict("revise", criterion="actor_and_action",
                      repair={"title": "Nora’s account describes the original observations."})
    checker = reviewer(cfg, inconsistent(introduced), verdict(), escaped, verdict())
    with pytest.raises(review.UnsupportedAttributionReview):
        run_gate(cfg, store, pending(store), Writer(), checker)
    assert checker.calls == 4 and not store.stories()
