"""Literal qualifier reminders have provenance, never a candidate verdict."""

import copy
import json

import pytest

from helpers import completion, verdict
from onionflash import review
from onionflash.config import DEFAULTS
from onionflash.review_evidence import evidence_context
from onionflash.review_evidence import _literal_spans, _UNCERTAINTY
from onionflash.source_packet import _passages
from test_review import candidate, reviewer
from test_review_evidence import packet


URL = "https://example.org/report"


def public(**changes):
    return candidate(title="The cache reportedly loses entries", summary="The cache reports missing entries.",
                     why_it_matters="", confidence="reported", state="developing", category="network",
                     tags=["network"], sources=[{"url": URL, "title": "Cache report"}], **changes)


def source_packet(*passages):
    source = packet("Cache report", *passages)
    source["sources"][0].update(kind="feed", authority="community", title="Cache report")
    return source


def qualifiers(context, field="title"):
    return next(row for row in context["fields"] if row["field"] == field).get("qualifier_words")


def words(spans):
    return [span["text"] for span in spans]


@pytest.mark.parametrize("phrase", ["as soon as possible", "as quickly as possible", "as safely and quickly as possible",
                                    "as reasonably early as possible", "as much as possible", "AS FAR AS POSSIBLE",
                                    "as quickly\nas possible", "as quickly\r\nas possible", "not as soon as possible"])
def test_degree_expressions_do_not_supply_epistemic_uncertainty(phrase):
    source = source_packet("Respond " + phrase + ".")
    assert all("qualifier_words" not in field for field in evidence_context(public(), source)["fields"])
    assert _literal_spans("Respond " + phrase + ".", _UNCERTAINTY) == []


@pytest.mark.parametrize("text,expected", [
    ("Respond as much as possible", ["possible"]),
    ("A possible compromise remains under investigation.", ["possible"]),
    ("A compromise is possible, but not confirmed.", ["possible"]),
    ("A compromise is not possible under these conditions.", ["possible"]),
    ("Respond as quickly as possible. A possible compromise remains under investigation.", ["possible"]),
    ("Respond as quickly as possible. The host is plausibly compromised.", ["plausibly"]),
    ("Treat this as an outage as possible compromise remains unconfirmed.", ["possible", "unconfirmed"]),
    ("Notify us as soon as possible compromises are identified.", ["possible"]),
    ("Act as soon as possible compromise reports emerge.", ["possible"]),
    ("Act as soon as possible-compromise reports suggest.", ["possible"]),
    ("Act as soon as not possible compromise reports suggest.", ["possible"]),
    ("Act as soon as possibly required.", ["possibly"]),
    ("A bypass soon as possible compromise is discussed.", ["possible"]),
    ("A possible-compromise label is discussed as quickly as possible.", ["possible"]),
    ("Act as soon. As possible compromise reports emerge, investigate.", ["possible"]),
    ("Act as soon as\n\npossible compromise reports emerge.", ["possible"]),
    ("Act as soon as\r\n\r\npossible compromise reports emerge.", ["possible"]),
    ("Act as soon `example` as possible compromise reports emerge.", ["possible"]),
])
def test_degree_filter_preserves_other_predicates_and_respects_word_and_context_boundaries(text, expected):
    spans = _literal_spans(text, _UNCERTAINTY)
    assert words(spans) == expected
    assert all(text[span["start"]:span["end"]] == span["text"] for span in spans)


@pytest.mark.parametrize("modifier", ["yet unproven", "previously undetected"])
def test_comma_parenthetical_cannot_turn_a_possible_compromise_into_a_degree_expression(modifier):
    text = f"Notify the cache team as soon as possible, {modifier}, compromises are reported."
    source, current = source_packet(text), public()
    before = copy.deepcopy((source, current))
    context = evidence_context(current, source)
    for field in ("title", "summary"):
        row, = qualifiers(context, field)["source_uncertainty"]
        span, = row["spans"]
        assert row["passage_ref"] == "S1:P2"
        assert span == {"start": text.index("possible"), "end": text.index("possible") + len("possible"),
                        "text": "possible"}
    assert (source, current) == before
    assert source["sources"][0]["passages"][1] in context["passages"]


@pytest.mark.parametrize("punctuation", [",", ":", ";"])
def test_clause_punctuation_does_not_decide_degree_completion(punctuation):
    text = f"Respond as quickly as possible{punctuation} investigation continues."
    assert words(_literal_spans(text, _UNCERTAINTY)) == ["possible"]


def test_source_fragment_end_cannot_terminate_a_degree_phrase():
    first = "Notify the cache team as soon as possible "
    continuation = "compromises are identified."
    chunks = _passages(first + continuation, len(first))
    assert [chunk["text"] for chunk in chunks] == [first, continuation]
    source = source_packet(*chunks)
    context = evidence_context(public(), source)
    row, = qualifiers(context)["source_uncertainty"]
    assert row["passage_ref"] == "S1:P2" and words(row["spans"]) == ["possible"]
    span, = row["spans"]
    assert first[span["start"]:span["end"]] == "possible"
    assert all(passage in context["passages"] for passage in source["sources"][0]["passages"][1:])


def test_complete_current_field_end_can_terminate_a_degree_phrase():
    source = source_packet("The cache plausibly loses entries.")
    current = public()
    current["title"] = "Respond to the cache report as soon as possible"
    cue = qualifiers(evidence_context(current, source))
    assert cue["uncertainty"] == []
    assert words(cue["source_uncertainty"][0]["spans"]) == ["plausibly"]


@pytest.mark.parametrize("verification", [False, True])
@pytest.mark.parametrize("other_qualifier", [False, True])
def test_degree_only_cue_and_guidance_disappear_without_hiding_other_uncertainty(monkeypatch, verification, other_qualifier):
    text = "Respond to the cache report as soon as possible."
    if other_qualifier:
        text += " The cache plausibly loses entries."
    source = source_packet(text)
    current = public()
    checker = reviewer(monkeypatch, completion(verdict()))
    checker.review(current, source, verification=verification)
    request = checker.client.requests[0][1]
    payload = json.loads(request["messages"][1]["content"])
    assert payload["candidate"] == current and payload["packet"] == source
    assert "application_issue" not in payload
    cue = qualifiers(payload["evidence_context"])
    assert bool(cue) == other_qualifier
    assert (review.QUALIFIER_CONTEXT_PROMPT in request["messages"][0]["content"]) == other_qualifier
    if cue:
        assert words(cue["source_uncertainty"][0]["spans"]) == ["plausibly"]


def test_literal_attribution_and_uncertainty_are_separate_with_exact_offsets():
    source = source_packet("The cache very plausibly loses entries; the affected entries need inspection.")
    current = public()
    before = copy.deepcopy((current, source))
    context = evidence_context(current, source)
    cue = qualifiers(context)
    assert words(cue["attribution"]) == ["reportedly"] and cue["uncertainty"] == []
    row, = cue["source_uncertainty"]
    assert row["source_ref"] == "S1" and row["passage_ref"] == "S1:P2"
    assert words(row["spans"]) == ["plausibly"]
    for span in cue["attribution"] + cue["uncertainty"]:
        assert current["title"][span["start"]:span["end"]] == span["text"]
    original_passage = source["sources"][0]["passages"][1]
    assert original_passage in context["passages"]
    for span in row["spans"]:
        assert original_passage["text"][span["start"]:span["end"]] == span["text"]
    assert (current, source) == before
    assert set(cue) == {"attribution", "uncertainty", "source_uncertainty"}


def test_already_qualified_candidate_remains_literal_not_a_missing_hedge_finding():
    current = public()
    current["title"] = "The cache reportedly may lose entries"
    cue = qualifiers(evidence_context(current, source_packet("The cache could lose entries.")))
    assert words(cue["attribution"]) == ["reportedly"]
    assert words(cue["uncertainty"]) == ["may"]
    assert words(cue["source_uncertainty"][0]["spans"]) == ["could"]


@pytest.mark.parametrize("text", ["The cache reports missing entries.", "The cache loses entries."])
def test_attribution_only_source_does_not_manufacture_probability(text):
    context = evidence_context(public(), source_packet(text))
    assert all("qualifier_words" not in row for row in context["fields"])


@pytest.mark.parametrize("later", [
    "Repeated measurements confirm the cache loses entries.",
    "The cache might lose entries; measurements remain inconclusive.",
    "Repeated measurements confirm the index loses entries; the cache remains untested.",
])
def test_later_context_and_dates_stay_whole_without_deciding_which_assertion_is_resolved(later):
    source = source_packet(
        {"text": "The cache possibly loses entries.", "author": "Morgan", "created_at": "2026-01-01T00:00:00Z"},
        {"text": later, "author": "Taylor", "created_at": "2026-01-02T00:00:00Z"})
    context = evidence_context(public(), source)
    assert qualifiers(context)
    assert context["latest_comment_refs"] == ["S1:P3"]
    assert all(passage in context["passages"] for passage in source["sources"][0]["passages"][1:])
    assert all(set(row) == {"source_ref", "passage_ref", "spans"}
               for row in qualifiers(context)["source_uncertainty"])


@pytest.mark.parametrize("text,expected", [
    ("The index possibly loses entries, while the cache has confirmed losses.", ["possibly"]),
    ("A possible outage follows confirmed cache entry loss.", ["possible"]),
    ("The cache is no longer suspected of losing entries.", ["suspected"]),
    ("Both May and Will report that the cache loses entries.", ["May"]),
    ('The note says, "The cache apparently loses entries."', ["apparently"]),
])
def test_objects_negation_names_and_genuine_speech_remain_ungraded_literal_context(text, expected):
    source = source_packet(text)
    context = evidence_context(public(), source)
    assert words(qualifiers(context)["source_uncertainty"][0]["spans"]) == expected
    assert source["sources"][0]["passages"][1] in context["passages"]


@pytest.mark.parametrize("text", [
    "```text\nThe cache possibly loses entries.\n```",
    "~~~text\nThe cache possibly loses entries.\n~~~",
    "Use `possibly` to describe the cache example.",
    "Use ``possibly`` to describe the cache example.",
    "> The cache possibly loses entries.",
    "> The cache behavior is uncertain:\npossibly it loses entries.",
    "    The cache possibly loses entries.",
    "\tThe cache possibly loses entries.",
    "Cache report: https://example.org/possibly/cache",
    "On Monday Morgan wrote:\nThe cache possibly loses entries.",
    "<code>The cache possibly loses entries.</code>",
    "<pre>The cache possibly loses entries.</pre>",
    "<blockquote>The cache possibly loses entries.</blockquote>",
])
def test_code_parent_quotes_and_urls_do_not_supply_uncertainty(text):
    assert qualifiers(evidence_context(public(), source_packet(text))) is None


def test_code_fences_across_same_note_chunks_do_not_create_source_assertions():
    note = {"author": "Morgan", "created_at": "2026-01-01T00:00:00Z", "url": URL + "#note_1"}
    source = source_packet({**note, "text": "Cache example:\n```text\n"},
                           {**note, "text": "The cache possibly loses entries.\n"},
                           {**note, "text": "```\nThe cache has measured entry losses."})
    assert qualifiers(evidence_context(public(), source)) is None


def test_chunk_boundaries_do_not_invent_a_newline_that_closes_code():
    note = {"author": "Morgan", "created_at": "2026-01-01T00:00:00Z", "url": URL + "#note_1"}
    source = source_packet({**note, "text": "```text\nCache example "},
                           {**note, "text": "```\nThe cache possibly loses entries.\n"},
                           {**note, "text": "```"})
    assert qualifiers(evidence_context(public(), source)) is None


def test_split_note_is_omitted_even_when_later_text_looks_like_narrative():
    note = {"author": "Morgan", "created_at": "2026-01-01T00:00:00Z", "url": URL + "#note_1"}
    source = source_packet({**note, "text": "``"},
                           {**note, "text": "`text\nThe cache possibly loses entries.\n``"},
                           {**note, "text": "`\nThe cache apparently loses entries."})
    context = evidence_context(public(), source)
    assert qualifiers(context) is None
    assert all(passage in context["passages"] for passage in source["sources"][0]["passages"][1:])


def test_dropped_whitespace_chunk_cannot_turn_a_code_line_into_a_fence_closer():
    first = "~~~text\n" + "x" * 1791 + "\n"
    original = first + " " * 1800 + "~~~\nThe cache possibly loses entries.\n~~~"
    chunks = _passages(original, 1800)
    assert [chunk["text"] for chunk in chunks] == [first, "~~~\nThe cache possibly loses entries.\n~~~"]
    source = source_packet(*chunks)
    before = copy.deepcopy(source)
    context = evidence_context(public(), source)
    assert qualifiers(context) is None and source == before
    assert all(passage in context["passages"] for passage in source["sources"][0]["passages"][1:])


@pytest.mark.parametrize("text", [
    "<blockquote><blockquote>The cache may lose entries.</blockquote>The cache could lose entries.</blockquote> The cache apparently loses entries.",
    "<blockquote>The cache may lose entries.</blockquote> The cache apparently loses entries.",
    "</blockquote>The cache could lose entries.",
    "<blockquote>The cache could lose entries.",
    "<pre><code>The cache may lose entries.</code>The cache could lose entries.</pre>",
    "<div>The cache apparently loses entries.</div>",
    "<!-- The cache could lose entries. --> The cache apparently loses entries.",
])
def test_html_marked_text_is_omitted_without_guessing_nested_or_unbalanced_scope(text):
    source = source_packet(text)
    context = evidence_context(public(), source)
    assert qualifiers(context) is None
    assert source["sources"][0]["passages"][1] in context["passages"]


@pytest.mark.parametrize("parts", [
    ("<blockquote><blockquote>The cache may lose entries.</blockquote>The cache could lose entries.</blockquote>",),
    ("The cache could lose entries.\n`", "The cache apparently loses entries."),
])
@pytest.mark.parametrize("verification", [False, True])
def test_omitted_scope_adds_no_guidance_or_defect_and_keeps_native_packet(monkeypatch, parts, verification):
    current, source = public(), source_packet(*parts)
    checker = reviewer(monkeypatch, completion(verdict("hold", criterion="source_support")))
    result = checker.review(current, source, verification=verification)
    request = checker.client.requests[0][1]
    payload = json.loads(request["messages"][1]["content"])
    assert request["messages"][0]["content"] == (review.VERIFY_PROMPT if verification else review.SYSTEM_PROMPT)
    assert set(payload) == {"candidate", "packet", "evidence_context"}
    assert payload["candidate"] == current and payload["packet"] == source
    assert qualifiers(payload["evidence_context"]) is None
    assert all(passage in payload["evidence_context"]["passages"] for passage in source["sources"][0]["passages"][1:])
    assert result["verdict"] == "hold" and checker.calls == 1


def test_ambiguous_note_does_not_hide_a_distinct_single_passage_narrative_note():
    note = {"author": "Morgan", "created_at": "2026-01-01T00:00:00Z", "url": URL + "#note_1"}
    source = source_packet({**note, "text": "Cache example: `could"},
                           {**note, "text": "The cache apparently loses entries."},
                           {"author": "Taylor", "created_at": "2026-01-02T00:00:00Z", "url": URL + "#note_2",
                            "text": "The cache plausibly loses entries."})
    context = evidence_context(public(), source)
    row, = qualifiers(context)["source_uncertainty"]
    assert row["passage_ref"] == "S1:P4" and words(row["spans"]) == ["plausibly"]
    span, = row["spans"]
    assert source["sources"][0]["passages"][3]["text"][span["start"]:span["end"]] == "plausibly"
    assert all(passage in context["passages"] for passage in source["sources"][0]["passages"][1:])


@pytest.mark.parametrize("opening,mixed", [("~~~", "~~~```"), ("```", "```~~~")])
@pytest.mark.parametrize("ending", ["", "\n{opening}"])
def test_mixed_fence_delimiters_never_end_a_code_block(opening, mixed, ending):
    text = f"{opening}text\nThe cache plausibly loses entries.\n{mixed}\nThe cache possibly loses entries."
    text += ending.format(opening=opening)
    assert qualifiers(evidence_context(public(), source_packet(text))) is None


@pytest.mark.parametrize("opening", ["~~~", "```"])
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_longer_same_delimiter_closer_preserves_following_prose_offsets(opening, newline):
    text = f"{opening}text\nThe cache plausibly loses entries.\n{opening * 2}\nThe cache apparently loses entries."
    text = text.replace("\n", newline)
    cue = qualifiers(evidence_context(public(), source_packet(text)))
    span, = cue["source_uncertainty"][0]["spans"]
    assert span == {"start": text.index("apparently"), "end": text.index("apparently") + len("apparently"),
                    "text": "apparently"}


@pytest.mark.parametrize("opening,shorter", [("~~~~", "~~~"), ("````", "```")])
def test_shorter_delimiter_run_does_not_close_the_original_fence(opening, shorter):
    text = f"{opening}text\nThe cache plausibly loses entries.\n{shorter}\nThe cache possibly loses entries."
    assert qualifiers(evidence_context(public(), source_packet(text))) is None


@pytest.mark.parametrize("indent", ["\t", "    "])
def test_indented_fence_example_does_not_hide_following_unindented_narrative(indent):
    text = f"{indent}~~~example\nThe cache apparently loses entries."
    cue = qualifiers(evidence_context(public(), source_packet(text)))
    assert words(cue["source_uncertainty"][0]["spans"]) == ["apparently"]


def test_sender_uncertainty_requires_an_exact_unquoted_passage_mapping():
    sender = "The cache apparently loses entries."
    parent = "The cache possibly loses entries."
    source = source_packet("> " + parent, sender)
    source["sources"][0]["unquoted_content"] = sender
    assert qualifiers(evidence_context(public(), source)) is None
    source = source_packet(sender)
    source["sources"][0]["unquoted_content"] = sender
    context = evidence_context(public(), source)
    row, = qualifiers(context)["source_uncertainty"]
    assert row["passage_ref"] == "S1:P2" and words(row["spans"]) == ["apparently"]
    source["sources"][0]["unquoted_content"] = "The sender discusses the cache."
    assert qualifiers(evidence_context(public(), source)) is None


def test_plain_multi_passage_body_keeps_literal_spans_without_joining_text():
    source = source_packet("The cache plausibly loses entries.", "The cache apparently loses entries.",
                           "The cache might lose entries.")
    before = copy.deepcopy(source)
    context = evidence_context(public(), source)
    rows = qualifiers(context)["source_uncertainty"]
    assert rows and any(row["passage_ref"] == "S1:P2" for row in rows)
    for row in rows:
        text = next(passage["text"] for passage in source["sources"][0]["passages"] if passage["id"] == row["passage_ref"])
        assert all(text[span["start"]:span["end"]] == span["text"] for span in row["spans"])
    assert source == before
    assert all(passage in context["passages"] for passage in source["sources"][0]["passages"][1:])


@pytest.mark.parametrize("marker", ["`", "~~", "<block", ">", "    Code example", "\tCode example",
                                     "On Monday Morgan", "Morgan wrote:"])
@pytest.mark.parametrize("marker_first", [False, True])
def test_any_cross_passage_boundary_marker_omits_the_whole_note(marker, marker_first):
    plain = "The cache apparently loses entries."
    source = source_packet(*([marker, plain] if marker_first else [plain, marker]))
    context = evidence_context(public(), source)
    assert qualifiers(context) is None
    assert all(passage in context["passages"] for passage in source["sources"][0]["passages"][1:])


def test_plain_passages_never_combine_word_fragments_into_an_annotation():
    source = source_packet("The cache is poss", "ibly losing entries.")
    assert qualifiers(evidence_context(public(), source)) is None


@pytest.mark.parametrize("parts", [
    ("The cache behavior is im", "possible to reproduce."),
    ("The cache seems", "ingly loses entries."),
    ("The cache may", "be loses entries."),
    ("Possible cache entry loss.",),
    ("The cache loss is possible",),
])
def test_unknown_passage_edges_never_certify_complete_qualifier_words(parts):
    source = source_packet(*parts)
    original = copy.deepcopy(source)
    context = evidence_context(public(), source)
    assert qualifiers(context) is None
    assert source == original
    assert all(passage in context["passages"] for passage in source["sources"][0]["passages"][1:])


def test_literal_interior_boundaries_preserve_qualifiers_and_offsets():
    text = "(Possibly) the cache loses entries; it seems."
    source = source_packet(text)
    cue = qualifiers(evidence_context(public(), source))
    spans = cue["source_uncertainty"][0]["spans"]
    assert words(spans) == ["Possibly", "seems"]
    assert all(text[span["start"]:span["end"]] == span["text"] for span in spans)


def test_title_body_and_distinct_notes_do_not_supply_each_others_word_boundaries():
    source = source_packet(
        "possible cache loss.",
        {"text": "The cache loss is possible", "author": "Riley", "created_at": "2026-01-01T00:00:00Z", "url": URL + "#note_1"},
        {"text": "The cache apparently loses entries.", "author": "Sam", "created_at": "2026-01-02T00:00:00Z", "url": URL + "#note_2"})
    source["sources"][0]["passages"][0]["text"] = "Cache report. "
    context = evidence_context(public(), source)
    row, = qualifiers(context)["source_uncertainty"]
    assert row["passage_ref"] == "S1:P4" and words(row["spans"]) == ["apparently"]


def test_producer_chunk_split_keeps_original_passages_without_a_fragment_cue():
    first = "The cache " + "x" * 1788 + "im"
    assert len(first) == 1800
    chunks = _passages(first + "possible cache behavior.", 1800)
    source = source_packet(*chunks)
    context = evidence_context(public(), source)
    assert qualifiers(context) is None
    assert all(passage in context["passages"] for passage in source["sources"][0]["passages"][1:])


def test_only_exact_citations_can_supply_qualifier_words():
    source = source_packet(
        {"text": "The cache possibly loses entries.", "url": URL + "#note_1"},
        {"text": "The cache apparently loses entries.", "url": URL + "#note_2"})
    current = public()
    current["sources"][0]["url"] = URL + "#note_2"
    row, = qualifiers(evidence_context(current, source))["source_uncertainty"]
    assert row["passage_ref"] == "S1:P3" and words(row["spans"]) == ["apparently"]
    current["sources"][0]["url"] = "https://example.org/other"
    assert qualifiers(evidence_context(current, source)) is None


@pytest.mark.parametrize("verification", [False, True])
def test_story_wire_delivers_conditional_cue_without_a_defect_or_protocol_change(monkeypatch, verification):
    current, source = public(), source_packet("The cache plausibly loses entries.")
    checker = reviewer(monkeypatch, completion(verdict()))
    result = checker.review(current, source, verification=verification)
    request = checker.client.requests[0][1]
    payload = json.loads(request["messages"][1]["content"])
    assert request["messages"][0]["content"] == (
        review.VERIFY_PROMPT if verification else review.SYSTEM_PROMPT) + "\n\n" + review.QUALIFIER_CONTEXT_PROMPT
    assert set(payload) == {"candidate", "packet", "evidence_context"}
    assert payload["candidate"] == current and payload["packet"] == source
    assert qualifiers(payload["evidence_context"])
    assert len(request["messages"]) == 2 and checker.calls == 1
    assert result == review.validate_review(verdict(), source)
    schema = request["response_format"]["json_schema"]["schema"]
    assert schema["required"] == review.SCHEMA["required"]
    assert "presence alone requires no edit or hold" in review.QUALIFIER_CONTEXT_PROMPT
    assert "confidence=reported do not replace" in review.QUALIFIER_CONTEXT_PROMPT
    assert "later context" in review.QUALIFIER_CONTEXT_PROMPT


def test_cue_follows_actual_repair_into_fresh_verification_and_preserves_actual_issue(monkeypatch):
    current, source = public(), source_packet("The cache plausibly loses entries.")
    corrected = "The cache plausibly loses entries"
    checker = reviewer(monkeypatch, completion(verdict("revise", criterion="uncertainty_attribution",
                                                      repair={"title": corrected})), completion(verdict()))
    result = checker.review(current, source, issue=review.RELEASE_ISSUE)
    repaired = review.apply_repair(current, result["repair"])
    checker.review(repaired, source, verification=True)
    payloads = [json.loads(body["messages"][1]["content"]) for _, body in checker.client.requests]
    assert payloads[0]["application_issue"] == review.RELEASE_ISSUE
    assert "application_issue" not in payloads[1]
    assert words(qualifiers(payloads[0]["evidence_context"])["attribution"]) == ["reportedly"]
    assert words(qualifiers(payloads[1]["evidence_context"])["uncertainty"]) == ["plausibly"]
    assert payloads[1]["candidate"] == repaired and payloads[1]["packet"] == source
    assert repaired["summary"] == current["summary"] and current["title"] != corrected
    assert checker.calls == 2 and all(len(body["messages"]) == 2 for _, body in checker.client.requests)


@pytest.mark.parametrize("decision,criterion", [("hold", "source_support"), ("skip", "news_value")])
def test_cue_cannot_override_model_refusal(monkeypatch, decision, criterion):
    checker = reviewer(monkeypatch, completion(verdict(decision, criterion=criterion)))
    result = checker.review(public(), source_packet("The cache plausibly loses entries."))
    assert result["verdict"] == decision


@pytest.mark.parametrize("verification", [False, True])
def test_entire_update_request_excludes_cue_and_keeps_readonly_history(monkeypatch, verification):
    current, source = public(), source_packet("The cache plausibly loses entries.")
    current["updates"] = [{"at": current["updated_at"], "text": "The cache reportedly loses entries.",
                           "sources": copy.deepcopy(current["sources"])}]
    before = copy.deepcopy((current, source))
    checker = reviewer(monkeypatch, completion(verdict(update=True)))
    checker.review(current, source, update=True, verification=verification)
    request = checker.client.requests[0][1]
    payload = json.loads(request["messages"][1]["content"])
    assert request["messages"][0]["content"] == (review.UPDATE_VERIFY_PROMPT if verification else review.UPDATE_SYSTEM_PROMPT)
    assert payload == {"candidate": current, "packet": source, "review_scope": "latest_update",
                       "evidence_context": {"fields": [{"field": "updates[-1].text", "matching_passage_refs": ["S1:P2", "S1:P1"]}],
                                            "passages": list(reversed(source["sources"][0]["passages"])),
                                            "latest_comment_refs": [], "packet_truncated": False}}
    assert (current, source) == before


def test_absent_cue_leaves_story_prompt_unchanged_and_guidance_is_policy_bound(monkeypatch):
    checker = reviewer(monkeypatch, completion(verdict()))
    checker.review(public(), source_packet("The cache reports entry losses."))
    request = checker.client.requests[0][1]
    assert request["messages"][0]["content"] == review.SYSTEM_PROMPT
    previous = review.policy_hash(DEFAULTS)
    monkeypatch.setattr(review, "QUALIFIER_CONTEXT_PROMPT", review.QUALIFIER_CONTEXT_PROMPT + " Different guidance.")
    assert review.policy_hash(DEFAULTS) != previous
