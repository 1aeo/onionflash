"""The quote menu may lose whole options without changing literal source spans.

These syntax and scripted transport checks make no semantic approval claims.
"""
import copy

import pytest

from helpers import Writer, item, pending, run_gate, verdict
from onionflash import candidate as candidate_mod, review, source_quote
from onionflash.config import DEFAULTS
from onionflash.util import digest
from test_review import candidate
from test_review_request_budget import context
from test_source_quote_catalog import fixture
from test_source_quote_repair import draft, native, payload, quote_enum, source
from test_source_quote_selection import rendered


REMOVED = "The recovered token has two possible values, which can permit account access."
KEPT = "A log reader who cannot open the protected directory can receive a shortened test token."


def packet_for(sentences):
    return fixture("Introduction.\n\n" + "\n\n".join(sentences) + "\n\nFollowing context.")


@pytest.mark.parametrize("modal", "can could may might must shall should will would".split())
@pytest.mark.parametrize("spacing", [" ", "\t", "\n", " \t\n "])
def test_fitting_menu_removes_whole_modal_relative_options(modal, spacing):
    removed = REMOVED.replace(", which can", "," + spacing + "WHICH" + spacing + modal.upper())
    public, packet = packet_for([KEPT, removed])
    original = copy.deepcopy((public, packet))
    catalog = source_quote.build(packet)
    assert len(catalog["eligible_spans"]) == len(catalog["choices"]) == 2
    assert source_quote.available(public, packet) == catalog["choices"][:1]
    # Packet-only validation preserves historical structural eligibility.
    source_quote.validate_replacement(rendered(source_quote.flat(removed)), packet)
    assert (public, packet) == original


@pytest.mark.parametrize("sentence,offered", [
    ("If the account association and a reliable check are available, the recovered token can authorize the matching account, which can allow access to its files.", False),
    ("The recovered token has two possible values and can permit account access.", True),
    ("The recovered token can permit account access.", True),
    (KEPT, True),
    (REMOVED.replace(", which", ",which"), False),
    (REMOVED.replace("which can", "which potentially can"), True),
    ("We encourage service users, especially those running public instances, to upgrade as soon as possible.", True),
    ("A receiving controller can misinterpret the injected line as a separate command.", True),
    ("The result which can affect access is described in the report.", True),
    ("The result, which cannot affect access, is described in the report.", True),
    ("The result, whichever can be selected, is described in the report.", True),
])
def test_syntax_limits_do_not_claim_to_distinguish_grounded_consequences(sentence, offered):
    public, packet = packet_for([sentence])
    catalog = source_quote.build(packet)
    assert len(catalog["choices"]) == 1
    assert source_quote.available(public, packet) == (catalog["choices"] if offered else [])


def test_count_overflow_filters_after_ranking_without_refill_and_keeps_duplicate_origins():
    sentences = [f"Users can inspect numbered output {number} when the option is enabled." for number in range(8)]
    public, packet = packet_for([*sentences, REMOVED])
    public["why_it_matters"] = REMOVED
    second = copy.deepcopy(packet["sources"][0])
    second.update(id="S2", url="https://example.org/second")
    for passage in second["passages"]:
        passage["id"] = passage["id"].replace("S1", "S2")
    public["sources"].append({"url": second["url"]})
    packet["sources"].append(second)
    original = copy.deepcopy((public, packet))
    choices = source_quote.available(public, packet)
    # The matching ninth option displaces option 7 before being removed.
    assert [entry["rendered"] for entry in choices] == [rendered(s) for s in sentences[:7]]
    assert len(choices) == 7
    assert all([o["ref"] for o in c["origins"]] == ["S1:P2", "S2:P2"] for c in choices)
    passages = source_quote.passages(choices, packet)
    for choice in choices:
        for origin in choice["origins"]:
            assert rendered(passages[origin["ref"]]["text"][origin["start"]:origin["end"]]) == choice["rendered"]
    assert (public, packet) == original


def test_byte_overflow_does_not_spend_removed_choice_bytes_on_an_alternative():
    sentences = [f"Users can inspect group {number} " + "résumé " * 55 + "when the option is enabled."
                 for number in range(7)]
    public, packet = packet_for([*sentences, REMOVED])
    public["why_it_matters"] = REMOVED
    # Existing selector takes the matching option and the first six large options.
    choices = source_quote.available(public, packet)
    assert [entry["rendered"] for entry in choices] == [rendered(s) for s in sentences[:6]]
    size = sum(len(entry["rendered"].encode()) for entry in choices)
    assert size <= 4096
    assert size + len(rendered(sentences[6]).encode()) <= 4096
    assert size + len(rendered(sentences[6]).encode()) + len(rendered(REMOVED).encode()) > 4096


def test_filtered_option_is_rejected_by_native_wire_apply_final_and_attribution_replay(context, native):
    cfg, _ = context
    public, packet = candidate(), source()
    packet["sources"][0]["passages"][1]["text"] = "Intro.\n\n" + REMOVED + "\n\n" + KEPT + "\n\nEnd."
    repair = {"why_it_matters": rendered(REMOVED), "title": "Juno reports an optional setting."}
    result = verdict("revise", criterion="source_support", repair=repair)
    assert review.validate_review(result, packet)["repair"] == repair
    with pytest.raises(review.ReviewError):
        review.validate_review(result, packet, candidate=public)
    with pytest.raises(review.ReviewError):
        review.apply_repair(public, repair, packet=packet)
    with pytest.raises(candidate_mod.ReviewRequired):
        candidate_mod.validate_approved(public, {**public, **repair}, packet=packet)
    checker = native(cfg, result)
    with pytest.raises(review.ReviewError):
        checker.review(public, packet)
    assert quote_enum(checker.sent[0]) == ["", rendered(KEPT)]
    choices = payload(checker.sent[0])["evidence_context"]["source_quote_choices"]
    assert choices == source_quote.available(public, packet)
    proof = {"candidate": {**public, **repair}, "reviews": [{"candidate_hash": digest(public),
             "request": 1, "result": result}]}
    assert "Juno" not in review.attribution_names({"candidate": public, "packet": packet}, proof)


def test_original_writer_text_with_same_syntax_remains_reviewable(context, native):
    cfg, _ = context
    public, packet = candidate(why_it_matters=REMOVED), source()
    assert candidate_mod.validate_approved(public, public, packet=packet)
    source_quote.validate_transition(public, public, packet)
    source_quote.validate_transition(public, {**public, "why_it_matters": ""}, packet)
    checker = native(cfg, verdict())
    assert checker.review(public, packet)["verdict"] == "approve"
    assert payload(checker.sent[0])["candidate"]["why_it_matters"] == REMOVED


def test_worker_rejects_filtered_proposal_and_requires_fresh_verification(context, native):
    cfg, store = context
    row = pending(store, item(title="A source report", content="Intro.\n\n" + REMOVED + "\n\n" + KEPT + "\n\nEnd."))
    checker = native(cfg,
        verdict("revise", criterion="source_support", repair={"why_it_matters": rendered(REMOVED)}),
        verdict("revise", criterion="source_support", repair={"why_it_matters": rendered(KEPT)}),
        verdict())
    result = run_gate(cfg, store, row, Writer(draft()), checker)
    assert result["status"] == "published"
    assert len(checker.sent) == 3
    assert quote_enum(checker.sent[0]) == quote_enum(checker.sent[1]) == ["", rendered(KEPT)]
    assert quote_enum(checker.sent[2]) == [""]
    assert store.stories()[0]["why_it_matters"] == rendered(KEPT)
    assert payload(checker.sent[2])["candidate"]["why_it_matters"] == rendered(KEPT)


def test_menu_filter_changes_review_policy_identity(monkeypatch):
    current = review.policy_hash(DEFAULTS)
    for field in ("pattern", "case_sensitive", "stage", "unit"):
        with monkeypatch.context() as patch:
            patch.setitem(source_quote.POLICY["menu_filter"], field, "different-menu-rule")
            assert review.policy_hash(DEFAULTS) != current
