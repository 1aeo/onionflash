"""Overflow menus select literal relevant members without expanding permissions."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from helpers import Writer, item, job, pending, run_gate, verdict
from onionflash import candidate as candidate_mod, review, review_gate, source_quote
from onionflash.config import DEFAULTS
from onionflash.llm import AnalysisError
from onionflash.util import digest
from test_review import candidate
from test_review_request_budget import context, record
from test_source_quote_catalog import fixture
from test_source_quote_repair import draft, native, payload, quote_enum, source


SENTENCES = [f"Users can inspect numbered output {number} when the option is enabled."
             for number in range(8)] + [
    "Operators may inspect zirconium records when the feature is enabled."]
BODY = "Introduction.\n\n" + "\n\n".join(SENTENCES) + "\n\nFollowing context."
IMPACT = "Zirconium records are available through the optional setting."


def rendered(text):
    return source_quote.PREFIX + text + "”"


def overflow():
    public, packet = fixture(BODY)
    public["why_it_matters"] = IMPACT
    return public, packet


def serialized(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def test_fitting_menu_is_byte_identical_even_when_later_choices_match_better():
    public, packet = fixture("Intro.\n\n" + "\n\n".join(SENTENCES[1:]) + "\n\nEnd.")
    public["why_it_matters"] = IMPACT
    original = copy.deepcopy((public, packet))
    catalog = source_quote.build(packet, cited_urls={s["url"] for s in public["sources"]})
    assert serialized(source_quote.available(public, packet)) == serialized(catalog["choices"])
    assert (public, packet) == original


def test_overflow_changes_membership_but_presents_original_source_order():
    public, packet = overflow()
    original = copy.deepcopy((public, packet))
    choices = source_quote.available(public, packet)
    assert [choice["rendered"] for choice in choices] == [rendered(text) for text in SENTENCES[:7] + SENTENCES[8:]]
    assert all(choice["semantic_grounding"] == "NOT_DETERMINED" for choice in choices)
    assert (public, packet) == original


def test_equal_rational_scores_keep_source_order_across_hash_seeds():
    sentences = [f"Users can inspect alpha beta gamma result number {number}." for number in range(8)]
    sentences.append("Users can inspect delta records when the option is enabled.")
    public, packet = fixture("Intro.\n\n" + "\n\n".join(sentences) + "\n\nEnd.")
    public["why_it_matters"] = "alpha beta gamma delta"
    packet["sources"][0]["passages"][0]["text"] = "alpha beta gamma"
    packet["sources"][0]["passages"].extend(
        {"id": f"S1:P{number}", "text": text} for number, text in enumerate(
            ["beta gamma", "gamma", "gamma", "gamma"], 3))
    # The competing overlaps are exactly 1/2 + 1/3 + 1/6 and 1.
    expected = [rendered(text) for text in sentences[:8]]
    script = ("import json,sys; from onionflash import source_quote; "
              "candidate,packet=json.load(sys.stdin); "
              "print(json.dumps([c['rendered'] for c in source_quote.available(candidate,packet)]))")
    for seed in ("0", "1", "17", "321"):
        output = subprocess.run([sys.executable, "-c", script], input=json.dumps([public, packet]),
            text=True, capture_output=True, check=True, env={**os.environ, "PYTHONHASHSEED": seed,
                "PYTHONPATH": str(Path(source_quote.__file__).resolve().parents[1])})
        assert json.loads(output.stdout) == expected


def test_selected_duplicate_preserves_every_origin_and_full_passage():
    public, packet = overflow()
    second = copy.deepcopy(packet["sources"][0])
    second.update(id="S2", url="https://example.org/second")
    for passage in second["passages"]:
        passage["id"] = passage["id"].replace("S1", "S2")
        passage.update(author="Morgan", created_at="2026-01-01T12:00:00Z")
    public["sources"].append({"url": second["url"]})
    packet["sources"].append(second)
    choices = source_quote.available(public, packet)
    passages = source_quote.passages(choices, packet)
    assert [origin["ref"] for origin in choices[-1]["origins"]] == ["S1:P2", "S2:P2"]
    assert [passages[ref]["text"] for ref in passages] == [BODY, BODY]
    assert passages["S2:P2"]["author"] == "Morgan"
    for choice in choices:
        for origin in choice["origins"]:
            assert rendered(passages[origin["ref"]]["text"][origin["start"]:origin["end"]]) == choice["rendered"]


def test_utf8_byte_overflow_selects_whole_choices_within_the_same_budget():
    sentences = [f"Users can inspect group {number} " + "résumé " * 70 + "when the option is enabled."
                 for number in range(7)] + [SENTENCES[-1]]
    public, packet = fixture("Intro.\n\n" + "\n\n".join(sentences) + "\n\nEnd.")
    public["why_it_matters"] = IMPACT
    catalog = source_quote.build(packet)
    assert len(catalog["eligible_spans"]) == 8
    choices = source_quote.available(public, packet)
    assert len(choices) < 8 and choices[-1]["rendered"] == rendered(sentences[-1])
    total = sum(len(choice["rendered"].encode()) for choice in choices)
    assert total <= 4096
    assert all(total + len(rendered(sentence).encode()) > 4096 for sentence in sentences
               if rendered(sentence) not in {choice["rendered"] for choice in choices})


def test_only_current_impact_supplies_queries_and_sentence_matches_are_used():
    public, packet = overflow()
    expected = source_quote.available(public, packet)
    public.update(title="Numbered output 7", summary="Numbered output 7 is enabled.",
                  updates=[{"text": "Numbered output 7 is enabled."}], tags=["numbered", "output"])
    assert source_quote.available(public, packet) == expected
    public["why_it_matters"] = (" ".join(f"unrelated{number}" for number in range(100))
                               + " Users can inspect numbered output when the option is enabled. Zirconium records.")
    assert source_quote.available(public, packet)[-1]["rendered"] == rendered(SENTENCES[-1])
    public["why_it_matters"] = "Numbered output 7 is enabled."
    assert [choice["rendered"] for choice in source_quote.available(public, packet)] == [
        rendered(sentence) for sentence in SENTENCES[:8]]


def test_packet_prepass_cannot_authorize_a_candidate_excluded_member(context, native):
    cfg, _ = context
    public, packet = candidate(why_it_matters=IMPACT), source()
    packet["sources"][0]["passages"][1]["text"] = BODY
    excluded = rendered(SENTENCES[7])
    response = verdict("revise", criterion="source_support", repair={"why_it_matters": excluded})
    assert review.validate_review(response, packet)["repair"]["why_it_matters"] == excluded
    with pytest.raises(review.ReviewError):
        review.validate_review(response, packet, candidate=public)
    with pytest.raises(review.ReviewError):
        review.apply_repair(public, {"why_it_matters": excluded}, packet=packet)
    with pytest.raises(candidate_mod.ReviewRequired):
        candidate_mod.validate_approved(public, {**public, "why_it_matters": excluded}, packet=packet)
    checker = native(cfg, response)
    with pytest.raises(review.ReviewError):
        checker.review(public, packet)
    selected = source_quote.available(public, packet)
    assert quote_enum(checker.sent[0]) == ["", *[choice["rendered"] for choice in selected]]
    assert payload(checker.sent[0])["evidence_context"]["source_quote_choices"] == selected


def test_attribution_replay_uses_the_same_candidate_membership():
    public, packet = candidate(why_it_matters=IMPACT), source()
    packet["sources"][0]["passages"][1]["text"] = BODY
    repair = {"why_it_matters": rendered(SENTENCES[-1]), "title": "Juno reports that the setting is available."}
    after = review.apply_repair(public, repair, packet=packet)
    proof = {"candidate": after, "reviews": [{"candidate_hash": digest(public), "request": 1,
             "result": {"verdict": "revise", "repair": repair}}]}
    assert "Juno" in review.attribution_names({"candidate": public, "packet": packet}, proof)
    public["why_it_matters"] = "Numbered output 7 is enabled."
    proof["reviews"][0]["candidate_hash"] = digest(public)
    assert "Juno" not in review.attribution_names({"candidate": public, "packet": packet}, proof)


def test_selected_quote_resumes_fresh_verification_and_commits_its_exact_proof(context, native, monkeypatch):
    cfg, store = context
    row = pending(store, item(title="A source report", content=BODY))
    writer_result = {**draft(), "why_it_matters": IMPACT}
    quote = rendered(SENTENCES[-1])
    first = native(cfg, verdict("revise", criterion="source_support", repair={"why_it_matters": quote}), 500)
    with pytest.raises(AnalysisError):
        run_gate(cfg, store, row, Writer(writer_result), first)
    assert job(store)["stage"] == "verify" and record(store)["candidate"]["why_it_matters"] == quote
    assert quote_enum(first.sent[1]) == [""]
    checker = native(cfg, verdict())
    with monkeypatch.context() as patch:
        def pause(*args, **kwargs):
            raise RuntimeError("Interrupted before commit")
        patch.setattr(store, "commit_candidate", pause)
        with pytest.raises(RuntimeError, match="Interrupted before commit"):
            run_gate(cfg, store, row, Writer(), checker)
    prepared = json.loads(job(store)["envelope_json"])
    proof = record(store)
    review_gate.validate_review_state(proof, "approved", proof["candidate"], prepared)
    assert proof["request_budget"]["reserved"] == 3
    writer, checker = Writer(), native(cfg)
    result = run_gate(cfg, store, row, writer, checker)
    assert result["status"] == "published" and result["cache_hit"]
    assert not writer.calls and not checker.sent
    assert store.stories()[0]["why_it_matters"] == quote


def test_overflow_keep_clear_and_update_permissions_are_unchanged():
    public, packet = overflow()
    assert source_quote.available(public, packet, update=True) == []
    source_quote.validate_transition(public, public, packet)
    source_quote.validate_transition(public, {**public, "why_it_matters": ""}, packet)
    for value in ("", rendered(SENTENCES[-1])):
        quoted = {**public, "why_it_matters": value}
        assert source_quote.available(quoted, packet) == []
        with pytest.raises(ValueError):
            source_quote.validate_transition(quoted, {**quoted, "why_it_matters": rendered(SENTENCES[0])}, packet)


def test_selection_policy_invalidates_review_identity(monkeypatch):
    current = review.policy_hash(DEFAULTS)
    for field in ("selection", "selection_order"):
        with monkeypatch.context() as patch:
            patch.setitem(source_quote.POLICY, field, "different-selection-rule")
            assert review.policy_hash(DEFAULTS) != current
