import copy
import importlib.util
import json
import re
import stat
from pathlib import Path

import pytest

from onionflash.config import DEFAULTS
from onionflash.review import CRITERIA, _packet_refs


ROOT = Path(__file__).resolve().parents[1]


def evaluator():
    spec = importlib.util.spec_from_file_location("review_eval_tool", ROOT / "tools/evaluate_review.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def evaluation(tmp_path):
    """The evaluator module and a configuration whose public output is under tmp_path."""
    config = copy.deepcopy(DEFAULTS)
    config["storage"]["output_dir"] = str(tmp_path / "public")
    return evaluator(), config


def corpus():
    return evaluator().expand(json.loads((ROOT / "tools/review_cases.json").read_text()))


def scripted(reply):
    """A reviewer stand-in whose verdict comes from reply(verification)."""
    class Reviewer:
        last_decoded = None
        def __init__(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def review(self, candidate, packet, *, coverage=None, verification=False):
            return reply(verification)
    return Reviewer


def test_controlled_corpus_is_blinded_and_covers_rubric():
    """Keep evaluation labels out of model input and cover every review criterion."""
    kept = evaluator().kept_unsupported
    cases = corpus()
    assert len({c["id"] for c in cases}) == len(cases)
    assert set(CRITERIA) <= {criterion for c in cases for criterion in c["coverage"]}
    assert any(c["expected"] == "approve" and "operational_advice" in c["coverage"] for c in cases)
    raw = json.loads((ROOT / "tools/review_cases.json").read_text())
    with pytest.raises(KeyError):  # an unknown coverage set fails to load
        evaluator().expand({**raw, "cases": [{**raw["cases"][0], "coverage_set": "missing"}]})
    for case in cases:
        payload = {"candidate": case["candidate"], "packet": case["packet"], "existing_coverage": case["existing_coverage"]}
        assert case["id"] not in json.dumps(payload)
        assert _packet_refs(case["packet"])
        # Recent rows have the compact keys that coverage_background sends.
        assert all(set(row) == {"id", "title", "summary", "category", "state", "updated_at", "summary_truncated"}
                   for row in case["existing_coverage"]["recent"]), case["id"]
        # A flawed draft flags wording that it contains and its faithful twins do not.
        assert case["expected"] == "skip" or bool(case.get("unsupported")) == (case["expected"] == "not_approve")
        flagged = kept(case, case["candidate"])
        assert set(case.get("unsupported", [])) <= set(flagged)
        assert bool(flagged) == bool(case.get("unsupported"))
        assert not any(kept(case, twin["candidate"]) for twin in cases
                       if not twin.get("unsupported") and twin["packet"] == case["packet"])
        # Nor does the smallest faithful repair of "the source confirms that X": "... does not confirm that X".
        negated, confirms = re.subn(r"\bconfirms?\b", "does not confirm", case["candidate"]["summary"])
        assert not confirms or not kept(case, {"title": "", "summary": negated, "why_it_matters": ""}), case["id"]


def test_evaluation_records_false_approvals_and_writes_private_new_file(evaluation, tmp_path, monkeypatch, capsys):
    module, config = evaluation
    # An approved tag notice publishes; the gate holds only a repair of one.
    selected = [c for c in corpus() if c["id"] in {"bastet-original", "legitimate-custom-config", "new-version-tag"}]
    monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda verification: {"verdict": "approve"}))
    output = tmp_path / "private/report.jsonl"
    result = module.evaluate(config, selected, output)
    assert result["false_approvals"] == 1 and result["matched"] == 2
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert json.loads(output.read_text().splitlines()[-1])["summary"] == result
    with pytest.raises(FileExistsError):
        module.evaluate(config, selected, output)
    with pytest.raises(ValueError, match="outside public"):
        module.evaluate(config, selected, tmp_path / "public/private-evidence.jsonl")
    assert "candidate" not in capsys.readouterr().out


def test_verified_repair_that_keeps_flagged_wording_is_a_false_approval(evaluation, tmp_path, monkeypatch):
    module, config = evaluation
    selected = [c for c in corpus() if c["id"] == "bastet-original"]
    # A priority-only repair keeps the unsupported operator advice; clearing why_it_matters removes it.
    for repair, kept, false_approvals in (({"priority": "high"}, ["update their configurations"], 1),
                                          ({"why_it_matters": ""}, [], 0)):
        monkeypatch.setattr(module, "EvaluationReviewer", scripted(
            lambda verification: {"verdict": "approve"} if verification else {"verdict": "revise", "repair": repair}))
        output = tmp_path / f"{false_approvals}.jsonl"
        result = module.evaluate(config, selected, output)
        assert (result["repairs_verified"], result["false_approvals"], result["matched"]) == (1, false_approvals, 1 - false_approvals)
        assert json.loads(output.read_text().splitlines()[0])["kept_unsupported"] == kept


def test_verified_repair_of_a_positive_case_is_an_approval(evaluation, tmp_path, monkeypatch):
    module, config = evaluation
    selected = [c for c in corpus() if c["id"] in {"bastet-corrected", "new-version-tag"}]
    # The gate publishes a repaired story only if verification approves it, and never repairs a tag notice.
    for verified, matched in (("approve", 1), ("hold", 0)):
        monkeypatch.setattr(module, "EvaluationReviewer", scripted(
            lambda verification: {"verdict": verified} if verification else {"verdict": "revise", "repair": {"priority": "high"}}))
        output = tmp_path / f"{verified}.jsonl"
        result = module.evaluate(config, selected, output)
        assert (result["matched"], result["positive_rejections"], result["false_approvals"], result["repairs_held"]) == (
            matched, 2 - matched, 0, 2 - matched)
        assert [json.loads(line)["final_verdict"] for line in output.read_text().splitlines()[:-1]] == [verified, "hold"]


def test_unusable_repair_is_scored_as_the_gate_hold(evaluation, tmp_path, monkeypatch):
    """A null or no-op repair holds in the gate, so it is neither an error nor a publication."""
    module, config = evaluation
    selected = [c for c in corpus() if c["id"] in {"bastet-original", "empty-context-release"}]
    for repair in (None, {"why_it_matters": ""}):
        monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda verification: {"verdict": "revise", "repair": repair}))
        result = module.evaluate(config, selected, tmp_path / f"{repair is None}.jsonl")
        assert (result["errors"], result["repairs_held"], result["matched"], result["positive_rejections"]) == (0, 2, 1, 1)


def test_repair_verification_refuses_a_negative_case_without_its_unsupported_wording(evaluation, tmp_path):
    module, config = evaluation
    case = dict(next(c for c in corpus() if c["id"] == "bastet-original"), unsupported=[])
    with pytest.raises(ValueError, match="Invalid or duplicate evaluation case"):
        module.evaluate(config, [case], tmp_path / "report.jsonl")


def test_editorial_skip_requires_skip_and_never_counts_repaired_publication_as_success(evaluation, tmp_path, monkeypatch):
    """Count publication of a negative editorial case as a failure even after repair."""
    module, config = evaluation
    case = next(c for c in corpus() if c["expected"] == "skip" and not c.get("unsupported"))
    for outcome, misses, false in (("skip", 0, 0), ("hold", 1, 0), ("approve", 1, 1)):
        monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda verification: {"verdict": outcome}))
        result = module.evaluate(config, [case], tmp_path / (outcome + ".jsonl"))
        assert result["editorial_misses"] == misses
        assert result["false_approvals"] == false
    monkeypatch.setattr(module, "EvaluationReviewer", scripted(
        lambda verification: {"verdict": "approve"} if verification else
        {"verdict": "revise", "repair": {"summary": "A supported but redundant statement."}}))
    result = module.evaluate(config, [case], tmp_path / "repaired.jsonl")
    assert result["false_approvals"] == result["editorial_misses"] == 1


def test_skipping_newsworthy_negative_is_an_editorial_miss(evaluation, tmp_path, monkeypatch):
    """A not_approve case is news with a flawed draft: it may hold, but never skip. A skipped approval is a rejection, not a miss."""
    module, config = evaluation
    selected = [c for c in corpus() if c["id"] in {"bastet-original", "bastet-corrected"}]
    for outcome, misses in (("skip", 1), ("hold", 0)):
        monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda verification: {"verdict": outcome}))
        result = module.evaluate(config, selected, tmp_path / (outcome + ".jsonl"))
        assert (result["editorial_misses"], result["matched"], result["positive_rejections"]) == (misses, 1 - misses, 1)


def test_coverage_background_is_passed_to_both_reviews_and_saved_privately(evaluation, tmp_path, monkeypatch):
    """Keep both stages and the private report bound to the same coverage context."""
    module, config = evaluation
    case = next(c for c in corpus() if c.get("existing_coverage", {}).get("recent"))
    seen = []
    class Inspector(scripted(lambda verification: {"verdict": "skip"})):
        def review(self, candidate, packet, *, coverage=None, verification=False):
            """Capture each background and simulate a repair followed by a final skip."""
            seen.append(coverage)
            return ({"verdict": "skip"} if verification else
                    {"verdict": "revise", "repair": {"summary": "A source-supported statement."}})
    monkeypatch.setattr(module, "EvaluationReviewer", Inspector)
    output = tmp_path / "coverage.jsonl"
    result = module.evaluate(config, [case], output)
    assert result["repairs_skipped"] == 1 and result["repairs_held"] == 0
    assert seen == [case["existing_coverage"], case["existing_coverage"]]
    assert json.loads(output.read_text().splitlines()[0])["existing_coverage"] == case["existing_coverage"]


def test_first_approval_is_not_publication_without_final_verification(evaluation, tmp_path, monkeypatch):
    """Score the final refusal instead of treating initial approval as publication."""
    module, config = evaluation
    case = next(c for c in corpus() if c["expected"] == "approve")
    monkeypatch.setattr(module, "EvaluationReviewer", scripted(
        lambda verification: {"verdict": "hold"} if verification else {"verdict": "approve"}))
    result = module.evaluate(config, [case], tmp_path / "final-hold.jsonl")
    assert result["positive_rejections"] == 1 and result["matched"] == 0
    record = json.loads((tmp_path / "final-hold.jsonl").read_text().splitlines()[0])
    assert record["published_candidate"] is None and record["final_verdict"] == "hold"


def test_evaluation_detects_unsupported_labels_after_text_is_repaired():
    """Removing a headline claim cannot hide its surviving misleading classification."""
    module = evaluator()
    case = next(c for c in corpus() if c["id"] == "bugfix-is-not-security-fix")
    repaired = {**case["candidate"], "title": "Browser update", "summary": "An Android bugfix was released."}
    assert module.kept_unsupported(case, repaired) == ["tags:security"]
    repaired["tags"] = ["release"]
    assert module.kept_unsupported(case, repaired) == []
