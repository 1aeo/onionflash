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
    for case in cases:
        payload = {"candidate": case["candidate"], "packet": case["packet"], "existing_coverage": case["existing_coverage"]}
        assert case["id"] not in json.dumps(payload)
        assert _packet_refs(case["packet"])
        # A negative case flags wording that it contains and its approved twins do not.
        assert bool(case.get("unsupported")) == (case["expected"] == "not_approve")
        flagged = kept(case, case["candidate"])
        assert set(case.get("unsupported", [])) <= set(flagged)
        assert bool(flagged) == (case["expected"] == "not_approve")
        assert not any(kept(case, twin["candidate"]) for twin in cases
                       if twin["expected"] == "approve" and twin["packet"] == case["packet"])
        # Nor does the smallest faithful repair of "the source confirms that X": "... does not confirm that X".
        negated, confirms = re.subn(r"\bconfirms?\b", "does not confirm", case["candidate"]["summary"])
        assert not confirms or not kept(case, {"title": "", "summary": negated, "why_it_matters": ""}), case["id"]


def test_evaluation_records_false_approvals_and_writes_private_new_file(tmp_path, monkeypatch, capsys):
    module = evaluator()
    config = copy.deepcopy(DEFAULTS)
    config["storage"]["output_dir"] = str(tmp_path / "public")
    selected = [c for c in corpus() if c["id"] in {"bastet-original", "legitimate-custom-config"}]
    monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda verification: {"verdict": "approve"}))
    output = tmp_path / "private/report.jsonl"
    result = module.evaluate(config, selected, output)
    assert result["false_approvals"] == 1 and result["matched"] == 1
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert json.loads(output.read_text().splitlines()[-1])["summary"] == result
    with pytest.raises(FileExistsError):
        module.evaluate(config, selected, output)
    with pytest.raises(ValueError, match="outside public"):
        module.evaluate(config, selected, tmp_path / "public/private-evidence.jsonl")
    assert "candidate" not in capsys.readouterr().out


def test_verified_repair_that_keeps_flagged_wording_is_a_false_approval(tmp_path, monkeypatch):
    module = evaluator()
    config = copy.deepcopy(DEFAULTS)
    config["storage"]["output_dir"] = str(tmp_path / "public")
    selected = [c for c in corpus() if c["id"] == "bastet-original"]
    # A priority-only repair keeps the unsupported operator advice; clearing why_it_matters removes it.
    for repair, kept, false_approvals in (({"priority": "high"}, ["update their configurations"], 1),
                                          ({"why_it_matters": ""}, [], 0)):
        monkeypatch.setattr(module, "EvaluationReviewer", scripted(
            lambda verification: {"verdict": "approve"} if verification else {"verdict": "revise", "repair": repair}))
        output = tmp_path / f"{false_approvals}.jsonl"
        result = module.evaluate(config, selected, output, verify_repairs=True)
        assert (result["repairs_verified"], result["false_approvals"], result["matched"]) == (1, false_approvals, 1 - false_approvals)
        assert json.loads(output.read_text().splitlines()[0])["kept_unsupported"] == kept


def test_verified_repair_of_a_positive_case_is_an_approval(tmp_path, monkeypatch):
    module = evaluator()
    config = copy.deepcopy(DEFAULTS)
    config["storage"]["output_dir"] = str(tmp_path / "public")
    selected = [c for c in corpus() if c["id"] == "bastet-corrected"]
    # The gate publishes the repaired story only if verification approves it.
    for verified, matched in (("approve", 1), ("hold", 0)):
        monkeypatch.setattr(module, "EvaluationReviewer", scripted(
            lambda verification: {"verdict": verified} if verification else {"verdict": "revise", "repair": {"priority": "high"}}))
        result = module.evaluate(config, selected, tmp_path / f"{verified}.jsonl", verify_repairs=True)
        assert (result["matched"], result["positive_rejections"], result["false_approvals"]) == (matched, 1 - matched, 0)


def test_repair_verification_refuses_a_negative_case_without_its_unsupported_wording(tmp_path):
    module = evaluator()
    config = copy.deepcopy(DEFAULTS)
    config["storage"]["output_dir"] = str(tmp_path / "public")
    case = dict(next(c for c in corpus() if c["id"] == "bastet-original"), unsupported=[])
    with pytest.raises(ValueError, match="Invalid or duplicate evaluation case"):
        module.evaluate(config, [case], tmp_path / "report.jsonl", verify_repairs=True)


def test_editorial_skip_requires_skip_and_never_counts_repaired_publication_as_success(tmp_path, monkeypatch):
    """Count publication of a negative editorial case as a failure even after repair."""
    module = evaluator()
    config = copy.deepcopy(DEFAULTS)
    config["storage"]["output_dir"] = str(tmp_path / "public")
    case = next(c for c in corpus() if c["expected"] == "skip")
    for outcome, misses, false in (("skip", 0, 0), ("hold", 1, 0), ("approve", 1, 1)):
        monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda verification: {"verdict": outcome}))
        result = module.evaluate(config, [case], tmp_path / (outcome + ".jsonl"))
        assert result["editorial_misses"] == misses
        assert result["false_approvals"] == false
    monkeypatch.setattr(module, "EvaluationReviewer", scripted(
        lambda verification: {"verdict": "approve"} if verification else
        {"verdict": "revise", "repair": {"summary": "A supported but redundant statement."}}))
    result = module.evaluate(config, [case], tmp_path / "repaired.jsonl", verify_repairs=True)
    assert result["false_approvals"] == result["editorial_misses"] == 1


def test_coverage_background_is_passed_to_both_reviews_and_saved_privately(tmp_path, monkeypatch):
    """Keep both stages and the private report bound to the same coverage context."""
    module = evaluator()
    config = copy.deepcopy(DEFAULTS)
    config["storage"]["output_dir"] = str(tmp_path / "public")
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
    result = module.evaluate(config, [case], output, verify_repairs=True)
    assert result["repairs_skipped"] == 1 and result["repairs_held"] == 0
    assert seen == [case["existing_coverage"], case["existing_coverage"]]
    assert json.loads(output.read_text().splitlines()[0])["existing_coverage"] == case["existing_coverage"]


def test_first_approval_is_not_publication_without_final_verification(tmp_path, monkeypatch):
    """Score the final refusal instead of treating initial approval as publication."""
    module = evaluator()
    config = copy.deepcopy(DEFAULTS)
    config["storage"]["output_dir"] = str(tmp_path / "public")
    case = next(c for c in corpus() if c["expected"] == "approve")
    monkeypatch.setattr(module, "EvaluationReviewer", scripted(
        lambda verification: {"verdict": "hold"} if verification else {"verdict": "approve"}))
    result = module.evaluate(config, [case], tmp_path / "final-hold.jsonl")
    assert result["positive_rejections"] == 1 and result["matched"] == 0
    record = json.loads((tmp_path / "final-hold.jsonl").read_text().splitlines()[0])
    assert record["published_candidate"] is None and record["final_verdict"] == "hold"
    with pytest.raises(ValueError, match="mandatory"):
        module.evaluate(config, [case], tmp_path / "bypass.jsonl", verify_repairs=False)


def test_evaluation_detects_unsupported_labels_after_text_is_repaired():
    """Removing a headline claim cannot hide its surviving misleading classification."""
    module = evaluator()
    case = next(c for c in corpus() if c["id"] == "bugfix-is-not-security-fix")
    repaired = {**case["candidate"], "title": "Browser update", "summary": "An Android bugfix was released."}
    assert module.kept_unsupported(case, repaired) == ["tags:security"]
    repaired["tags"] = ["release"]
    assert module.kept_unsupported(case, repaired) == []
