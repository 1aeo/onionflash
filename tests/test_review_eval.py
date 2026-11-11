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
        def review(self, candidate, packet, *, verification=False):
            return reply(verification)
    return Reviewer


def test_controlled_corpus_is_blinded_and_covers_rubric():
    kept = evaluator().kept_unsupported
    cases = corpus()
    assert len({c["id"] for c in cases}) == len(cases)
    assert set(CRITERIA) <= {criterion for c in cases for criterion in c["coverage"]}
    assert any(c["expected"] == "approve" and "operational_advice" in c["coverage"] for c in cases)
    for case in cases:
        payload = {"candidate": case["candidate"], "packet": case["packet"]}
        assert case["id"] not in json.dumps(payload)
        assert _packet_refs(case["packet"])
        # A negative case flags wording that it contains and its approved twins do not.
        assert bool(case.get("unsupported")) == (case["expected"] == "not_approve")
        assert kept(case, case["candidate"]) == case.get("unsupported", [])
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


def test_repair_verification_refuses_a_negative_case_without_its_unsupported_wording(tmp_path):
    module = evaluator()
    config = copy.deepcopy(DEFAULTS)
    config["storage"]["output_dir"] = str(tmp_path / "public")
    case = dict(next(c for c in corpus() if c["id"] == "bastet-original"), unsupported=[])
    with pytest.raises(ValueError, match="Invalid or duplicate evaluation case"):
        module.evaluate(config, [case], tmp_path / "report.jsonl", verify_repairs=True)
