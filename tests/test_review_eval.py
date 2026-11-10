import copy
import importlib.util
import json
import stat
from pathlib import Path

import pytest

from onionflash.config import DEFAULTS
from onionflash.render import _prepare_story
from onionflash.review import CRITERIA, _packet_refs


ROOT = Path(__file__).resolve().parents[1]


def evaluator():
    spec = importlib.util.spec_from_file_location("review_eval_tool", ROOT / "tools/evaluate_review.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def corpus():
    return json.loads((ROOT / "tests/fixtures/review_cases.json").read_text())["cases"]


def test_controlled_corpus_is_blinded_canonical_and_covers_rubric():
    cases = corpus()
    assert len({c["id"] for c in cases}) == len(cases)
    assert set(CRITERIA) <= {criterion for c in cases for criterion in c["coverage"]}
    assert any(c["expected"] == "approve" and "operational_advice" in c["coverage"] for c in cases)
    for case in cases:
        payload = {"candidate": case["candidate"], "packet": case["packet"]}
        assert case["id"] not in json.dumps(payload)
        assert case["candidate"] == _prepare_story(case["candidate"], editorial=case["candidate"].get("editorial"))
        assert _packet_refs(case["packet"])


def test_evaluation_records_false_approvals_and_writes_private_new_file(tmp_path, monkeypatch, capsys):
    module = evaluator()
    config = copy.deepcopy(DEFAULTS)
    config["storage"]["output_dir"] = str(tmp_path / "public")
    selected = [c for c in corpus() if c["id"] in {"bastet-original", "legitimate-custom-config"}]

    class AlwaysApproves:
        def __init__(self, *args, **kwargs):
            self.last_decoded = None
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def review(self, *args, **kwargs):
            return {"verdict": "approve"}

    monkeypatch.setattr(module, "EvaluationReviewer", AlwaysApproves)
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
