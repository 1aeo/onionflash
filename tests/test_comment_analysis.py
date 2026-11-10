import copy
import json

from onionflash import cli
from onionflash.analyze import Analyzer, cache_key
from onionflash.comments import analysis_content
from onionflash.config import DEFAULTS
from onionflash.store import Store
from test_core import DATE, analysis, item


def test_long_description_keeps_comment_evidence_in_both_model_passes(monkeypatch):
    config = copy.deepcopy(DEFAULTS)
    config["llm"].update(base_url="https://example.org/v1", api_key_env="TEST_COMMENT_KEY", max_input_chars=1200)
    monkeypatch.setenv("TEST_COMMENT_KEY", "private-test-key")
    note = {"id": "gid://gitlab/Note/42", "url": "https://example.org/news/1#note_42",
            "title": "Public comment by @maintainer", "author": "maintainer",
            "created_at": DATE, "updated_at": DATE,
            "body": "The proposed fix still needs review."}
    payload = item(content="Original issue context. " * 1000)
    payload.update(source_content=payload["content"], public_comments=[note])
    draft = analysis(title="Maintainer reports a proposed fix",
                     summary="A public comment describes a proposed fix for the reported issue.",
                     why_it_matters=note["body"], evidence=[note["body"]])
    requests = []

    class ControlledAnalyzer(Analyzer):
        def _complete(self, request, key):
            requests.append(request)
            if request["response_format"]["json_schema"]["name"] == "onionflash_news":
                return copy.deepcopy(draft)
            return {"unsupported": [], **{name: draft[name] for name in ("title", "summary", "why_it_matters")}}

    with ControlledAnalyzer(config) as analyzer:
        result = analyzer.analyze(payload)
    assert result["evidence"] == [note["body"]]
    initial = json.loads(requests[0]["messages"][1]["content"])
    review = json.loads(requests[1]["messages"][1]["content"])["source"]
    expected = analysis_content(payload, 1200)
    assert initial["content"] == review["content"] == expected
    assert note["body"] in expected and "@maintainer" in expected
    assert len(expected) <= 1200
    assert "private-test-key" not in json.dumps(requests)


def test_input_budget_changes_analysis_record_identity():
    cfg = copy.deepcopy(DEFAULTS)["llm"]
    row = {"content_hash": "same-source", "payload": json.dumps(item())}
    first = cache_key(row, cfg)
    cfg["max_input_chars"] += 1000
    assert cache_key(row, cfg) != first


def test_optional_comment_failure_does_not_stop_saved_analysis(tmp_path, monkeypatch):
    config = copy.deepcopy(DEFAULTS)
    config["sources"] = []
    monkeypatch.setattr(cli, "build", lambda *args: {})

    def broken_comments(*args, **kwargs):
        raise ValueError("RAW PRIVATE RESPONSE MUST NOT APPEAR")

    monkeypatch.setattr(cli, "enrich_comments", broken_comments)

    class SavedAnalyzer:
        def __init__(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def analyze(self, payload):
            return analysis()

    monkeypatch.setattr(cli, "Analyzer", SavedAnalyzer)
    with Store(tmp_path / "state.db") as store:
        store.ingest(item(), DATE)
        report = cli.run(config, store)
        assert report["comments"]["failed"] == 1
        assert "RAW PRIVATE" not in json.dumps(report)
        assert report["analyzed"] == 1 and store.story_count() == 1


def test_comments_use_collection_window_without_spending_analysis_reserve(tmp_path, monkeypatch):
    config = copy.deepcopy(DEFAULTS)
    config["sources"] = []
    config["comments"]["enabled"] = True
    config["collection"].update(run_budget_seconds=240, analysis_reserve_fraction=0.5)
    captured = {}
    monkeypatch.setattr(cli.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(cli, "build", lambda *args: {})

    def comments(*args, deadline=None, **kwargs):
        captured["comments"] = deadline
        return {"enabled": True, "checked": 0, "changed": 0, "failed": 0, "skipped": 0, "budget_reached": False}

    class NoAnalysis:
        def __init__(self, config, deadline=None):
            captured["analysis"] = deadline
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    monkeypatch.setattr(cli, "enrich_comments", comments)
    monkeypatch.setattr(cli, "Analyzer", NoAnalysis)
    with Store(tmp_path / "state.db") as store:
        cli.run(config, store)
    assert captured == {"comments": 220.0, "analysis": 340.0}
