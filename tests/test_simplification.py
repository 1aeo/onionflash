import pytest
import sqlite3
from unittest.mock import patch

from onionflash.analyze import AnalysisError, validate_analysis, _json_object
from onionflash.transport import FetchError, Response
from onionflash.collect import collect_source
from test_core import FakeClient, source, response, DATE
from onionflash.config import DEFAULTS
from onionflash.store import Store, backup_database
from onionflash.util import plain_text, canonical_url
import onionflash.cli as cli


def candidate(tags):
    item = {"title": "Tor 1.2.3 release announcement", "content": "",
            "kind": "feed", "authority": "official", "product": "tor"}
    result = {"publish": True, "title": item["title"],
              "summary": "The upstream source announces Tor 1.2.3.",
              "why_it_matters": "Read the upstream announcement for release details.",
              "category": "release", "priority": "normal", "confidence": "confirmed",
              "state": "released", "products": ["tor", "tor"], "tags": tags,
              "evidence": [item["title"]]}
    return result, item


def test_harmless_duplicate_model_labels_are_normalized():
    result, item = candidate(["release", "release"])
    accepted = validate_analysis(result, item)
    assert accepted["products"] == ["tor"]
    assert accepted["tags"] == ["release"]


def test_unknown_model_labels_still_fail_closed():
    result, item = candidate(["release", "unknown-label"])
    with pytest.raises(AnalysisError, match="Invalid model tags"):
        validate_analysis(result, item)


def test_deep_provider_json_is_a_sanitized_fetch_failure():
    body = b"[" * 10000 + b"]" * 10000
    with pytest.raises(FetchError, match="invalid JSON response"):
        Response(200, body, {}, "https://example.org").json()


def test_deep_model_json_is_rejected_without_aborting_the_pipeline():
    with pytest.raises(AnalysisError, match="invalid JSON"):
        _json_object("[" * 10000 + "]" * 10000)


def test_deep_gitlab_json_can_use_the_configured_fallback():
    stream = source(kind="gitlab_issue", fallback_urls=["https://mirror.example.org/issues"])
    client = FakeClient([response(b"[" * 10000 + b"]" * 10000), response(b"[]")])
    result = collect_source(client, stream, {}, DEFAULTS["collection"], DATE)
    assert result["items"] == []
    assert len(client.calls) == 2


def test_private_backup_copies_committed_wal_data(tmp_path):
    source, destination = tmp_path / "source.db", tmp_path / "copy.db"
    with Store(source) as store:
        store.set_meta(kept="committed")
        backup_database(source, destination)
    assert destination.stat().st_mode & 0o777 == 0o600
    with sqlite3.connect(destination) as connection:
        assert connection.execute("SELECT value FROM metadata WHERE key='kept'").fetchone()[0] == "committed"
    with pytest.raises(ValueError, match="must be new"):
        backup_database(source, destination)


def test_failed_backup_closes_source_and_removes_private_partial(tmp_path):
    source, destination = tmp_path / "source.db", tmp_path / "partial.db"
    with Store(source):
        pass
    original_connect, opened = sqlite3.connect, []
    def connect(path, *args, **kwargs):
        if path == destination:
            assert destination.stat().st_mode & 0o777 == 0o600
            raise RuntimeError("simulated destination failure")
        assert "mode=ro" in path
        connection = original_connect(path, *args, **kwargs)
        opened.append(connection)
        return connection
    with patch("onionflash.store.sqlite3.connect", side_effect=connect), pytest.raises(RuntimeError):
        backup_database(source, destination)
    assert not destination.exists()
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        opened[0].execute("SELECT 1")


def test_shared_render_dependencies_invalidate_public_build_cache(tmp_path, monkeypatch):
    from onionflash import publication
    package = tmp_path / "package"
    package.mkdir()
    (package / "assets").mkdir()
    for name in ("render.py", "publication.py", "editorial.py", "schema.py", "util.py"):
        (package / name).write_text("initial")
    monkeypatch.setattr(publication, "__file__", str(package / "publication.py"))
    first = publication.template_identity({})
    (package / "schema.py").write_text("changed labels")
    second = publication.template_identity({})
    assert first != second
    (package / "util.py").write_text("changed timestamp formatting")
    assert second != publication.template_identity({})


def test_invalid_unicode_cannot_poison_source_or_model_persistence():
    assert plain_text("security\ud800 report", 100) == "security\ufffd report"
    with pytest.raises(ValueError):
        canonical_url("https://example.org/\ud800")
    with pytest.raises(AnalysisError, match="invalid JSON"):
        _json_object('{"title":"\\ud800"}')
