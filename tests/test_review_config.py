import copy

import pytest

from onionflash import review
from onionflash.config import DEFAULTS, load_config
from onionflash.review import Reviewer


def configured(tmp_path, extra):
    path = tmp_path / "config.toml"
    path.write_text('[[sources]]\nid="test"\nurl="https://example.org/feed.xml"\n' + extra)
    return load_config(path)


def test_review_keeps_only_its_model_and_older_review_settings_still_load(tmp_path, caplog):
    # Older files may set limits that held every story or cut every reply short; they are ignored now.
    with caplog.at_level("WARNING", logger="onionflash.config"):
        cfg = configured(tmp_path, '[llm]\ntimeout_seconds=45\n[review]\nmodel="critic-model"\ntimeout_seconds=300\n'
                                   'total_timeout_seconds=30\nmax_output_tokens=128\nmax_passages=1\nmax_repairs=0\n')
    assert cfg["review"] == {"model": "critic-model"}
    assert "Ignoring setting review.max_passages" in caplog.text and "Ignoring setting review.max_repairs" in caplog.text
    with Reviewer(cfg) as reviewer:
        assert reviewer.llm["model"] == "critic-model" and reviewer.llm["max_output_tokens"] == review.OUTPUT_TOKENS
        assert (reviewer.http_settings["timeout_seconds"], reviewer.http_settings["total_timeout_seconds"]) == (45, 180)


def test_review_model_must_be_a_short_identifier(tmp_path):
    with pytest.raises(ValueError, match="review.model"):
        configured(tmp_path, '[review]\nmodel=[]\n')


def test_empty_review_model_inherits_configured_writer():
    cfg = copy.deepcopy(DEFAULTS)
    cfg["llm"]["model"] = "configured-local-model"
    with Reviewer(cfg) as reviewer:
        assert reviewer.llm["model"] == "configured-local-model"
