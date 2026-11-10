import copy

import pytest

from onionflash.config import DEFAULTS, load_config
from onionflash.review import Reviewer


def configured(tmp_path, extra):
    path = tmp_path / "config.toml"
    path.write_text('[[sources]]\nid="test"\nurl="https://example.org/feed.xml"\n' + extra)
    return load_config(path)


def test_review_settings_remain_configurable_after_writer_limits_were_retired(tmp_path):
    cfg = configured(tmp_path, '[review]\nmodel="critic-model"\ntimeout_seconds=45\ntotal_timeout_seconds=30\nmax_output_tokens=1800\nmax_source_chars=12000\nmax_repairs=0\n')
    assert cfg["review"]["model"] == "critic-model"
    assert cfg["review"]["max_repairs"] == 0
    with Reviewer(cfg) as reviewer:
        assert reviewer.llm["model"] == "critic-model"
        assert reviewer.http_settings["timeout_seconds"] == 45
        assert reviewer.http_settings["total_timeout_seconds"] == 30
        assert reviewer.llm["max_output_tokens"] == 1800


@pytest.mark.parametrize("setting", ["max_repairs=2", "max_repairs=-1", "max_cache_entries=true",
                                    "max_sources=0", "max_source_chars=999", "timeout_seconds=nan",
                                    "total_timeout_seconds=2\nconnect_timeout_seconds=10",
                                    "max_source_chars=1000\npassage_chars=1800", "model=[]"])
def test_review_bounds_fail_closed(tmp_path, setting):
    with pytest.raises(ValueError):
        configured(tmp_path, '[review]\n' + setting + '\n')


def test_empty_review_model_inherits_configured_writer():
    cfg = copy.deepcopy(DEFAULTS)
    cfg["llm"]["model"] = "configured-local-model"
    with Reviewer(cfg) as reviewer:
        assert reviewer.llm["model"] == "configured-local-model"
