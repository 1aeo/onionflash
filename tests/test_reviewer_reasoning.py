"""Reviewer reasoning is an explicit independent request policy."""

import copy

import pytest

from helpers import FakeLLM, STORY, completion, verdict
from onionflash import analyze, review
from onionflash.config import DEFAULTS, load_config
from onionflash.doctor import LinkChecker
from onionflash.llm import generation_options
from onionflash.render import prepare_story


@pytest.mark.parametrize("model", ["", "nemotron-3-ultra"])
@pytest.mark.parametrize("verification", [False, True])
@pytest.mark.parametrize("update", [False, True])
def test_full_reasoning_uses_native_requests_independent_of_writer_and_linker(monkeypatch, model, verification, update):
    monkeypatch.setenv("ONIONFLASH_LLM_API_KEY", "synthetic-unit-key")
    config = copy.deepcopy(DEFAULTS)
    config["llm"].update(base_url="https://llm.example/v1", timeout_seconds=1800, writer_reasoning=True)
    config["review"].update(model=model, reasoning=True)
    original = copy.deepcopy(config)
    candidate = prepare_story(copy.deepcopy(STORY))
    if update:
        candidate["updates"] = [{"text": "The announcement reports a release.", "sources": candidate["sources"]}]
    packet = {"sources": [{"id": "S1", "url": candidate["sources"][0]["url"], "kind": "feed", "authority": "official",
                           "passages": [{"id": "S1:P1", "text": "The announcement reports a release."}]}]}
    with review.Reviewer(config) as checker:
        checker.client = FakeLLM(completion(verdict(update=update)))
        assert checker.review(candidate, packet, verification=verification, update=update)["verdict"] == "approve"
        body = checker.client.requests[0][1]
        assert body["chat_template_kwargs"] == {"enable_thinking": True}
        assert body["temperature"] == 1.0 and body["top_p"] == 0.95 and body["max_tokens"] == 32768
        assert checker.http_settings["timeout_seconds"] == 1800
        assert checker.http_settings["max_response_bytes"] == 2097152
        if model:
            assert body["model"] == model and "reasoning_effort" not in body
        else:
            assert body["reasoning_effort"] == "xhigh" and body["presence_penalty"] == 0.0
    assert config == original
    with LinkChecker(config) as linker:
        assert linker.llm["enable_thinking"] is False and linker.llm["max_output_tokens"] == 1200
    assert generation_options(analyze.writer_settings(config["llm"]))["reasoning_effort"] == "xhigh"
    plain = copy.deepcopy(config)
    plain["review"]["reasoning"] = False
    assert review.policy_hash(config) != review.policy_hash(plain)
    assert analyze.cache_key({"content_hash": "x"}, config["llm"]) == analyze.cache_key({"content_hash": "x"}, plain["llm"])


@pytest.mark.parametrize("value", [False, True])
def test_review_reasoning_config_is_validated(tmp_path, value):
    path = tmp_path / "app.toml"
    path.write_text(f'[review]\nreasoning={str(value).lower()}\n[[sources]]\nid="sample"\nurl="https://example.org/feed"\n')
    assert load_config(path)["review"]["reasoning"] is value


@pytest.mark.parametrize("literal", ['"true"', "1", "[]"])
def test_invalid_reasoning_setting_is_rejected(tmp_path, literal):
    path = tmp_path / "app.toml"
    path.write_text(f'[review]\nreasoning={literal}\n[[sources]]\nid="sample"\nurl="https://example.org/feed"\n')
    with pytest.raises(ValueError, match="reasoning"):
        load_config(path)


def test_review_reasoning_requires_provider_contract_in_config_and_direct_use(tmp_path):
    path = tmp_path / "app.toml"
    path.write_text('[review]\nreasoning=true\n[llm]\nsend_chat_template_kwargs=false\n[[sources]]\nid="sample"\nurl="https://example.org/feed"\n')
    with pytest.raises(ValueError, match="review.reasoning requires"):
        load_config(path)
    config = copy.deepcopy(DEFAULTS)
    config["review"]["reasoning"] = True
    config["llm"]["send_chat_template_kwargs"] = False
    with pytest.raises(ValueError, match="review.reasoning requires"):
        review._llm(config)


def test_review_flag_does_not_enable_writer_reasoning():
    config = copy.deepcopy(DEFAULTS)
    config["review"]["reasoning"] = True
    assert generation_options(analyze.writer_settings(config["llm"]))["chat_template_kwargs"] == {"enable_thinking": False}
    assert review._llm(config)["enable_thinking"] is True
