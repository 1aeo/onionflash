"""Native review sampling remains isolated from writer and routing client settings."""

import copy

import pytest

from helpers import FakeLLM, STORY, completion, verdict
from onionflash import analyze, review
from onionflash.config import DEFAULTS
from onionflash.llm import generation_options
from onionflash.render import prepare_story


@pytest.mark.parametrize("verification", [False, True])
@pytest.mark.parametrize("update", [False, True])
def test_native_review_requests_use_declared_sampling_without_mutating_config(monkeypatch, verification, update):
    monkeypatch.setenv("ONIONFLASH_LLM_API_KEY", "synthetic-unit-key")
    config = copy.deepcopy(DEFAULTS)
    config["llm"].update(base_url="https://llm.example/v1", writer_reasoning=True, timeout_seconds=1800)
    original = copy.deepcopy(config)
    candidate = prepare_story(copy.deepcopy(STORY))
    if update:
        candidate["updates"] = [{"text": "The announcement reports a new release.", "sources": candidate["sources"]}]
    packet = {"sources": [{"id": "S1", "url": candidate["sources"][0]["url"], "kind": "feed", "authority": "official",
                           "passages": [{"id": "S1:P1", "text": "The announcement reports a new release."}]}]}
    with review.Reviewer(config) as checker:
        checker.client = FakeLLM(completion(verdict(update=update)))
        assert checker.review(candidate, packet, verification=verification, update=update)["verdict"] == "approve"
        body = checker.client.requests[0][1]
        for key, value in {"temperature": 0.7, "top_p": 0.8, "top_k": 20, "min_p": 0.0,
                           "presence_penalty": 1.5, "repetition_penalty": 1.0,
                           "max_tokens": review.OUTPUT_TOKENS,
                           "chat_template_kwargs": {"enable_thinking": False}}.items():
            assert body[key] == value
        assert "reasoning_effort" not in body
        assert checker.http_settings["timeout_seconds"] == 1800
    assert config == original
    writer = generation_options(analyze.writer_settings(config["llm"]))
    assert writer["temperature"] == 1.0 and writer["presence_penalty"] == 0.0
    assert writer["reasoning_effort"] == "xhigh" and writer["chat_template_kwargs"]["enable_thinking"] is True
    assert generation_options(config["llm"]) == {"temperature": 0, "max_tokens": 1200,
                                               "chat_template_kwargs": {"enable_thinking": False}}


def test_standard_api_contract_does_not_receive_native_sampling_extensions():
    config = copy.deepcopy(DEFAULTS)
    config["llm"]["send_chat_template_kwargs"] = False
    assert generation_options(review._llm(config)) == {
        "temperature": 0.7, "max_tokens": review.OUTPUT_TOKENS, "top_p": 0.8, "presence_penalty": 1.5}


def test_review_model_override_and_explicit_thinking_profile_are_preserved():
    config = copy.deepcopy(DEFAULTS)
    config["review"]["model"] = "alternate-model"
    config["llm"].update(enable_thinking=True, temperature=1.0, top_p=0.95, presence_penalty=0.0)
    settings = review._llm(config)
    assert settings["model"] == "alternate-model"
    assert settings["temperature"] == 1.0 and settings["top_p"] == 0.95
    assert settings["presence_penalty"] == 0.0 and settings["enable_thinking"] is True


@pytest.mark.parametrize("field,value", [("temperature", 0.6), ("top_p", 0.9), ("top_k", 30),
                                         ("min_p", 0.1), ("presence_penalty", 1.0), ("repetition_penalty", 1.1)])
def test_each_effective_sampling_change_invalidates_review_identity(monkeypatch, field, value):
    previous = review.policy_hash(DEFAULTS)
    monkeypatch.setitem(review.REVIEW_SAMPLING, field, value)
    assert review.policy_hash(DEFAULTS) != previous
