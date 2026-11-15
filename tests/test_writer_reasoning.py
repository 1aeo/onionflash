"""Writer reasoning is an explicit, isolated generation profile."""
import copy
import json

import httpx
import pytest

from onionflash.analyze import Analyzer
from onionflash.config import DEFAULTS, load_config
from onionflash.doctor import LinkChecker
from onionflash.review import Reviewer
from onionflash.transport import HttpClient
from test_transport import public_dns

PROMPT = "Summarize only supplied evidence."
PAYLOAD = {"source": "The report states a bounded effect."}
SCHEMA = {"type": "object"}


@pytest.fixture
def capture(monkeypatch):
    monkeypatch.setenv("NATIVE_WRITER_TEST_KEY", "synthetic-fixture-value")

    def run(cls, settings):
        observed = []
        client = cls(settings)

        def reply(request):
            observed.append(request)
            return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {"content": "{}"}}]})

        client.client = HttpClient(client.http_settings, transport=httpx.MockTransport(reply), resolver=public_dns)
        try:
            assert client.complete(PROMPT, PAYLOAD, SCHEMA, "profile_probe") == {}
            assert len(observed) == client.calls == 1
            return observed[0], copy.deepcopy(client.llm), copy.deepcopy(client.http_settings)
        finally:
            client.close()
    return run


def settings(enabled=False):
    config = copy.deepcopy(DEFAULTS)
    config["llm"].update(base_url="https://model.example/v1", model="writer-model",
                         api_key_env="NATIVE_WRITER_TEST_KEY", writer_reasoning=enabled,
                         timeout_seconds=3600)
    config["review"]["model"] = "review-model"
    return config


def test_enabled_writer_sends_the_declared_profile_exactly(capture):
    config = settings(True)
    before = copy.deepcopy(config)
    sent, effective, transport = capture(Analyzer, config)
    expected = {
        "model": "writer-model",
        "messages": [{"role": "system", "content": PROMPT},
                     {"role": "user", "content": json.dumps(PAYLOAD, ensure_ascii=False, allow_nan=False)}],
        "temperature": 1.0, "max_tokens": 32768,
        "response_format": {"type": "json_schema", "json_schema": {"name": "profile_probe", "strict": True, "schema": SCHEMA}},
        "top_p": 0.95, "top_k": 20, "min_p": 0.0,
        "presence_penalty": 0.0, "repetition_penalty": 1.0, "reasoning_effort": "xhigh",
        "chat_template_kwargs": {"enable_thinking": True},
    }
    assert sent.content == httpx.Request("POST", "https://model.example/v1/chat/completions", json=expected).content
    assert transport["max_response_bytes"] == 2097152
    assert transport["timeout_seconds"] == effective["timeout_seconds"] == 3600
    assert transport["total_timeout_seconds"] == 3610
    assert config == before


@pytest.mark.parametrize("cls", [Reviewer, LinkChecker])
def test_writer_option_does_not_change_other_stages(capture, cls):
    off = settings(False)
    before, effective_before, transport_before = capture(cls, off)
    enabled = settings(True)
    original = copy.deepcopy(enabled)
    capture(Analyzer, enabled)
    after, effective_after, transport_after = capture(cls, enabled)
    assert before.content == after.content
    assert transport_before == transport_after
    assert enabled == original
    assert json.loads(after.content)["chat_template_kwargs"] == {"enable_thinking": False}
    assert "reasoning_effort" not in json.loads(after.content)
    assert effective_before["max_output_tokens"] == effective_after["max_output_tokens"]


@pytest.mark.parametrize("template", [False, True])
def test_disabled_writer_keeps_existing_wire_semantics(capture, template):
    config = settings(False)
    config["llm"]["send_chat_template_kwargs"] = template
    sent, effective, transport = capture(Analyzer, config)
    body = json.loads(sent.content)
    assert body["temperature"] == 0 and body["max_tokens"] == 1200
    assert transport["max_response_bytes"] == 65536 and not effective["enable_thinking"]
    assert ("chat_template_kwargs" in body) is template
    assert not {"top_p", "top_k", "min_p", "presence_penalty", "repetition_penalty", "reasoning_effort"} & body.keys()


def test_profile_does_not_override_the_configured_timeout(capture):
    config = settings(True)
    config["llm"]["timeout_seconds"] = 45
    _, effective, transport = capture(Analyzer, config)
    assert effective["timeout_seconds"] == transport["timeout_seconds"] == 45


@pytest.mark.parametrize("enabled", [False, True])
def test_writer_reasoning_is_a_validated_operator_setting(tmp_path, enabled):
    path = tmp_path / "app.toml"
    path.write_text(f'[llm]\nwriter_reasoning = {str(enabled).lower()}\n[[sources]]\nid="sample"\nurl="https://example.org/feed"\n')
    assert load_config(path)["llm"]["writer_reasoning"] is enabled


def test_reasoning_requires_the_declared_chat_template_contract(tmp_path):
    path = tmp_path / "app.toml"
    path.write_text('[llm]\nwriter_reasoning=true\nsend_chat_template_kwargs=false\n[[sources]]\nid="sample"\nurl="https://example.org/feed"\n')
    with pytest.raises(ValueError, match="writer_reasoning requires"):
        load_config(path)
    config = settings(True)
    config["llm"]["send_chat_template_kwargs"] = False
    with pytest.raises(ValueError, match="writer_reasoning requires"):
        Analyzer(config)


@pytest.mark.parametrize("value", ['"true"', "1", "[]"])
def test_writer_reasoning_rejects_non_boolean_values(tmp_path, value):
    path = tmp_path / "app.toml"
    path.write_text(f'[llm]\nwriter_reasoning={value}\n[[sources]]\nid="sample"\nurl="https://example.org/feed"\n')
    with pytest.raises(ValueError, match="writer_reasoning must be a boolean"):
        load_config(path)
