"""Only deadline refusal before dispatch can refund a review reservation."""
import copy

import httpx
import pytest

from onionflash import review
from onionflash.llm import AnalysisError, CompletionClient
from onionflash.config import DEFAULTS
from onionflash.transport import DeadlineReached
from test_completion_redirects import completion_client, complete, ledger  # noqa: F401 (fixture)


@pytest.mark.parametrize("failure", [httpx.ReadTimeout, httpx.WriteTimeout, httpx.ConnectTimeout,
                                    httpx.RemoteProtocolError, DeadlineReached])
def test_deadline_after_dispatch_keeps_request_charged(completion_client, failure):
    record, requests, persisted = ledger()
    clock, sent = [0.0], []

    def handle(request):
        sent.append(request)
        clock[0] = 2.0
        if failure is DeadlineReached:
            raise DeadlineReached()
        raise failure("controlled transport failure", request=request)

    client, _ = completion_client(handle, fallbacks=["https://fallback.example/v1"])
    client.client.clock = lambda: clock[0]
    client.client.deadline = 1.0
    with pytest.raises(AnalysisError, match="LLM request failed"):
        complete(client, requests)
    assert len(sent) == record["request_budget"]["reserved"] == requests.actual == client.calls == 1
    assert [value["request_budget"]["reserved"] for value in persisted] == [1]

    # Reusing this client after the expired deadline proves the next call unsent.
    with pytest.raises(AnalysisError, match="LLM request failed"):
        complete(client, requests)
    assert len(sent) == record["request_budget"]["reserved"] == requests.actual == client.calls == 1
    assert [value["request_budget"]["reserved"] for value in persisted] == [1, 2, 1]


def test_repeated_dispatched_timeouts_cannot_replenish_budget(completion_client):
    record, requests, _ = ledger()
    clock, sent = [0.0], []

    def handle(request):
        sent.append(request)
        clock[0] = 2.0
        raise httpx.ReadTimeout("controlled timeout", request=request)

    client, _ = completion_client(handle)
    client.client.clock = lambda: clock[0]
    client.client.deadline = 1.0
    for _ in range(7):
        clock[0] = 0.0
        with pytest.raises(AnalysisError):
            complete(client, requests)
    clock[0] = 0.0
    with pytest.raises(review.ReviewLimitReached):
        complete(client, requests)
    assert len(sent) == record["request_budget"]["reserved"] == requests.actual == client.calls == 7


def test_response_body_timeout_remains_charged(completion_client):
    record, requests, _ = ledger()
    clock, sent = [0.0], []

    class IncompleteBody(httpx.SyncByteStream):
        def __iter__(self):
            yield b'{"choices":'
            clock[0] = 2.0
            raise httpx.ReadTimeout("controlled body timeout")

    def handle(request):
        sent.append(request)
        return httpx.Response(200, stream=IncompleteBody())

    client, _ = completion_client(handle)
    client.client.clock = lambda: clock[0]
    client.client.deadline = 1.0
    with pytest.raises(AnalysisError):
        complete(client, requests)
    assert len(sent) == record["request_budget"]["reserved"] == requests.actual == client.calls == 1


@pytest.mark.parametrize("setting,value", [("retry_attempts", 2), ("max_redirects", 1)])
def test_review_identity_binds_the_effective_completion_transport(monkeypatch, setting, value):
    config = copy.deepcopy(DEFAULTS)
    before = review.policy_hash(config)
    transport = {**CompletionClient.REQUEST_POLICY["transport"], setting: value}
    monkeypatch.setitem(CompletionClient.REQUEST_POLICY, "transport", transport)
    client = CompletionClient(config)
    assert client.http_settings[setting] == value
    assert review.policy_hash(config) != before


def test_collection_settings_do_not_change_completion_policy_but_refund_contract_does(monkeypatch):
    config = copy.deepcopy(DEFAULTS)
    before = review.policy_hash(config)
    config["http"].update(max_redirects=9, retry_attempts=8)
    client = CompletionClient(config)
    assert client.http_settings["max_redirects"] == 0 and client.http_settings["retry_attempts"] == 1
    assert review.policy_hash(config) == before
    monkeypatch.setitem(CompletionClient.REQUEST_POLICY, "deadline_refund", "legacy")
    assert review.policy_hash(config) != before
