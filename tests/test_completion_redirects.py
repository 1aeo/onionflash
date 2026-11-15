"""Completion redirects cannot send requests outside the review ledger."""
import copy
import json

import httpx
import pytest

from onionflash import review, review_gate
from onionflash.analyze import Analyzer
from onionflash.llm import AnalysisError
from onionflash.config import DEFAULTS
from onionflash.transport import HttpClient
from test_transport import public_dns


@pytest.fixture
def completion_client(monkeypatch):
    clients = []
    monkeypatch.setenv("COMPLETION_TEST_KEY", "synthetic-fixture-value")

    def make(handler, *, client_type=review.Reviewer, fallbacks=()):
        config = copy.deepcopy(DEFAULTS)
        config["llm"].update(base_url="https://model.example/v1", fallback_base_urls=list(fallbacks),
                             api_key_env="COMPLETION_TEST_KEY")
        result = client_type(config)
        result.client = HttpClient(result.http_settings, transport=httpx.MockTransport(handler),
                                   resolver=public_dns)
        clients.append(result)
        return result, config

    yield make
    for client in clients:
        client.client.close()


def ledger():
    record = {"reviews": [], **review_gate.initial_review_state()}
    persisted = []
    requests = review_gate.ReviewRequests(record, lambda: persisted.append(copy.deepcopy(record)))
    return record, requests, persisted


def complete(client, requests):
    return client.complete("Assess the supplied evidence.", {"source": "An attributed statement."},
                           {"type": "object"}, "test_completion", on_request=requests.callback())


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("client_type", [Analyzer, review.Reviewer])
def test_redirect_never_forwards_completion_or_releases_spent_reservation(completion_client, status, client_type):
    record, requests, persisted = ledger()
    sent = []

    def handle(request):
        assert persisted[-1]["request_budget"]["reserved"] == len(sent) + 1
        sent.append(request)
        return httpx.Response(status, headers={"location": "/unmetered-hop"})

    client, _ = completion_client(handle, client_type=client_type)
    with pytest.raises(AnalysisError, match="LLM request failed"):
        complete(client, requests)
    assert [(request.method, request.url.path) for request in sent] == [("POST", "/v1/chat/completions")]
    assert record["request_budget"]["reserved"] == requests.actual == client.calls == 1


def test_redirects_cannot_exceed_budget_through_configured_fallbacks(completion_client):
    record, requests, persisted = ledger()
    sent = []

    def handle(request):
        assert persisted[-1]["request_budget"]["reserved"] == len(sent) + 1
        sent.append(request)
        return httpx.Response(307, headers={"location": "/same-origin-loop"})

    fallbacks = [f"https://fallback-{number}.example/v1" for number in range(1, 10)]
    client, _ = completion_client(handle, fallbacks=fallbacks)
    with pytest.raises(review.ReviewLimitReached, match="budget exhausted"):
        complete(client, requests)
    assert len(sent) == record["request_budget"]["reserved"] == requests.actual == client.calls == 7
    assert all(request.method == "POST" and request.url.path == "/v1/chat/completions" for request in sent)
    assert [request.url.host for request in sent] == ["model.example", *[f"fallback-{n}.example" for n in range(1, 7)]]


def test_explicit_fallback_after_redirect_has_its_own_reservation(completion_client):
    record, requests, persisted = ledger()
    sent = []

    def handle(request):
        assert persisted[-1]["request_budget"]["reserved"] == len(sent) + 1
        sent.append(request)
        if request.url.host == "model.example":
            return httpx.Response(307, headers={"location": "/redirect-is-not-a-fallback"})
        return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {
            "content": json.dumps({"assessed": True})}}]})

    client, _ = completion_client(handle, fallbacks=["https://fallback.example/v1"])
    assert complete(client, requests) == {"assessed": True}
    assert [(r.url.host, r.url.path) for r in sent] == [
        ("model.example", "/v1/chat/completions"), ("fallback.example", "/v1/chat/completions")]
    assert record["request_budget"]["reserved"] == requests.actual == client.calls == 2
    assert all(r.headers["authorization"] == "Bearer synthetic-fixture-value" for r in sent)


def test_unsent_fallback_refund_keeps_redirected_request_spent(completion_client):
    record, requests, persisted = ledger()
    sent = []

    def handle(request):
        sent.append(request)
        client.client.deadline = 0
        return httpx.Response(302, headers={"location": "/ignored-hop"})

    client, _ = completion_client(handle, fallbacks=["https://fallback.example/v1"])
    with pytest.raises(AnalysisError, match="LLM request failed"):
        complete(client, requests)
    assert len(sent) == record["request_budget"]["reserved"] == requests.actual == client.calls == 1
    assert [r["request_budget"]["reserved"] for r in persisted] == [1, 2, 1]


def test_completion_policy_leaves_source_collection_redirects_available(completion_client):
    sent = []

    def handle(request):
        sent.append(request)
        if request.url.path == "/feed":
            return httpx.Response(302, headers={"location": "/new-feed"})
        return httpx.Response(200, content=b"source content")

    _, config = completion_client(handle)
    assert config["http"] == DEFAULTS["http"]
    with HttpClient(config["http"], transport=httpx.MockTransport(handle), resolver=public_dns) as collector:
        assert collector.request("GET", "https://source.example/feed").body == b"source content"
    assert [(r.method, r.url.path) for r in sent] == [("GET", "/feed"), ("GET", "/new-feed")]
