"""Run admission and in-flight transport budgets have distinct, resumable outcomes."""
import copy
import json

import httpx
import pytest

from helpers import DATE, analysis, job, pending, verdict
from onionflash import cli, doctor, llm, review_gate
from onionflash.config import DEFAULTS, completion_budget_seconds, load_config, run_command_budget_seconds
from onionflash.llm import AnalysisError, CompletionDeferred
from onionflash.transport import HttpClient
from test_completion_redirects import completion_client, complete, ledger  # noqa: F401
from test_transport import public_dns


def response(value):
    return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(value)}}]})


@pytest.mark.parametrize("timeout", [1, 120, 600, 3600, 3599.5])
def test_configured_completion_allowance_is_explicit(tmp_path, timeout):
    path = tmp_path / "config.toml"
    path.write_text(f'[llm]\ntimeout_seconds = {timeout}\n[[sources]]\nid = "test"\nurl = "https://example.org/feed.xml"\n')
    config = load_config(path)
    assert config["llm"]["timeout_seconds"] == timeout
    assert config["collection"] == DEFAULTS["collection"]
    assert config["http"] == DEFAULTS["http"]
    allowance = max(180, timeout + 10)
    assert completion_budget_seconds(config["llm"]) == allowance
    assert run_command_budget_seconds(config) == 240 + allowance


@pytest.mark.parametrize("timeout", ["0", "3600.1", "true", "nan", "inf"])
def test_invalid_completion_allowance_rejected(tmp_path, timeout):
    path = tmp_path / "config.toml"
    path.write_text(f'[llm]\ntimeout_seconds = {timeout}\n[[sources]]\nid = "test"\nurl = "https://example.org/feed.xml"\n')
    with pytest.raises(ValueError, match="timeout_seconds"):
        load_config(path)


def test_expired_admission_is_unsent_even_without_credentials(completion_client, monkeypatch):
    client, config = completion_client(lambda request: pytest.fail("Request must remain unsent"))
    monkeypatch.delenv(config["llm"]["api_key_env"])
    client.clock, client.deadline = lambda: 10, 10
    record, requests, persisted = ledger()
    with pytest.raises(CompletionDeferred):
        complete(client, requests)
    assert client.calls == requests.actual == record["request_budget"]["reserved"] == 0
    assert persisted == []


def test_expiry_during_reservation_refunds_only_unsent_attempt(completion_client):
    client, _ = completion_client(lambda request: pytest.fail("Request must remain unsent"))
    clock = [0]
    client.clock, client.deadline = lambda: clock[0], 10
    record = {"reviews": [], **review_gate.initial_review_state()}
    saved = []

    def persist():
        saved.append(copy.deepcopy(record))
        clock[0] = 10

    requests = review_gate.ReviewRequests(record, persist)
    with pytest.raises(CompletionDeferred):
        complete(client, requests)
    assert [entry["request_budget"]["reserved"] for entry in saved] == [1, 0]
    assert client.calls == requests.actual == record["request_budget"]["reserved"] == 0


@pytest.mark.parametrize("expire", ["after_failure", "during_fallback_reservation"])
def test_real_failure_survives_later_fallback_admission_refusal(completion_client, expire):
    clock, sent = [0], []

    def handle(request):
        sent.append(request)
        clock[0] = 10 if expire == "after_failure" else 1
        return httpx.Response(503)

    client, _ = completion_client(handle, fallbacks=["https://fallback.example/v1"])
    client.clock, client.deadline = lambda: clock[0], 10
    client.client.clock = client.clock
    record = {"reviews": [], **review_gate.initial_review_state()}
    saved = []

    def persist():
        saved.append(copy.deepcopy(record))
        if record["request_budget"]["reserved"] == 2:
            clock[0] = 10

    requests = review_gate.ReviewRequests(record, persist)
    with pytest.raises(AnalysisError, match="HTTP 503") as caught:
        complete(client, requests)
    assert caught.value.retryable
    assert len(sent) == client.calls == requests.actual == record["request_budget"]["reserved"] == 1
    assert [entry["request_budget"]["reserved"] for entry in saved] == ([1] if expire == "after_failure" else [1, 2, 1])


@pytest.mark.parametrize("expire", ["writer", "review", "reservation"])
def test_native_run_defers_unsent_work_without_strikes_and_resumes(context, monkeypatch, expire):
    config, store = context
    config["sources"] = []
    config["llm"].update(base_url="https://model.example/v1", api_key_env="ADMISSION_TEST_KEY",
                         writer_reasoning=True, timeout_seconds=3600)
    row = pending(store)
    clock, sent, settings_seen = [0.0], [], []
    monkeypatch.setenv("ADMISSION_TEST_KEY", "synthetic-fixture-value")
    monkeypatch.setattr(cli.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(cli, "now_iso", lambda: DATE)
    monkeypatch.setattr(cli, "build", lambda *_args: {})
    monkeypatch.setattr(review_gate, "now_iso", lambda: DATE)

    def handle(request):
        body = json.loads(request.content)
        writer = body["max_tokens"] == 32768
        sent.append("writer" if writer else "review")
        if (expire == "writer" and len(sent) == 1) or (expire == "review" and len(sent) == 2):
            clock[0] += 300  # Past run admission, within the admitted transport allowance.
        return response(analysis(why_it_matters="") if writer else verdict())

    def factory(settings, **kwargs):
        settings_seen.append(copy.deepcopy(settings))
        return HttpClient(settings, **kwargs, transport=httpx.MockTransport(handle), resolver=public_dns)

    monkeypatch.setattr(llm, "HttpClient", factory)
    if expire == "reservation":
        original = review_gate._save
        expired = []

        def expire_save(*args, **kwargs):
            result = original(*args, **kwargs)
            if not expired and args[7].get("request_budget", {}).get("reserved") == 1:
                expired.append(True)
                clock[0] = 240
            return result
        monkeypatch.setattr(review_gate, "_save", expire_save)

    first = cli.run(config, store)
    saved = job(store)
    record = json.loads(saved["record_json"])
    assert first["budget_reached"] and first["analysis_failed"] == 0
    assert first["model_calls"] == len(sent) == (2 if expire == "review" else 1)
    assert saved["stage"] == ("verify" if expire == "review" else "review")
    assert record["request_budget"]["reserved"] == (1 if expire == "review" else 0)
    current = store.db.execute("SELECT status,attempts,rejections,last_error,next_attempt_at FROM items WHERE id=?", (row["id"],)).fetchone()
    assert tuple(current) == ("pending", 0, 0, None, None)
    assert store.stories() == []
    assert all(settings["timeout_seconds"] == 3600 and settings["total_timeout_seconds"] == 3610 for settings in settings_seen)
    second = cli.run(config, store)
    assert second["analysis_failed"] == 0 and second["model_calls"] == (1 if expire == "review" else 2)
    assert sent == ["writer", "review", "review"]
    assert len(store.stories()) == 1 and job(store) is None


def test_link_admission_deferral_keeps_host_pending_without_failure(context, monkeypatch):
    _config, store = context
    host = {"id": "existing-host", "hash": "stable-hash", "public": {}}
    monkeypatch.setattr(doctor, "candidate_hosts", lambda *_args, **_kwargs: [host])
    logged = []
    monkeypatch.setattr(doctor, "_log_incident", lambda *_args, **kwargs: logged.append(kwargs))

    def defer(*_args):
        raise CompletionDeferred("Admission ended")

    assert doctor._resolve_host_link(store.db, {"key": "incident"}, evaluate_mode=True,
                                     observed=DATE, linker=defer, allow_network=True) == ("pending_link", None, 0)
    assert store.db.execute("SELECT COUNT(*) FROM network_links").fetchone()[0] == 0
    assert len(logged) == 1 and "error" not in logged[0]


def test_writer_mode_change_redrafts_without_resetting_review_spend(context):
    from helpers import Reviewer, Writer, run_gate

    config, store = context
    row = pending(store)
    writer = Writer(analysis(why_it_matters=""))
    with pytest.raises(AnalysisError):
        run_gate(config, store, row, writer, Reviewer(AnalysisError("Temporary endpoint failure", retryable=True)))
    before = job(store)
    assert json.loads(before["record_json"])["request_budget"]["reserved"] == 1
    config["llm"]["writer_reasoning"] = True
    next_writer = Writer(analysis(why_it_matters=""))
    with pytest.raises(AnalysisError):
        run_gate(config, store, row, next_writer, Reviewer(AnalysisError("Temporary endpoint failure", retryable=True)))
    after = job(store)
    assert len(next_writer.calls) == 1 and before["writer_key"] != after["writer_key"]
    assert before["policy_hash"] == after["policy_hash"]
    assert json.loads(after["record_json"])["request_budget"]["reserved"] == 2
    assert store.stories() == []
