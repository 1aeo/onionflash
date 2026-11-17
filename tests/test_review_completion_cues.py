"""Existing completion checks guide repairs without authorizing publication."""

import json

import pytest

from helpers import Writer, analysis, make_item, pending, run_gate, verdict
from onionflash import review
from test_review_request_budget import context, inconsistent, reviewer, saved_audit


def pending_request(store):
    source = make_item(kind="gitlab_issue", upstream_state="opened", authority="development",
                       title="Remove an obsolete authority entry",
                       content="Please remove the obsolete authority entry. The entry can no longer be trusted.")
    draft = analysis(title="Obsolete authority entry removed",
                     summary="The obsolete authority entry was removed from the source code.",
                     why_it_matters="The entry can no longer be trusted.",
                     category="network", tags=["network"], state="developing", confidence="reported")
    return pending(store, source), Writer(draft)


def repair():
    return verdict("revise", criterion="status", repair={
        "title": "Removal of an obsolete authority entry requested",
        "summary": "The issue requests removing an obsolete authority entry from the source code.",
    })


@pytest.mark.parametrize("with_correction", [False, True])
def test_request_repair_keeps_impact_and_receives_fresh_verification(context, with_correction):
    config, store = context
    row, writer = pending_request(store)
    replies = ([inconsistent({})] if with_correction else []) + [repair(), verdict()]
    checker = reviewer(config, *replies)
    result = run_gate(config, store, row, writer, checker)
    assert result["status"] == "published"
    assert checker.calls == 2 + int(with_correction)
    payloads = [json.loads(body["messages"][1]["content"]) for body in checker.client.requests]
    assert payloads[0]["application_issue"] == review.COMPLETION_ISSUE + '\n["removed"]'
    if with_correction:
        assert payloads[1] == {**payloads[0], "validation_error": review.INCONSISTENT_VERDICT}
    assert "application_issue" not in payloads[-1]
    assert payloads[-1]["candidate"]["why_it_matters"] == "The entry can no longer be trusted."
    audit = saved_audit(store)
    assert audit["reviews"][-1]["stage"] == "verification"
    assert audit["outcome"] == "approved"
    assert store.stories()[0]["summary"] == payloads[-1]["candidate"]["summary"]


def test_ignored_completion_cue_still_holds_after_two_approvals(context):
    config, store = context
    row, writer = pending_request(store)
    checker = reviewer(config, verdict(), verdict())
    result = run_gate(config, store, row, writer, checker)
    assert result["status"] == "held" and checker.calls == 2
    assert store.stories() == []
    payloads = [json.loads(body["messages"][1]["content"]) for body in checker.client.requests]
    assert payloads[0]["candidate"] == payloads[1]["candidate"]
    assert payloads[0]["application_issue"] == payloads[1]["application_issue"]
    assert saved_audit(store)["hold_code"] == "completed_action"


def test_completion_cue_changes_policy_identity(monkeypatch):
    from onionflash.config import DEFAULTS

    before = review.policy_hash(DEFAULTS)
    monkeypatch.setattr(review, "COMPLETION_ISSUE", "A different completion instruction.")
    assert review.policy_hash(DEFAULTS) != before
