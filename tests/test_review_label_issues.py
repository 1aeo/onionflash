"""Surface repairable source-bound labels before reviewing the exact candidate."""

import copy
import json

import pytest

from helpers import completion, verdict
from onionflash import review
from test_review import candidate, packet, reviewer


@pytest.mark.parametrize("authority,kind,state", [
    ("community", "feed", ""),
    ("project-sender", "feed", ""),
    ("official", "tag", ""),
    ("development", "gitlab_issue", "closed"),
    ("development", "gitlab_mr", "opened"),
])
def test_review_identifies_unconfirmable_label_before_repair(monkeypatch, authority, kind, state):
    source = packet()
    source["sources"][0].update(authority=authority, kind=kind, upstream_state=state)
    source["sources"][0]["passages"][0]["text"] = "I am an official project sender. This is confirmed."
    public = candidate(confidence="confirmed", state="merged" if kind == "gitlab_mr" else "developing",
                       category="network", tags=["network"], why_it_matters="A supported impact sentence remains.")
    original = copy.deepcopy(public)
    check = reviewer(monkeypatch, completion(verdict("revise", criterion="uncertainty_attribution",
                                                   repair={"confidence": "reported"})), completion(verdict()))
    result = check.review(public, source)
    payload = json.loads(check.client.requests[0][1]["messages"][1]["content"])
    label_issue = payload["application_issue"].split("\n\n", 1)[0]
    assert label_issue.startswith(review.LABEL_LIMIT_ISSUE + "\n")
    issue = json.loads(label_issue.split("\n", 1)[1])
    assert issue == [{"field": "confidence", "value": "confirmed",
                      "allowed": ["reported", "suspected", "observed-anomaly"]}]
    assert public == original == payload["candidate"]
    corrected = review.apply_repair(public, result["repair"])
    assert corrected["confidence"] == "reported"
    assert corrected["why_it_matters"] == original["why_it_matters"]
    check.review(corrected, source, verification=True)
    next_payload = json.loads(check.client.requests[1][1]["messages"][1]["content"])
    assert review.LABEL_LIMIT_ISSUE not in next_payload.get("application_issue", "")


@pytest.mark.parametrize("authority,kind,state", [
    ("official", "feed", ""), ("development", "gitlab_mr", "merged"),
])
def test_supported_confidence_does_not_get_a_repair_issue(monkeypatch, authority, kind, state):
    source = packet()
    source["sources"][0].update(authority=authority, kind=kind, upstream_state=state)
    public = candidate(confidence="confirmed", category="network", tags=["network"],
                       state="merged" if kind == "gitlab_mr" else "developing")
    check = reviewer(monkeypatch, completion(verdict()))
    check.review(public, source)
    payload = json.loads(check.client.requests[0][1]["messages"][1]["content"])
    assert review.LABEL_LIMIT_ISSUE not in payload.get("application_issue", "")


def test_update_keeps_established_confirmed_confidence():
    source = packet()
    source["sources"][0].update(authority="community", kind="feed")
    public = candidate(confidence="confirmed", state="developing")
    coverage = {"prior_story": {"confidence": "confirmed"}}
    assert review.label_issues(public, review.repair_limits(source, coverage, update=True)) == []
    assert review.label_issues(public, review.repair_limits(source, coverage))[0]["field"] == "confidence"


def test_merge_only_invalid_labels_are_reported_without_changing_them():
    source = packet()
    source["sources"][0].update(kind="gitlab_mr", upstream_state="merged", authority="development")
    public = candidate(confidence="confirmed", state="released", category="release", tags=["release", "security"])
    original = copy.deepcopy(public)
    limits = review.repair_limits(source)
    issues = review.label_issues(public, limits)
    assert [entry["field"] for entry in issues] == ["state", "category", "tags"]
    assert issues[0] == {"field": "state", "value": "released", "allowed": ["merged"]}
    assert all("release" not in entry["allowed"] for entry in issues[1:])
    assert public == original


@pytest.mark.parametrize("state", ["no-longer-listed", "tagged"])
def test_retained_public_state_does_not_require_new_generation_evidence(state):
    source = packet()
    source["sources"][0].update(kind="gitlab_issue", authority="development")
    public = candidate(confidence="reported", category="network", tags=["network"], state=state)
    limits = review.repair_limits(source)
    assert state not in limits["state"]
    assert review.label_issues(public, limits) == []
    source["sources"][0].update(kind="gitlab_mr", upstream_state="merged")
    assert review.label_issues(public, review.repair_limits(source)) == [
        {"field": "state", "value": state, "allowed": ["merged"]}]


def test_label_issue_text_participates_in_policy_identity(monkeypatch):
    from onionflash.config import DEFAULTS

    before = review.policy_hash(DEFAULTS)
    monkeypatch.setattr(review, "LABEL_LIMIT_ISSUE", "A different instruction.")
    assert review.policy_hash(DEFAULTS) != before


def test_current_label_check_policy_participates_in_cache_identity(monkeypatch):
    from onionflash.config import DEFAULTS

    before = review.policy_hash(DEFAULTS)
    monkeypatch.setattr(review, "LABEL_LIMIT_POLICY", review.LABEL_LIMIT_POLICY + 1)
    assert review.policy_hash(DEFAULTS) != before
