"""A cited release feed can admit one prose repair, never a publication decision."""
import copy
import json

import pytest

from helpers import DATE, Reviewer, Writer, analysis, job, make_item, make_tag, pending, run_gate, verdict
from onionflash import render, review, review_gate
from onionflash.config import DEFAULTS
from onionflash.llm import AnalysisError
from onionflash.util import digest, release_mentions
from test_review_request_budget import context, reviewer


TITLE = "Tor Browser 17.2 release checklist"
REPAIR = {"title": "Tor Browser 17.2 is now available",
          "summary": "An official announcement introduces Tor Browser 17.2."}


def draft():
    return analysis(title=TITLE, summary="The release checklist records package preparation.",
                    why_it_matters="", category="network", tags=["network"], products=["tor-browser"],
                    priority="normal", confidence="reported", state="developing")


def incoming():
    return make_item(title="Tor Browser 17.2 released", content="Tor Browser 17.2 is now available.",
                     kind="feed", product="tor-browser", authority="official", labels=[])


@pytest.fixture
def prepared(context):
    _, store = context
    item = incoming()
    row = pending(store, item)
    return store.prepare_candidate(row, draft(), DATE)


def refusal(repair=None, action="revise"):
    return verdict(action, criterion="news_value", repair=REPAIR if repair is None and action == "revise" else repair)


def chain(prepared, reply=None, first=None):
    public = prepared["candidate"]
    replies = (first or verdict(), reply or refusal())
    return [{"stage": stage, "candidate_hash": digest(public),
             "result": review.validate_review(result, prepared["packet"], coverage=prepared["coverage"])}
            for stage, result in zip(("review", "verification"), replies)]


def audit(prepared, cfg):
    return {"candidate": copy.deepcopy(prepared["candidate"]), "reviews": [],
            "policy_hash": review.policy_hash(cfg), **review_gate.initial_review_state()}


def step(checker, stage, public, prepared, record, requests):
    action, value = review_gate.advance_review(checker, stage, public, prepared, record, requests)
    if action in {"verify", "repair"}:
        record["candidate"] = value
    return action, value


def test_prose_repair_is_applied_then_independently_verified(context, prepared):
    cfg, store = context
    original = copy.deepcopy(prepared["candidate"])
    record = audit(prepared, cfg)
    requests = review_gate.ReviewRequests(record)
    checker = reviewer(cfg, verdict(), refusal(), verdict())
    action, public = step(checker, "review", original, prepared, record, requests)
    assert action == "verify" and public == original
    action, repaired = step(checker, action, public, prepared, record, requests)
    assert action == "verify" and {k: repaired[k] for k in REPAIR} == REPAIR
    assert {k:v for k,v in repaired.items() if k not in REPAIR} == {k:v for k,v in original.items() if k not in REPAIR}
    assert record["reviews"][-1]["result"]["criteria"]["news_value"]["outcome"] == "fail"
    review_gate.validate_review_state(record, "verify", repaired, prepared)
    action, approved = step(checker, action, repaired, prepared, record, requests)
    assert action == "approve" and approved == repaired and requests.actual == 3
    wire = [json.loads(r["messages"][1]["content"]) for r in checker.client.requests]
    assert [p["candidate"] for p in wire] == [original, original, repaired]
    assert wire[0]["packet"] == wire[1]["packet"] == wire[2]["packet"]
    assert "criteria" not in wire[2] and "previous_review" not in wire[2]
    assert review.VERIFY_PROMPT in checker.client.requests[2]["messages"][0]["content"]
    record.update(candidate=repaired, outcome="approved",
                  approval_key=review_gate._approval_key(repaired, prepared, record["policy_hash"]))
    review_gate.validate_review_state(record, "approved", repaired, prepared)
    assert not store.stories()  # Review evidence alone does not commit a story.


@pytest.mark.parametrize("damage", [
    "no-feed", "tag-only", "checklist-only", "no-release-evidence", "unrelated", "ambiguous-title", "ambiguous-repair", "ambiguous-feed",
    "uncited", "unofficial", "truncated", "missing-context", "missing-packet", "missing-sources", "missing-passages",
    "stale", "future", "missing-date", "invalid-date", "naive-date", "revision-date", "delayed",
    "prior-story", "existing-target", "association", "update", "primary-tag", "editorial-tag",
])
def test_ineligible_release_context_keeps_the_news_hold(prepared, damage):
    packet, public = prepared["packet"], prepared["candidate"]
    feed = next(s for s in packet["sources"] if s["kind"] == "feed")
    reply = refusal()
    if damage == "no-feed": feed["kind"] = "gitlab_mr"
    elif damage == "tag-only": feed.update(kind="tag", title="tor-browser-17.2")
    elif damage == "no-release-evidence": feed["title"] = "Tor Browser 17.2 engineering notes"
    elif damage == "checklist-only": feed.update(kind="gitlab_issue", title="Checklist: make a version tag")
    elif damage == "unrelated": feed["title"] = "Tor Browser 18.0 released"
    elif damage == "ambiguous-title": public["title"] += " and Tor Browser 18.0"
    elif damage == "ambiguous-repair": reply["repair"]["title"] += " and Tor Browser 18.0"
    elif damage == "ambiguous-feed": feed["title"] += " and Tor Browser 18.0"
    elif damage == "uncited": public["sources"] = [s for s in public["sources"] if s["url"] != feed["url"]]
    elif damage == "unofficial": feed["authority"] = "community"
    elif damage == "delayed": feed["title"] = "Tor Browser 17.2 release delayed"
    elif damage == "truncated": packet["truncated"] = True
    elif damage == "missing-context": packet.pop("truncated")
    elif damage == "missing-packet": prepared["packet"] = None
    elif damage == "missing-sources": packet["missing_sources"] = ["https://example.org/missing"]
    elif damage == "missing-passages": feed["passages"] = []
    elif damage in {"stale", "future", "missing-date", "invalid-date", "naive-date"}:
        feed["published_at"] = {"stale": "2026-10-25T11:59:59Z", "future": "2026-11-08T12:00:01Z",
                               "missing-date": None, "invalid-date": "invalid", "naive-date": "2026-11-08"}[damage]
    elif damage in {"primary-tag", "revision-date"}:
        item = json.loads(prepared["row"]["payload"])
        item["kind" if damage == "primary-tag" else "updated_at"] = "tag" if damage == "primary-tag" else None
        prepared["row"]["payload"] = json.dumps(item)
    elif damage == "editorial-tag": prepared["payload"]["editorial_kind"] = "tag"
    elif damage == "prior-story": prepared["coverage"]["prior_story"] = {"id": "covered"}
    elif damage == "existing-target": prepared["row"]["story_id"] = "covered"
    elif damage == "association": prepared["how"] = "source"
    elif damage == "update": prepared["mode"] = "update"
    # Validate replies against the intact reference set even for missing-context probes.
    entries = chain({**prepared, "packet": packet}, reply)
    assert review_gate.next_step(entries, public, prepared) == ("hold", ("verification", "disagreed_news"))


@pytest.mark.parametrize("repair", [{}, {"title": TITLE}, {"title": "  " + TITLE + "  "},
                                    {"state": "released"}, {**REPAIR, "tags": ["release"]},
                                    {"summary": ""}, {"summary": 42}])
def test_noop_or_nonprose_repairs_keep_the_news_hold(prepared, repair):
    entries = chain(prepared)
    entries[-1]["result"]["repair"] = repair
    assert review_gate.next_step(entries, prepared["candidate"], prepared) == ("hold", ("verification", "disagreed_news"))


@pytest.mark.parametrize("criterion,outcome", [("news_value", "insufficient"), ("new_information", "fail"),
                                             ("new_information", "insufficient"), ("source_support", "fail")])
def test_only_an_explicit_single_news_failure_can_be_repaired(prepared, criterion, outcome):
    entries = chain(prepared)
    entries[-1]["result"]["criteria"][criterion]["outcome"] = outcome
    assert review_gate.next_step(entries, prepared["candidate"], prepared) == ("hold", ("verification", "disagreed_news"))


@pytest.mark.parametrize("action", ["hold", "skip"])
def test_no_repair_verdict_keeps_the_news_hold(prepared, action):
    assert review_gate.next_step(chain(prepared, refusal(action=action)), prepared["candidate"], prepared) == (
        "hold", ("verification", "disagreed_news"))


@pytest.mark.parametrize("action", ["revise", "hold", "skip"])
def test_second_news_failure_holds_without_another_repair(context, prepared, action):
    cfg, _ = context
    record = audit(prepared, cfg)
    requests = review_gate.ReviewRequests(record)
    final = refusal({"summary": "Another proposed release description."} if action == "revise" else None, action)
    checker = Reviewer(verdict(), refusal(), final)
    stage, public = step(checker, "review", prepared["candidate"], prepared, record, requests)
    stage, public = step(checker, stage, public, prepared, record, requests)
    assert step(checker, stage, public, prepared, record, requests) == ("hold", ("verification", "disagreed_news"))
    assert requests.actual == 3


def test_initial_news_refusal_still_holds_as_official_not_news(prepared):
    entries = chain(prepared, first=refusal())
    assert review_gate.next_step(entries, prepared["candidate"], prepared) == ("hold", ("verification", "official_not_news"))


def test_recency_boundary_is_inclusive_and_uses_revision_not_publication(prepared):
    feed = next(s for s in prepared["packet"]["sources"] if s["kind"] == "feed")
    feed["published_at"] = "2026-10-25T12:00:00Z"
    prepared["candidate"]["published_at"] = "2020-01-01T00:00:00Z"
    assert review_gate.next_step(chain(prepared), prepared["candidate"], prepared)[0] == "verify"
    feed["published_at"] = "2026-10-25T14:00:00+02:00"
    assert review_gate.next_step(chain(prepared), prepared["candidate"], prepared)[0] == "verify"


def test_request_budget_still_blocks_an_eighth_call(context, prepared):
    cfg, _ = context
    record = audit(prepared, cfg)
    requests = review_gate.ReviewRequests(record)
    checker = Reviewer(verdict(), refusal(), verdict())
    stage, public = step(checker, "review", prepared["candidate"], prepared, record, requests)
    stage, public = step(checker, stage, public, prepared, record, requests)
    record["request_budget"]["reserved"] = 7
    with pytest.raises(review.ReviewLimitReached):
        step(checker, stage, public, prepared, record, requests)
    assert requests.actual == 2 and len(checker.calls) == 2


def test_repair_does_not_bypass_unsupported_completion_final_guard(context, prepared):
    cfg, _ = context
    prepared["payload"]["editorial_kind"] = "gitlab_issue"
    record = audit(prepared, cfg)
    requests = review_gate.ReviewRequests(record)
    checker = Reviewer(verdict(), refusal({**REPAIR, "summary": "Tor Browser 17.2 fixed the connection failure."}), verdict())
    stage, public = step(checker, "review", prepared["candidate"], prepared, record, requests)
    stage, public = step(checker, stage, public, prepared, record, requests)
    assert stage == "verify"
    assert step(checker, stage, public, prepared, record, requests) == ("hold", ("final_check", "completed_action"))


def test_native_release_feed_repair_publishes_exact_freshly_verified_candidate(context):
    cfg, store = context
    row = pending(store, incoming())
    checker = Reviewer(verdict(), refusal(), verdict())
    result = run_gate(cfg, store, row, Writer(draft()), checker)
    assert result == {"status": "published", "writer_calls": 1, "review_calls": 3, "cache_hit": False}
    saved = store.stories()[0]
    assert {k:saved[k] for k in REPAIR} == REPAIR
    assert [c[2] for c in checker.calls] == [False, True, True]
    public = render.prepare_story(saved)
    assert {k:v for k,v in public.items() if k != "added_at"} == {
        k:v for k,v in checker.calls[2][0].items() if k != "added_at"}
    proof = json.loads(store.db.execute("SELECT review_record FROM analyses").fetchone()[0])
    assert proof["request_budget"]["reserved"] == 3 and len(proof["reviews"]) == 3
    assert proof["reviews"][1]["result"]["criteria"]["news_value"]["outcome"] == "fail"
    assert job(store) is None


def test_native_pending_repair_resumes_with_same_candidate_and_remaining_budget(context):
    cfg, store = context
    row = pending(store, incoming())
    checker = Reviewer(verdict(), refusal(), AnalysisError("timeout", retryable=True))
    with pytest.raises(AnalysisError):
        run_gate(cfg, store, row, Writer(draft()), checker)
    saved_job, _, envelope, record, same_source = review_gate._saved_job(store, row, cfg)
    assert same_source and saved_job["stage"] == "verify"
    assert record["request_budget"]["reserved"] == 3 and len(record["reviews"]) == 2
    repaired = checker.calls[-1][0]
    assert record["candidate"] == repaired and {k:repaired[k] for k in REPAIR} == REPAIR
    review_gate.validate_review_state(record, "verify", repaired, envelope)
    resumed = Reviewer(verdict())
    result = run_gate(cfg, store, row, Writer(draft()), resumed)
    assert result == {"status": "published", "writer_calls": 0, "review_calls": 1, "cache_hit": False}
    assert resumed.calls == [(repaired, checker.calls[-1][1], True)]
    proof = json.loads(store.db.execute("SELECT review_record FROM analyses").fetchone()[0])
    assert proof["request_budget"]["reserved"] == 4
    assert [entry["request"] for entry in proof["reviews"]] == [1, 2, 4]


def test_native_approved_repair_survives_commit_interruption_and_reuses_exact_receipt(context, monkeypatch):
    from onionflash.candidate import StaleCandidate

    cfg, store = context
    row = pending(store, incoming())
    commit = store.commit_candidate
    def interrupted(*args, **kwargs):
        raise StaleCandidate("Commit interrupted")
    monkeypatch.setattr(store, "commit_candidate", interrupted)
    checker = Reviewer(verdict(), refusal(), verdict())
    assert run_gate(cfg, store, row, Writer(draft()), checker)["status"] == "stale"
    saved_job, _, envelope, record, same_source = review_gate._saved_job(store, row, cfg)
    assert same_source and saved_job["stage"] == "approved"
    review_gate.validate_review_state(record, "approved", record["candidate"], envelope)
    assert record["candidate"] == checker.calls[-1][0]
    monkeypatch.setattr(store, "commit_candidate", commit)
    resumed = Reviewer(verdict())
    result = run_gate(cfg, store, row, Writer(draft()), resumed)
    assert result == {"status": "published", "writer_calls": 0, "review_calls": 0, "cache_hit": True}
    assert resumed.calls == [] and store.stories()[0]["title"] == REPAIR["title"]


def test_native_new_story_does_not_infer_uncited_tag_evidence(context):
    cfg, store = context
    row = pending(store, {**incoming(), "kind": "gitlab_issue", "title": TITLE})
    store.ingest(make_tag(title="tor-browser-17.2", content="", product="tor-browser"), DATE)
    checker = Reviewer(verdict(), refusal())
    result = run_gate(cfg, store, row, Writer(draft()), checker)
    assert result["status"] == "held" and len(checker.calls) == 2
    assert all(s["kind"] != "tag" for s in checker.calls[1][1]["sources"])
    assert json.loads(job(store)["record_json"])["hold_code"] == "disagreed_news"
    assert not store.stories()


def test_framing_policy_changes_cache_identity_without_prompt_version_bumps(monkeypatch):
    before = review.policy_hash(DEFAULTS)
    monkeypatch.setattr(review, "RELEASE_FRAMING_POLICY", review.RELEASE_FRAMING_POLICY + 1)
    assert review.policy_hash(DEFAULTS) != before


def test_expanded_release_verbs_invalidate_old_single_identity_admission(prepared, monkeypatch):
    # The earlier grammar did not recognize the second product/version here.
    # Its stored framing path must not be reused under the expanded grammar.
    public = prepared["candidate"]
    public["title"] += "; Arti releases v2.8.0"
    assert release_mentions({"title": public["title"]}) == [
        "release:tor-browser:17.2", "release:arti:2.8.0"]
    assert review_gate.next_step(chain(prepared), public, prepared) == (
        "hold", ("verification", "disagreed_news"))
    current_policy = review.policy_hash(DEFAULTS)
    monkeypatch.setattr(review, "RELEASE_FRAMING_POLICY", 1)
    assert review.policy_hash(DEFAULTS) != current_policy


@pytest.mark.parametrize("reverse", [False, True])
def test_cited_announcement_can_anchor_a_composite_packet_in_either_order(prepared, reverse):
    feed = prepared["packet"]["sources"][0]
    issue = {**copy.deepcopy(feed), "id": "S2", "kind": "gitlab_issue", "authority": "development",
             "url": "https://example.org/checklist", "title": TITLE,
             "passages": [{"id": "S2:P1", "text": "The release checklist records package preparation."}]}
    prepared["packet"]["sources"] = [issue, feed] if reverse else [feed, issue]
    prepared["candidate"]["sources"].append({"url": issue["url"], "title": issue["title"]})
    prepared["candidate"] = render.prepare_story(prepared["candidate"])
    prepared["payload"]["editorial_kind"] = "gitlab_issue"
    item = json.loads(prepared["row"]["payload"])
    item.update(kind="gitlab_issue", authority="development", title=TITLE, url=issue["url"])
    prepared["row"]["payload"] = json.dumps(item)
    action, public = review_gate.next_step(chain(prepared), prepared["candidate"], prepared)
    assert action == "verify" and {k:public[k] for k in REPAIR} == REPAIR


def test_multiple_cited_release_announcements_are_ambiguous(prepared):
    other = {**copy.deepcopy(prepared["packet"]["sources"][0]), "id": "S2", "url": "https://example.org/another"}
    prepared["packet"]["sources"].append(other)
    prepared["candidate"]["sources"].append({"url": other["url"], "title": other["title"]})
    assert review_gate.next_step(chain(prepared), prepared["candidate"], prepared) == (
        "hold", ("verification", "disagreed_news"))


def test_native_repeated_candidate_guard_still_holds(context):
    cfg, store = context
    row = pending(store, incoming())
    checker = Reviewer(verdict("revise", repair={"title": REPAIR["title"]}), refusal({"title": TITLE}))
    assert run_gate(cfg, store, row, Writer(draft()), checker)["status"] == "held"
    assert json.loads(job(store)["record_json"])["hold_code"] == "repeated_repair"
    assert len(checker.calls) == 2 and not store.stories()


def test_native_five_repair_limit_still_holds(context):
    cfg, store = context
    row = pending(store, incoming())
    changes = [verdict("revise", repair={"summary": f"The source describes release detail {n}."}) for n in range(5)]
    checker = Reviewer(verdict(), *changes, refusal())
    assert run_gate(cfg, store, row, Writer(draft()), checker)["status"] == "held"
    record = json.loads(job(store)["record_json"])
    assert record["hold_code"] == "repairs_exhausted" and record["request_budget"]["reserved"] == 7
    assert len(checker.calls) == 7 and not store.stories()


def test_native_fresh_status_refusal_cannot_publish(context):
    cfg, store = context
    row = pending(store, incoming())
    checker = Reviewer(verdict(), refusal(), verdict("hold", criterion="status"))
    assert run_gate(cfg, store, row, Writer(draft()), checker)["status"] == "held"
    assert json.loads(job(store)["record_json"])["hold_code"] == "model_hold"
    assert len(checker.calls) == 3 and not store.stories()


@pytest.mark.parametrize("title", ["Tor Browser 17.2 release planned", "Tor Browser 17.2 is not released"])
def test_release_hint_does_not_override_factual_verification(context, title):
    cfg, store = context
    row = pending(store, {**incoming(), "title": title, "content": "The release has not shipped."})
    checker = Reviewer(verdict(), refusal(), verdict("hold", criterion="source_support"))
    assert run_gate(cfg, store, row, Writer(draft()), checker)["status"] == "held"
    assert len(checker.calls) == 3
    proof = json.loads(job(store)["record_json"])
    assert proof["hold_code"] == "model_hold" and proof["verified_facts"] is False
    assert not store.stories()
