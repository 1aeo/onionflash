"""The final-candidate gate resumes completed stages and never publishes unchecked."""

import contextlib
import copy
import json
import sqlite3

import pytest

from approval_helpers import approve, update_analysis, verdict
from onionflash import decisions, editorial, rejection, review, review_gate
from onionflash.analyze import AnalysisError, cache_key, tag_notice, tag_update
from onionflash.store import Store
from onionflash.util import digest, item_cluster
from test_core import DAMAGE, DATE, analysis, config, damaged, item


LATER = "2026-11-10T12:00:00Z"


class Writer:
    def __init__(self, result=None):
        self._explicit = result is not None
        self.result, self.calls = result or analysis(), []

    def analyze(self, incoming, prior=None):
        self.calls.append(copy.deepcopy(incoming))
        if prior is not None and "update" not in self.result:
            if incoming.get("kind") == "tag":
                return tag_update(incoming, prior)
            if not self._explicit:
                return update_analysis(confidence=prior["confidence"], state=prior["state"],
                                       evidence=self.result["evidence"])
            return update_analysis(update=(self.result.get("summary") or self.result.get("title"))[:300],
                                   confidence=self.result.get("confidence", prior["confidence"]),
                                   state=self.result.get("state", prior["state"]),
                                   evidence=self.result["evidence"])
        return copy.deepcopy(self.result)


class Reviewer:
    """Returns validated verdicts, as review.Reviewer does."""
    def __init__(self, *responses):
        """Script reviewer responses, adding final approval only for approval shorthand."""
        self.responses, self.calls, self.coverages, self.issues = list(responses), [], [], []
        # A shorthand approval includes an independent final approval. Empty
        # and failure scripts remain strict, so unexpected calls still fail.
        if len(responses) == 1 and (callable(responses[0]) or
                isinstance(responses[0], dict) and responses[0].get("verdict") == "approve"):
            self.responses.append(verdict())

    def review(self, candidate, packet, *, coverage=None, verification=False, issue=None, update=False):
        """Capture exact review inputs and validate or raise the next scripted response."""
        self.calls.append((copy.deepcopy(candidate), copy.deepcopy(packet), verification))
        self.coverages.append(copy.deepcopy(coverage))
        self.issues.append(issue)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return review.validate_review(
            response() if callable(response) else copy.deepcopy(response),
            packet,
            update=update,
            coverage=coverage,
        )


@pytest.fixture
def context(tmp_path):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        yield cfg, store


def pending(store, incoming=None):
    store.ingest(incoming or item(), DATE)
    return store.pending(1, LATER)[0]


def run(cfg, store, row, writer, checker, **kwargs):
    return review_gate.process_item(cfg, store, row, writer, checker, LATER, **kwargs)


def job(store):
    row = store.db.execute("SELECT * FROM review_jobs").fetchone()
    return dict(row) if row else None


def seed_legacy(store, incoming=None, result=None):
    incoming = incoming or item(content=item()["content"] * 3)
    store.ingest(incoming, incoming["updated_at"])
    row = store.pending(1, LATER)[0]
    prepared = store.prepare_candidate(row, result or analysis(), DATE)
    data = prepared["payload"]
    with store.db:
        store.db.execute("INSERT INTO stories VALUES(?,?,?,?,?)", (data["id"], prepared["cluster_key"],
                         json.dumps(data), data["published_at"], data["updated_at"]))
        store.db.execute("UPDATE items SET status='published',story_id=? WHERE id=?", (data["id"], row["id"]))
    return incoming, data["id"]


def test_approved_exact_candidate_commits_and_keeps_private_complete_audit(context):
    """Publish reviewed text and retain both stages with their evidence privately."""
    cfg, store = context
    row = pending(store)
    writer, checker = Writer(), Reviewer(verdict())
    result = run(cfg, store, row, writer, checker)
    assert result == {"status": "published", "writer_calls": 1, "review_calls": 2, "cache_hit": False}
    assert job(store) is None
    assert store.stories()[0]["summary"] == checker.calls[0][0]["summary"]
    saved = store.db.execute("SELECT result,review_record FROM analyses").fetchone()
    audit = json.loads(saved[1])
    assert json.loads(saved[0]) == analysis() and audit["writer"] == {"key": cache_key(row, cfg["llm"])}
    assert audit["prepared"]["packet"]["sources"]
    assert [r["stage"] for r in audit["reviews"]] == ["review", "verification"] and audit["outcome"] == "approved"


def test_a_new_story_is_dated_when_the_review_commits_not_when_the_item_started(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    # The item starts before midnight; the review returns and commits after it.
    monkeypatch.setattr(review_gate, "now_iso", lambda: "2026-11-11T00:01:00Z")
    review_gate.process_item(cfg, store, row, Writer(), Reviewer(verdict()), "2026-11-10T23:59:00Z")
    assert store.stories()[0]["added_at"] == "2026-11-11T00:01:00Z"


@pytest.mark.parametrize("failure", [AnalysisError("timeout", retryable=True), {}])
def test_review_timeout_or_malformed_verdict_resumes_without_regenerating_writer(context, failure):
    """Resume the unfinished review while retaining its already completed writer draft."""
    cfg, store = context
    row = pending(store)
    writer, checker = Writer(), Reviewer(failure)
    with pytest.raises(AnalysisError) as caught:
        run(cfg, store, row, writer, checker)
    # A timeout backs off; a malformed verdict is one of the item's three strikes.
    assert caught.value.retryable == isinstance(failure, AnalysisError) and job(store)["stage"] == "review"
    assert len(store.stories()) == 0
    paused = Reviewer(verdict())
    assert run(cfg, store, row, Writer(), paused, allow_network=False)["status"] == "deferred"
    assert paused.calls == [] and job(store)["stage"] == "review"
    next_writer, next_checker = Writer(), Reviewer(verdict())
    result = run(cfg, store, row, next_writer, next_checker)
    assert result["status"] == "published" and result["writer_calls"] == 0
    assert next_writer.calls == [] and len(next_checker.calls) == 2


def test_repair_requires_fresh_verification_and_resumes_that_exact_stage(context):
    cfg, store = context
    row = pending(store)
    writer = Writer(analysis(why_it_matters="Operators must edit their relay configuration."))
    first = Reviewer(verdict("revise", repair={"why_it_matters": ""}), AnalysisError("timeout", retryable=True))
    with pytest.raises(AnalysisError):
        run(cfg, store, row, writer, first)
    assert [call[2] for call in first.calls] == [False, True]
    assert job(store)["stage"] == "verify" and len(store.stories()) == 0
    repaired = first.calls[1][0]
    assert repaired["why_it_matters"] == ""
    second = Reviewer(verdict())
    result = run(cfg, store, row, Writer(), second)
    assert result["writer_calls"] == 0 and result["review_calls"] == 1
    assert second.calls == [(repaired, first.calls[1][1], True)]
    audit = json.loads(store.db.execute("SELECT review_record FROM analyses").fetchone()[0])
    assert [entry["stage"] for entry in audit["reviews"]] == ["review", "verification"]


def failing(action, *criteria, repair=None):
    """A reply in which each named criterion fails."""
    reply = verdict(action, repair=repair, criterion=criteria[0])
    for name in criteria[1:]:
        reply["criteria"][name].update(reason="The source does not support this claim.", outcome="fail")
    return reply


def audit(store):
    return json.loads(store.db.execute("SELECT review_record FROM analyses ORDER BY rowid DESC").fetchone()[0])


def codes(store, row):
    return [entry["code"] for entry in decisions.for_item(store.db, row["id"])]


def test_verification_repairs_are_verified_fresh_until_one_approves(context):
    """A verification that refuses proposes its own repair, and each repaired text gets another fresh verification."""
    cfg, store = context
    row = pending(store)
    checker = Reviewer(verdict(), verdict("revise", repair={"summary": "A first repair."}),
                       verdict("revise", repair={"summary": "A second repair."}), verdict())
    result = run(cfg, store, row, Writer(), checker)
    assert result == {"status": "published", "writer_calls": 1, "review_calls": 4, "cache_hit": False}
    assert [call[2] for call in checker.calls] == [False, True, True, True]
    # Each verification receives only the latest text, with the same packet and coverage.
    assert [call[0]["summary"] for call in checker.calls[1:]] == [checker.calls[0][0]["summary"], "A first repair.", "A second repair."]
    assert all(call[1] == checker.calls[0][1] for call in checker.calls) and all(c == checker.coverages[0] for c in checker.coverages)
    assert store.stories()[0]["summary"] == "A second repair."
    assert [entry["stage"] for entry in audit(store)["reviews"]] == ["review", "verification", "verification", "verification"]
    assert audit(store)["outcome"] == "approved"


@pytest.mark.parametrize("case", ["hold", "revise-without-repair", "repeated-text", "tag-notice"])
def test_verification_refusal_that_cannot_be_repaired_holds(context, case):
    """Each holds with its own code. A repeated text, which the chain refused once already, costs no further request."""
    cfg, store = context
    tag = item(url="https://example.org/tags/tor-0.4.9.16", title="tor-0.4.9.16", kind="tag", content="")
    incoming, draft = (tag, tag_notice(tag)) if case == "tag-notice" else (item(), analysis())
    first = verdict() if case == "tag-notice" else verdict("revise", repair={"summary": "A shorter summary."})
    second, reason = {"hold": (verdict("hold"), "model_hold"),
                      "revise-without-repair": (verdict("revise"), "unusable_repair"),
                      "repeated-text": (verdict("revise", repair={"summary": analysis()["summary"]}), "repeated_repair"),
                      "tag-notice": (verdict("revise", repair={"title": "Tor 0.4.9.16 released"}), "tag_repair")}[case]
    row = pending(store, incoming)
    result = run(cfg, store, row, Writer(draft), Reviewer(first, second))
    assert result["status"] == "held" and result["review_calls"] == 2
    assert store.pending_count() == 0 and store.rejected_count() == 1 and store.stories() == [] and job(store)["stage"] == "held"
    assert store.db.execute("SELECT last_error FROM items").fetchone()[0] == "Final review held: " + review_gate.HOLDS[reason]
    assert codes(store, row) == ["held.verification." + reason]
    assert (audit(store)["outcome"], audit(store)["hold_code"], len(audit(store)["reviews"])) == ("held", reason, 2)
    assert audit(store)["verified_facts"] is False  # the verification failed a factual criterion


def test_verification_repairs_stop_after_five_and_the_count_survives_interruption(context):
    cfg, store = context
    row = pending(store)
    repairs = [verdict("revise", repair={"summary": f"Repair number {n}."}) for n in range(7)]
    # The critique and three verifications each propose a repair; the fourth verification times out.
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(*repairs[:4], AnalysisError("timeout", retryable=True)))
    assert job(store)["stage"] == "verify"
    writer, checker = Writer(), Reviewer(*repairs[4:])
    result = run(cfg, store, row, writer, checker)
    assert result["status"] == "held" and result["writer_calls"] == 0 and result["review_calls"] == 3
    assert writer.calls == [] and [call[2] for call in checker.calls] == [True, True, True]
    assert codes(store, row) == ["held.verification.repairs_exhausted"] and store.stories() == []
    # Seven reviews: the critique and six verifications. The sixth verification's repair is never applied.
    shown = rejection.show_item(store, row["id"])["final_review"]
    assert shown["hold_code"] == "repairs_exhausted" and shown["candidate"]["summary"] == "Repair number 5."
    assert shown["base_candidate"]["summary"] == analysis()["summary"]
    assert [(entry["phase"], entry["verdict"]) for entry in shown["reviews"]] == [("review", "revise")] + [("verification", "revise")] * 6
    assert all(entry["failed"] == {"operational_advice": "fail: The source does not support this claim."} for entry in shown["reviews"])
    assert [entry["repair"]["summary"] for entry in shown["reviews"]] == [f"Repair number {n}." for n in range(7)]


@pytest.mark.parametrize("replies,status", [
    ([verdict(), verdict("skip", criterion="news_value")], "held"),
    ([failing("revise", "news_value", "operational_advice", repair={"summary": "A shorter summary."}), verdict()], "held"),
    ([verdict(), failing("revise", "news_value", "operational_advice", repair={"summary": "A shorter summary."})], "held"),
    ([failing("revise", "news_value", "operational_advice", repair={"summary": "A shorter summary."}),
      verdict("skip", criterion="news_value")], "ignored"),
], ids=["approve-then-skip", "not-news-repair-then-approve", "approve-then-not-news-revise", "both-not-news"])
def test_reviews_that_disagree_on_news_value_hold(context, replies, status):
    """A verification that disagrees with the first review on whether news value and new information both pass
    holds the item, either way and whatever its verdict; reviews that agree the item is not news skip it."""
    cfg, store = context
    row = pending(store)
    result = run(cfg, store, row, Writer(), Reviewer(*replies))
    assert (result["status"], result["review_calls"]) == (status, 2) and store.stories() == []
    assert store.db.execute("SELECT last_error FROM items").fetchone()[0] == (
        "Final review held: the reviews disagree on news value" if status == "held" else "Final review skipped: news_value")
    assert codes(store, row) == (["held.verification.disagreed_news"] if status == "held" else ["skipped.verification.news_value"])


OFFICIAL = {"authority": "official", "kind": "feed"}
COVERED = {"url": "https://example.org/covered-story", "content": "Earlier distinct report."}
COVERED_ID = digest(item_cluster(item(**COVERED)))[:24]


def duplicate_skip(*extra_criteria):
    reply = failing("skip", "new_information", *extra_criteria)
    reply["criteria"]["new_information"]["reason"] = f"Already covered in {COVERED_ID}."
    return reply


@pytest.mark.parametrize("source,replies,status,code", [
    (OFFICIAL, [verdict("skip", criterion="news_value")] * 2, "held", "held.verification.official_not_news"),
    (OFFICIAL, [verdict("skip", criterion="news_value"),
                failing("revise", "news_value", "operational_advice", repair={"summary": "A shorter summary."}),
                verdict("skip", criterion="news_value")], "held", "held.verification.official_not_news"),
    (OFFICIAL, [verdict("revise", criterion="news_value"), verdict("skip", criterion="news_value")],
     "held", "held.verification.official_not_news"),
    (OFFICIAL, [verdict("revise", criterion="news_value"), failing("revise", "news_value", "operational_advice")],
     "held", "held.verification.unusable_repair"),
    (OFFICIAL, [duplicate_skip()], "ignored", "skipped.review.new_information"),
    (OFFICIAL, [duplicate_skip("news_value")], "ignored", "skipped.review.new_information_and_news_value"),
    (OFFICIAL, [{**verdict("skip", criterion="news_value"),
                 "criteria": {**verdict("skip", criterion="news_value")["criteria"],
                              "new_information": {"reason": "Coverage is truncated.", "source_refs": [], "outcome": "insufficient"}}}],
     "held", "held.review.model_hold"),
    # Neither review finds the item news, so the verification's finding that it is covered already stands.
    (OFFICIAL, [verdict("skip", criterion="news_value"), duplicate_skip()],
     "ignored", "skipped.verification.new_information"),
    ({}, [verdict("skip", criterion="news_value")], "ignored", "skipped.review.news_value"),
    ({**OFFICIAL, "kind": "tag", "title": "tor-0.4.9.16", "content": ""}, [verdict("skip", criterion="news_value")],
     "ignored", "skipped.review.news_value"),
], ids=["official-feed-news_value", "official-feed-fact-repair", "official-feed-no-usable-repair",
        "official-feed-verification-without-a-usable-repair", "official-feed-new_information-only",
        "official-feed-both", "official-feed-uncertain-novelty", "official-feed-then-duplicate",
        "development-item", "official-tag"])
def test_official_item_failing_news_value_is_held_not_skipped(context, source, replies, status, code):
    """Only news value failing on an official item other than a tag holds it, after a fresh verification passed
    its facts (repairing them first if needed, unless a verification's repair cannot be applied); a duplicate still skips."""
    cfg, store = context
    _, covered_id = seed_legacy(store, item(**COVERED))
    assert covered_id == COVERED_ID
    row = pending(store, item(**source))
    checker = Reviewer(*replies)
    result = run(cfg, store, row, Writer(), checker)
    assert (result["status"], result["review_calls"]) == (status, len(replies)) and codes(store, row) == [code]
    if status == "ignored":
        assert review._skip_stands(audit(store)["reviews"][-1]["result"]["criteria"], checker.coverages[-1])
    if status == "held":
        reason = code.rsplit(".", 1)[1]
        assert [call[2] for call in checker.calls] == [False] + [True] * (len(replies) - 1)
        assert (audit(store)["hold_code"], audit(store)["verified_facts"]) == (reason, reason == "official_not_news")
        assert store.db.execute("SELECT last_error FROM items WHERE id=?", (row["id"],)).fetchone()[0] == (
            "Final review held: " + review_gate.HOLDS[reason])


def test_a_hold_whose_verification_cites_no_source_does_not_record_verified_facts(context):
    cfg, store = context
    uncited = verdict("skip", criterion="news_value")
    uncited["criteria"]["source_support"]["source_refs"] = []
    row = pending(store, item(**OFFICIAL))
    assert run(cfg, store, row, Writer(), Reviewer(verdict("skip", criterion="news_value"), uncited))["status"] == "held"
    assert (audit(store)["hold_code"], audit(store)["verified_facts"]) == ("official_not_news", False)


@pytest.mark.parametrize("draft,replies,flags,status,code", [
    ({"category": "release", "tags": ["release"]},
     [verdict(), verdict("revise", repair={"category": "security", "tags": ["security"]}, criterion="status"), verdict()],
     [False, False, True], "published", None),
    ({}, [verdict(), verdict("revise", repair={"category": "release"}), verdict(),
          verdict("revise", repair={"category": "feature", "tags": ["feature"]}, criterion="status"), verdict()],
     [False, True, True, False, True], "published", None),
    ({"category": "release", "tags": ["release"]}, [verdict(), verdict()], [False, False], "held", "held.review.release_labels"),
    ({"category": "release", "tags": ["release"]}, [verdict(), verdict("revise", repair={"summary": "A shorter summary."})],
     [False, False], "held", "held.review.release_labels"),
    ({"category": "release", "tags": ["release"]}, [verdict(), verdict("hold", criterion="status")],
     [False, False], "held", "held.review.release_labels"),
    ({"category": "release", "tags": ["release"]}, [verdict(), verdict("skip", criterion="news_value")],
     [False, False], "held", "held.review.disagreed_news"),
], ids=["repaired", "introduced-by-a-verification", "unfixed", "left-by-a-repair", "held-by-the-request", "disagreed-by-the-request"])
def test_release_labels_on_an_unreleased_story_get_a_repair_request_then_a_fresh_verification(context, draft, replies, flags, status, code):
    """An approval of release labels on a state that is not released or tagged asks a review to repair them, naming
    the problem, and a fresh verification checks the repair; labels the request leaves in place, or holds, hold."""
    cfg, store = context
    row = pending(store)
    checker = Reviewer(*replies)
    result = run(cfg, store, row, Writer(analysis(**draft)), checker)
    assert result["status"] == status and [call[2] for call in checker.calls] == flags
    repair = flags.index(False, 1)  # the repair request
    assert checker.issues == [review.RELEASE_ISSUE if n == repair else None for n in range(len(flags))]
    assert audit(store)["reviews"][repair]["issue"] == "release_labels"
    if status == "published":
        assert store.stories()[0]["category"] != "release" and "release" not in store.stories()[0]["tags"]
    else:
        assert codes(store, row) == [code] and audit(store)["verified_facts"] is False


FIVE_REPAIRS = [verdict("revise", repair={"summary": f"Repair number {n}."}) for n in range(5)]


@pytest.mark.parametrize("replies,code", [
    # A request after the sixth review would leave no verification for its repair.
    ([verdict("revise", repair={"summary": "A first repair."}), *FIVE_REPAIRS[:4], verdict()], "held.verification.release_labels"),
    ([verdict("revise", repair={"summary": "A first repair."}), *FIVE_REPAIRS, verdict()], "held.verification.release_labels"),
    ([verdict(), verdict("revise", repair={"category": "security", "tags": ["security"]}, criterion="status"), *FIVE_REPAIRS],
     "held.verification.repairs_exhausted"),
], ids=["labels-approved-after-four-repairs", "labels-approved-after-five-repairs", "after-a-release-label-request"])
def test_an_item_gets_at_most_seven_review_requests(context, replies, code):
    """At most five repairs follow the first review, a release-label repair request counting as one."""
    cfg, store = context
    row = pending(store)
    result = run(cfg, store, row, Writer(analysis(category="release", tags=["release"])), Reviewer(*replies))
    assert (result["status"], result["review_calls"]) == ("held", len(replies)) and codes(store, row) == [code]


def test_a_decision_after_several_repairs_resumes_from_its_receipt_without_a_model_call(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    commit = store.commit_candidate
    monkeypatch.setattr(store, "commit_candidate", lambda *args, **kw: (_ for _ in ()).throw(RuntimeError("simulated crash before commit")))
    checker = Reviewer(verdict("revise", repair={"summary": "A first repair."}),
                       verdict("revise", repair={"summary": "A second repair."}), verdict())
    with pytest.raises(RuntimeError, match="simulated crash"):
        run(cfg, store, row, Writer(), checker)
    monkeypatch.setattr(store, "commit_candidate", commit)
    writer, resumed = Writer(), Reviewer()
    result = run(cfg, store, row, writer, resumed, allow_network=False)
    assert result["status"] == "published" and result["cache_hit"] and writer.calls == resumed.calls == []
    assert store.stories()[0]["summary"] == "A second repair."


@pytest.mark.parametrize("column", ["draft_json", "envelope_json", "record_json"])
@pytest.mark.parametrize("kind", DAMAGE)
def test_a_damaged_review_job_fails_the_item_and_is_never_reviewed_afresh(context, column, kind):
    cfg, store = context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(verdict(), AnalysisError("timeout", retryable=True)))
    with store.db:
        store.db.execute(f"UPDATE review_jobs SET {column}=CAST(? AS TEXT)", (damaged(job(store)[column], kind),))
    writer, checker = Writer(), Reviewer()
    with pytest.raises(AnalysisError, match="Saved review job is damaged") as caught:
        run(cfg, store, row, writer, checker)
    assert (caught.value.retryable, caught.value.code) == (False, "app.damaged_job") and writer.calls == checker.calls == []


def test_a_damaged_review_job_never_stops_the_run(context, monkeypatch):
    from onionflash import cli
    cfg, store = context
    cfg["sources"] = []
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(AnalysisError("timeout", retryable=True)))
    with store.db:
        store.db.execute("UPDATE review_jobs SET record_json=CAST(? AS TEXT)", (b'{"\xff"',))
    monkeypatch.setattr(cli, "build", lambda *args: {})
    for _ in range(3):  # three failures reject it
        assert cli.run(cfg, store)["analysis_failed"] == 1
        with store.db:
            store.db.execute("UPDATE items SET next_attempt_at=NULL")
    assert tuple(store.db.execute("SELECT status,last_error FROM items").fetchone()) == ("rejected", "Saved review job is damaged")
    assert codes(store, row) == ["failed.app.damaged_job"]


@pytest.mark.parametrize("draft,stage", [({}, "verify"), ({"category": "release", "tags": ["release"]}, "repair")])
def test_pending_resumes_an_unfinished_verification_or_repair_before_new_work(context, draft, stage):
    cfg, store = context
    store.ingest(item(), DATE)
    store.ingest(item(url="https://example.org/routine", title="A routine report", labels=[]), DATE)
    first, routine = store.pending(2, LATER)
    assert routine["url"].endswith("/routine")  # it sorts after the security report
    with pytest.raises(AnalysisError):
        run(cfg, store, routine, Writer(analysis(**draft)), Reviewer(verdict(), AnalysisError("timeout", retryable=True)))
    assert job(store)["stage"] == stage
    assert [row["url"] for row in store.pending(2, LATER)] == [routine["url"], first["url"]]


@pytest.mark.parametrize("repair", [None, {"title": analysis()["title"]}, {"title": ""}],
                         ids=["missing", "unchanged", "invalid"])
def test_unusable_repair_holds_after_one_call_for_operator_inspection(context, repair):
    cfg, store = context
    row = pending(store)
    result = run(cfg, store, row, Writer(), Reviewer(verdict("revise", repair=repair)))
    assert result["status"] == "held" and result["review_calls"] == 1
    assert [entry["id"] for entry in rejection.list_items(store)["items"]] == [row["id"]]
    assert rejection.show_item(store, row["id"])["final_review"]["latest_review"]["verdict"] == "revise"


@pytest.mark.parametrize("decision", ["approve", "skip"])
def test_completed_decision_resumes_after_crash_without_any_model_call(context, monkeypatch, decision):
    cfg, store = context
    row = pending(store)
    commit = store.commit_candidate
    monkeypatch.setattr(store, "commit_candidate", lambda *args, **kw: (_ for _ in ()).throw(RuntimeError("simulated crash before commit")))
    with pytest.raises(RuntimeError, match="simulated crash"):
        run(cfg, store, row, Writer(), Reviewer(verdict(decision, criterion="news_value")))
    assert job(store)["stage"] == ("approved" if decision == "approve" else "skipped") and len(store.stories()) == 0
    store.defer(row["id"], "Unexpected RuntimeError", cfg["llm"], LATER, terminal=True)  # as the run loop does
    row = dict(store.db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone())
    monkeypatch.setattr(store, "commit_candidate", commit)
    # Another item's commit leaves the receipt that this job pins.
    store.ingest(item(url="https://example.org/other-report", content="A routine reply."), DATE)
    other = dict(store.db.execute("SELECT * FROM items WHERE url=?", ("https://example.org/other-report",)).fetchone())
    assert run(cfg, store, other, Writer(), Reviewer(verdict("skip", criterion="news_value")))["status"] == "ignored"
    writer, checker = Writer(), Reviewer()
    result = run(cfg, store, row, writer, checker, allow_network=False)
    assert result["status"] == ("published" if decision == "approve" else "ignored") and result["cache_hit"]
    assert writer.calls == checker.calls == [] and job(store) is None
    assert len(store.stories()) == (1 if decision == "approve" else 0)
    assert not store.db.execute("SELECT 1 FROM review_approvals").fetchone()


@pytest.mark.parametrize("receipt", ["damaged", "missing"])
def test_a_recorded_decision_without_a_usable_receipt_reviews_the_draft_again(context, monkeypatch, receipt):
    """Nothing shows that the repaired text was verified, so the review starts again from the writer's draft."""
    cfg, store = context
    row = pending(store)
    commit = store.commit_candidate
    monkeypatch.setattr(store, "commit_candidate", lambda *args, **kw: (_ for _ in ()).throw(RuntimeError("simulated crash before commit")))
    first = Reviewer(verdict("revise", repair={"why_it_matters": ""}), verdict())
    with pytest.raises(RuntimeError, match="simulated crash"):
        run(cfg, store, row, Writer(analysis(why_it_matters="Operators must edit their relay configuration.")), first)
    monkeypatch.setattr(store, "commit_candidate", commit)
    with store.db:
        store.db.execute("UPDATE review_approvals SET review_record_json='{'" if receipt == "damaged" else "DELETE FROM review_approvals")
    checker = Reviewer(verdict())
    assert run(cfg, store, row, Writer(), checker)["status"] == "published"
    assert [call[0] for call in checker.calls] == [first.calls[0][0]] * 2
    audit = json.loads(store.db.execute("SELECT review_record FROM analyses").fetchone()[0])
    assert [entry["stage"] for entry in audit["reviews"]] == ["review", "verification"]


FINAL_CHECKS = {  # the source and the draft that fail each final check
    "completed_action": ({}, {"title": "Tor authority bastet removed from source after reported compromise"}),
    "compromise_headline": ({}, {"title": "Bastet directory authority compromised"}),
    "confirmed_source": ({}, {"confidence": "confirmed"}),
    "merge_state": ({"kind": "gitlab_mr", "upstream_state": "merged"}, {"state": "released"}),
}


@pytest.mark.parametrize("reason", FINAL_CHECKS)
def test_verified_approval_failing_a_final_check_is_held_with_its_code(context, reason):
    """The check runs on the verified text before any receipt; a skip is not checked."""
    cfg, store = context
    source, draft = FINAL_CHECKS[reason]
    row = pending(store, item(**source))
    result = run(cfg, store, row, Writer(analysis(**draft)), Reviewer(verdict()))
    assert result["status"] == "held" and result["review_calls"] == 2
    assert store.db.execute("SELECT last_error FROM items").fetchone()[0] == "Final review held: " + review_gate.HOLDS[reason]
    assert [entry["code"] for entry in decisions.for_item(store.db, row["id"])] == [f"held.final_check.{reason}"]
    assert store.stories() == [] and not store.db.execute("SELECT 1 FROM review_approvals").fetchone()
    other = pending(store, item(**source, url="https://example.org/news/2"))
    assert run(cfg, store, other, Writer(analysis(**draft)), Reviewer(verdict("skip", criterion="news_value")))["status"] == "ignored"


def test_a_resumed_approval_is_checked_again_without_a_model_call(context, monkeypatch):
    """An approval saved before a commit that did not happen is checked when it is reused."""
    cfg, store = context
    row = pending(store)
    commit, check = store.commit_candidate, review.final_holds
    monkeypatch.setattr(store, "commit_candidate", lambda *args, **kw: (_ for _ in ()).throw(RuntimeError("simulated crash before commit")))
    monkeypatch.setattr(review, "final_holds", lambda candidate, prepared: [])
    with pytest.raises(RuntimeError, match="simulated crash"):
        run(cfg, store, row, Writer(analysis(confidence="confirmed")), Reviewer(verdict()))
    monkeypatch.setattr(store, "commit_candidate", commit)
    monkeypatch.setattr(review, "final_holds", check)
    writer, checker = Writer(), Reviewer()
    result = run(cfg, store, row, writer, checker, allow_network=False)
    assert result["status"] == "held" and result["cache_hit"] and writer.calls == checker.calls == []
    assert [entry["code"] for entry in decisions.for_item(store.db, row["id"])] == ["held.final_check.confirmed_source"]
    assert rejection.show_item(store, row["id"])["final_review"]["latest_review"]["verdict"] == "approve"


def test_changed_source_invalidates_staged_draft_and_prior_approval(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(AnalysisError("timeout", retryable=True)))
    incoming = item(content=item()["content"] + " A later source correction.", updated_at=LATER)
    store.ingest(incoming, LATER)
    changed = store.pending(1, LATER)[0]
    assert changed["content_hash"] != row["content_hash"]
    writer = Writer()
    result = run(cfg, store, changed, writer, Reviewer(verdict()))
    assert result["writer_calls"] == 1 and len(writer.calls) == 1


def test_policy_change_reuses_writer_but_requires_a_new_review(context):
    """Invalidate review approval on policy change without discarding the source draft."""
    cfg, store = context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(verdict(), AnalysisError("timeout", retryable=True)))
    cfg["review"]["model"] = "different-review-model"
    result = run(cfg, store, row, Writer(), Reviewer(verdict()))
    assert result["writer_calls"] == 0 and result["review_calls"] == 2 and not result["cache_hit"]


def test_update_review_repairs_only_the_new_entry_and_commits_the_verified_repair(context):
    cfg, store = context
    prior_why = "The report requests removal of the old directory-authority keys."
    original = item(content=item()["content"] * 3, updated_at="2026-11-09T12:00:00Z")
    seed_legacy(store, original, analysis(why_it_matters=prior_why))
    incoming = item(url="https://example.org/news/mirror", source_id="mirror", content=original["content"])
    row = pending(store, incoming)
    checker = Reviewer(
        verdict("revise", repair={"update": "A second mirror reported the key issue."}, update=True),
        verdict(update=True),
    )
    draft = update_analysis(update="Operators must reconfigure now; a second mirror reported the key issue.")
    result = run(cfg, store, row, Writer(draft), checker)
    reviewed, evidence, _ = checker.calls[0]
    passages = [p["text"] for source in evidence["sources"] for p in source["passages"]]
    assert reviewed["why_it_matters"] == prior_why and len(evidence["sources"]) == 2
    assert original["content"] in passages and not any(prior_why in text for text in passages)
    assert result["status"] == "published"
    story = store.stories()[0]
    assert story["why_it_matters"] == prior_why
    assert story["updates"] == [{"at": incoming["updated_at"], "text": "A second mirror reported the key issue.",
                                 "sources": [{"url": incoming["url"], "title": incoming["title"]}]}]
    assert len(store.stories()) == 1


def test_human_lock_during_review_preserves_operator_text(context):
    cfg, store = context
    original, story_id = seed_legacy(store)
    row = pending(store, {**original, "content": original["content"] + " A later report.", "updated_at": LATER})
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(AnalysisError("timeout", retryable=True)))
    editorial.correct(store.db, story_id, {"why_it_matters": "Operator-reviewed wording."},
                      reason="Corrected unsupported advice.", expect_hash=editorial.show(store.db, story_id)["hash"], observed=LATER)
    second = run(cfg, store, row, Writer(), Reviewer(), allow_network=False)
    assert second["status"] == "locked" and second["writer_calls"] == second["review_calls"] == 0
    assert store.stories()[0]["why_it_matters"] == "Operator-reviewed wording."


def test_tag_update_holds_on_repair_and_keeps_prose_on_approval(context):
    """A tag cites tagged/released stories directly, and updates merged stories without allowing tag_repair."""
    cfg, store = context
    original = item(title="Tor 0.4.9.16 released", kind="feed", content="Tor 0.4.9.16 was released with an announced change.")
    seed_legacy(store, original, analysis(title="Tor release announcement", state="tagged"))
    tag = item(url="https://example.org/tags/tor-0.4.9.16", title="tor-0.4.9.16", kind="tag", content="")
    row = pending(store, tag)
    result = run(cfg, store, row, Writer(), Reviewer())
    assert result["status"] == "cited" and result["writer_calls"] == 0 and result["review_calls"] == 0
    story = store.stories()[0]
    assert story["title"] == "Tor release announcement" and "updates" not in story and len(story["sources"]) == 2

    merged_item = item(
        url="https://example.org/mr/0.4.9.17",
        title="Tor 0.4.9.17 release branch merged",
        kind="feed",
        content="Release preparation branch for Tor 0.4.9.17 merged.",
    )
    seed_legacy(store, merged_item, analysis(title="Tor 0.4.9.17 branch merged", state="merged", category="release", tags=["tor", "release"]))
    merged_story = next(s for s in store.stories() if "0.4.9.17" in s["title"])
    tag17 = item(url="https://example.org/tags/tor-0.4.9.17", title="tor-0.4.9.17", kind="tag", content="", updated_at=LATER)
    row17 = pending(store, tag17)
    lit17 = update_analysis(
        update="The upstream feed lists the tag “tor-0.4.9.17”.",
        state="tagged",
        confidence=merged_story["confidence"],
        evidence=["tor-0.4.9.17"],
    )
    held17 = run(
        cfg,
        store,
        row17,
        Writer(lit17),
        Reviewer(verdict("revise", update=True, repair={"state": "released"})),
    )
    assert held17["status"] == "held" and held17["review_calls"] == 1
    assert store.db.execute("SELECT last_error FROM items WHERE id=?", (row17["id"],)).fetchone()[0] == (
        "Final review held: review proposed editing a literal tag notice"
    )

    tag17b = item(url="https://example.org/tags/tor-0.4.9.17-mirror", title="tor-0.4.9.17", kind="tag", content="", updated_at=LATER)
    row17b = pending(store, tag17b)
    ok17 = run(cfg, store, row17b, Writer(lit17), Reviewer(verdict(update=True), verdict(update=True)))
    assert ok17["status"] == "published"
    updated17 = next(s for s in store.stories() if s["id"] == merged_story["id"])
    assert updated17["title"] == "Tor 0.4.9.17 branch merged"
    assert updated17["state"] == "tagged"
    assert updated17["updates"][-1]["text"] == "The upstream feed lists the tag “tor-0.4.9.17”."


def test_tag_draft_requires_final_review_and_waits_when_network_is_disabled(context):
    """Defer an unreviewed tag until both publication reviews can run."""
    cfg, store = context
    tag = item(title="tor-0.4.9.16", kind="tag", content="")
    row = pending(store, tag)
    checker = Reviewer()
    result = run(cfg, store, row, Writer(tag_notice(tag)), checker, allow_network=False)
    assert result["status"] == "deferred" and checker.calls == []
    assert result["writer_calls"] == 0 and store.stories() == []
    reviewed = run(cfg, store, row, Writer(tag_notice(tag)), Reviewer(verdict()))
    assert reviewed["status"] == "published" and reviewed["writer_calls"] == 0 and reviewed["review_calls"] == 2


def test_tag_notice_stays_literal_when_review_proposes_a_repair(context):
    """Hold a tag notice that review would edit, even when verification would approve the edit."""
    cfg, store = context
    tag = item(title="tor-0.4.9.16", kind="tag", content="")
    row = pending(store, tag)
    checker = Reviewer(verdict("revise", repair={"title": "Tor 0.4.9.16 released", "state": "released"}), verdict())
    result = run(cfg, store, row, Writer(tag_notice(tag)), checker)
    assert result["status"] == "held" and result["review_calls"] == 1 and store.stories() == []
    assert store.db.execute("SELECT last_error FROM items").fetchone()[0] == "Final review held: review proposed editing a literal tag notice"


def test_network_disabled_defers_new_network_work_without_failure(context):
    cfg, store = context
    row = pending(store)
    writer, checker = Writer(), Reviewer()
    result = run(cfg, store, row, writer, checker, allow_network=False)
    assert result["status"] == "deferred" and writer.calls == checker.calls == []
    assert store.pending_count() == 1 and store.rejected_count() == 0


def test_missing_retained_source_holds_without_a_review_call(context):
    cfg, store = context
    original = item(content=item()["content"] * 3, updated_at="2026-11-09T12:00:00Z")
    seed_legacy(store, original)
    with store.db:
        body = json.loads(store.db.execute("SELECT payload FROM items WHERE id=?", (original["id"],)).fetchone()[0])
        body.pop("content")
        store.db.execute("UPDATE items SET payload=? WHERE id=?", (json.dumps(body), original["id"]))
    row = pending(store, item(url="https://example.org/news/mirror", source_id="mirror", content=original["content"]))
    result = run(cfg, store, row, Writer(), Reviewer())
    assert result["status"] == "held" and result["review_calls"] == 0
    assert store.db.execute("SELECT status FROM items WHERE id=?", (original["id"],)).fetchone()[0] == "published"


@pytest.mark.parametrize("cached", [{"verdict": "approve"}, verdict("hold")], ids=["incomplete-approval", "hold"])
def test_cache_reviews_again_unless_the_receipt_is_a_complete_decision(context, cached):
    """Neither an incomplete approval nor a cached hold can stand in for a fresh review."""
    cfg, store = context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(AnalysisError("timeout", retryable=True)))
    saved = job(store)
    approve(store, json.loads(saved["envelope_json"]), policy=saved["policy_hash"], result=cached)
    result = run(cfg, store, row, Writer(), Reviewer(verdict()))
    assert result["review_calls"] == 2 and not result["cache_hit"]


def test_cache_pruning_retains_active_approval_jobs(context, monkeypatch):
    cfg, store = context
    monkeypatch.setattr(review_gate, "MAX_APPROVALS", 1)
    row = pending(store)
    monkeypatch.setattr(store, "commit_candidate", lambda *args, **kw: (_ for _ in ()).throw(RuntimeError("crash")))
    with pytest.raises(RuntimeError):
        run(cfg, store, row, Writer(), Reviewer(verdict()))
    active = job(store)["approval_key"]
    with store.db:
        for n in range(3):
            store.db.execute("INSERT INTO review_approvals VALUES(?,?,?,?,?,?,?,?,?)", (
                f"unused-{n}", "c", "s", "p", "b", "{}", "{}", DATE, DATE))
    review_gate._prune(store, 1)
    assert store.db.execute("SELECT 1 FROM review_approvals WHERE key=?", (active,)).fetchone()
    assert store.db.execute("SELECT COUNT(*) FROM review_approvals").fetchone()[0] == 2
    assert job(store)["stage"] == "approved"


def test_status_reads_stage_counts_without_exposing_audit(context):
    cfg, store = context
    assert review_gate.status(store) == {"stages": {}, "approval_cache_entries": 0}
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(AnalysisError("timeout", retryable=True)))
    assert review_gate.status(store) == {"stages": {"review": 1}, "approval_cache_entries": 0}
    run(cfg, store, row, Writer(), Reviewer(verdict("hold")))
    assert review_gate.status(store) == {"stages": {"held": 1}, "approval_cache_entries": 0}


def test_operator_retry_preserves_held_audit_and_reuses_the_completed_draft(context):
    cfg, store = context
    row = pending(store)
    assert run(cfg, store, row, Writer(), Reviewer(verdict("hold")))["status"] == "held"
    assert store.db.execute("SELECT last_error FROM items").fetchone()[0] == "Final review held: review did not approve the candidate"
    rejection.retry_item(store, row["id"], row["content_hash"], "The review prompt was revised", LATER)
    audit = json.loads(store.db.execute("SELECT review_record FROM analyses WHERE cache_key=?",
                                        (cache_key(row, cfg["llm"]),)).fetchone()[0])
    assert audit["outcome"] == "held" and audit["reviews"][0]["result"]["verdict"] == "hold"  # retry keeps it
    assert job(store)["stage"] == "drafted"
    retry = store.pending(1, LATER)[0]
    writer = Writer()
    assert run(cfg, store, retry, writer, Reviewer(verdict()))["status"] == "published"
    assert writer.calls == []
    final = json.loads(store.db.execute("SELECT review_record FROM analyses ORDER BY rowid DESC").fetchone()[0])
    assert final["outcome"] == "approved" and final["writer"] == {"key": cache_key(row, cfg["llm"])}
    shown = rejection.show_item(store, row["id"])["final_review"]
    assert shown["latest_review"]["verdict"] == "approve" and shown["source_packet"]["sources"] and shown["coverage"] is not None


def test_a_source_that_reverts_to_a_held_revision_is_held_again_without_a_review(context):
    cfg, store = context
    assert run(cfg, store, pending(store), Writer(), Reviewer(verdict("hold")))["status"] == "held"
    store.ingest(item(content=item()["content"] + " Edited."), DATE)  # a revision that is never drafted
    assert run(cfg, store, store.pending(1, LATER)[0], Writer(), Reviewer(), allow_network=False)["status"] == "deferred"
    store.ingest(item(), DATE)
    checker = Reviewer(verdict())
    assert run(cfg, store, store.pending(1, LATER)[0], Writer(), checker)["status"] == "held"
    assert checker.calls == []


def test_rejected_show_explains_structured_hold_with_the_actual_candidate_and_passages(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    assert run(cfg, store, row, Writer(), Reviewer(verdict("hold")))["status"] == "held"
    before = list(store.db.iterdump())
    # A hold waits for an operator, so its saved verdict stays readable after a later rubric change.
    monkeypatch.setattr(review, "CRITERIA", (*review.CRITERIA, "a_later_criterion"))
    shown = rejection.show_item(store, row["id"])["final_review"]
    assert shown["stage"] == "held"
    assert shown["candidate"]["title"] == analysis()["title"]
    assert shown["latest_review"]["verdict"] == "hold"
    assert shown["latest_review"]["criteria"]["operational_advice"]["outcome"] == "fail"
    assert shown["latest_review"]["criteria"]["operational_advice"]["source_refs"] == ["S1"]
    assert shown["source_packet"]["sources"][0]["passages"][0]["id"] == "S1:P1"
    assert list(store.db.iterdump()) == before


def test_rejected_show_displays_repaired_candidate_pending_independent_verification(context):
    cfg, store = context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(verdict("revise", repair={"why_it_matters": ""}),
                                               AnalysisError("timeout", retryable=True)))
    shown = rejection.show_item(store, row["id"])["final_review"]
    assert shown["stage"] == "verify" and shown["candidate"]["why_it_matters"] == ""
    assert shown["latest_review"]["verdict"] == "revise"
    assert shown["latest_review"]["candidate_hash"] != digest(shown["candidate"])


def test_rejected_show_reads_a_reused_approval_after_an_interrupted_commit(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    monkeypatch.setattr(store, "commit_candidate", lambda *args, **kw: (_ for _ in ()).throw(RuntimeError("simulated crash")))
    with pytest.raises(RuntimeError):
        run(cfg, store, row, Writer(), Reviewer(verdict()))
    with store.db:  # an operator retry starts a new record without reviews of its own
        review_gate.reset_review_work(store, row["id"])
    with pytest.raises(RuntimeError):  # the saved approval is reused, and the commit is interrupted again
        run(cfg, store, row, Writer(), Reviewer())
    shown = rejection.show_item(store, row["id"])["final_review"]
    assert shown["stage"] == "approved" and shown["latest_review"]["verdict"] == "approve"


@pytest.mark.parametrize("kind", [*DAMAGE, "review-not-an-object", "review-without-result"])
def test_rejected_show_and_retry_survive_a_damaged_review_record(context, kind):
    cfg, store = context
    row = pending(store)
    assert run(cfg, store, row, Writer(), Reviewer(verdict("hold")))["status"] == "held"
    # Besides the damaged() kinds, a record can be a valid object of the wrong shape.
    shapes = {"review-not-an-object": b'{"reviews": [1]}', "review-without-result": b'{"reviews": [{"stage": "held"}]}'}
    with store.db:
        value = shapes.get(kind) or damaged(job(store)["record_json"], kind)
        store.db.execute("UPDATE review_jobs SET record_json=CAST(? AS TEXT) WHERE item_id=?", (value, row["id"]))
    shown = rejection.show_item(store, row["id"])
    assert shown["final_review"] == {"stage": "held", "error": "Saved review record cannot be read"}
    assert shown["saved_item"] is not None
    rejection.retry_item(store, row["id"], row["content_hash"], "Retry after inspection", LATER)
    assert job(store)["stage"] == "drafted"


@pytest.mark.parametrize("kind", DAMAGE)
def test_retry_drops_a_damaged_draft_and_the_writer_drafts_again(context, kind):
    cfg, store = context
    row = pending(store)
    assert run(cfg, store, row, Writer(), Reviewer(verdict("hold")))["status"] == "held"
    with store.db:
        store.db.execute("UPDATE review_jobs SET draft_json=CAST(? AS TEXT)", (damaged(job(store)["draft_json"], kind),))
    rejection.retry_item(store, row["id"], row["content_hash"], "Retry after inspection", LATER)
    writer = Writer()
    assert run(cfg, store, store.pending(1, LATER)[0], writer, Reviewer(verdict()))["status"] == "published"
    assert len(writer.calls) == 1


def test_rejected_show_without_a_current_job_stays_read_only(context):
    _, store = context
    row = pending(store)
    before = list(store.db.iterdump())
    assert rejection.show_item(store, row["id"])["final_review"] is None
    assert list(store.db.iterdump()) == before


def test_hold_audit_and_rejection_roll_back_together_if_job_update_fails(context):
    cfg, store = context
    row = pending(store)
    store.db.execute("""CREATE TRIGGER fail_held_job BEFORE UPDATE ON review_jobs
        WHEN NEW.stage='held' BEGIN SELECT RAISE(ABORT,'hold unavailable'); END""")
    store.db.commit()
    with pytest.raises(sqlite3.IntegrityError, match="hold unavailable"):
        run(cfg, store, row, Writer(), Reviewer(verdict("hold")))
    assert store.db.execute("SELECT COUNT(*) FROM analyses").fetchone()[0] == 0
    assert store.pending_count() == 1 and job(store)["stage"] == "review"


def test_approval_receipt_and_job_pin_roll_back_together_if_job_save_fails(context):
    """Persist the receipt and its unfinished-job pin atomically."""
    cfg, store = context
    row = pending(store)
    store.db.execute("""CREATE TRIGGER fail_approved_job BEFORE INSERT ON review_jobs
        WHEN NEW.stage='approved' BEGIN SELECT RAISE(ABORT,'job save unavailable'); END""")
    store.db.commit()
    with pytest.raises(sqlite3.IntegrityError, match="job save unavailable"):
        run(cfg, store, row, Writer(), Reviewer(verdict()))
    assert store.db.execute("SELECT COUNT(*) FROM review_approvals").fetchone()[0] == 0
    assert job(store)["stage"] == "verify" and job(store)["approval_key"] is None
    assert len(store.stories()) == 0
    store.db.execute("DROP TRIGGER fail_approved_job")
    store.db.commit()
    result = run(cfg, store, row, Writer(), Reviewer(verdict()))
    assert result["status"] == "published" and result["writer_calls"] == 0


def test_resuming_approved_job_never_temporarily_unpins_its_receipt(context, monkeypatch):
    cfg, store = context
    monkeypatch.setattr(review_gate, "MAX_APPROVALS", 1)
    row = pending(store)
    commit = store.commit_candidate
    monkeypatch.setattr(store, "commit_candidate", lambda *args, **kw: (_ for _ in ()).throw(RuntimeError("crash before commit")))
    with pytest.raises(RuntimeError):
        run(cfg, store, row, Writer(), Reviewer(verdict()))
    key = job(store)["approval_key"]
    monkeypatch.setattr(store, "commit_candidate", commit)
    save = review_gate._save
    def crash_during_resume(*args, **kwargs):
        save(*args, **kwargs)
        raise RuntimeError("crash after initial resume save")
    monkeypatch.setattr(review_gate, "_save", crash_during_resume)
    with pytest.raises(RuntimeError):
        run(cfg, store, row, Writer(), Reviewer(), allow_network=False)
    assert job(store)["approval_key"] == key
    with store.db:
        store.db.execute("INSERT INTO review_approvals VALUES(?,?,?,?,?,?,?,?,?)", (
            "newer-unused", "c", "s", "p", "b", "{}", "{}", LATER, "2099-01-01T00:00:00Z"))
    review_gate._prune(store, 1)
    assert store.db.execute("SELECT 1 FROM review_approvals WHERE key=?", (key,)).fetchone()
    monkeypatch.setattr(review_gate, "_save", save)
    result = run(cfg, store, row, Writer(), Reviewer(), allow_network=False)
    assert result["status"] == "published" and result["cache_hit"] and result["review_calls"] == 0


def test_a_database_error_during_analysis_is_not_an_item_strike(context, monkeypatch):
    import sqlite3
    from onionflash import cli
    cfg, store = context
    cfg["sources"] = []

    def locked(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(cli, "process_item", locked)
    store.ingest(item(url="https://example.org/locked"), DATE)
    with pytest.raises(sqlite3.OperationalError):
        cli.run(cfg, store)
    assert tuple(store.db.execute("SELECT status,rejections FROM items").fetchone()) == ("pending", 0)


def test_run_report_counts_review_outcomes(context, monkeypatch):
    from onionflash import cli
    cfg, store = context
    cfg["sources"] = []
    outcomes = iter([("held", False), ("stale", False), ("published", True), ("ignored", False), ("ignored", True)])
    monkeypatch.setattr(cli, "process_item", lambda *args, **kwargs: dict(zip(("status", "cache_hit"), next(outcomes))))
    monkeypatch.setattr(cli, "build", lambda *args: {})
    for name in ("one", "two", "three", "four", "five"):
        store.ingest(item(url="https://example.org/" + name), DATE)
    report = cli.run(cfg, store)
    counts = [report[key] for key in ("analyzed", "analysis_failed", "review_stale", "review_cache_hits")]
    # A hold is a decision, not a failure. Holds and skips are counted by code under decisions, and
    # this stand-in for the gate logs none, on a database that has no decisions yet.
    assert counts == [4, 0, 1, 2] and report["decisions"] == {}
    assert "review_held" not in report and "review_skipped" not in report


def test_run_report_counts_the_model_requests_of_items_that_fail(context, monkeypatch):
    from onionflash import analyze, cli
    from onionflash.transport import FetchError, Response
    cfg, store = context
    cfg["sources"] = []
    cfg["llm"]["base_url"] = "https://llm.example/v1"
    monkeypatch.setenv(cfg["llm"]["api_key_env"], "test-key")

    class Transport:  # the writer's requests succeed; every review request fails in transport
        def request(self, method, url, headers=None, json_body=None):
            if json_body["response_format"]["json_schema"]["name"] != "onionflash_news":
                raise FetchError("network request failed", retryable=True)
            body = {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(analysis(why_it_matters=""))}}]}
            return Response(200, json.dumps(body).encode(), {}, url)
        def close(self):
            pass

    monkeypatch.setattr(analyze, "HttpClient", lambda *args, **kwargs: Transport())
    monkeypatch.setattr(cli, "build", lambda *args: {})
    for name in ("one", "two"):
        store.ingest(item(url="https://example.org/" + name), DATE)
    report = cli.run(cfg, store)
    # Each item's writer request and failed review request count.
    assert (report["analysis_failed"], report["model_calls"]) == (2, 4)


def test_unusable_replies_and_drafts_take_strikes_and_the_run_still_builds(context, monkeypatch):
    """Isolate invalid model output so other queued work and the site build continue."""
    from onionflash import cli
    cfg, store = context
    cfg["sources"] = []

    class Drafts:
        calls = 0
        def analyze(self, incoming):
            # Publishing drops U+FFFF, so this draft cannot form a public story.
            return analysis(title="\uffff") if incoming["url"].endswith("/draft") else analysis()

    class Replies:
        calls = 0
        def review(self, candidate, packet, *, coverage=None, verification=False, issue=None):
            """Return malformed replies only for the designated failure fixtures."""
            return review.validate_review({} if "/reply" in packet["sources"][0]["url"] else verdict(), packet)

    built = []
    monkeypatch.setattr(cli, "Analyzer", lambda *args, **kwargs: contextlib.nullcontext(Drafts()))
    monkeypatch.setattr(cli, "Reviewer", lambda *args, **kwargs: contextlib.nullcontext(Replies()))
    monkeypatch.setattr(cli, "build", lambda *args: built.append(True) or {})
    for name in ("reply-1", "reply-2", "draft"):
        store.ingest(item(url="https://example.org/" + name), DATE)
    # No security title or label, so this item sorts after both unusable replies.
    store.ingest(item(url="https://example.org/good", title="A routine report", labels=[]), DATE)
    report = cli.run(cfg, store)
    states = {url.rsplit("/", 1)[1]: (status, rejections, error)
              for url, status, rejections, error in store.db.execute("SELECT url,status,rejections,last_error FROM items")}
    assert built == [True] and report["analysis_failed"] == 3
    status, rejections, error = states.pop("draft")
    assert (status, rejections) == ("pending", 1) and error.startswith("Unexpected ValueError at render.py:")
    assert states == {"reply-1": ("pending", 1, "Review response fields do not match schema"),
                      "reply-2": ("pending", 1, "Review response fields do not match schema"),
                      "good": ("published", 0, None)}


def test_own_item_newness_skips_unchanged_or_quoted_and_unlock_requeues_locked_updates(context):
    from onionflash.comments import _compose

    cfg, store = context
    url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41499"
    n1 = {"id": "gid://gitlab/Note/1", "url": url + "#note_1", "title": "Public comment by @alice",
          "author": "alice", "created_at": DATE, "body": "Initial report details for the relay issue."}
    issue = _compose(item(url=url, updated_at=DATE), [n1], DATE, source_key="k")
    first_row = pending(store, issue)
    assert run(cfg, store, first_row, Writer(analysis(evidence=["Initial report details for the relay issue."])),
               Reviewer(verdict()))["status"] == "published"
    story_id = store.stories()[0]["id"]

    # A reply containing only >-quoted text after DATE has no new unquoted content -> 0 model calls.
    n2 = {"id": "gid://gitlab/Note/2", "url": url + "#note_2", "title": "Public comment by @bob",
          "author": "bob", "created_at": LATER, "body": "> Initial report details for the relay issue.\n> Agreed."}
    assert store.ingest(_compose(issue, [n1, n2], LATER, source_key="k"), LATER)
    w_quote, r_quote = Writer(), Reviewer()
    res_quote = run(cfg, store, store.pending(1, LATER)[0], w_quote, r_quote)
    assert res_quote == {"status": "ignored", "writer_calls": 0, "review_calls": 0, "cache_hit": False}
    assert store.db.execute("SELECT code FROM decision_log ORDER BY id DESC LIMIT 1").fetchone()[0] == "skipped.gate.no_new_content"

    # A re-observed tag on its own tag notice also skips with 0 model calls.
    tag = item(kind="tag", title="tor-0.4.9.99", url="https://example.org/tags/tor-0.4.9.99", content="")
    store.ingest(tag, DATE)
    tag_row = next(r for r in store.pending(5, DATE) if r["id"] == tag["id"])
    assert run(cfg, store, tag_row, Writer(), Reviewer(verdict()))["status"] == "published"
    assert store.ingest({**tag, "content": "new annotation", "updated_at": LATER}, LATER)
    tag_row2 = next(r for r in store.pending(5, LATER) if r["id"] == tag["id"])
    assert run(cfg, store, tag_row2, Writer(), Reviewer()) == {"status": "ignored", "writer_calls": 0, "review_calls": 0, "cache_hit": False}

    # Lock the issue story, hold a genuine new-note update while locked, then unlock -> item is requeued and publishes.
    shown = editorial.show(store.db, story_id)
    locked = editorial.correct(store.db, story_id, {"priority": "normal"}, reason="Lower priority.",
                               expect_hash=shown["hash"], observed=LATER)
    later2 = "2026-11-10T14:00:00Z"
    n3 = {"id": "gid://gitlab/Note/3", "url": url + "#note_3", "title": "Public comment by @maint",
          "author": "maint", "created_at": later2, "body": "Maintainers merged the fix into main."}
    assert store.ingest(_compose(issue, [n1, n2, n3], later2, source_key="k"), later2)
    locked_row = next(r for r in store.pending(5, later2) if r["id"] == issue["id"])
    w_locked = Writer(update_analysis(update="Maintainers merged the fix.", state="merged",
                                      evidence=["Maintainers merged the fix into main."]))
    assert run(cfg, store, locked_row, w_locked, Reviewer())["status"] == "locked"
    # Writer saw only the new unquoted note, with unchanged issue body cleared.
    assert w_locked.calls[0]["content"] == ""
    assert [n["url"] for n in w_locked.calls[0]["public_comments"]] == [url + "#note_3"]
    assert store.pending(5, later2) == []

    editorial.unlock(store.db, story_id, reason="Allow queued updates.", expect_hash=locked["hash"], observed="2026-11-10T15:00:00Z")
    requeued = [r for r in store.pending(5, "2026-11-10T15:00:00Z") if r["id"] == issue["id"]]
    assert len(requeued) == 1
    w_after = Writer(update_analysis(update="Maintainers merged the fix.", state="merged",
                                     evidence=["Maintainers merged the fix into main."]))
    assert run(cfg, store, requeued[0], w_after, Reviewer(verdict(update=True)))["status"] == "published"
    updated_story = next(s for s in store.stories(5) if s["id"] == story_id)
    assert updated_story["updates"] == [{"at": later2, "text": "Maintainers merged the fix.",
                                         "sources": [{"url": url + "#note_3", "title": n3["title"]}]}]

    # Cross-item mailing-list replies in update scope strip >-quoted parent text and quote headers;
    # a pure-quote reply skips with 0 model calls while an unquoted reply strips quoted history for the writer.
    later3 = "2026-11-10T16:00:00Z"
    list_base = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/"
    opener = item(
        kind="feed",
        url=list_base + "MSG0/",
        source_id="msg-0",
        title="[tor-announce] Tor 0.4.9.15 released",
        content="Initial report details for the relay issue.",
        updated_at=DATE,
    )
    assert store.ingest(opener, DATE)
    assert run(cfg, store, store.pending(1, DATE)[0],
               Writer(analysis(evidence=["Initial report details for the relay issue."])),
               Reviewer(verdict()))["status"] == "published"
    pure_quote = item(
        kind="feed",
        url=list_base + "MSG1/",
        source_id="msg-1",
        title="[tor-relays] Re: Tor 0.4.9.15 released",
        content="On Wed, Nov 10, 2026 at 09:00 AM, alice via tor-relays wrote:\n\n> Initial report details for the relay issue.\n>> Older nested quote with 53-day-old relay numbers.",
        updated_at=later3,
    )
    assert store.ingest(pure_quote, later3)
    assert run(cfg, store, store.pending(1, later3)[0], Writer(), Reviewer()) == {
        "status": "ignored", "writer_calls": 0, "review_calls": 0, "cache_hit": False
    }
    assert store.db.execute("SELECT code FROM decision_log ORDER BY id DESC LIMIT 1").fetchone()[0] == "skipped.gate.no_new_content"

    later4 = "2026-11-10T17:00:00Z"
    reply_with_text = item(
        kind="feed",
        url=list_base + "MSG2/",
        source_id="msg-2",
        title="[tor-relays] Re: Tor 0.4.9.15 released",
        content="Operator observed three dropped circuits.\n\nOn Wed, Nov 10, 2026 at 09:00 AM, alice via tor-relays wrote:\n\n> Quoted 53-day-old relay backstory.",
        updated_at=later4,
    )
    assert store.ingest(reply_with_text, later4)
    w_reply = Writer(update_analysis(update="An operator observed three dropped circuits.", state="developing",
                                     evidence=["Operator observed three dropped circuits."]))
    assert run(cfg, store, store.pending(1, later4)[0], w_reply, Reviewer(verdict(update=True)))["status"] == "published"
    assert w_reply.calls[0]["content"].strip() == "Operator observed three dropped circuits."
    assert "53-day-old" not in w_reply.calls[0]["content"]
    assert "wrote:" not in w_reply.calls[0]["content"]


def test_pending_update_draft_rewrites_when_another_update_commits_first(context):
    cfg, store = context
    original = item(title="Tor 0.4.9.16 released", kind="feed", authority="official",
                    content="Tor 0.4.9.16 was released with fixes.")
    seed_legacy(store, original, analysis(title="Tor 0.4.9.16 released", state="released", confidence="confirmed"))
    m1 = item(title="Tor 0.4.9.16 released", kind="feed", url="https://example.org/m1", source_id="m1",
              content="Debian packages for Tor 0.4.9.16 are live.", updated_at=LATER)
    m2 = item(title="Tor 0.4.9.16 released", kind="feed", url="https://example.org/m2", source_id="m2",
              content="RPM packages for Tor 0.4.9.16 are live.", updated_at="2026-11-10T13:00:00Z")
    store.ingest(m1, LATER)
    store.ingest(m2, LATER)
    rows = {r["url"]: r for r in store.pending(5, LATER)}

    # m1 drafts first and fails transiently in review; then m2 commits an update, changing prior_story.
    w1 = Writer(update_analysis(update="Debian packages are live.", confidence="confirmed", state="released",
                                evidence=["Debian packages for Tor 0.4.9.16 are live."]))
    with pytest.raises(AnalysisError):
        run(cfg, store, rows["https://example.org/m1"], w1, Reviewer(AnalysisError("timeout", retryable=True)))
    assert len(w1.calls) == 1

    w2 = Writer(update_analysis(update="RPM packages are live.", confidence="confirmed", state="released",
                                evidence=["RPM packages for Tor 0.4.9.16 are live."]))
    assert run(cfg, store, rows["https://example.org/m2"], w2, Reviewer(verdict(update=True)))["status"] == "published"

    # Retrying m1 must call the writer again because cache_key(row, llm, prior) changed when m2 updated prior_story.
    res = run(cfg, store, rows["https://example.org/m1"], w1, Reviewer(verdict(update=True)))
    assert res["status"] == "published" and res["writer_calls"] == 1 and len(w1.calls) == 2
    assert len(store.stories()[0]["updates"]) == 2


def test_own_comment_cutoff_ignores_other_sources_and_admits_edited_notes(context):
    cfg, store = context
    issue_url = "https://gitlab.torproject.org/tpo/core/tor/-/issues/49500"
    canonical_issue_url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/49500"
    issue_a = item(
        id="gitlab:49500",
        kind="gitlab_issue",
        url=issue_url,
        title="Tor 0.4.9.30 relay descriptor stall",
        content="Initial report of descriptor stall in Tor 0.4.9.30.",
        published_at="2026-11-08T10:00:00Z",
        updated_at="2026-11-08T10:00:00Z",
        public_comments=[],
    )
    row_a = pending(store, issue_a)
    assert review_gate.process_item(
        cfg,
        store,
        row_a,
        Writer(analysis(
            title="Descriptor stall reported in Tor 0.4.9.30",
            summary="Initial report of descriptor stall in Tor 0.4.9.30.",
            state="developing",
            evidence=["Initial report of descriptor stall in Tor 0.4.9.30."],
        )),
        Reviewer(verdict(), verdict()),
        "2026-11-08T10:05:00Z",
    )["status"] == "published"
    story_id = store.stories()[0]["id"]

    # Another source adds an update dated Nov 10, advancing story["updated_at"] to Nov 10.
    other_src = item(
        kind="gitlab_mr",
        url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1950",
        title="Investigate descriptor stall (closes #49500)",
        content="Closes #49500 with diagnostic logging.",
        upstream_state="merged",
        published_at="2026-11-10T12:00:00Z",
        updated_at="2026-11-10T12:00:00Z",
    )
    row_b = pending(store, other_src)
    assert review_gate.process_item(
        cfg,
        store,
        row_b,
        Writer(update_analysis(
            update="A merge request added diagnostic logging for the stall.",
            state="merged",
            evidence=["Closes #49500 with diagnostic logging."],
        )),
        Reviewer(verdict(update=True), verdict(update=True)),
        "2026-11-10T12:05:00Z",
    )["status"] == "published"
    assert store.stories()[0]["updated_at"] == "2026-11-10T12:00:00Z"

    # Issue A is re-polled on Nov 11 with a comment created on Nov 9 (after A's Nov 8 checkpoint, before B's Nov 10 update).
    note_v1 = {
        "id": "501",
        "author": "maintainer",
        "title": "Comment by maintainer",
        "created_at": "2026-11-09T09:00:00Z",
        "url": issue_url + "#note_501",
        "body": "Root cause narrowed to malformed extra-info lines.",
    }
    issue_a_nov9 = {**issue_a, "updated_at": "2026-11-09T09:00:00Z", "public_comments": [note_v1]}
    assert store.ingest(issue_a_nov9, "2026-11-11T08:00:00Z")
    row_nov9 = store.pending(1, "2026-11-11T08:00:00Z")[0]
    w_nov9 = Writer(update_analysis(
        update="Maintainers narrowed the root cause to malformed extra-info lines.",
        state="merged",
        evidence=["Root cause narrowed to malformed extra-info lines."],
    ))
    res_nov9 = review_gate.process_item(cfg, store, row_nov9, w_nov9, Reviewer(verdict(update=True), verdict(update=True)), "2026-11-11T08:00:00Z")
    assert res_nov9["status"] == "published" and len(w_nov9.calls) == 1
    story_after_nov9 = next(s for s in store.stories() if s["id"] == story_id)
    assert story_after_nov9["updates"][-1]["sources"] == [{"url": canonical_issue_url + "#note_501", "title": "Comment by maintainer"}]

    # Later, the author edits note 501 in place (same id "501", same created_at Nov 9 <= cutoff, updated body at Nov 12).
    note_v2 = {**note_v1, "body": "Correction: extra-info parsing was unaffected; bug is in routerstatus retry."}
    issue_a_edited = {**issue_a, "updated_at": "2026-11-12T14:00:00Z", "public_comments": [note_v2]}
    assert store.ingest(issue_a_edited, "2026-11-12T14:05:00Z")
    row_edit = store.pending(1, "2026-11-12T14:05:00Z")[0]
    w_edit = Writer(update_analysis(
        update="A corrected maintainer note places the bug in routerstatus retry rather than extra-info parsing.",
        state="merged",
        evidence=["Correction: extra-info parsing was unaffected; bug is in routerstatus retry."],
    ))
    res_edit = review_gate.process_item(cfg, store, row_edit, w_edit, Reviewer(verdict(update=True), verdict(update=True)), "2026-11-12T14:05:00Z")
    assert res_edit["status"] == "published" and len(w_edit.calls) == 1
    story_after_edit = next(s for s in store.stories() if s["id"] == story_id)
    assert story_after_edit["updates"][-1]["at"] == "2026-11-12T14:00:00Z"
    assert story_after_edit["updates"][-1]["sources"] == [{"url": canonical_issue_url + "#note_501", "title": "Comment by maintainer"}]

    # Re-polling when only quoted text is appended to note 501 (unquoted body unchanged) skips with 0 model calls.
    note_v2_quoted = {**note_v2, "body": note_v2["body"] + "\n\n> Earlier quoted context."}
    issue_a_same = {**issue_a, "updated_at": "2026-11-12T15:00:00Z", "public_comments": [note_v2_quoted]}
    assert store.ingest(issue_a_same, "2026-11-12T15:05:00Z")
    row_same = store.pending(1, "2026-11-12T15:05:00Z")[0]
    res_same = review_gate.process_item(cfg, store, row_same, Writer(), Reviewer(), "2026-11-12T15:05:00Z")
    assert res_same["status"] == "ignored" and res_same["writer_calls"] == 0 and res_same["review_calls"] == 0
    assert store.db.execute("SELECT code FROM decision_log ORDER BY id DESC LIMIT 1").fetchone()[0] == "skipped.gate.no_new_content"
    # Even when old_item=None (legacy story without an analyses snapshot) and item["url"] uses /-/issues/,
    # _source_cutoff matches canonical /-/work_items/#note_501 in updates while ignoring other_src's date.
    legacy_story = next(s for s in store.stories() if s["id"] == story_id)
    assert review_gate.candidate_mod._source_cutoff(store.db, legacy_story, None, issue_a_edited) == "2026-11-12T14:00:00Z"
