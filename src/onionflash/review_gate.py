"""Durable stages for reviewing the exact candidate before its guarded commit.

The existing item queue owns scheduling and backoff. These private tables keep
one unfinished job per item, overwritten when its inputs change or an operator
retries the item, and the receipt of its recorded decision until that decision
commits; they are not a cache of writer responses for arbitrary future items.
Every job record keeps the item row as input_row, which this release never
reads, because earlier releases read it after a code rollback.
"""

from __future__ import annotations

import json

from . import candidate as candidate_mod, decisions, render, review
from .analyze import AnalysisError, cache_key
from .util import after, digest, now_iso, saved_object

MAX_APPROVALS = 2000  # cached approvals kept besides those unfinished jobs pin
# An item starts a new story only if its newest dated development is at most this many days older
# than the collection of its current revision: the same window the collector's lookback uses.
NEW_STORY_DAYS = 14
HIGH_SECURITY_SEVERITIES = frozenset({"severity::high", "severity::critical"})
# The repairs that may follow the first review, a release-label repair request counting as one, each
# checked by another fresh verification: an item gets at most MAX_VERIFY_REPAIRS + 2 review requests.
MAX_VERIFY_REPAIRS = 5
# An item from these sources, other than a version tag, that fails only news value is held for the
# operator, never skipped.
OFFICIAL_AUTHORITIES = frozenset({"official", "project-sender"})
# Each hold reason and its operator text, which follows "Final review held: " in last_error. A hold
# is logged as held.<stage>.<reason>, the stage being gate, review, verification or final_check.
HOLDS = {
    "missing_sources": "required source material is unavailable",
    "repeat_hold": "operator review is required",
    "model_hold": "review did not approve the candidate",
    "tag_repair": "review proposed editing a literal tag notice",
    "unusable_repair": "review proposed an unusable repair",
    "repeated_repair": "review proposed a text already reviewed",
    "disagreed_news": "the reviews disagree on news value",
    "official_not_news": "review found an official item not newsworthy",
    "repairs_exhausted": "review still refused after the repair limit",
    "release_labels": "release labels need a released or tagged state",
    # review.final_holds, which holds a verified approval
    "completed_action": "the story reports a completed action that its sources do not",
    "compromise_headline": "the headline drops the sources' doubt about a compromise",
    "confirmed_source": "confirmed needs an official announcement or a merged merge request",
    "merge_state": "a story told only by merge requests must be marked merged",
}


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)


def status(store):
    """Read compact stage/cache counts without loading bodies."""
    return {"stages": dict(store.db.execute("SELECT stage,COUNT(*) FROM review_jobs GROUP BY stage")),
            "approval_cache_entries": store.db.execute("SELECT COUNT(*) FROM review_approvals").fetchone()[0]}


def reset_review_work(store, item_id):
    """Explicit operator retry starts a new review, retaining its completed draft.

    The caller owns the transaction.
    """
    row = store.db.execute("SELECT writer_key,CAST(draft_json AS BLOB) AS draft FROM review_jobs WHERE item_id=?",
                           (item_id,)).fetchone()
    if row is None:
        return
    item = dict(store.db.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone())
    record = {"schema_version": 1, "writer": {"key": row["writer_key"]}, "input_row": item, "reviews": []}
    # A damaged draft is dropped, so the writer drafts again.
    keep = saved_object(row["draft"]) is not None
    store.db.execute("""UPDATE review_jobs SET stage='drafted',draft_json=CASE WHEN ? THEN draft_json END,envelope_json=NULL,
        record_json=?,approval_key=NULL,updated_at=? WHERE item_id=?""", (keep, _json(record), now_iso(), item_id))


def _save(store, item_id, writer_key, policy_hash, stage, draft, prepared, record, observed,
          *, prepared_at, approval_key=None, approval_receipt=None):
    with store.db:
        if approval_receipt is not None:
            # Receipt and the unfinished job's pin become durable together.
            store.db.execute("""INSERT OR REPLACE INTO review_approvals
                (key,candidate_hash,source_hash,policy_hash,binding_hash,result_json,
                 review_record_json,created_at,last_used_at) VALUES(?,?,?,?,?,?,?,?,?)""", approval_receipt)
        store.db.execute("""INSERT INTO review_jobs
            (item_id,writer_key,policy_hash,stage,draft_json,envelope_json,record_json,
             approval_key,prepared_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(item_id) DO UPDATE SET writer_key=excluded.writer_key,
            policy_hash=excluded.policy_hash,stage=excluded.stage,draft_json=excluded.draft_json,
            envelope_json=excluded.envelope_json,record_json=excluded.record_json,
            approval_key=excluded.approval_key,prepared_at=excluded.prepared_at,updated_at=excluded.updated_at""",
            (item_id, writer_key, policy_hash, stage, _json(draft) if draft is not None else None,
             _json(prepared) if prepared is not None else None, _json(record), approval_key, prepared_at, observed))


def _identity(prepared):
    return tuple(prepared[key] for key in ("candidate_hash", "source_hash", "binding_hash"))


def _approval_key(candidate, prepared, policy):
    return digest([digest(candidate), prepared["source_hash"], policy, prepared["binding_hash"]])


def _prune(store, maximum):
    with store.db:
        store.db.execute("""DELETE FROM review_approvals WHERE key IN (
            SELECT key FROM review_approvals
            WHERE key NOT IN (SELECT approval_key FROM review_jobs WHERE approval_key IS NOT NULL)
            ORDER BY last_used_at DESC,key LIMIT -1 OFFSET ?)
        """, (maximum,))


def _news(result) -> bool:
    return all(result["criteria"][name]["outcome"] == "pass" for name in review.EDITORIAL_CRITERIA)


def next_step(reviews, candidate, prepared):
    """What follows the latest review of `candidate`, decided from the chain of reviews alone.

    ("verify", text) sends text to a fresh verification, ("repair", text) asks a review to repair
    its release labels, ("approve" | "skip", candidate) commits, and ("hold", (stage, reason))
    holds. The evaluation follows the same steps.
    """
    latest = reviews[-1]
    result, stage, later = latest["result"], latest["stage"], len(reviews) > 1
    verdict = result["verdict"]
    failed = {name for name, check in result["criteria"].items() if check["outcome"] != "pass"}
    item = json.loads(prepared["row"]["payload"])
    official = item.get("authority") in OFFICIAL_AUTHORITIES and item.get("kind") != "tag"
    # An official item that fails only news value is the operator's to judge, once a fresh
    # verification has passed its facts; a duplicate still skips.
    disputed = official and failed & review.EDITORIAL_CRITERIA == {"news_value"}
    if later and _news(result) != _news(reviews[0]["result"]):
        return "hold", (stage, "disagreed_news")
    if disputed:
        if stage == "verification" and failed == {"news_value"}:
            return "hold", (stage, "official_not_news")
        if verdict != "revise":
            return ("hold", (stage, "model_hold")) if later else ("verify", candidate)
    elif verdict == "skip" and (not official or result["criteria"]["new_information"]["outcome"] == "fail"):
        return "skip", candidate
    if verdict == "approve":
        if stage == "verification" and (held := review.final_holds(candidate, prepared)):
            return "hold", ("final_check", held[0])
        if not review.release_labels_match_state(candidate):
            # A review told the problem may repair it, if the repair can still be verified within the limit.
            if latest.get("issue") or len(reviews) > MAX_VERIFY_REPAIRS:
                return "hold", (stage, "release_labels")
            return "repair", candidate
        return ("verify" if stage == "review" else "approve"), candidate
    if verdict != "revise" or (later and failed & review.EDITORIAL_CRITERIA and not disputed):
        return "hold", (stage, "release_labels" if latest.get("issue") else "model_hold")
    if prepared["payload"]["editorial_kind"] == "tag":
        return "hold", (stage, "tag_repair")
    if len(reviews) > MAX_VERIFY_REPAIRS + 1:
        return "hold", (stage, "repairs_exhausted")
    try:
        repaired = review.apply_repair(candidate, result["repair"])
    except review.ReviewError:
        # After a disputed official item's first review, the unchanged text goes to its fresh verification.
        return ("verify", candidate) if disputed and not later else ("hold", (stage, "unusable_repair"))
    if latest.get("issue") and not review.release_labels_match_state(repaired):
        return "hold", (stage, "release_labels")  # the repair request left the labels in place
    if digest(repaired) in {entry["candidate_hash"] for entry in reviews}:
        return "hold", (stage, "repeated_repair")  # every text of the chain was refused once already
    return "verify", repaired


def call_review(reviewer, stage, candidate, prepared) -> dict:
    """Ask for the review that `stage` names and return the chain entry that records its reply."""
    result = reviewer.review(candidate, prepared["packet"], coverage=prepared["coverage"], verification=stage == "verify",
                             issue=review.RELEASE_ISSUE if stage == "repair" else None)
    return {"stage": "verification" if stage == "verify" else "review", **({"issue": "release_labels"} if stage == "repair" else {}),
            "candidate_hash": digest(candidate), "result": result}


def _verified(reviews) -> bool:
    """Whether the latest review is a fresh verification that passed every factual criterion and cites a source."""
    criteria = reviews[-1]["result"]["criteria"] if reviews and reviews[-1]["stage"] == "verification" else None
    return bool(criteria and criteria["source_support"]["source_refs"]) and all(
        check["outcome"] == "pass" for name, check in criteria.items() if name not in review.EDITORIAL_CRITERIA)


def _hold(store, row, draft, writer_key, record, observed, stage, reason):
    """One semantic hold is terminal; only source change/operator retry requeues."""
    record.update(outcome="held", hold_code=reason, hold_reason=HOLDS[reason], verified_facts=_verified(record["reviews"]))
    with store.db:
        store.record_analysis(row, draft, writer_key, observed, review_record=record)
        store.db.execute("""UPDATE items SET status='rejected',attempts=attempts+1,
            rejections=MAX(rejections,3),next_attempt_at=NULL,last_error=? WHERE id=?""",
            ("Final review held: " + HOLDS[reason], row["id"]))
        store.db.execute("""UPDATE review_jobs SET stage='held',record_json=?,approval_key=NULL,
            updated_at=? WHERE item_id=?""", (_json(record), observed, row["id"]))
        decisions.record(store.db, row["id"], f"held.{stage}.{reason}", observed, review=record)


def developed_at(item: dict) -> str:
    """The newest dated public development the pipeline can cite; an upstream updated_at never counts.

    published_at is the post, creation, merge, tag or timeline event date the collector stored. An
    issue adds its verified public notes and the date it was closed. Collected dates are all
    format_utc strings, so string order is time order.
    """
    dates = [item["published_at"]]
    if item.get("kind") == "gitlab_issue":
        dates += [note["created_at"] for note in item.get("public_comments") or []]
        if item.get("upstream_state") == "closed" and item.get("closed_at"):
            dates.append(item["closed_at"])
    return max(dates)


def _security_disclosure(item: dict) -> bool:
    """A high- or critical-severity security issue may become public long after it was filed."""
    if item.get("kind") != "gitlab_issue":
        return False
    labels = {label.strip().casefold() for label in (item.get("labels") or []) if isinstance(label, str)}
    return "security" in labels and bool(labels & HIGH_SECURITY_SEVERITIES)


def _not_recent(config, store, row, item, observed) -> str | None:
    """Ignore, before any model call, an item that would start a story from an old development.

    An update of an existing story, a locked one included, is left to review, and so is a revision
    an operator retried or a high- or critical-severity security issue. Like any skip, a new
    revision of the item queues it again; an issue whose notes were never verified also gets a
    comment check, so a fresh public note does that.
    """
    developed = developed_at(item)
    if (developed >= after(-NEW_STORY_DAYS * 86400, row["last_seen"])
            or _security_disclosure(item)
            or candidate_mod.existing_story(store.db, row) is not None):
        return None
    if store.db.execute("SELECT 1 FROM rejection_actions WHERE item_id=? AND content_hash=? AND action='retry'",
                        (row["id"], row["content_hash"])).fetchone():
        return None
    reason = f"Not recent: newest dated development {developed} is over {NEW_STORY_DAYS} days before collection"
    with store.db:
        if not store.db.execute("""UPDATE items SET status='ignored',next_attempt_at=NULL,last_error=?
                WHERE id=? AND content_hash=? AND status='pending'""", (reason, row["id"], row["content_hash"])).rowcount:
            return "stale"  # the row changed since it was read, as a stale candidate does
        store.db.execute("DELETE FROM review_jobs WHERE item_id=?", (row["id"],))
        if item.get("kind") == "gitlab_issue" and "comments_source_key" not in item:
            from .comments import request_check
            request_check(store.db, config, row, observed)
        decisions.record(store.db, row["id"], "skipped.gate.not_recent", observed,
                         developed_at=developed, collected_at=row["last_seen"])
    return "ignored"


def process_item(config, store, row, writer, reviewer, observed=None, *, allow_network=True):
    """Resume writer → exact-candidate review → fresh verification of each approved or repaired text → commit.

    Transport errors leave the current stage durable and raise a retryable
    AnalysisError for the existing queue's backoff. An unusable reply keeps the
    stage too, but its AnalysisError counts toward the item's three failures, as
    a saved job that cannot be read does. next_step bounds the repairs; a hold
    marks the item rejected immediately.
    """
    from .candidate import ReviewRequired, StaleCandidate

    observed = observed or now_iso()
    policy = review.policy_hash(config)
    writer_key = cache_key(row, config["llm"])
    report = {"status": "pending", "writer_calls": 0, "review_calls": 0, "cache_hit": False}
    skipped = _not_recent(config, store, row, json.loads(row["payload"]), observed)  # needs no network
    if skipped:
        return {**report, "status": skipped}
    job = store.db.execute("""SELECT writer_key,policy_hash,stage,approval_key,prepared_at,CAST(draft_json AS BLOB) AS draft,
        CAST(envelope_json AS BLOB) AS envelope,CAST(record_json AS BLOB) AS record FROM review_jobs WHERE item_id=?""",
        (row["id"],)).fetchone()
    if job is not None and job["writer_key"] == writer_key:
        draft, old, record = (saved_object(job[key]) for key in ("draft", "envelope", "record"))
        # A job whose JSON cannot be read fails the item; reviewing it afresh could pass over its hold.
        # The other columns hold only the ASCII keys, stages and times that the application writes.
        if record is None or (draft is None) != (job["draft"] is None) or (old is None) != (job["envelope"] is None):
            raise AnalysisError("Saved review job is damaged", code="app.damaged_job")
        prepared_at = job["prepared_at"]
    else:
        job, draft, old = None, None, None
        record = {"schema_version": 1, "writer": None, "input_row": row, "reviews": []}
        prepared_at = observed
    if draft is None:
        if not allow_network and json.loads(row["payload"])["kind"] != "tag":
            return {**report, "status": "deferred"}
        report["writer_calls"] += json.loads(row["payload"])["kind"] != "tag"
        draft = writer.analyze(json.loads(row["payload"]))
        record["writer"] = {"key": writer_key}  # The draft itself is saved in the job, then in analyses.
        if getattr(writer, "clears", 0):  # writer validation cleared the draft's impact sentence
            record["writer"]["clears"] = writer.clears  # kept until an operator retry resets the record
        _save(store, row["id"], writer_key, policy, "drafted", draft, None, record, observed, prepared_at=prepared_at)
    try:
        prepared = store.prepare_candidate(row, draft, prepared_at)
        same = old is not None and job["policy_hash"] == policy and _identity(old) == _identity(prepared)
        stage = job["stage"] if same else "review"
        fresh = {"schema_version": 1, "writer": record["writer"], "input_row": row, "reviews": [], "policy_hash": policy,
                 "prepared": {key: prepared[key] for key in ("candidate", "packet", "coverage", "candidate_hash", "source_hash", "coverage_hash", "binding_hash")}}
        record = record if same else fresh
        candidate = record.get("candidate", prepared["candidate"])
        _save(store, row["id"], writer_key, policy, stage, draft, prepared, record, observed, prepared_at=prepared_at,
              approval_key=job["approval_key"] if same else None)
        if prepared.get("locked"):
            record["outcome"] = "locked"
            store.commit_candidate(prepared, prepared["candidate"], writer_key, now_iso(), review_record=record)
            return {**report, "status": record["outcome"]}
        if prepared["packet"]["missing_sources"]:
            _hold(store, row, draft, writer_key, record, observed, "gate", "missing_sources")
            return {**report, "status": "held"}
        if stage == "held":
            # The same candidate held before: a source reverted to a held revision,
            # or an item was requeued without reset_review_work. Do not review it again.
            _hold(store, row, draft, writer_key, record, observed, "gate", "repeat_hold")
            return {**report, "status": "held"}
        key = _approval_key(candidate, prepared, policy)
        cached = store.db.execute("SELECT * FROM review_approvals WHERE key=?", (key,)).fetchone()
        if cached is not None:
            try:
                verdict = review.validate_review(json.loads(cached["result_json"]), prepared["packet"])
                proof = json.loads(cached["review_record_json"])
                valid = verdict["verdict"] in {"approve", "skip"}
            except (AnalysisError, ValueError, TypeError, KeyError):
                valid = False
            if valid:
                record["approval"] = proof
                record["approval_key"] = key
                if verdict["verdict"] == "approve" and (held := review.final_holds(candidate, prepared)):
                    _hold(store, row, draft, writer_key, record, observed, "final_check", held[0])
                    return {**report, "status": "held", "cache_hit": True}
                record["outcome"] = "skipped" if verdict["verdict"] == "skip" else "approved"
                _save(store, row["id"], writer_key, policy, record["outcome"], draft, prepared, record, observed,
                      prepared_at=prepared_at, approval_key=key)
                committed = store.commit_candidate(prepared, candidate, writer_key, now_iso(), approval_key=key,
                                                   policy_hash=policy, review_record=record, decision=verdict["verdict"])
                report.update(status=committed["status"], cache_hit=True)
                return report
            with store.db:
                store.db.execute("DELETE FROM review_approvals WHERE key=?", (key,))
        if stage in {"approved", "skipped"}:  # without a usable receipt, review the writer's draft again
            stage, candidate, record = "review", prepared["candidate"], fresh
        while True:
            if not allow_network:
                return {**report, "status": "deferred"}
            report["review_calls"] += 1
            record["reviews"].append({**call_review(reviewer, stage, candidate, prepared), "source_hash": prepared["source_hash"],
                                      "coverage_hash": prepared["coverage_hash"], "policy_hash": policy})
            action, value = next_step(record["reviews"], candidate, prepared)
            if action == "hold":
                _hold(store, row, draft, writer_key, record, observed, *value)
                return {**report, "status": "held"}
            if action in {"approve", "skip"}:
                key = _approval_key(candidate, prepared, policy)
                record.update(candidate=candidate, approval_key=key, outcome="skipped" if action == "skip" else "approved")
                receipt = (key, digest(candidate), prepared["source_hash"], policy, prepared["binding_hash"],
                           _json(record["reviews"][-1]["result"]), _json(record), observed, observed)
                _save(store, row["id"], writer_key, policy, record["outcome"], draft, prepared, record, observed,
                      prepared_at=prepared_at, approval_key=key, approval_receipt=receipt)
                committed = store.commit_candidate(prepared, candidate, writer_key, now_iso(), approval_key=key,
                                                   policy_hash=policy, review_record=record, decision=action)
                return {**report, "status": committed["status"]}
            stage, candidate = action, value  # the next review: a verification or a release-label repair
            record["candidate"] = candidate
            _save(store, row["id"], writer_key, policy, stage, draft, prepared, record, observed, prepared_at=prepared_at)
    except (StaleCandidate, ReviewRequired):
        return {**report, "status": "stale"}
    finally:
        _prune(store, MAX_APPROVALS)


def _new_coverage(old_coverage, current_coverage) -> list[dict]:
    old_recent = old_coverage.get("recent") if isinstance(old_coverage, dict) else None
    seen = {
        (entry["id"], entry["updated_at"])
        for entry in (old_recent if isinstance(old_recent, list) else ())
        if isinstance(entry, dict) and isinstance(entry.get("id"), str) and isinstance(entry.get("updated_at"), str)
    }
    return [
        {"id": entry["id"], "title": entry["title"], "updated_at": entry["updated_at"]}
        for entry in ((current_coverage or {}).get("recent") or ())
        if (entry["id"], entry["updated_at"]) not in seen
    ]


def _check_approval(config, store, item_id: str) -> tuple[dict, tuple | None]:
    def refuse(reason: str, editorial_failures=(), new_coverage=()):
        return {
            "eligible": False,
            "reason": reason,
            "hash": None,
            "editorial_failures": list(editorial_failures),
            "new_coverage": list(new_coverage),
        }, None

    item_row = store.db.execute(
        """SELECT id,url,source_id,content_hash,cluster_key,status,attempts,rejections,
           next_attempt_at,last_error,story_id,first_seen,last_seen,priority_score,
           typeof(payload) AS payload_type,CAST(payload AS BLOB) AS payload_blob
           FROM items WHERE id=?""",
        (item_id,),
    ).fetchone()
    job = store.db.execute(
        """SELECT writer_key,policy_hash,stage,prepared_at,CAST(draft_json AS BLOB) AS draft,
           CAST(envelope_json AS BLOB) AS envelope,CAST(record_json AS BLOB) AS record
           FROM review_jobs WHERE item_id=?""",
        (item_id,),
    ).fetchone()
    if item_row is None or item_row["status"] != "rejected" or job is None or job["stage"] != "held":
        return refuse("Only a held final review can be approved")
    payload_obj = saved_object(item_row["payload_blob"]) if item_row["payload_type"] == "text" else None
    draft, saved_env, record = (saved_object(job[key]) for key in ("draft", "envelope", "record"))
    if (payload_obj is None or draft is None or saved_env is None or record is None
            or not isinstance(job["writer_key"], str) or not job["writer_key"]
            or not isinstance(job["prepared_at"], str)):
        return refuse("Saved review record cannot be read")
    reviews = record.get("reviews")
    if not isinstance(reviews, list):
        return refuse("Saved review record cannot be read")
    try:
        if any(not isinstance(entry, dict) or entry["stage"] not in {"review", "verification"} for entry in reviews):
            return refuse("Saved review record cannot be read")
        editorial_failures = [
            f"{entry['stage']}:{name}"
            for entry in reviews
            for name in ("news_value", "new_information")
            if entry["result"]["criteria"][name]["outcome"] != "pass"
        ]
    except (TypeError, KeyError, AttributeError):
        return refuse("Saved review record cannot be read")
    policy = review.policy_hash(config)
    if (job["policy_hash"] != policy or record.get("policy_hash") != policy
            or any(entry.get("policy_hash") != policy for entry in reviews)):
        return refuse("An earlier review policy or packet reviewed it; retry it", editorial_failures)
    row = {key: item_row[key] for key in (
        "id", "url", "source_id", "content_hash", "cluster_key", "status", "attempts", "rejections",
        "next_attempt_at", "last_error", "story_id", "first_seen", "last_seen", "priority_score")}
    row["payload"] = item_row["payload_blob"].decode("utf-8")
    try:
        prepared = store.prepare_candidate(row, draft, job["prepared_at"])
    except Exception:
        return refuse("Its story or sources changed since the review; retry it", editorial_failures)
    if prepared["locked"]:
        return refuse("Its story is editorially locked", editorial_failures)
    held_prepared = record.get("prepared")
    if not isinstance(held_prepared, dict):
        return refuse("Saved review record cannot be read", editorial_failures)
    new_coverage = _new_coverage(held_prepared.get("coverage"), prepared["coverage"])
    if prepared["packet"]["missing_sources"]:
        return refuse("Final review held: " + HOLDS["missing_sources"], editorial_failures, new_coverage)
    saved_binding = saved_env.get("binding") if isinstance(saved_env.get("binding"), dict) else {}
    if (prepared["story_id"] != saved_env.get("story_id")
            or prepared["candidate_hash"] != held_prepared.get("candidate_hash")
            or prepared["candidate_hash"] != saved_env.get("candidate_hash")
            or prepared["source_hash"] != held_prepared.get("source_hash")
            or prepared["source_hash"] != saved_env.get("source_hash")
            or any(prepared["binding"][key] != saved_binding.get(key)
                   for key in ("prior_story", "lock", "sources", "payload_hash"))):
        return refuse("Its story or sources changed since the review; retry it", editorial_failures, new_coverage)
    if any(entry.get("source_hash") != prepared["source_hash"] for entry in reviews):
        return refuse("An earlier review policy or packet reviewed it; retry it", editorial_failures, new_coverage)
    try:
        validated = [review.validate_review(entry["result"], prepared["packet"]) for entry in reviews]
    except (AnalysisError, ValueError, TypeError, KeyError):
        return refuse("Saved review record cannot be read", editorial_failures, new_coverage)
    if any(result["criteria"]["new_information"]["outcome"] != "pass" for result in validated):
        return refuse("A review failed new_information (already covered); dismiss it", editorial_failures, new_coverage)
    candidate = record.get("candidate")
    original = prepared["candidate"]
    if not isinstance(candidate, dict) or set(candidate) != set(original):
        return refuse("No fresh verification reviewed this exact text", editorial_failures, new_coverage)
    if any(candidate[key] != original[key] for key in original if key not in candidate_mod.SEMANTIC_FIELDS):
        return refuse("Saved review record cannot be read", editorial_failures, new_coverage)
    try:
        if render._prepare_story(candidate, editorial=original.get("editorial")) != candidate:
            return refuse("Saved review record cannot be read", editorial_failures, new_coverage)
    except (ValueError, TypeError, KeyError):
        return refuse("Saved review record cannot be read", editorial_failures, new_coverage)
    candidate_hash = digest(candidate)
    reviews_of_text = [
        (entry, result)
        for entry, result in zip(reviews, validated)
        if entry.get("candidate_hash") == candidate_hash
    ]
    if not any(entry.get("stage") == "verification" for entry, _ in reviews_of_text):
        return refuse("No fresh verification reviewed this exact text", editorial_failures, new_coverage)
    failed_facts = [
        name for name in review.CRITERIA
        if name not in review.EDITORIAL_CRITERIA
        and any(result["criteria"][name]["outcome"] != "pass" for _, result in reviews_of_text)
    ]
    if failed_facts:
        return refuse(f"A review failed {', '.join(failed_facts)}; dismiss or retry it", editorial_failures, new_coverage)
    if (record.get("verified_facts") is not True or not _verified(reviews)
            or any(not result["criteria"]["source_support"]["source_refs"] for _, result in reviews_of_text)):
        return refuse("No fresh verification with cited sources approved the facts; retry or dismiss it",
                      editorial_failures, new_coverage)
    if held := review.final_holds(candidate, prepared):
        return refuse("Final review held: " + HOLDS[held[0]], editorial_failures, new_coverage)
    if not review.release_labels_match_state(candidate):
        return refuse("Final review held: " + HOLDS["release_labels"], editorial_failures, new_coverage)
    if not editorial_failures:
        return refuse("Only a held news-value dispute can be approved", editorial_failures, new_coverage)
    exact_entries = [entry for entry, _ in reviews_of_text]
    approval_hash = digest(["approve-as-reviewed", prepared["binding_hash"], candidate_hash, policy, digest(exact_entries)])
    return {
        "eligible": True,
        "reason": None,
        "hash": approval_hash,
        "editorial_failures": editorial_failures,
        "new_coverage": new_coverage,
    }, (prepared, candidate, job["writer_key"], record)


def approval(config, store, item_id: str) -> dict:
    """Read-only eligibility and binding hash for `rejected approve`; never raises on damaged rows."""
    return _check_approval(config, store, item_id)[0]


def approve(config, store, item_id: str, approval_hash: str, reason: str, stamp: str) -> dict:
    """Publish an eligible held candidate exactly as reviewed, without model calls."""
    if store.db.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone() is None:
        raise ValueError("Source item was not found")
    info, handle = _check_approval(config, store, item_id)
    if not info["eligible"]:
        raise ValueError(info["reason"])
    if info["hash"] != approval_hash:
        raise ValueError("Approval hash does not match the current candidate, coverage and policy; inspect the item before approving")
    prepared, candidate, writer_key, record = handle
    audit = json.loads(_json(record))
    audit["outcome"] = "operator_approved"
    audit["operator_approval"] = {
        "reason": reason,
        "approved_at": stamp,
        "approval_hash": approval_hash,
        "new_coverage": info["new_coverage"],
    }
    try:
        committed = store.commit_candidate(prepared, candidate, writer_key, stamp, review_record=audit, operator=True)
    except (candidate_mod.StaleCandidate, candidate_mod.ReviewRequired) as exc:
        raise ValueError(str(exc)) from None
    return {
        "item_id": item_id,
        "content_hash": prepared["row"]["content_hash"],
        "action": "approve",
        "status": committed["status"],
        "story_id": committed["story_id"],
        "analysis_key": committed["analysis_key"],
        "publication_pending": True,
    }
