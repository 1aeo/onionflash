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

from . import decisions
from .analyze import AnalysisError, cache_key
from .util import digest, now_iso, saved_object

MAX_APPROVALS = 2000  # cached approvals kept besides those unfinished jobs pin
# Each hold reason and its operator text, which follows "Final review held: " in last_error. A hold
# is logged as held.<stage>.<reason>, the stage being gate, review or verification.
HOLDS = {
    "missing_sources": "required source material is unavailable",
    "repeat_hold": "operator review is required",
    "model_hold": "review did not approve the candidate",
    "tag_repair": "review proposed editing a literal tag notice",
    "unusable_repair": "review proposed an unusable repair",
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


def _hold(store, row, draft, writer_key, record, observed, stage, reason):
    """One semantic hold is terminal; only source change/operator retry requeues."""
    record["outcome"] = "held"
    record["hold_reason"] = HOLDS[reason]
    with store.db:
        store.record_analysis(row, draft, writer_key, observed, review_record=record)
        store.db.execute("""UPDATE items SET status='rejected',attempts=attempts+1,
            rejections=MAX(rejections,3),next_attempt_at=NULL,last_error=? WHERE id=?""",
            ("Final review held: " + HOLDS[reason], row["id"]))
        store.db.execute("""UPDATE review_jobs SET stage='held',record_json=?,approval_key=NULL,
            updated_at=? WHERE item_id=?""", (_json(record), observed, row["id"]))
        decisions.record(store.db, row["id"], f"held.{stage}.{reason}", observed, review=record)


def process_item(config, store, row, writer, reviewer, observed=None, *, allow_network=True):
    """Resume writer → exact-candidate review → verification of an approval or repair → commit.

    Transport errors leave the current stage durable and raise a retryable
    AnalysisError for the existing queue's backoff. An unusable reply keeps the
    stage too, but its AnalysisError counts toward the item's three failures.
    Semantic rejection, including an unusable repair, marks the item rejected
    immediately; it never starts an endless rewrite loop.
    """
    from . import review
    from .candidate import ReviewRequired, StaleCandidate

    observed = observed or now_iso()
    policy = review.policy_hash(config)
    writer_key = cache_key(row, config["llm"])
    report = {"status": "pending", "writer_calls": 0, "review_calls": 0, "cache_hit": False}
    job = store.db.execute("SELECT * FROM review_jobs WHERE item_id=?", (row["id"],)).fetchone()
    if job is not None and job["writer_key"] == writer_key:
        draft = json.loads(job["draft_json"]) if job["draft_json"] is not None else None
        record = json.loads(job["record_json"])
        prepared_at = job["prepared_at"]
    else:
        job, draft = None, None
        record = {"schema_version": 1, "writer": None, "input_row": row, "reviews": []}
        prepared_at = observed
    if draft is None:
        if not allow_network and json.loads(row["payload"])["kind"] != "tag":
            return {**report, "status": "deferred"}
        report["writer_calls"] += json.loads(row["payload"])["kind"] != "tag"
        draft = writer.analyze(json.loads(row["payload"]))
        record["writer"] = {"key": writer_key}  # The draft itself is saved in the job, then in analyses.
        _save(store, row["id"], writer_key, policy, "drafted", draft, None, record, observed, prepared_at=prepared_at)
    try:
        prepared = store.prepare_candidate(row, draft, prepared_at)
        old = json.loads(job["envelope_json"]) if job is not None and job["envelope_json"] else None
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
            verification = stage == "verify"
            phase = "verification" if verification else "review"
            if not allow_network:
                return {**report, "status": "deferred"}
            report["review_calls"] += 1
            verdict = reviewer.review(candidate, prepared["packet"], coverage=prepared["coverage"], verification=verification)
            record["reviews"].append({"stage": phase,
                                      "candidate_hash": digest(candidate), "source_hash": prepared["source_hash"],
                                      "coverage_hash": prepared["coverage_hash"],
                                      "policy_hash": policy, "result": verdict})
            if verdict["verdict"] == "approve" and not verification:
                stage = "verify"
                record["candidate"] = candidate
                _save(store, row["id"], writer_key, policy, stage, draft, prepared, record, observed,
                      prepared_at=prepared_at)
                continue
            if verdict["verdict"] in {"approve", "skip"}:
                key = _approval_key(candidate, prepared, policy)
                record.update(candidate=candidate, approval_key=key,
                              outcome="skipped" if verdict["verdict"] == "skip" else "approved")
                receipt = (key, digest(candidate), prepared["source_hash"], policy, prepared["binding_hash"],
                           _json(verdict), _json(record), observed, observed)
                _save(store, row["id"], writer_key, policy, record["outcome"], draft, prepared, record, observed,
                      prepared_at=prepared_at, approval_key=key, approval_receipt=receipt)
                committed = store.commit_candidate(prepared, candidate, writer_key, now_iso(), approval_key=key,
                                                   policy_hash=policy, review_record=record, decision=verdict["verdict"])
                return {**report, "status": committed["status"]}
            if verdict["verdict"] == "hold" or verification:  # one repair at most, and only a verified one
                _hold(store, row, draft, writer_key, record, observed, phase, "model_hold")
                return {**report, "status": "held"}
            if prepared["payload"]["editorial_kind"] == "tag":
                _hold(store, row, draft, writer_key, record, observed, phase, "tag_repair")
                return {**report, "status": "held"}
            try:
                candidate = review.apply_repair(candidate, verdict["repair"])
            except review.ReviewError:
                _hold(store, row, draft, writer_key, record, observed, phase, "unusable_repair")
                return {**report, "status": "held"}
            stage = "verify"
            record["candidate"] = candidate
            _save(store, row["id"], writer_key, policy, stage, draft, prepared, record, observed, prepared_at=prepared_at)
    except (StaleCandidate, ReviewRequired):
        return {**report, "status": "stale"}
    finally:
        _prune(store, MAX_APPROVALS)
