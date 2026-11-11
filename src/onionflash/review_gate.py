"""Durable stages for reviewing the exact candidate before its guarded commit.

The existing item queue owns scheduling and backoff. These private tables retain
one unfinished job per item and a bounded cache of exact review approvals; they
are not a cache of writer responses for arbitrary future items.
"""

from __future__ import annotations

import json

from .analyze import AnalysisError, cache_key
from .util import digest, now_iso


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)


def initialize(store):
    store.db.executescript("""
        CREATE TABLE IF NOT EXISTS review_jobs (
            item_id TEXT PRIMARY KEY, writer_key TEXT NOT NULL,
            policy_hash TEXT NOT NULL, stage TEXT NOT NULL,
            draft_json TEXT, envelope_json TEXT, record_json TEXT NOT NULL,
            approval_key TEXT, prepared_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS review_approvals (
            key TEXT PRIMARY KEY, candidate_hash TEXT NOT NULL,
            source_hash TEXT NOT NULL, policy_hash TEXT NOT NULL,
            binding_hash TEXT NOT NULL, result_json TEXT NOT NULL,
            review_record_json TEXT NOT NULL, created_at TEXT NOT NULL,
            last_used_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS review_approvals_used ON review_approvals(last_used_at,key);
    """)


def status(store):
    """Read compact stage/cache counts without creating tables or loading bodies."""
    tables = {row[0] for row in store.db.execute("""SELECT name FROM sqlite_master
        WHERE type='table' AND name IN ('review_jobs','review_approvals')""")}
    stages = dict(store.db.execute("SELECT stage,COUNT(*) FROM review_jobs GROUP BY stage")) if "review_jobs" in tables else {}
    approvals = store.db.execute("SELECT COUNT(*) FROM review_approvals").fetchone()[0] if "review_approvals" in tables else 0
    return {"stages": stages, "approval_cache_entries": approvals}


def reset_review_work(store, item_id):
    """Explicit operator retry starts a new review, retaining its completed draft.

    The caller owns the transaction and preserves the superseded review audit.
    """
    if not store.db.execute("SELECT 1 FROM sqlite_master WHERE name='review_jobs'").fetchone():
        return
    row = store.db.execute("SELECT * FROM review_jobs WHERE item_id=?", (item_id,)).fetchone()
    if row is None:
        return
    _archive_job(store, row, now_iso(), "explicit operator retry")
    old = json.loads(row["record_json"])
    record = {"schema_version": 1, "writer": old.get("writer"), "input_row": old["input_row"], "reviews": []}
    store.db.execute("""UPDATE review_jobs SET stage='drafted',envelope_json=NULL,
        record_json=?,approval_key=NULL,updated_at=? WHERE item_id=?""", (_json(record), now_iso(), item_id))


def _archive_job(store, job, observed, reason):
    """Retain an invalidated stage and its original source, in the caller's txn."""
    record = json.loads(job["record_json"])
    envelope = json.loads(job["envelope_json"]) if job["envelope_json"] is not None else None
    source_row = envelope["row"] if envelope is not None else record["input_row"]
    draft = json.loads(job["draft_json"]) if job["draft_json"] is not None else {}
    audit = {**record, "outcome": "superseded", "stage": job["stage"],
             "superseded_reason": reason, "superseded_at": observed, "source_envelope": envelope}
    input_chars = envelope.get("input_chars") if envelope else (record.get("writer") or {}).get("input_chars")
    store.record_analysis(source_row, draft, job["writer_key"], observed,
                          input_chars=input_chars, review_record=audit)


def _save(store, item_id, writer_key, policy_hash, stage, draft, prepared, record, observed,
          *, prepared_at, approval_key=None, supersede=None, reason=None, approval_receipt=None):
    with store.db:
        if supersede is not None:
            _archive_job(store, supersede, observed, reason)
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


def _commit_decision(store, prepared, candidate, writer_key, policy, record, key, verdict):
    commit = store.skip_candidate if verdict == "skip" else store.commit_candidate
    return commit(prepared, candidate, writer_key, now_iso(), approval_key=key,
                  policy_hash=policy, review_record=record)


def _current(store, row):
    current = store.db.execute("SELECT content_hash,payload,status FROM items WHERE id=?", (row["id"],)).fetchone()
    return (current is not None and current["content_hash"] == row["content_hash"]
            and current["payload"] == row["payload"] and current["status"] == "pending")


def _hold(store, row, prepared, draft, writer_key, record, observed, reason):
    """One semantic hold is terminal; only source change/operator retry requeues."""
    record["outcome"] = "held"
    record["hold_reason"] = reason
    store.db.execute("BEGIN IMMEDIATE")
    with store.db:
        from .candidate import assert_current
        assert_current(store.db, prepared)
        store.record_analysis(row, draft, writer_key, observed,
                              input_chars=prepared.get("input_chars"), review_record=record)
        changed = store.db.execute("""UPDATE items SET status='rejected',attempts=attempts+1,
            rejections=MAX(rejections,3),next_attempt_at=NULL,last_error=?
            WHERE id=? AND content_hash=? AND payload=? AND status='pending'""",
            ("Final review held: " + reason, row["id"], row["content_hash"], row["payload"]))
        if changed.rowcount != 1:
            from .store import StaleCandidate
            raise StaleCandidate("Source item changed before review hold")
        store.db.execute("""UPDATE review_jobs SET stage='held',record_json=?,approval_key=NULL,
            updated_at=? WHERE item_id=?""", (_json(record), observed, row["id"]))


def process_item(config, store, row, writer, reviewer, observed=None, *, allow_network=True):
    """Resume writer → exact-candidate review → optional verification → CAS commit.

    Transport errors leave the current stage durable and raise a retryable
    AnalysisError for the existing queue's backoff. An unusable reply keeps the
    stage too, but its AnalysisError counts toward the item's three failures.
    Semantic rejection, including an unusable repair, marks the item rejected
    immediately; it never starts an endless rewrite loop.
    """
    from . import review
    from .store import ReviewRequired, StaleCandidate

    observed = observed or now_iso()
    settings = config["review"]
    policy = review.policy_hash(config)
    writer_key = cache_key(row, config["llm"])
    report = {"status": "pending", "writer_calls": 0, "review_calls": 0, "cache_hit": False}
    initialize(store)
    if not _current(store, row):
        return {**report, "status": "stale"}
    job = store.db.execute("SELECT * FROM review_jobs WHERE item_id=?", (row["id"],)).fetchone()
    superseded_input = None
    if job is not None and job["writer_key"] == writer_key:
        draft = json.loads(job["draft_json"]) if job["draft_json"] is not None else None
        record = json.loads(job["record_json"])
        prepared_at = job["prepared_at"]
    else:
        superseded_input = job
        job, draft = None, None
        record = {"schema_version": 1, "writer": None, "input_row": row, "reviews": []}
        prepared_at = observed
    if draft is None:
        if not allow_network and json.loads(row["payload"])["kind"] != "tag":
            return {**report, "status": "deferred"}
        report["writer_calls"] += json.loads(row["payload"])["kind"] != "tag"
        draft = writer.analyze(json.loads(row["payload"]))
        record["writer"] = {"key": writer_key, "result": draft, "input_chars": config["llm"]["max_input_chars"]}
        _save(store, row["id"], writer_key, policy, "drafted", draft, None, record, observed, prepared_at=prepared_at,
              supersede=superseded_input, reason="source or writer input changed")
    if not draft["publish"]:
        try:
            store.finish(row, draft, writer_key, observed, input_chars=config["llm"]["max_input_chars"])
        except (StaleCandidate, ReviewRequired):
            return {**report, "status": "stale"}
        with store.db:
            store.db.execute("DELETE FROM review_jobs WHERE item_id=?", (row["id"],))
        return {**report, "status": "ignored"}
    try:
        prepared = store.prepare_candidate(row, draft, prepared_at,
                                           input_chars=config["llm"]["max_input_chars"], review_settings=settings)
        old = json.loads(job["envelope_json"]) if job is not None and job["envelope_json"] else None
        same = old is not None and job["policy_hash"] == policy and _identity(old) == _identity(prepared)
        stage = job["stage"] if same else "review"
        superseded_context = job if job is not None and not same and (old is not None or job["policy_hash"] != policy) else None
        if not same:
            record = {"schema_version": 1, "writer": record["writer"], "input_row": row, "reviews": [], "policy_hash": policy,
                      "prepared": {key: prepared[key] for key in ("candidate", "packet", "coverage", "candidate_hash", "source_hash", "coverage_hash", "binding_hash")}}
        candidate = record.get("candidate", prepared["candidate"])
        _save(store, row["id"], writer_key, policy, stage, draft, prepared, record, observed, prepared_at=prepared_at,
              supersede=superseded_context, reason="candidate context or review policy changed",
              approval_key=job["approval_key"] if same else None)
        if prepared.get("locked"):
            record["outcome"] = "locked"
            store.commit_candidate(prepared, prepared["candidate"], writer_key, now_iso(), review_record=record)
            return {**report, "status": record["outcome"]}
        if prepared.get("missing_sources"):
            _hold(store, row, prepared, draft, writer_key, record, observed, "required source material is unavailable")
            return {**report, "status": "held"}
        if stage == "held":
            # The same candidate held before: a source reverted to a held revision,
            # or an item was requeued without reset_review_work. Do not review it again.
            _hold(store, row, prepared, draft, writer_key, record, observed, "operator review is required")
            return {**report, "status": "held"}
        key = _approval_key(candidate, prepared, policy)
        cached = store.db.execute("SELECT * FROM review_approvals WHERE key=?", (key,)).fetchone()
        if cached is not None:
            try:
                verdict = review.validate_review(json.loads(cached["result_json"]), prepared["packet"])
                proof = json.loads(cached["review_record_json"])
                valid = (verdict["verdict"] in {"approve", "skip"} and cached["candidate_hash"] == digest(candidate)
                         and cached["source_hash"] == prepared["source_hash"] and cached["policy_hash"] == policy
                         and cached["binding_hash"] == prepared["binding_hash"]
                         and review.decision_record_matches(proof, verdict, candidate=candidate, prepared=prepared, policy_hash=policy))
            except (AnalysisError, ValueError, TypeError, KeyError):
                valid = False
            if valid:
                record["approval"] = proof
                record["approval_key"] = key
                record["outcome"] = "skipped" if verdict["verdict"] == "skip" else "approved"
                _save(store, row["id"], writer_key, policy, record["outcome"], draft, prepared, record, observed,
                      prepared_at=prepared_at, approval_key=key)
                with store.db:
                    store.db.execute("UPDATE review_approvals SET last_used_at=? WHERE key=?", (observed, key))
                committed = _commit_decision(store, prepared, candidate, writer_key, policy, record, key, verdict["verdict"])
                report.update(status=committed["status"], cache_hit=True)
                return report
            with store.db:
                store.db.execute("DELETE FROM review_approvals WHERE key=?", (key,))
            if stage in {"approved", "skipped"}:
                invalidated = store.db.execute("SELECT * FROM review_jobs WHERE item_id=?", (row["id"],)).fetchone()
                record = {"schema_version": 1, "writer": record["writer"], "input_row": row,
                          "reviews": [], "policy_hash": policy, "prepared": record["prepared"]}
                candidate, stage = prepared["candidate"], "review"
                _save(store, row["id"], writer_key, policy, stage, draft, prepared, record, observed,
                      prepared_at=prepared_at, supersede=invalidated, reason="invalid cached review decision")
        while True:
            verification = stage == "verify"
            if not allow_network:
                return {**report, "status": "deferred"}
            report["review_calls"] += 1
            verdict = reviewer.review(candidate, prepared["packet"], coverage=prepared["coverage"], verification=verification)
            record["reviews"].append({"stage": "verification" if verification else "review",
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
                committed = _commit_decision(store, prepared, candidate, writer_key, policy, record, key, verdict["verdict"])
                return {**report, "status": committed["status"]}
            if verdict["verdict"] == "hold" or verification or settings["max_repairs"] == 0:
                reason = "verification did not approve the repair" if verification else "review did not approve the candidate"
                _hold(store, row, prepared, draft, writer_key, record, observed, reason)
                return {**report, "status": "held"}
            try:
                candidate = review.apply_repair(candidate, verdict["repair"])
            except review.ReviewError:
                _hold(store, row, prepared, draft, writer_key, record, observed, "review proposed an unusable repair")
                return {**report, "status": "held"}
            stage = "verify"
            record["candidate"] = candidate
            _save(store, row["id"], writer_key, policy, stage, draft, prepared, record, observed, prepared_at=prepared_at)
    except (StaleCandidate, ReviewRequired):
        return {**report, "status": "stale"}
    finally:
        _prune(store, settings["max_cache_entries"])
