"""Authentic synthetic v2 receipts, isolated from the current reply producer.

The fixture was emitted by the earlier native transition. Tests never rewrite its
policy to the current one. Selecting its historical contract is only for testing
the retained reader; real policy-upgrade tests must use the real policy hash.
"""
import copy
import hashlib
import json
from pathlib import Path

from onionflash import review, review_gate
from onionflash.analyze import cache_key


_FIXTURE = Path(__file__).with_name("fixtures") / "legacy_review_v2.json"
_FIXTURE_SHA256 = "878126ebd31ddb028c69f6f66728d8f9ce93f1a7d715d4163d097ce2db91db0b"
_JOB_COLUMNS = ("item_id", "writer_key", "policy_hash", "stage", "draft_json",
                "envelope_json", "record_json", "approval_key", "prepared_at", "updated_at")


def _load(name):
    raw = _FIXTURE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == _FIXTURE_SHA256
    return copy.deepcopy(json.loads(raw)["fixtures"][name])


def legacy_update():
    """Return an unchanged historical update prefix for direct reader checks."""
    saved = _load("update")
    return saved["record"], saved["prepared"], saved["candidate"]


def _install_recorded_job(cfg, store, row, *, label_repair=False):
    saved = _load("release_labels" if label_repair else "story")
    job = saved["job"]
    assert row == saved["row"]
    assert set(job) == set(_JOB_COLUMNS)
    assert cache_key(row, cfg["llm"]) == job["writer_key"]
    assert review.policy_hash(cfg) != job["policy_hash"]
    assert store.db.execute("SELECT 1 FROM review_jobs WHERE item_id=?", (row["id"],)).fetchone() is None
    record = json.loads(job["record_json"])
    prepared = json.loads(job["envelope_json"])
    review_gate.validate_review_state(record, job["stage"], record["candidate"], prepared)
    with store.db:
        store.db.execute(
            "INSERT INTO review_jobs (" + ",".join(_JOB_COLUMNS) + ") VALUES (" +
            ",".join("?" for _ in _JOB_COLUMNS) + ")",
            tuple(job[name] for name in _JOB_COLUMNS),
        )
    return record


def install_legacy_pending(cfg, store, row, monkeypatch, *, label_repair=False):
    """Install a real old receipt and explicitly select its reader-only contract."""
    if label_repair:
        # This historical contract predates the merge-evidence backstop. Keep
        # its recorded text and policy intact while testing that old path.
        # Real policy-upgrade tests retain the current guard and fingerprint.
        monkeypatch.setattr(review.merge_evidence, "missing_completion", lambda *args, **kwargs: False)
    record = _install_recorded_job(cfg, store, row, label_repair=label_repair)
    # Keep every recorded identity intact. This explicitly exercises the old
    # reader contract, not an upgrade or the current invalid-response producer.
    historical_policy = record["policy_hash"]
    monkeypatch.setattr(review, "policy_hash", lambda config: historical_policy)
    assert review.policy_hash(cfg) == historical_policy
    return record


def install_for_policy_upgrade(cfg, store, row):
    """Install the old job without changing current policy selection or its hash."""
    current = review.policy_hash(cfg)
    record = _install_recorded_job(cfg, store, row)
    assert review.policy_hash(cfg) == current != record["policy_hash"]
    return record
