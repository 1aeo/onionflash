"""Synthetic review replies and approvals for tests, never production bypasses.

Tests of ordering, rendering, correction and retention prepare published data
through the real approval boundary with `finish_reviewed`. Gate and protocol
tests script their reviewer replies with `verdict`.
"""

import json

from onionflash import review, review_gate
from onionflash.config import DEFAULTS
from onionflash.util import digest


def verdict(action="approve", *, repair=None, criterion="operational_advice", ref="S1"):
    """A reviewer reply in which every criterion passes, or `criterion` fails with one issue."""
    checks = {name: {"outcome": "pass", "source_refs": [ref], "reason": "Supported by the supplied source."}
              for name in review.CRITERIA}
    issues = []
    if action != "approve":
        checks[criterion]["outcome"] = "fail"
        issues = [{"criterion": criterion, "source_refs": [ref], "explanation": "The source does not support this claim."}]
    # A reply names every editable field and leaves the unchanged ones null.
    wire = None if repair is None else {key: repair.get(key) for key in review.EDITABLE}
    return {"verdict": action, "criteria": checks, "issues": issues, "repair": wire}


def approved_result(packet):
    return review.validate_review(verdict(), packet)


class ApprovingReviewer:
    """Use only where an existing CLI test supplies an equally synthetic writer."""
    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def review(self, candidate, packet, *, verification=False):
        return approved_result(packet)


def approve(store, prepared, candidate=None, *, policy="test-policy", result=None):
    """Record the receipt the gate saves when review approves this exact candidate."""
    candidate = candidate or prepared["candidate"]
    result = result or approved_result(prepared["packet"])
    key = review_gate._approval_key(candidate, prepared, policy)
    audit = {"candidate": candidate, "packet": prepared["packet"], "reviews": [{"result": result}], "outcome": "approved"}
    review_gate.initialize(store)
    with store.db:
        store.db.execute("""INSERT OR REPLACE INTO review_approvals (key,candidate_hash,source_hash,policy_hash,
            binding_hash,result_json,review_record_json,created_at,last_used_at) VALUES(?,?,?,?,?,?,?,?,?)""",
            (key, digest(candidate), prepared["source_hash"], policy, prepared["binding_hash"],
             json.dumps(result), json.dumps(audit), prepared["observed"], prepared["observed"]))
    return {"approval_key": key, "policy_hash": policy}


def finish_reviewed(store, row, result, key, observed, *, input_chars=None):
    if not result["publish"]:
        return store.finish(row, result, key, observed, input_chars=input_chars)
    prepared = store.prepare_candidate(row, result, observed, input_chars=input_chars,
                                       review_settings=DEFAULTS["review"])
    receipt = approve(store, prepared) if prepared["requires_review"] else {}
    return store.commit_candidate(prepared, prepared["candidate"], key, observed, **receipt)
