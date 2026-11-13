"""Synthetic review replies and approvals for tests, never production bypasses.

Tests of ordering, rendering, correction and retention prepare published data
through the real approval boundary with `finish_reviewed`. Gate and protocol
tests script their reviewer replies with `verdict`.
"""

import json

from onionflash import review, review_gate
from onionflash.util import digest


def verdict(action="approve", *, repair=None, criterion="operational_advice", ref="S1"):
    """A reviewer reply in which every criterion passes, or `criterion` fails."""
    checks = {name: {"reason": "Supported by the supplied source.", "source_refs": [ref], "outcome": "pass"}
              for name in review.CRITERIA}
    if action != "approve":
        checks[criterion].update(reason="The source does not support this claim.", outcome="fail")
    # A reply names every editable field and leaves the unchanged ones null.
    wire = None if repair is None else {key: repair.get(key) for key in review.EDITABLE}
    return {"criteria": checks, "verdict": action, "repair": wire}


def approved_result(packet):
    return review.validate_review(verdict(), packet)


class ApprovingReviewer:
    """Use only where an existing CLI test supplies an equally synthetic writer."""
    calls = 0

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def review(self, candidate, packet, *, coverage=None, verification=False, issue=None, on_request=None):
        if on_request is not None:
            on_request(1)
        return approved_result(packet)


def approve(store, prepared, candidate=None, *, policy="test-policy", result=None):
    """Record the receipt the gate saves when review approves this exact candidate."""
    candidate = candidate or prepared["candidate"]
    result = result or approved_result(prepared["packet"])
    key = review_gate._approval_key(candidate, prepared, policy)
    context = {"source_hash": prepared["source_hash"], "coverage_hash": prepared["coverage_hash"],
               "binding_hash": prepared["binding_hash"], "policy_hash": policy}
    if result["verdict"] == "skip":
        reviews = [{"stage": "review", "candidate_hash": digest(candidate), "request": 1, "result": result, **context}]
    else:
        changes = {key: candidate[key] for key in review.EDITABLE if candidate[key] != prepared["candidate"][key]}
        first = review.validate_review(verdict("revise", repair=changes) if changes else verdict(), prepared["packet"])
        reviews = [{"stage": "review", "candidate_hash": digest(prepared["candidate"]), "request": 1, "result": first, **context},
                   {"stage": "verification", "candidate_hash": digest(candidate), "request": 2, "result": result, **context}]
    audit = {"candidate": candidate, "packet": prepared["packet"], "coverage": prepared["coverage"], "reviews": reviews,
             "policy_hash": policy, "request_budget": {"reserved": len(reviews), "inconsistent_requests": []},
             "untrusted_proposals": [], "approval_key": key, "outcome": "skipped" if result.get("verdict") == "skip" else "approved"}
    with store.db:
        store.db.execute("""INSERT OR REPLACE INTO review_approvals (key,candidate_hash,source_hash,policy_hash,
            binding_hash,result_json,review_record_json,created_at,last_used_at) VALUES(?,?,?,?,?,?,?,?,?)""",
            (key, digest(candidate), prepared["source_hash"], policy, prepared["binding_hash"],
             json.dumps(result), json.dumps(audit), prepared["observed"], prepared["observed"]))
    return {"approval_key": key, "policy_hash": policy}


def finish_reviewed(store, row, result, key, observed, *, decision="approve"):
    prepared = store.prepare_candidate(row, result, observed)
    reply = verdict("skip", criterion="news_value") if decision == "skip" else None
    receipt = {} if prepared["locked"] else approve(store, prepared, result=reply)
    return store.commit_candidate(prepared, prepared["candidate"], key, observed, decision=decision, **receipt)
