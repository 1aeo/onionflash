"""Explicit synthetic approvals for legacy fixtures, never production bypasses.

These helpers let tests of ordering, rendering, correction and retention prepare
published data through the real approval boundary. Gate/protocol tests use their
own responses and do not import or globally install this fixture behavior.
"""

import json

from onionflash import review, review_gate
from onionflash.config import DEFAULTS
from onionflash.util import digest


def approved_result(candidate, packet):
    refs = [packet["sources"][0]["id"]] if packet["sources"] else []
    result = {"verdict": "approve", "criteria": {
        name: {"outcome": "pass", "source_refs": refs,
               "reason": "Explicit synthetic approval for this isolated test fixture."}
        for name in review.CRITERIA}, "issues": [], "repair": None}
    return review.validate_review(result, candidate, packet, verification=True)


class ApprovingReviewer:
    """Use only where an existing CLI test supplies an equally synthetic writer."""
    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def review(self, candidate, packet, *, verification=False):
        return approved_result(candidate, packet)


def finish_reviewed(store, row, result, key, observed, *, input_chars=None):
    if not result["publish"]:
        return store.finish(row, result, key, observed, input_chars=input_chars)
    prepared = store.prepare_candidate(row, result, observed, input_chars=input_chars,
                                       review_settings=DEFAULTS["review"])
    receipt, audit = {}, None
    if prepared["requires_review"]:
        review_gate.initialize(store)
        approval = approved_result(prepared["candidate"], prepared["packet"])
        policy = review.policy_hash(DEFAULTS)
        approval_key = digest(["synthetic-fixture-approval", prepared["candidate_hash"],
                               prepared["source_hash"], policy, prepared["binding_hash"]])
        audit = {"fixture": True, "candidate": prepared["candidate"], "packet": prepared["packet"],
                 "reviews": [{"result": approval}], "outcome": "approved"}
        with store.db:
            store.db.execute("""INSERT OR REPLACE INTO review_approvals
                (key,candidate_hash,source_hash,policy_hash,binding_hash,result_json,review_record_json,created_at,last_used_at)
                VALUES(?,?,?,?,?,?,?,?,?)""", (approval_key, prepared["candidate_hash"], prepared["source_hash"],
                    policy, prepared["binding_hash"], json.dumps(approval), json.dumps(audit), observed, observed))
        receipt = {"approval_key": approval_key, "policy_hash": policy}
    return store.commit_candidate(prepared, prepared["candidate"], key, observed,
                                  review_record=audit, **receipt)
