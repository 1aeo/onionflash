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
MAX_REVIEW_REQUESTS = MAX_VERIFY_REPAIRS + 2
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


def initial_review_state():
    """Only newly created chains initialize these fields; saved chains require them."""
    return {"request_budget": {"reserved": 0, "inconsistent_requests": []}, "untrusted_proposals": []}


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
    record = {"schema_version": 1, "writer": {"key": row["writer_key"]}, "input_row": item, "reviews": [], **initial_review_state()}
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


class ReviewRequests:
    """Reserve endpoint attempts before sending; interruptions never replenish them."""

    def __init__(self, record, persist=lambda: None):
        self.record, self.persist, self.actual = record, persist, 0
        if not isinstance(record, dict) or not isinstance(record.get("reviews"), list):
            raise AnalysisError("Saved review state is damaged", code="app.damaged_job")
        if "request_budget" not in record or not isinstance(record.get("untrusted_proposals"), list):
            raise AnalysisError("Saved review ledger is missing", code="app.damaged_job")
        state = record["request_budget"]
        if (not isinstance(state, dict) or set(state) != {"reserved", "inconsistent_requests"}
                or type(state.get("reserved")) is not int
                or not len(record["reviews"]) <= state["reserved"] <= MAX_REVIEW_REQUESTS
                or not isinstance(state.get("inconsistent_requests"), list)
                or any(type(n) is not int or not 1 <= n <= state["reserved"] for n in state["inconsistent_requests"])
                or state["inconsistent_requests"] != sorted(set(state["inconsistent_requests"]))):
            raise AnalysisError("Saved review request budget is damaged", code="app.damaged_job")
        self.state = state

    def callback(self):
        previous = None

        def count(delta):
            nonlocal previous
            if delta == 1:
                if self.state["reserved"] >= MAX_REVIEW_REQUESTS:
                    raise review.ReviewLimitReached("Review request budget exhausted")
                previous = self.state["reserved"]
                self.state["reserved"] += 1
            elif delta == -1 and previous is not None:
                self.state["reserved"] = previous
                previous = None
            else:
                raise ValueError("Invalid review request accounting")
            self.persist()
            self.actual += delta
        return count


def _context(prepared, policy):
    """Bind a proposal to sources, coverage and the current candidate assembly."""
    source, coverage = digest(prepared["packet"]), digest(prepared.get("coverage"))
    binding = digest(prepared["binding"]) if "binding" in prepared else digest([prepared["row"], prepared["payload"]])
    for key, value in (("source_hash", source), ("coverage_hash", coverage), ("binding_hash", binding)):
        if key in prepared and prepared[key] != value:
            raise AnalysisError("Saved proposal binding is damaged", code="app.damaged_job")
    return {"source_hash": source, "coverage_hash": coverage, "binding_hash": binding, "policy_hash": policy}


def pending_proposal(record):
    return next((proposal for proposal in record.get("untrusted_proposals", [])
                 if proposal["disposition"] == "pending"), None)


def proposal_needs_check(record):
    """Earlier verified facts cannot clear a later invalid proposal attempt."""
    active = [p for p in record.get("untrusted_proposals", []) if p["disposition"] != "discarded_context"]
    latest = max((entry.get("request", 0) for entry in record["reviews"]), default=0)
    return bool(pending_proposal(record)) or bool(active and latest <= active[-1]["request"])


def validate_review_state(record, stage, candidate, prepared, *, allow_cached=True):
    """Fail closed on damaged bookkeeping before it can reach a cached approval."""
    budget = ReviewRequests(record).state
    proposals = record.get("untrusted_proposals", [])
    dispositions = {"pending", "superseded_unverified", "discarded_context", "unusable", "literal_tag", "labels", "repeated",
                    "checked_approve", "checked_revise", "checked_hold", "checked_skip"}
    fields = {"error", "request", "stage", "candidate_before_hash", "candidate_after_hash", "context", "changed_fields", "repair",
              "accepted", "disposition"}
    def hashed(value):
        return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)
    try:
        if stage == "drafted":
            if prepared is not None or record["reviews"] or proposals or budget["reserved"] or "candidate" in record:
                raise ValueError()
            return
        if not isinstance(prepared, dict):
            raise ValueError()
        if not isinstance(proposals, list) or len(proposals) > MAX_REVIEW_REQUESTS:
            raise ValueError()
        for entry in record["reviews"]:
            if (not isinstance(entry, dict) or entry.get("stage") not in {"review", "verification"}
                    or not hashed(entry.get("candidate_hash"))):
                raise ValueError()
            review.validate_review(entry["result"], prepared["packet"])
        for proposal in proposals:
            if (not isinstance(proposal, dict) or set(proposal) != fields
                    or proposal["error"] != review.INCONSISTENT_VERDICT
                    or type(proposal["request"]) is not int or not 1 <= proposal["request"] <= budget["reserved"]
                    or proposal["stage"] not in {"review", "verify", "repair"}
                    or not hashed(proposal["candidate_before_hash"])
                    or (proposal["candidate_after_hash"] is not None and not hashed(proposal["candidate_after_hash"]))
                    or type(proposal["accepted"]) is not bool or proposal["disposition"] not in dispositions
                    or not isinstance(proposal["context"], dict)
                    or set(proposal["context"]) != {"source_hash", "coverage_hash", "binding_hash", "policy_hash"}
                    or not all(hashed(value) for value in proposal["context"].values())
                    or not isinstance(proposal["changed_fields"], list)
                    or proposal["changed_fields"] != sorted(set(proposal["changed_fields"]))
                    or set(proposal["changed_fields"]) - set(review.EDITABLE)):
                raise ValueError()
            accepted = proposal["accepted"]
            if (proposal["repair"] is not None and not isinstance(proposal["repair"], dict)):
                raise ValueError()
            if proposal["repair"] is not None:
                review._repair_fields(proposal["repair"])
            if accepted and (proposal["candidate_after_hash"] is None or not proposal["changed_fields"]):
                raise ValueError()
            if accepted and proposal["disposition"] in {"unusable", "literal_tag", "labels", "repeated"}:
                raise ValueError()
            if proposal["disposition"] in {"pending", "superseded_unverified"} and not accepted:
                raise ValueError()
            if proposal["disposition"].startswith("checked_"):
                verdict = proposal["disposition"].removeprefix("checked_")
                if not accepted or not any(entry["stage"] == "verification"
                        and entry["candidate_hash"] == proposal["candidate_after_hash"]
                        and type(entry.get("request")) is int and proposal["request"] < entry["request"] <= budget["reserved"]
                        and entry["result"]["verdict"] == verdict
                        and all(entry.get(key) == value for key, value in proposal["context"].items())
                        for entry in record["reviews"]):
                    raise ValueError()
        if [p["request"] for p in proposals] != budget["inconsistent_requests"]:
            raise ValueError()
        waiting = [p for p in proposals if p["disposition"] == "pending"]
        if len(waiting) > 1:
            raise ValueError()
        if waiting:
            if (stage != "verify" or waiting[0]["candidate_after_hash"] != digest(candidate)
                    or waiting[0]["context"] != _context(prepared, record["policy_hash"])
                    or any(entry["candidate_hash"] == waiting[0]["candidate_after_hash"]
                           and entry.get("request", 0) > waiting[0]["request"] for entry in record["reviews"])):
                raise ValueError()
        _validate_candidate_path(record, stage, candidate, prepared, allow_cached=allow_cached)
    except (ValueError, TypeError, KeyError, AttributeError, review.ReviewError):
        raise AnalysisError("Saved review proposal state is damaged", code="app.damaged_job") from None


def _validate_candidate_path(record, stage, candidate, prepared, *, allow_cached):
    """Reconstruct the exact edited text; removing a pending flag cannot bless it."""
    context = _context(prepared, record["policy_hash"])
    current = prepared.get("candidate", record.get("candidate"))
    expected_stage, trusted, seen = "review", [], {digest(current)}
    last_action, last_value = None, None
    events = [(entry.get("request"), False, entry) for entry in record["reviews"]]
    events += [(proposal["request"], True, proposal) for proposal in record["untrusted_proposals"]
               if proposal["disposition"] != "discarded_context"]
    if (any(type(number) is not int or not 1 <= number <= record["request_budget"]["reserved"] for number, _, _ in events)
            or len({number for number, _, _ in events}) != len(events)):
        raise ValueError()
    for _, proposal, entry in sorted(events, key=lambda value: value[0]):
        if proposal:
            if entry["context"] != context or entry["stage"] != expected_stage or entry["candidate_before_hash"] != digest(current):
                raise ValueError()
            if entry["candidate_after_hash"] is not None:
                after = review.apply_repair(current, entry["repair"])
                if (digest(after) != entry["candidate_after_hash"]
                        or entry["changed_fields"] != sorted(key for key in current if after.get(key) != current[key])):
                    raise ValueError()
            if entry["accepted"]:
                if (prepared["payload"]["editorial_kind"] == "tag" or digest(after) in seen
                        or not _allowed_proposal(current, after, prepared)):
                    raise ValueError()
                current, expected_stage = after, "verify"
                seen.add(digest(current))
        else:
            actual_stage = "repair" if entry.get("issue") == "release_labels" else "verify" if entry["stage"] == "verification" else "review"
            if (actual_stage != expected_stage or entry["candidate_hash"] != digest(current)
                    or any(entry.get(key) != value for key, value in context.items())):
                raise ValueError()
            trusted.append(entry)
            action, value = next_step(trusted, current, prepared)
            last_action, last_value = action, value
            if action in {"verify", "repair"}:
                if digest(value) != digest(current) and digest(value) in seen:
                    expected_stage = "held"
                else:
                    current, expected_stage = value, action
                    seen.add(digest(current))
            else:
                expected_stage = {"approve": "approved", "skip": "skipped", "hold": "held"}[action]
    if (digest(current) != digest(candidate)
            or (not allow_cached and digest(record.get("candidate")) != digest(candidate))):
        raise ValueError()
    # A zero-call cache hit records its validated proof separately from the
    # current chain. It does not manufacture current-chain reviewer requests.
    cached_terminal = False
    if stage in {"approved", "skipped"} or "approval" in record:
        key = digest([digest(candidate), context["source_hash"], record["policy_hash"], context["binding_hash"]])
        if record.get("approval_key") != key:
            raise ValueError()
        if "approval" in record:
            proof = record["approval"]
            proof_stage = stage
            if stage == "held" and record.get("hold_code") in review.final_holds(candidate, prepared):
                proof_stage = "approved"
            if (not allow_cached or proposal_needs_check(record) or proof_stage not in {"approved", "skipped"}
                    or record.get("outcome") != stage or not isinstance(proof, dict)
                    or proof.get("policy_hash") != record["policy_hash"] or proof.get("approval_key") != key
                    or proof.get("outcome") != proof_stage):
                raise ValueError()
            validate_review_state(proof, proof_stage, candidate, prepared, allow_cached=False)
            cached_terminal = True
    # A completed approval may now hit a final guard. Its validated receipt
    # still lets the normal cache path record that hold without a model call.
    guarded_approval = (stage == "approved" and expected_stage == "held" and last_action == "hold"
                        and last_value[0] == "final_check")
    if (stage != expected_stage and not guarded_approval and not cached_terminal
            and not (stage == "held" and record.get("hold_code") in {"missing_sources", "repeat_hold"})):
        raise ValueError()


def _allowed_proposal(before, after, prepared):
    limits = review.label_limits(prepared["packet"]["sources"])
    return (set(after) == set(before)
            and all(after[key] == before[key] for key in before if key not in review.EDITABLE)
            and all(after[field] in allowed for field, allowed in limits.items()))


def _seen_candidates(record, candidate, prepared):
    context = _context(prepared, record["policy_hash"])
    return {digest(candidate), *(entry["candidate_hash"] for entry in record["reviews"]),
            *(value for proposal in record.get("untrusted_proposals", [])
              if proposal["context"] == context and proposal["disposition"] != "discarded_context"
              for value in (proposal["candidate_before_hash"], proposal["candidate_after_hash"]) if value)}


def recovery_status(record):
    """Report protocol failures separately from legitimate final review decisions."""
    proposals = record.get("untrusted_proposals", [])
    terminal = record.get("outcome") in {"approved", "skipped", "held", "locked"}
    unresolved = bool(proposals) and (proposal_needs_check(record) or not terminal
        or record.get("hold_code") in {"unusable_repair", "repeated_repair", "repairs_exhausted", "release_labels"})
    return {"raw_inconsistency_count": len(proposals), "accepted_proposal_count": sum(p["accepted"] for p in proposals),
            "unresolved_inconsistency": unresolved}


def call_review(reviewer, stage, candidate, prepared, *, requests) -> dict:
    """Return only a genuinely validated reply; an invalid reply remains an exception."""
    result = reviewer.review(candidate, prepared["packet"], coverage=prepared["coverage"], verification=stage == "verify",
                             issue=review.RELEASE_ISSUE if stage == "repair" else None, on_request=requests.callback())
    return {"stage": "verification" if stage == "verify" else "review", **({"issue": "release_labels"} if stage == "repair" else {}),
            "candidate_hash": digest(candidate), "request": requests.state["reserved"], "result": result}


def advance_review(reviewer, stage, candidate, prepared, record, requests):
    """Runtime and evaluation share the same untrusted-proposal transition.

    The first valid fresh verification after an invalid initial reply is the first
    trusted news decision. Invalid criteria never become a disagreement anchor.
    """
    validate_review_state(record, stage, candidate, prepared)
    seen = _seen_candidates(record, candidate, prepared)
    waiting = pending_proposal(record)
    before = requests.actual
    try:
        entry = call_review(reviewer, stage, candidate, prepared, requests=requests)
    except review.InconsistentReview as error:
        if requests.actual == before:
            raise
        event = {"error": review.INCONSISTENT_VERDICT, "request": requests.state["reserved"], "stage": stage,
                 "candidate_before_hash": digest(candidate), "candidate_after_hash": None,
                 "context": _context(prepared, record["policy_hash"]), "changed_fields": [],
                 "repair": None, "accepted": False, "disposition": "unusable"}
        requests.state["inconsistent_requests"].append(event["request"])
        record.setdefault("untrusted_proposals", []).append(event)
        try:
            if prepared["payload"]["editorial_kind"] == "tag":
                event["disposition"] = "literal_tag"
                raise review.ReviewError("Literal tags cannot use untrusted edits")
            repaired = review.apply_repair(candidate, error.proposal)
            event["candidate_after_hash"] = digest(repaired)
            event["changed_fields"] = sorted(key for key in candidate if repaired.get(key) != candidate[key])
            event["repair"] = {key: repaired[key] for key in event["changed_fields"]}
            if not _allowed_proposal(candidate, repaired, prepared):
                event["disposition"] = "labels"
                raise review.ReviewError("Untrusted edit exceeds packet label limits")
            if event["candidate_after_hash"] in seen:
                event["disposition"] = "repeated"
                raise review.ReviewError("Untrusted edit repeats a reviewed candidate")
        except review.ReviewError:
            requests.persist()
            raise error
        if waiting is not None:
            waiting["disposition"] = "superseded_unverified"
        event.update(accepted=True, disposition="pending")
        # The caller persists this audit, exact candidate and verify stage before
        # requesting its next step. No invalid reply is appended to reviews.
        return "verify", repaired
    if waiting is not None:
        if entry["stage"] != "verification" or entry["candidate_hash"] != waiting["candidate_after_hash"]:
            raise AnalysisError("Proposal verification identity changed", code="app.damaged_job")
        waiting["disposition"] = "checked_" + entry["result"]["verdict"]
    record["reviews"].append({**entry, **_context(prepared, record["policy_hash"])})
    action, value = next_step(record["reviews"], candidate, prepared)
    if action in {"verify", "repair"} and digest(value) != digest(candidate) and digest(value) in seen:
        return "hold", ("verification" if stage == "verify" else "review", "repeated_repair")
    return action, value


def _verified(reviews) -> bool:
    """Whether the latest review is a fresh verification that passed every factual criterion and cites a source."""
    criteria = reviews[-1]["result"]["criteria"] if reviews and reviews[-1]["stage"] == "verification" else None
    return bool(criteria and criteria["source_support"]["source_refs"]) and all(
        check["outcome"] == "pass" for name, check in criteria.items() if name not in review.EDITORIAL_CRITERIA)


def _hold(store, row, draft, writer_key, record, observed, stage, reason):
    """One semantic hold is terminal; only source change/operator retry requeues."""
    record.update(outcome="held", hold_code=reason, hold_reason=HOLDS[reason], verified_facts=not proposal_needs_check(record) and _verified(record["reviews"]))
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
    from .editorial import RetiredStory, retired

    observed = observed or now_iso()
    policy = review.policy_hash(config)
    writer_key = cache_key(row, config["llm"])
    report = {"status": "pending", "writer_calls": 0, "review_calls": 0, "cache_hit": False}
    try:
        if candidate_mod.existing_story(store.db, row) is None and retired(
                store.db, story_id=digest(row["cluster_key"])[:24], cluster_key=row["cluster_key"]) is not None:
            raise RetiredStory("Story is retired")
    except RetiredStory:
        with store.db:
            if not store.db.execute("""UPDATE items SET status='ignored',story_id=NULL,next_attempt_at=NULL,
                    last_error='Retired story; never recreated' WHERE id=? AND content_hash=? AND status='pending'""",
                    (row["id"], row["content_hash"])).rowcount:
                return {**report, "status": "stale"}
            store.db.execute("DELETE FROM review_jobs WHERE item_id=?", (row["id"],))
            decisions.record(store.db, row["id"], "skipped.gate.retired_story", observed)
        return {**report, "status": "ignored"}
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
        record = {"schema_version": 1, "writer": None, "input_row": row, "reviews": [], **initial_review_state()}
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
        if job is not None and job["policy_hash"] == policy:
            if job["stage"] != "drafted" and record.get("policy_hash") != policy:
                raise AnalysisError("Saved review policy is damaged", code="app.damaged_job")
            if job["stage"] in {"approved", "skipped"} and job["approval_key"] != record.get("approval_key"):
                raise AnalysisError("Saved approval key is damaged", code="app.damaged_job")
            validate_review_state(record, job["stage"], record.get("candidate", (old or {}).get("candidate")), old)
        prepared = store.prepare_candidate(row, draft, prepared_at)
        same = old is not None and job["policy_hash"] == policy and _identity(old) == _identity(prepared)
        stage = job["stage"] if same else "review"
        fresh = {"schema_version": 1, "writer": record["writer"], "input_row": row, "reviews": [], "policy_hash": policy, **initial_review_state(),
                 "prepared": {key: prepared[key] for key in ("candidate", "packet", "coverage", "candidate_hash", "source_hash", "coverage_hash", "binding_hash")}}
        # A coverage change invalidates old reviews, not the request budget of
        # this source revision and policy. Explicit operator retry starts afresh.
        if job is not None and job["policy_hash"] == policy:
            fresh["request_budget"] = record["request_budget"]
            if record.get("untrusted_proposals"):
                fresh["untrusted_proposals"] = [{**proposal, "disposition": "discarded_context"}
                                                for proposal in record["untrusted_proposals"]]
        record = record if same else fresh
        candidate = record.get("candidate", prepared["candidate"])
        validate_review_state(record, stage, candidate, prepared)
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
        cached = None if proposal_needs_check(record) else store.db.execute("SELECT * FROM review_approvals WHERE key=?", (key,)).fetchone()
        if cached is not None:
            try:
                verdict = review.validate_review(json.loads(cached["result_json"]), prepared["packet"])
                proof = json.loads(cached["review_record_json"])
                if not isinstance(proof, dict) or proof.get("policy_hash") != policy:
                    raise AnalysisError("Cached review policy is damaged", code="app.damaged_job")
                validate_review_state(proof, "approved" if verdict["verdict"] == "approve" else "skipped", candidate, prepared, allow_cached=False)
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
        requests = ReviewRequests(record, lambda: _save(store, row["id"], writer_key, policy, stage, draft, prepared,
                                                        record, observed, prepared_at=prepared_at))
        while True:
            if not allow_network:
                return {**report, "status": "deferred"}
            try:
                action, value = advance_review(reviewer, stage, candidate, prepared, record, requests)
            except review.ReviewLimitReached as exc:
                store.reject(row["id"], str(exc), "failed." + exc.code, observed)
                raise
            finally:
                report["review_calls"] = requests.actual
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
    try:
        validate_review_state(record, "held", record.get("candidate", saved_env.get("candidate")), saved_env)
    except (AnalysisError, ValueError, TypeError, KeyError):
        return refuse("Saved proposal or review state cannot be read")
    if proposal_needs_check(record):
        return refuse("An untrusted proposal still needs a fresh valid review")
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
