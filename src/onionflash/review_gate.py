"""Durable stages for reviewing the exact candidate before its guarded commit.

The existing item queue owns scheduling and backoff. These private tables keep
one unfinished job per item, overwritten when its inputs change or an operator
retries the item, and the receipt of its recorded decision until that decision
commits; they are not a cache of writer responses for arbitrary future items.
New jobs bind input_hash to a validated source snapshot, kept in the draft
record until the prepared envelope supplies it. Older representations must
also prove their source before a mismatch can reset automatic review work.
"""

from __future__ import annotations

import contextlib
import copy
import json
import re

from . import candidate as candidate_mod, decisions, editorial, review
from .analyze import cache_key
from .llm import AnalysisError, CompletionDeferred, RequestObserver
from .util import (
    DIRAUTH_GITLAB_USERS, _GITLAB_OWN, after, canonical_url, digest, gitlab_refs, is_dirauth_item,
    is_hackerone_item, now_iso, saved_object, thread_subject,
)

REVIEW_STATE_VERSION = 2
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
OFFICIAL_AUTHORITIES = frozenset({"official", "project-sender", "hackerone", "dirauth-operator"})
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
    "shouting_caps": "the candidate contains unnormalized all-caps shouting",
    "malformed_version": "the candidate cites a nonexistent three-part C-Tor version",
    "untrusted_operator_claim": "an uncorroborated mailing-list incident claim needs a trusted source",
    "named_attribution": "a named attribution has no literal source evidence",
}


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)


def _dirauth_users(config, store):
    if isinstance(config, dict) and "dirauth_gitlab_users" in (config.get("collection") or {}):
        return config["collection"]["dirauth_gitlab_users"]
    return getattr(store, "dirauth_users", None)


def _dirauth_set(users) -> set[str]:
    return {
        u.strip().lower()
        for u in (DIRAUTH_GITLAB_USERS if users is None else users)
        if isinstance(u, str) and u.strip()
    }


def _prepare_candidate(store, row, draft, prepared_at, dirauth_users):
    had_attr = hasattr(store, "dirauth_users")
    prior_users = getattr(store, "dirauth_users", None)
    if dirauth_users is not None:
        store.dirauth_users = tuple(dirauth_users)
    try:
        return store.prepare_candidate(row, draft, prepared_at)
    finally:
        if had_attr:
            store.dirauth_users = prior_users
        elif hasattr(store, "dirauth_users"):
            delattr(store, "dirauth_users")


def _record_input_hash(record: object) -> str | None:
    if not isinstance(record, dict):
        return None
    if isinstance(record.get("input_hash"), str):
        return record["input_hash"]
    legacy = record.get("input_row")
    return legacy.get("content_hash") if isinstance(legacy, dict) else None


def initial_review_state():
    """Only newly created chains initialize these fields; saved chains require them."""
    # Keep the real version-two ledger shape: this legacy-named index covers all
    # rejected-response events; each event's fixed error distinguishes its type.
    return {"request_budget": {"reserved": 0, "inconsistent_requests": [], "validation_reask": None},
            "untrusted_proposals": []}


def _carried_requests(record):
    """A different automatic review target invalidates proof, not spent requests."""
    ReviewRequests(record)
    return {"request_budget": copy.deepcopy(record["request_budget"]),
            "untrusted_proposals": [{**copy.deepcopy(proposal), "disposition": "discarded_context"}
                                    for proposal in record["untrusted_proposals"]]}


def status(store):
    """Read compact stage/cache counts without loading bodies."""
    stages = store.db.execute(
        """SELECT stage,COUNT(*) FROM review_jobs WHERE NOT EXISTS (
               SELECT 1 FROM items i WHERE i.id=review_jobs.item_id AND i.status IN ('published','ignored','dismissed')
           ) GROUP BY stage"""
    )
    return {"stages": dict(stages),
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
    record = {"schema_version": REVIEW_STATE_VERSION, "writer": {"key": row["writer_key"]}, "input_hash": item["content_hash"], "input_proof": 1, "input_row": item, "reviews": [], **initial_review_state()}
    # A damaged draft is dropped, so the writer drafts again.
    keep = saved_object(row["draft"]) is not None
    store.db.execute("""UPDATE review_jobs SET stage='drafted',draft_json=CASE WHEN ? THEN draft_json END,envelope_json=NULL,
        record_json=?,approval_key=NULL,updated_at=? WHERE item_id=?""", (keep, _json(record), now_iso(), item_id))


def _save(store, row, writer_key, policy_hash, stage, draft, prepared, record, observed,
          *, prepared_at, approval_key=None, approval_receipt=None):
    with store.db:
        store.require_pending_item(row, "Source item changed before saving review state")
        if prepared is not None and record.get("input_proof") == 1:
            # The envelope already retains this source snapshot.
            record.pop("input_row", None)
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
            (row["id"], writer_key, policy_hash, stage, _json(draft) if draft is not None else None,
             _json(prepared) if prepared is not None else None, _json(record), approval_key, prepared_at, observed))


def _identity(prepared):
    return tuple(prepared[key] for key in ("candidate_hash", "source_hash", "binding_hash"))


def _policy_copies(record, policy):
    """Check retained policy metadata without interpreting older verdict schemas."""
    if not isinstance(policy, str) or not re.fullmatch(r"[0-9a-f]{64}", policy):
        raise ValueError()
    pending = [record]
    while pending:
        proof = pending.pop()
        if not isinstance(proof, dict) or ("policy_hash" in proof and proof["policy_hash"] != policy):
            raise ValueError()
        reviews, proposals = proof.get("reviews", []), proof.get("untrusted_proposals", [])
        if not isinstance(reviews, list) or not isinstance(proposals, list):
            raise ValueError()
        for entry in reviews:
            if not isinstance(entry, dict) or ("policy_hash" in entry and entry["policy_hash"] != policy):
                raise ValueError()
        for proposal in proposals:
            if not isinstance(proposal, dict):
                raise ValueError()
            context = proposal.get("context")
            if context is not None and (not isinstance(context, dict)
                    or ("policy_hash" in context and context["policy_hash"] != policy)):
                raise ValueError()
        if proof.get("approval") is not None:
            pending.append(proof["approval"])


def _saved_job(store, row, config):
    """Validate saved identity before a mismatch can start a fresh automatic review."""
    from .store import item_hash

    job = store.db.execute(
        """SELECT writer_key,policy_hash,stage,approval_key,prepared_at,
           typeof(draft_json) AS draft_type,CAST(draft_json AS BLOB) AS draft,
           typeof(envelope_json) AS envelope_type,CAST(envelope_json AS BLOB) AS envelope,
           typeof(record_json) AS record_type,CAST(record_json AS BLOB) AS record
           FROM review_jobs WHERE item_id=?""",
        (row["id"],),
    ).fetchone()
    if job is None:
        return None, None, None, None, False
    draft, prepared, record = (
        saved_object(job[key]) if job[key + "_type"] == "text" else None
        for key in ("draft", "envelope", "record")
    )
    try:
        if (record is None or (draft is None) != (job["draft"] is None)
                or (prepared is None) != (job["envelope"] is None)):
            raise ValueError()

        def source_identity(value):
            if not isinstance(value, dict):
                raise ValueError()
            payload = saved_object(value["payload"].encode("utf-8"))
            if (not isinstance(payload, dict) or value["id"] != row["id"] or payload.get("id") != value["id"]
                    or payload.get("url") != value["url"] or payload.get("source_id") != value["source_id"]
                    or not isinstance(value["content_hash"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", value["content_hash"])):
                raise ValueError()
            if item_hash(payload) != value["content_hash"]:
                # Older saved rows hashed the composed description. Require
                # that exact historical formula, never an arbitrary old hash.
                if (not isinstance(payload.get("source_content"), str)
                        or item_hash({k: v for k, v in payload.items() if k != "source_content"})
                        != value["content_hash"]):
                    raise ValueError()
            return value["content_hash"]

        version, marker = record.get("schema_version"), record.get("input_proof")
        if type(version) is not int or version not in {1, REVIEW_STATE_VERSION}:
            raise ValueError()
        if version == REVIEW_STATE_VERSION:
            if type(marker) is not int or marker != 1:
                raise ValueError()
            ReviewRequests(record)
        elif {"input_proof", "request_budget", "untrusted_proposals"} & set(record):
            # These fields were never emitted by a merged version-one producer.
            raise ValueError()
        if "input_hash" in record and (not isinstance(record["input_hash"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", record["input_hash"])):
            raise ValueError()
        if version == REVIEW_STATE_VERSION:
            if "input_hash" not in record:
                raise ValueError()
            proof_row = record.get("input_row") if prepared is None else prepared["row"]
        elif "input_row" in record and "input_hash" not in record:
            # Older records carried their complete source in the record.
            proof_row = record["input_row"]
        elif ("input_hash" in record and "input_row" not in record
                and job["policy_hash"] != review.policy_hash(config)):
            # Compact legacy records can use their retained envelope as proof.
            # A hash alone cannot distinguish an old source from damaged state.
            if prepared is None:
                raise AnalysisError("Saved source proof is unavailable; an explicit retry is required",
                                    code="app.source_proof_unavailable")
            proof_row = prepared["row"]
        else:
            raise ValueError()
        source_hash = source_identity(proof_row)
        if _record_input_hash(record) != source_hash:
            raise ValueError()
        if "input_row" in record and (source_identity(record["input_row"]) != source_hash
                or candidate_mod.item_fingerprint(record["input_row"]) != candidate_mod.item_fingerprint(proof_row)):
            raise ValueError()
        source_identity(row)
        same_source = (item_hash(saved_object(proof_row["payload"].encode("utf-8")))
                       == item_hash(saved_object(row["payload"].encode("utf-8"))))
        if (not isinstance(job["writer_key"], str) or not re.fullmatch(r"[0-9a-f]{64}", job["writer_key"])
                or not isinstance(record.get("writer"), dict) or record["writer"].get("key") != job["writer_key"]):
            raise ValueError()
        if prepared is not None:
            if (source_identity(prepared["row"]) != source_hash
                    or candidate_mod.item_fingerprint(proof_row) != candidate_mod.item_fingerprint(prepared["row"])
                    or prepared["binding"]["item"] != candidate_mod.item_fingerprint(prepared["row"])):
                raise ValueError()
        elif job["stage"] != "drafted":
            raise ValueError()
        if job["stage"] != "drafted" and record.get("policy_hash") != job["policy_hash"]:
            raise ValueError()
        _policy_copies(record, job["policy_hash"])
        if job["stage"] in {"approved", "skipped"} and job["approval_key"] != record.get("approval_key"):
            raise ValueError()
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        raise AnalysisError("Saved review job is damaged", code="app.damaged_job") from None
    if job["policy_hash"] == review.policy_hash(config):
        validate_review_state(record, job["stage"], record.get("candidate", (prepared or {}).get("candidate")), prepared)
    return job, draft, prepared, record, same_source


def _approval_key(candidate, prepared, policy):
    return digest([digest(candidate), prepared["source_hash"], policy, prepared["binding_hash"]])


def _prune(store, maximum):
    with store.db:
        store.db.execute("""DELETE FROM review_approvals WHERE key IN (
            SELECT key FROM review_approvals
            WHERE key NOT IN (SELECT approval_key FROM review_jobs WHERE approval_key IS NOT NULL)
            ORDER BY last_used_at DESC,key LIMIT -1 OFFSET ?)
        """, (maximum,))


_VERSION_TOKEN = re.compile(r"\b\d+\.\d+(?:\.\d+)*(?:-[a-z0-9.]+)?\b", re.I)
_PROPOSAL_TOKEN = re.compile(r"\bproposal\s+\d{3,4}\b|\bcve-\d{4}-\d+\b", re.I)
_SPECIFIC_WORD = re.compile(r"[a-z0-9]{4,}")
_GENERIC_WORDS = frozenset({
    "tor", "arti", "tails", "browser", "onion", "flash", "project", "release", "released",
    "update", "updated", "issue", "merge", "request", "report", "reported", "network",
    "relay", "relays", "service", "services", "version", "versions", "security",
    "fix", "fixes", "fixed", "change", "changes", "support", "default", "with", "from",
    "that", "this", "after", "when", "into", "over", "under", "their", "have", "were",
})


def _story_text(story: dict) -> str:
    updates = " ".join(str(e.get("text") or "") for e in (story.get("updates") or ()) if isinstance(e, dict))
    return "\n".join(str(p or "") for p in (story.get("title"), story.get("summary"), story.get("latest_update"), updates) if p)


def _story_urls(story: dict) -> set[str]:
    urls = set()
    for src in story.get("sources") or ():
        if isinstance(src, dict) and isinstance(src.get("url"), str):
            with contextlib.suppress(ValueError, TypeError, UnicodeError):
                urls.add(canonical_url(src["url"]))
    return urls


def _story_gitlab_refs(story: dict) -> set[str]:
    """Project-qualified GitLab issue and merge-request URLs derived from citation URLs."""
    text = _story_text(story)
    src_urls = [
        src["url"]
        for src in (
            *(story.get("sources") or ()),
            *(cs for u in (story.get("updates") or ()) if isinstance(u, dict) for cs in (u.get("sources") or ())),
        )
        if isinstance(src, dict) and isinstance(src.get("url"), str)
    ]
    refs = set()
    for group in gitlab_refs({"url": "", "title": "", "content": "\n".join([*src_urls, text])}):
        refs.update(group)
    projects = {}
    for raw_url in src_urls:
        with contextlib.suppress(ValueError, TypeError, UnicodeError):
            clean = canonical_url(raw_url)
            if match := _GITLAB_OWN.match(clean):
                projects[(match.group(1), match.group(2).lower())] = clean
    if len(projects) == 1:
        [context_url] = projects.values()
        for group in gitlab_refs({"url": context_url, "title": "", "content": text}):
            refs.update(group)
    return refs


def _specific_story_overlap(story_a: dict, story_b: dict) -> bool:
    """Require concrete shared identifiers before merging two published stories."""
    urls_a, urls_b = _story_urls(story_a), _story_urls(story_b)
    text_a, text_b = _story_text(story_a), _story_text(story_b)
    refs_a, refs_b = _story_gitlab_refs(story_a), _story_gitlab_refs(story_b)
    prods_a, prods_b = set(story_a.get("products") or ()), set(story_b.get("products") or ())
    if prods_a and prods_b and not (prods_a & prods_b) and not (urls_a & urls_b) and not (refs_a & refs_b):
        return False
    if story_b.get("related") or (urls_a & urls_b) or (refs_a & refs_b):
        return True
    if ({m.casefold() for m in _PROPOSAL_TOKEN.findall(text_a)}
            & {m.casefold() for m in _PROPOSAL_TOKEN.findall(text_b)}):
        return True
    vers_a = {m.casefold() for m in _VERSION_TOKEN.findall(text_a)}
    vers_b = {m.casefold() for m in _VERSION_TOKEN.findall(text_b)}
    if vers_a & vers_b:
        return True
    if vers_a and vers_b:
        return False
    subj_a, _ = thread_subject({"title": story_a.get("title") or ""})
    subj_b, _ = thread_subject({"title": story_b.get("title") or ""})
    if subj_a and subj_a == subj_b:
        return True
    words_a = {w for w in _SPECIFIC_WORD.findall(text_a.casefold()) if w not in _GENERIC_WORDS}
    words_b = {w for w in _SPECIFIC_WORD.findall(text_b.casefold()) if w not in _GENERIC_WORDS}
    return len(words_a & words_b) >= 2


def _live_recent(coverage: dict, target_id: str) -> dict | None:
    target = next((row for row in (coverage.get("recent") or ())
                   if isinstance(row, dict) and row.get("id") == target_id and not row.get("retracted")), None)
    return None if target is None or target.get("origin") == "network-health" else target


def _can_auto_merge_review(candidate: dict, prepared: dict, result: dict) -> bool:
    coverage = prepared.get("coverage") or {}
    prior = coverage.get("prior_story")
    target_id = result.get("same_story")
    if (not isinstance(prior, dict) or not isinstance(target_id, str)
            or not target_id or target_id == prior.get("id")
            or result["verdict"] not in {"approve", "revise", "skip"}):
        return False
    if (target := _live_recent(coverage, target_id)) is None:
        return False
    prior_view = {**prior, "title": prior.get("title") or candidate.get("title", ""),
                  "summary": prior.get("summary") or candidate.get("summary", ""),
                  "products": prior.get("products") or candidate.get("products", []),
                  "sources": candidate.get("sources") or prior.get("sources") or []}
    return _specific_story_overlap(prior_view, target)


def _auto_merge_pair(store, a_id: str, b_id: str) -> tuple[str, str] | None:
    """Return (newer_duplicate_id, earlier_survivor_id) when both published stories can auto-merge."""
    if not isinstance(a_id, str) or not isinstance(b_id, str) or not a_id or not b_id or a_id == b_id:
        return None
    tables = {r[0] for r in store.db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('public_catalog','public_render_queue')"
    )}
    if "public_catalog" not in tables:
        return None
    render_guard = (
        "AND NOT EXISTS (SELECT 1 FROM public_render_queue q WHERE q.story_id=s.id AND q.last_error IS NOT NULL)"
        if "public_render_queue" in tables else ""
    )
    rows = {
        row["id"]: row
        for row in store.db.execute(
            f"""SELECT s.id,s.cluster_key,s.published_at,CAST(s.payload AS BLOB) AS payload,c.added_at
                FROM stories s JOIN public_catalog c ON c.story_id=s.id
                LEFT JOIN editorial_controls e ON e.story_id=s.id
                WHERE s.id IN (?,?) AND COALESCE(e.retracted,0)=0 AND COALESCE(e.locked,0)=0
                  AND NOT EXISTS (SELECT 1 FROM story_aliases a WHERE a.story_id=s.id) {render_guard}""",
            (a_id, b_id),
        ).fetchall()
    }
    if len(rows) != 2:
        return None
    pa, pb = saved_object(rows[a_id]["payload"]), saved_object(rows[b_id]["payload"])
    if not isinstance(pa, dict) or not isinstance(pb, dict):
        return None
    cka, ckb = rows[a_id]["cluster_key"], rows[b_id]["cluster_key"]
    if (pa.get("origin") == "network-health" or pb.get("origin") == "network-health"
            or cka.startswith("network:") or ckb.startswith("network:")
            or (cka.startswith("release:") and ckb.startswith("release:") and cka != ckb)
            or not _specific_story_overlap(pa, pb)):
        return None
    key_a = (pa.get("added_at") or rows[a_id]["added_at"] or rows[a_id]["published_at"], rows[a_id]["published_at"], a_id)
    key_b = (pb.get("added_at") or rows[b_id]["added_at"] or rows[b_id]["published_at"], rows[b_id]["published_at"], b_id)
    dup_id, surv_id = (b_id, a_id) if key_a < key_b else (a_id, b_id)
    dup_p, surv_p = (pb, pa) if dup_id == b_id else (pa, pb)
    if (pa.get("network") or pb.get("network")
            or dup_p.get("updates")
            or (dup_p.get("confidence") == "confirmed" and surv_p.get("confidence") != "confirmed")
            or len(_story_urls(dup_p) - _story_urls(surv_p)) > 1):
        return None
    return dup_id, surv_id


def _news(result) -> bool:
    return all(result["criteria"][name]["outcome"] == "pass" for name in review.EDITORIAL_CRITERIA)


def _can_route(candidate: dict, prepared: dict, result: dict, target_id) -> bool:
    """Only route new non-tag, non-release candidates when deterministic context overlaps."""
    if not isinstance(target_id, str) or not target_id:
        return False
    if prepared.get("mode", "story") != "story" or prepared["row"].get("story_id"):
        return False
    coverage = prepared.get("coverage") or {}
    verdict = result["verdict"]
    if (coverage.get("prior_story") is not None
            or verdict not in {"approve", "revise", "skip"}
            or (verdict == "skip" and result["criteria"]["new_information"]["outcome"] != "fail")):
        return False
    item = json.loads(prepared["row"]["payload"])
    cluster_key = prepared.get("cluster_key") or prepared["row"].get("cluster_key") or ""
    if (item.get("kind") == "tag" or item.get("origin") == "network-health"
            or cluster_key.startswith(("release:", "network:"))):
        return False
    if (target := _live_recent(coverage, target_id)) is None:
        return False
    cand_products = set(candidate.get("products") or ())
    if isinstance(item.get("product"), str) and item["product"]:
        cand_products.add(item["product"])
    if cand_products & set(target.get("products") or ()) or target.get("related"):
        return True
    target_text = f"{target.get('title') or ''}\n{target.get('summary') or ''}\n{target.get('latest_update') or ''}"
    if set(sum(gitlab_refs(item), [])) & set(sum(gitlab_refs({"url": "", "title": "", "content": target_text}), [])):
        return True
    item_subj, _ = thread_subject(item)
    target_subj, _ = thread_subject({"url": item.get("url"), "title": target.get("title")})
    return bool(item_subj and item_subj == target_subj)


def next_step(reviews, candidate, prepared):
    """What follows the latest review of `candidate`, decided from the chain of reviews alone.

    ("route", story_id) attaches an unmapped item to an existing story, ("verify", text) sends text
    to a fresh verification, ("repair", text) asks a review to repair its release labels,
    ("approve" | "skip", candidate) commits, and ("hold", (stage, reason)) holds.
    The evaluation follows the same steps.
    """
    latest = reviews[-1]
    result, stage, later = latest["result"], latest["stage"], len(reviews) > 1
    if _can_route(candidate, prepared, result, result.get("same_story")):
        return "route", result["same_story"]
    verdict = result["verdict"]
    failed = {name for name, check in result["criteria"].items() if check["outcome"] != "pass"}
    item = json.loads(prepared["row"]["payload"])
    recent_dev = (
        developed_at(item) >= after(-NEW_STORY_DAYS * 86400, item["updated_at"])
        or _security_disclosure(item)
        or (prepared.get("coverage") or {}).get("prior_story") is not None
    )
    official = (
        item.get("authority") in {"official", "project-sender", "hackerone"}
        or is_hackerone_item(item)
        or ((item.get("authority") in OFFICIAL_AUTHORITIES or is_dirauth_item(item, prepared.get("dirauth_users"))) and recent_dev)
    ) and item.get("kind") != "tag"
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
    elif verdict == "skip" and (
        not official
        or (result["criteria"]["new_information"]["outcome"] == "fail" and not result.get("same_story"))
    ):
        if stage == "review" and not later and _can_auto_merge_review(candidate, prepared, result):
            return "verify", candidate
        return "skip", candidate
    elif verdict == "skip" and official and result.get("same_story") and stage == "review" and not later:
        return "verify", candidate
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
    is_update = prepared.get("mode") == "update"
    if (item.get("kind") == "tag") if is_update else (prepared["payload"]["editorial_kind"] == "tag"):
        return "hold", (stage, "tag_repair")
    if len(reviews) > MAX_VERIFY_REPAIRS + 1:
        return "hold", (stage, "repairs_exhausted")
    try:
        repaired = review.apply_repair(candidate, result["repair"], update=is_update)
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
        if (not isinstance(state, dict) or set(state) != {"reserved", "inconsistent_requests", "validation_reask"}
                or type(state.get("reserved")) is not int
                or not len(record["reviews"]) <= state["reserved"] <= MAX_REVIEW_REQUESTS
                or not isinstance(state.get("inconsistent_requests"), list)
                or any(type(n) is not int or not 1 <= n <= state["reserved"] for n in state["inconsistent_requests"])
                or state["inconsistent_requests"] != sorted(set(state["inconsistent_requests"]))):
            raise AnalysisError("Saved review request budget is damaged", code="app.damaged_job")
        correction = state["validation_reask"]
        if correction is not None:
            if (not isinstance(correction, dict)
                    or set(correction) != {"trigger", "attempts", "response", "transport_failed"}
                    or type(correction.get("trigger")) is not int
                    or not 1 <= correction["trigger"] < MAX_REVIEW_REQUESTS
                    or correction["trigger"] > state["reserved"]
                    or not isinstance(correction.get("attempts"), list)
                    or any(type(n) is not int or not correction["trigger"] < n <= state["reserved"]
                           for n in correction["attempts"])
                    or correction["attempts"] != list(range(correction["trigger"] + 1,
                                                           max(correction["attempts"], default=correction["trigger"]) + 1))
                    or (correction.get("response") is not None
                        and (type(correction["response"]) is not int or not correction["attempts"]
                             or correction["response"] != correction["attempts"][-1]))
                    or type(correction.get("transport_failed")) is not bool
                    or (correction["response"] is not None and correction["transport_failed"])):
                raise AnalysisError("Saved validation correction is damaged", code="app.damaged_job")
        self.state = state

    def callback(self, *, correction=False):
        """Return a `RequestObserver` that reserves and persists review request slots."""
        requests = self

        class Counter(RequestObserver):
            previous = None

            def __call__(self, delta):
                state = requests.state
                reask = state["validation_reask"] if correction else None
                if correction and (reask is None or reask["response"] is not None):
                    raise AnalysisError("Validation correction is not pending", code="app.damaged_job")
                if delta == 1:
                    if state["reserved"] >= MAX_REVIEW_REQUESTS:
                        raise review.ReviewLimitReached("Review request budget exhausted")
                    if correction and reask["attempts"] and not reask["transport_failed"]:
                        raise AnalysisError("Validation correction is already in flight", code="app.damaged_job")
                    self.previous = (state["reserved"], copy.deepcopy(reask))
                    state["reserved"] += 1
                    if correction:
                        reask["attempts"].append(state["reserved"])
                        reask["transport_failed"] = False
                elif delta == -1 and self.previous is not None:
                    state["reserved"] = self.previous[0]
                    if correction:
                        state["validation_reask"] = self.previous[1]
                    self.previous = None
                else:
                    raise ValueError("Invalid review request accounting")
                requests.persist()
                requests.actual += delta

            def response_received(self):
                if not correction:
                    return
                reask = requests.state["validation_reask"]
                if (reask is None or reask["response"] is not None or not reask["attempts"]
                        or reask["attempts"][-1] != requests.state["reserved"]):
                    raise AnalysisError("Validation response is not reserved", code="app.damaged_job")
                reask["response"] = requests.state["reserved"]
                reask["transport_failed"] = False
                requests.persist()

            def transport_failed(self):
                if not correction:
                    return
                reask = requests.state["validation_reask"]
                if reask is None or reask["response"] is not None:
                    raise AnalysisError("Validation response cannot be retried", code="app.damaged_job")
                reask["transport_failed"] = True
                requests.persist()

        return Counter()


def _context(prepared, policy):
    """Bind a proposal to sources, coverage and the current candidate assembly."""
    source, coverage = digest(prepared["packet"]), digest(prepared.get("coverage"))
    binding = digest(prepared["binding"]) if "binding" in prepared else digest([prepared.get("mode", "story"), prepared["row"], prepared["payload"]])
    for key, value in (("source_hash", source), ("coverage_hash", coverage), ("binding_hash", binding)):
        if key in prepared and prepared[key] != value:
            raise AnalysisError("Saved proposal binding is damaged", code="app.damaged_job")
    return {"source_hash": source, "coverage_hash": coverage, "binding_hash": binding, "policy_hash": policy}


def pending_proposal(record):
    """Return the active pending untrusted repair proposal on `record`, if any."""
    return next((proposal for proposal in record.get("untrusted_proposals", [])
                 if proposal["disposition"] == "pending"), None)


def proposal_needs_check(record):
    """Earlier verified facts cannot clear a later invalid proposal attempt."""
    active = [p for p in record.get("untrusted_proposals", []) if p["disposition"] != "discarded_context"]
    latest = max((entry.get("request", 0) for entry in record["reviews"]), default=0)
    return bool(pending_proposal(record)) or bool(active and latest <= active[-1]["request"])


def _validate_reask(record, stage):
    """Bind the one correction slot to its rejected reply and observed response."""
    budget, proposals = record["request_budget"], record["untrusted_proposals"]
    correction = budget["validation_reask"]
    triggers = [proposal for proposal in proposals if proposal["reask_trigger"]]
    responses = [(entry, False) for entry in record["reviews"]]
    responses += [(proposal, True) for proposal in proposals]
    if any(type(entry.get("reask_response", False)) is not bool for entry, _ in responses):
        raise ValueError()
    if correction is None:
        if triggers or any(entry.get("reask_response", False) for entry, _ in responses):
            raise ValueError()
        if any(not p["accepted"] and p["request"] < MAX_REVIEW_REQUESTS for p in proposals):
            raise ValueError()
        return
    if len(triggers) != 1 or triggers[0]["request"] != correction["trigger"] or triggers[0]["accepted"]:
        raise ValueError()
    trigger = triggers[0]
    active = trigger["disposition"] != "discarded_context"
    observed = correction["response"]
    for entry, untrusted in responses:
        marked = entry.get("reask_response", False)
        if type(marked) is not bool or marked != (entry.get("request") == observed):
            raise ValueError()
        if entry.get("request") in correction["attempts"] and not marked:
            raise ValueError()  # A transport retry cannot follow a received semantic reply.
        if marked:
            actual_context = entry["context"] if untrusted else {key: entry.get(key) for key in trigger["context"]}
            actual_stage = (entry["stage"] if untrusted else "repair" if entry.get("issue") == "release_labels"
                            else "verify" if entry["stage"] == "verification" else "review")
            before_hash = entry["candidate_before_hash"] if untrusted else entry["candidate_hash"]
            if (actual_context != trigger["context"] or actual_stage != trigger["stage"]
                    or before_hash != trigger["candidate_before_hash"]
                    or (untrusted and entry["mode"] != trigger["mode"])):
                raise ValueError()
    if active and observed is None and budget["reserved"] != (correction["attempts"][-1] if correction["attempts"] else correction["trigger"]):
        raise ValueError()
    if (active and observed is not None and not any(entry.get("request") == observed for entry, _ in responses)
            and stage in {"approved", "skipped", "routed", "held", "locked"}):
        raise ValueError()


def _pending_reask(record, stage, candidate, prepared):
    """Resume only confirmed transport failures; an unknown or invalid reply is terminal."""
    events = [(entry["request"], None) for entry in record["reviews"]]
    events += [(proposal["request"], proposal) for proposal in record["untrusted_proposals"]
               if proposal["disposition"] != "discarded_context"]
    latest = max(events, default=(0, None), key=lambda event: event[0])[1]
    if latest is None or latest["accepted"]:
        return False
    correction = record["request_budget"]["validation_reask"]
    if correction is None or correction["trigger"] != latest["request"]:
        raise review.validation_failure(latest["error"])
    if (latest["stage"] != stage or latest["mode"] != prepared.get("mode", "story")
            or latest["candidate_before_hash"] != digest(candidate)
            or latest["context"] != _context(prepared, record["policy_hash"])):
        raise AnalysisError("Validation correction target changed", code="app.damaged_job")
    if correction["response"] is not None:
        raise review.ReviewError("Validation correction did not yield a usable review")
    if correction["attempts"] and not correction["transport_failed"]:
        raise review.ReviewError("Interrupted validation correction cannot be repeated")
    return latest["error"]


def validate_review_state(record, stage, candidate, prepared, *, allow_cached=True):
    """Fail closed on damaged bookkeeping before it can reach a cached approval."""
    budget = ReviewRequests(record).state
    proposals = record.get("untrusted_proposals", [])
    dispositions = {"pending", "superseded_unverified", "discarded_context", "unusable", "literal_tag", "labels", "repeated",
                    "checked_approve", "checked_revise", "checked_hold", "checked_skip"}
    fields = {"error", "request", "stage", "mode", "candidate_before_hash", "candidate_after_hash", "context", "changed_fields", "repair",
              "accepted", "disposition", "reask_trigger", "reask_response"}
    def hashed(value):
        return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)
    try:
        if stage == "drafted":
            if (prepared is not None or record["reviews"] or "candidate" in record
                    or any(p.get("disposition") != "discarded_context" for p in proposals)):
                raise ValueError()
        elif not isinstance(prepared, dict):
            raise ValueError()
        if not isinstance(proposals, list) or len(proposals) > MAX_REVIEW_REQUESTS:
            raise ValueError()
        for entry in record["reviews"]:
            if (not isinstance(entry, dict) or entry.get("stage") not in {"review", "verification"}
                    or not hashed(entry.get("candidate_hash"))):
                raise ValueError()
            review.validate_review(entry["result"], prepared["packet"],
                                   update=prepared.get("mode") == "update", coverage=prepared.get("coverage"))
        for proposal in proposals:
            if (not isinstance(proposal, dict) or set(proposal) != fields
                    or proposal["error"] not in review.VALIDATION_ERRORS
                    or type(proposal["request"]) is not int or not 1 <= proposal["request"] <= budget["reserved"]
                    or proposal["stage"] not in {"review", "verify", "repair"}
                    or proposal["mode"] not in {"story", "update"}
                    or not hashed(proposal["candidate_before_hash"])
                    or (proposal["candidate_after_hash"] is not None and not hashed(proposal["candidate_after_hash"]))
                    or type(proposal["accepted"]) is not bool or proposal["disposition"] not in dispositions
                    or type(proposal["reask_trigger"]) is not bool or type(proposal["reask_response"]) is not bool
                    or not isinstance(proposal["context"], dict)
                    or set(proposal["context"]) != {"source_hash", "coverage_hash", "binding_hash", "policy_hash"}
                    or not all(hashed(value) for value in proposal["context"].values())
                    or not isinstance(proposal["changed_fields"], list)
                    or proposal["changed_fields"] != sorted(set(proposal["changed_fields"]))
                    or set(proposal["changed_fields"]) - set(candidate_mod.UPDATE_FIELDS if proposal["mode"] == "update" else review.EDITABLE)):
                raise ValueError()
            accepted = proposal["accepted"]
            if proposal["error"] != review.INCONSISTENT_VERDICT and (
                    accepted or proposal["repair"] is not None or proposal["candidate_after_hash"] is not None
                    or proposal["changed_fields"] or proposal["disposition"] not in {"unusable", "discarded_context"}):
                raise ValueError()
            if (proposal["repair"] is not None and not isinstance(proposal["repair"], dict)):
                raise ValueError()
            if proposal["repair"] is not None:
                review._repair_fields(proposal["repair"], update=proposal["mode"] == "update")
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
        _validate_reask(record, stage)
        if stage == "drafted":
            return
        if stage == "locked":
            if (not prepared.get("locked") or candidate is not None or prepared.get("candidate") is not None
                    or record.get("outcome") != "locked" or record["reviews"]
                    or any(p["disposition"] != "discarded_context" for p in proposals)):
                raise ValueError()
            _context(prepared, record["policy_hash"])
            return
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
    known_attributions = {flag["name"] for flag in review.missing_named_attributions(
        current, prepared["packet"], update=prepared.get("mode") == "update")}
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
            if (entry["context"] != context or entry["stage"] != expected_stage
                    or entry["mode"] != prepared.get("mode", "story") or entry["candidate_before_hash"] != digest(current)):
                raise ValueError()
            if entry["candidate_after_hash"] is not None:
                after = review.apply_repair(current, entry["repair"], update=entry["mode"] == "update")
                if (digest(after) != entry["candidate_after_hash"]
                        or entry["changed_fields"] != sorted(key for key in current if after.get(key) != current[key])):
                    raise ValueError()
            if entry["accepted"]:
                if (_literal_tag(prepared) or digest(after) in seen
                        or not _allowed_proposal(current, after, prepared, entry["repair"])):
                    raise ValueError()
                current, expected_stage = after, "verify"
                known_attributions.update(flag["name"] for flag in review.missing_named_attributions(
                    current, prepared["packet"], update=prepared.get("mode") == "update"))
                seen.add(digest(current))
        else:
            actual_stage = "repair" if entry.get("issue") == "release_labels" else "verify" if entry["stage"] == "verification" else "review"
            if (actual_stage != expected_stage or entry["candidate_hash"] != digest(current)
                    or any(entry.get(key) != value for key, value in context.items())):
                raise ValueError()
            review.validate_review(entry["result"], prepared["packet"], update=prepared.get("mode") == "update",
                                   coverage=prepared.get("coverage"), candidate=current, attribution_names=known_attributions)
            trusted.append(entry)
            action, value = next_step(trusted, current, prepared)
            last_action, last_value = action, value
            if action in {"verify", "repair"}:
                if digest(value) != digest(current) and digest(value) in seen:
                    expected_stage = "held"
                else:
                    current, expected_stage = value, action
                    known_attributions.update(flag["name"] for flag in review.missing_named_attributions(
                        current, prepared["packet"], update=prepared.get("mode") == "update"))
                    seen.add(digest(current))
            else:
                expected_stage = {"approve": "approved", "skip": "skipped", "hold": "held", "route": "routed"}[action]
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
    merged_handoff = (stage == "routed" and expected_stage in {"approved", "skipped"}
                      and record.get("merged_duplicate") == prepared.get("story_id")
                      and len(trusted) >= 2 and trusted[-1]["stage"] == "verification"
                      and trusted[0]["result"].get("same_story") == record.get("routed_to")
                      and trusted[-1]["result"].get("same_story") == record.get("routed_to")
                      and _can_auto_merge_review(candidate, prepared, trusted[-1]["result"]))
    if stage == "routed" and last_action == "route" and record.get("routed_to") != last_value:
        raise ValueError()
    if (stage != expected_stage and not guarded_approval and not cached_terminal and not merged_handoff
            and not (stage == "held" and record.get("hold_code") in {"missing_sources", "repeat_hold"})):
        raise ValueError()


def _literal_tag(prepared):
    return (json.loads(prepared["row"]["payload"]).get("kind") if prepared.get("mode") == "update"
            else prepared["payload"]["editorial_kind"]) == "tag"


def _allowed_proposal(before, after, prepared, repair):
    """Check proposed labels without reclassifying read-only update context."""
    update = prepared.get("mode") == "update"
    limits = review.repair_limits(prepared["packet"], prepared.get("coverage"), update=update)
    editable = candidate_mod.UPDATE_FIELDS if update else review.EDITABLE
    if (set(after) != set(before)
            or any(after[key] != before[key] for key in before if key not in editable)
            or any(repair[field] not in allowed for field, allowed in limits.items() if field in repair)
            or ("tags" in repair and any(tag not in limits["category"] for tag in repair["tags"]))):
        return False
    if not update and (any(after[field] not in allowed for field, allowed in limits.items())
                       or any(tag not in limits["category"] for tag in after["tags"])):
        return False
    if update:
        old, new = before.get("updates"), after.get("updates")
        return bool(old and new and len(old) == len(new) and old[:-1] == new[:-1]
                    and {k: v for k, v in old[-1].items() if k != "text"}
                    == {k: v for k, v in new[-1].items() if k != "text"})
    return True


def _seen_candidates(record, candidate, prepared):
    context = _context(prepared, record["policy_hash"])
    return {digest(candidate), *(entry["candidate_hash"] for entry in record["reviews"]),
            *(value for proposal in record.get("untrusted_proposals", [])
              if proposal["context"] == context and proposal["disposition"] != "discarded_context"
              for value in (proposal["candidate_before_hash"], proposal["candidate_after_hash"]) if value)}


def recovery_status(record):
    """Report protocol failures separately from legitimate final review decisions."""
    proposals = record.get("untrusted_proposals", [])
    terminal = record.get("outcome") in {"approved", "skipped", "held", "locked", "routed"}
    unresolved = bool(proposals) and (proposal_needs_check(record) or not terminal
        or record.get("hold_code") in {"unusable_repair", "repeated_repair", "repairs_exhausted", "release_labels"})
    inconsistent = sum(p["error"] == review.INCONSISTENT_VERDICT for p in proposals)
    degenerate = sum(p["error"] == review.DEGENERATE_REASONS for p in proposals)
    attribution = sum(p["error"] == review.UNSUPPORTED_ATTRIBUTION for p in proposals)
    return {"raw_inconsistency_count": inconsistent, "raw_degenerate_count": degenerate, "raw_attribution_count": attribution,
            "accepted_proposal_count": sum(p["accepted"] for p in proposals),
            "unresolved_inconsistency": bool(inconsistent and unresolved),
            "unresolved_degenerate": bool(degenerate and unresolved), "unresolved_attribution": bool(attribution and unresolved)}


def call_review(reviewer, stage, candidate, prepared, *, requests, correction=False) -> dict:
    """Return only a genuinely validated reply; an invalid reply remains an exception."""
    known_attributions = review.attribution_names(prepared, requests.record)
    result = reviewer.review(candidate, prepared["packet"], coverage=prepared["coverage"], verification=stage == "verify",
                             issue=review.RELEASE_ISSUE if stage == "repair" else None,
                             on_request=requests.callback(correction=correction),
                             **({"validation_error": correction} if correction else {}),
                             **({"attribution_names": known_attributions} if known_attributions else {}),
                             **({"update": True} if prepared.get("mode") == "update" else {}))
    if correction and requests.state["validation_reask"]["response"] != requests.state["reserved"]:
        raise AnalysisError("Validation response was not observed", code="app.damaged_job")
    return {"stage": "verification" if stage == "verify" else "review", **({"issue": "release_labels"} if stage == "repair" else {}),
            **({"reask_response": True} if correction else {}),
            "candidate_hash": digest(candidate), "request": requests.state["reserved"], "result": result}


def advance_review(reviewer, stage, candidate, prepared, record, requests):
    """Runtime and evaluation share the same untrusted-proposal transition.

    An untrusted edit still requires its fresh verification. A validation
    correction keeps the current stage and candidate; invalid criteria never
    become a disagreement anchor.
    """
    validate_review_state(record, stage, candidate, prepared)
    correction = _pending_reask(record, stage, candidate, prepared)
    seen = _seen_candidates(record, candidate, prepared)
    waiting = pending_proposal(record)
    before = requests.actual
    try:
        entry = call_review(reviewer, stage, candidate, prepared, requests=requests, correction=correction)
    except review.CorrectableReviewError as error:
        if requests.actual == before:
            raise
        if correction and requests.state["validation_reask"]["response"] != requests.state["reserved"]:
            raise AnalysisError("Validation response was not observed", code="app.damaged_job")
        event = {"error": error.validation_error, "request": requests.state["reserved"], "stage": stage,
                 "mode": prepared.get("mode", "story"),
                 "candidate_before_hash": digest(candidate), "candidate_after_hash": None,
                 "context": _context(prepared, record["policy_hash"]), "changed_fields": [],
                 "repair": None, "accepted": False, "disposition": "unusable",
                 "reask_trigger": False, "reask_response": bool(correction)}
        requests.state["inconsistent_requests"].append(event["request"])
        record.setdefault("untrusted_proposals", []).append(event)
        try:
            if not isinstance(error, review.InconsistentReview):
                raise error
            if _literal_tag(prepared):
                event["disposition"] = "literal_tag"
                raise review.ReviewError("Literal tags cannot use untrusted edits")
            repaired = review.apply_repair(candidate, error.proposal, update=prepared.get("mode") == "update")
            event["candidate_after_hash"] = digest(repaired)
            event["changed_fields"] = sorted(key for key in candidate if repaired.get(key) != candidate[key])
            event["repair"] = {key: repaired[key] for key in event["changed_fields"] if key != "updates"}
            if "updates" in event["changed_fields"]:
                event["repair"]["update"] = repaired["updates"][-1]["text"]
            if not _allowed_proposal(candidate, repaired, prepared, error.proposal):
                event["disposition"] = "labels"
                raise review.ReviewError("Untrusted edit exceeds packet label limits")
            if event["candidate_after_hash"] in seen:
                event["disposition"] = "repeated"
                raise review.ReviewError("Untrusted edit repeats a reviewed candidate")
        except review.ReviewError:
            if requests.state["validation_reask"] is None and requests.state["reserved"] < MAX_REVIEW_REQUESTS:
                event["reask_trigger"] = True
                requests.state["validation_reask"] = {"trigger": event["request"], "attempts": [],
                                                       "response": None, "transport_failed": False}
                requests.persist()
                # The correction keeps this exact stage and candidate. Invalid
                # criteria are still absent from the trusted review history.
                return advance_review(reviewer, stage, candidate, prepared, record, requests)
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


def _ignore_at_gate(store, row: dict, observed: str, error: str, code: str, *,
                    clear_story: bool = False, before_log=None, **details) -> str:
    story_clause = ",story_id=NULL" if clear_story else ""
    try:
        with store.db:
            store.require_pending_item(row, "Source item changed before gate skip")
            if not store.db.execute(
                f"""UPDATE items SET status='ignored'{story_clause},next_attempt_at=NULL,last_error=?
                    WHERE id=? AND content_hash=? AND status='pending'""",
                (error, row["id"], row["content_hash"]),
            ).rowcount:
                return "stale"
            store.db.execute("DELETE FROM review_jobs WHERE item_id=?", (row["id"],))
            if before_log is not None:
                before_log()
            decisions.record(store.db, row["id"], code, observed, **details)
    except candidate_mod.StaleCandidate:
        return "stale"
    return "ignored"


def _attach_item(store, db, row: dict, draft: dict, writer_key: str, routed_record: dict, observed: str,
                 target_id: str, note: str, *, require_unmapped: bool = False) -> None:
    guard = " AND story_id IS NULL" if require_unmapped else ""
    updated = db.execute(
        f"""UPDATE items SET status='pending',story_id=?,attempts=0,rejections=0,
            next_attempt_at=NULL,last_error=?
            WHERE id=? AND content_hash=? AND status='pending'{guard}""",
        (target_id, note, row["id"], row["content_hash"]),
    ).rowcount
    if updated != 1:
        raise candidate_mod.StaleCandidate("Source item changed before routing")
    store.record_analysis(row, draft, writer_key, observed, review_record=routed_record)
    _save_handoff(store, row, routed_record, observed)


def _hold(store, row, draft, writer_key, record, observed, stage, reason):
    """One semantic hold is terminal; only source change/operator retry requeues."""

    record.update(outcome="held", hold_code=reason, hold_reason=HOLDS[reason], verified_facts=not proposal_needs_check(record) and _verified(record["reviews"]))
    with store.db:
        store.require_pending_item(row, "Source item changed before hold completed")
        if not store.db.execute("""UPDATE items SET status='rejected',attempts=attempts+1,
            rejections=MAX(rejections,3),next_attempt_at=NULL,last_error=?
            WHERE id=? AND content_hash=? AND status='pending'""",
            ("Final review held: " + HOLDS[reason], row["id"], row["content_hash"])).rowcount:
            raise candidate_mod.StaleCandidate("Source item changed before hold completed")
        store.record_analysis(row, draft, writer_key, observed, review_record=record)
        store.db.execute("""UPDATE review_jobs SET stage='held',record_json=?,approval_key=NULL,
            updated_at=? WHERE item_id=?""", (_json(record), observed, row["id"]))
        decisions.record(store.db, row["id"], f"held.{stage}.{reason}", observed, review=record)


def _route(store, row, draft, writer_key, record, observed, target, stage) -> str:
    """Attach an unmapped item to `target` once and clear its standalone draft for update review."""
    routed = False
    with store.db:
        store.require_pending_item(row, "Source item changed before routing")
        found = store.db.execute(
            """SELECT CAST(s.payload AS BLOB) AS payload
               FROM stories s LEFT JOIN editorial_controls e ON e.story_id=s.id
               WHERE s.id=? AND COALESCE(e.retracted,0)=0""",
            (target,),
        ).fetchone()
        target_payload = saved_object(found["payload"]) if found is not None else None
        if (isinstance(target_payload, dict)
                and target_payload.get("origin") != "network-health"
                and editorial.retired(store.db, story_id=target) is None):
            routed_record = {**record, "outcome": "routed", "routed_to": target}
            _attach_item(store, store.db, row, draft, writer_key, routed_record, observed,
                         target, candidate_mod.UNVERIFIED_ROUTE, require_unmapped=True)
            record.update(outcome="routed", routed_to=target)
            routed = True
    if not routed:
        _hold(store, row, draft, writer_key, record, observed, stage, "model_hold")
        return "held"
    return "routed"


def _try_auto_merge(config, store, pair: tuple[str, str], *, propagate: bool,
                    prepared: dict | None = None, draft: dict | None = None,
                    writer_key: str | None = None, record: dict | None = None,
                    observed: str | None = None) -> bool:
    dup_id, survivor_id = pair

    def guard(db) -> None:
        """Re-verify prepared bindings and merge eligibility inside the merge transaction."""
        if propagate:
            candidate_mod.verify_prepared_binding(db, prepared)
        if _auto_merge_pair(store, dup_id, survivor_id) != pair:
            raise candidate_mod.StaleCandidate("Duplicate stories changed before automatic merge")

    if propagate:
        routed_record = {**record, "candidate": record.get("candidate", prepared["candidate"]), "outcome": "routed", "routed_to": survivor_id, "merged_duplicate": dup_id}
        complete = lambda db: _attach_item(
            store, db, prepared["row"], draft, writer_key, routed_record, observed,
            survivor_id, "Attached to survivor story after duplicate merge",
        )
    else:
        complete = None
    try:
        editorial.merge(
            store.db, dup_id, survivor_id,
            reason="Combined duplicate coverage of the same event",
            base_url=config["site"]["base_url"],
            observed=now_iso(),
            automatic=True,
            _guard=guard,
            _complete=complete,
        )
    except (candidate_mod.StaleCandidate, editorial.RetiredStory):
        if propagate:
            raise
        return False
    except ValueError:
        return False
    if propagate:
        record.update(candidate=routed_record["candidate"], outcome="routed", routed_to=survivor_id, merged_duplicate=dup_id)
    return True


def _save_handoff(store, row, record, observed):
    """Keep the exact old proof and budget until the routed item is prepared again.

    The caller owns the transaction that changes the item's association.
    """
    if not store.db.execute("""UPDATE review_jobs SET stage='routed',record_json=?,approval_key=NULL,updated_at=?
                               WHERE item_id=?""", (_json(record), observed, row["id"])).rowcount:
        raise AnalysisError("Review handoff has no durable job", code="app.damaged_job")


def developed_at(item: dict) -> str:
    """The newest dated public development the pipeline can cite; an upstream updated_at never counts.

    published_at is the post, creation, merge, tag or timeline event date the collector stored. An
    issue adds its verified public notes and the date it was closed. Collected dates are all
    format_utc strings, so string order is time order.
    """
    dates = [item["published_at"]]
    if item.get("kind") == "gitlab_issue":
        dates += [note["created_at"] for note in item.get("public_comments") or []]
        dates += [note["created_at"] for note in item.get("dirauth_notes") or []]
        if item.get("upstream_state") == "closed" and item.get("closed_at"):
            dates.append(item["closed_at"])
    return max(dates)


def _security_disclosure(item: dict) -> bool:
    """A HackerOne disclosure or high/critical security issue may become public long after filing."""
    if is_hackerone_item(item):
        return True
    if item.get("kind") != "gitlab_issue":
        return False
    labels = {label.strip().casefold() for label in (item.get("labels") or []) if isinstance(label, str)}
    return "security" in labels and bool(labels & HIGH_SECURITY_SEVERITIES)


def _not_recent(config, store, row, item, observed, *, existing=candidate_mod._UNSET) -> str | None:
    """Ignore, before any model call, an item that would start a story from an old development.

    An update of an existing story, a locked one included, is left to review, and so is a revision
    an operator retried, a HackerOne disclosure or a high- or critical-severity security issue. Like any skip, a new
    revision of the item queues it again; an issue whose notes were never verified also gets a
    comment check, so a fresh public note does that.
    """
    developed = developed_at(item)
    if existing is candidate_mod._UNSET:
        existing = candidate_mod.existing_story(store.db, row)
    if (developed >= after(-NEW_STORY_DAYS * 86400, row["last_seen"])
            or _security_disclosure(item)
            or existing is not None
            or store.db.execute("SELECT 1 FROM rejection_actions WHERE item_id=? AND content_hash=? AND action='retry'",
                                (row["id"], row["content_hash"])).fetchone()):
        return None
    def maybe_check_comments() -> None:
        """Queue an initial public-comment check before ignoring an unverified GitLab issue."""
        if item.get("kind") == "gitlab_issue" and "comments_source_key" not in item:
            from .comments import request_check
            request_check(store.db, config, row, observed)

    try:
        with store.db:
            current = store.require_pending_item(row, "Source item changed before recency skip")
            # Collection and closing dates do not alter review evidence identity,
            # but a fresh date or operator retry can change recency eligibility.
            current_item = json.loads(current["payload"])
            try:
                current_developed = developed_at(current_item)
                threshold = after(-NEW_STORY_DAYS * 86400, current["last_seen"])
            except (ValueError, TypeError, KeyError):
                return "stale"
            if (current_developed >= threshold
                    or _security_disclosure(current_item)
                    or candidate_mod.existing_story(store.db, current) is not None
                    or store.db.execute("SELECT 1 FROM rejection_actions WHERE item_id=? AND content_hash=? AND action='retry'",
                                        (row["id"], row["content_hash"])).fetchone()):
                return "stale"
            reason = f"Not recent: newest dated development {current_developed} is over {NEW_STORY_DAYS} days before collection"
            return _ignore_at_gate(store, row, observed, reason, "skipped.gate.not_recent",
                                   before_log=maybe_check_comments, developed_at=current_developed,
                                   collected_at=current["last_seen"])
    except candidate_mod.StaleCandidate:
        return "stale"


def process_item(config, store, row, writer, reviewer, observed=None, *, allow_network=True):
    """Resume writer → exact-candidate review → fresh verification of each approved or repaired text → commit.

    Transport errors leave the current stage durable and raise a retryable
    AnalysisError for the existing queue's backoff. An unusable reply keeps the
    stage too, but its AnalysisError counts toward the item's three failures, as
    a saved job that cannot be read does. next_step bounds the repairs; a hold
    marks the item rejected immediately.
    """
    from .candidate import ReviewRequired, StaleCandidate
    from .editorial import RetiredStory, is_locked, retired

    observed = observed or now_iso()
    report = {"status": "pending", "writer_calls": 0, "review_calls": 0, "cache_hit": False}

    def _ignore_retired() -> dict:
        status_out = _ignore_at_gate(store, row, observed, "Retired story; never recreated",
                                     "skipped.gate.retired_story", clear_story=True)
        return {**report, "status": status_out}

    try:
        existing = candidate_mod.existing_story(store.db, row)
        if existing is None and retired(
                store.db, story_id=digest(row["cluster_key"])[:24], cluster_key=row["cluster_key"]) is not None:
            raise RetiredStory("Story is retired")
        job, saved_draft, saved_prepared, saved_record, same_source = _saved_job(store, row, config)
        item_payload = json.loads(row["payload"])
        skipped = _not_recent(config, store, row, item_payload, observed, existing=existing)
        if skipped:
            return {**report, "status": skipped}
        if existing is not None and candidate_mod.relation(json.loads(existing["payload"]), item_payload, store.db) == "citation":
            cited = store.add_citation(row, existing["id"], observed)
            return {**report, "status": cited["status"]}
        own_state, writer_item = candidate_mod.own_update_input(store.db, row, item_payload, existing=existing)
        if own_state == "skip":
            status_out = _ignore_at_gate(store, row, observed, "No new content after story update",
                                         "skipped.gate.no_new_content")
            return {**report, "status": status_out}
        policy = review.policy_hash(config)
        prior = candidate_mod.update_target(store.db, row, existing=existing)
    except RetiredStory:
        return _ignore_retired()
    except StaleCandidate:
        return {**report, "status": "stale"}

    writer_key = cache_key(row, config["llm"], prior)
    locked_reuse = (job is not None and existing is not None and is_locked(store.db, existing["id"])
                    and same_source and saved_draft is not None)
    carry = None
    if (job is not None and job["policy_hash"] == policy and same_source
            and (job["writer_key"] != writer_key or job["stage"] == "routed")):
        carry = _carried_requests(saved_record)
    if job is not None and same_source and job["stage"] != "routed" and (job["writer_key"] == writer_key or locked_reuse):
        writer_key = job["writer_key"]
        draft, old, record = saved_draft, saved_prepared, saved_record
        prepared_at = job["prepared_at"]
    else:
        job, draft, old = None, None, None
        record = {"schema_version": REVIEW_STATE_VERSION, "writer": None, "input_hash": row["content_hash"], "input_proof": 1, "input_row": row, "reviews": [], **initial_review_state()}
        if carry is not None:
            record.update(carry)
        prepared_at = observed
    try:
        if draft is None:
            if not allow_network and item_payload["kind"] != "tag":
                return {**report, "status": "deferred"}
            report["writer_calls"] += item_payload["kind"] != "tag"
            draft = writer.analyze(writer_item) if prior is None else writer.analyze(writer_item, prior=prior)
            record["writer"] = {"key": writer_key}  # The draft itself is saved in the job, then in analyses.
            if getattr(writer, "clears", 0):  # writer validation cleared the draft's impact sentence
                record["writer"]["clears"] = writer.clears  # kept until an operator retry resets the record
            _save(store, row, writer_key, policy, "drafted", draft, None, record, observed, prepared_at=prepared_at)
        prepared = _prepare_candidate(store, row, draft, prepared_at, _dirauth_users(config, store))
        same = (
            old is not None
            and job["policy_hash"] == policy
            and _identity(old) == _identity(prepared)
            and _dirauth_set(old.get("dirauth_users")) == _dirauth_set(prepared.get("dirauth_users"))
        )
        stage = job["stage"] if same else "review"
        fresh_prepared = {
            key: prepared[key]
            for key in ("mode", "candidate", "packet", "coverage", "candidate_hash", "source_hash", "coverage_hash", "binding_hash")
        }
        if "dirauth_users" in prepared:
            fresh_prepared["dirauth_users"] = prepared["dirauth_users"]
        fresh = {"schema_version": REVIEW_STATE_VERSION, "writer": record["writer"], "input_hash": row["content_hash"], "input_proof": 1, "input_row": row, "reviews": [], "policy_hash": policy, **initial_review_state(),
                 "prepared": fresh_prepared}
        # A coverage change invalidates old reviews, not the request budget of
        # this source revision and policy. Explicit operator retry starts afresh.
        if (job is not None and job["policy_hash"] == policy) or carry is not None:
            fresh.update(_carried_requests(record))
        record = record if same else fresh
        candidate = record.get("candidate", prepared["candidate"])
        validate_review_state(record, stage, candidate, prepared)
        _save(store, row, writer_key, policy, stage, draft, prepared, record, observed, prepared_at=prepared_at,
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
                verdict = review.validate_review(json.loads(cached["result_json"]), prepared["packet"],
                                                 update=prepared.get("mode") == "update", coverage=prepared["coverage"], candidate=candidate,
                                                 attribution_names=review.attribution_names(prepared, json.loads(cached["review_record_json"])))
                proof = json.loads(cached["review_record_json"])
                if not isinstance(proof, dict) or proof.get("policy_hash") != policy:
                    raise AnalysisError("Cached review policy is damaged", code="app.damaged_job")
                validate_review_state(proof, "approved" if verdict["verdict"] == "approve" else "skipped", candidate, prepared, allow_cached=False)
                valid = verdict["verdict"] in {"approve", "skip"} and verdict.get("same_story") is None
            except (AnalysisError, ValueError, TypeError, KeyError):
                valid = False
            if valid:
                record["approval"] = proof
                record["approval_key"] = key
                if verdict["verdict"] == "approve" and (held := review.final_holds(candidate, prepared, known_attributions=review.attribution_names(prepared, proof))):
                    _hold(store, row, draft, writer_key, record, observed, "final_check", held[0])
                    return {**report, "status": "held", "cache_hit": True}
                record["outcome"] = "skipped" if verdict["verdict"] == "skip" else "approved"
                _save(store, row, writer_key, policy, record["outcome"], draft, prepared, record, observed,
                      prepared_at=prepared_at, approval_key=key)
                committed = store.commit_candidate(prepared, candidate, writer_key, now_iso(), approval_key=key,
                                                   policy_hash=policy, review_record=record, decision=verdict["verdict"])
                report.update(status=committed["status"], cache_hit=True)
                return report
            with store.db:
                store.db.execute("DELETE FROM review_approvals WHERE key=?", (key,))
        if stage in {"approved", "skipped"}:  # without a usable receipt, review the writer's draft again
            stage, candidate, record = "review", prepared["candidate"], fresh
        requests = ReviewRequests(record, lambda: _save(store, row, writer_key, policy, stage, draft, prepared,
                                                        record, observed, prepared_at=prepared_at))
        while True:
            if not allow_network:
                return {**report, "status": "deferred"}
            try:
                action, value = advance_review(reviewer, stage, candidate, prepared, record, requests)
            except review.ReviewLimitReached as exc:
                with store.db:
                    store.require_pending_item(row, "Source item changed before review limit rejection")
                    store.reject(row["id"], str(exc), "failed." + exc.code, observed)
                raise
            finally:
                report["review_calls"] = requests.actual
            if action == "route":
                record["candidate"] = candidate
                status_out = _route(store, row, draft, writer_key, record, observed, value, record["reviews"][-1]["stage"])
                return {**report, "status": status_out}
            if action == "hold":
                _hold(store, row, draft, writer_key, record, observed, *value)
                return {**report, "status": "held"}
            if action in {"approve", "skip"}:
                agreed_dup = None
                if (prepared["coverage"].get("prior_story") is not None
                        and len(record["reviews"]) >= 2
                        and record["reviews"][-1]["stage"] == "verification"):
                    first_same = record["reviews"][0]["result"].get("same_story")
                    final_same = record["reviews"][-1]["result"].get("same_story")
                    if isinstance(first_same, str) and first_same and first_same == final_same:
                        agreed_dup = _auto_merge_pair(store, prepared["story_id"], first_same)
                if agreed_dup is not None and agreed_dup[0] == prepared["story_id"] and _try_auto_merge(
                    config, store, agreed_dup, propagate=True, prepared=prepared,
                    draft=draft, writer_key=writer_key, record=record, observed=observed,
                ):
                    return {**report, "status": "routed"}
                key = _approval_key(candidate, prepared, policy)
                record.update(candidate=candidate, approval_key=key, outcome="skipped" if action == "skip" else "approved")
                receipt = (key, digest(candidate), prepared["source_hash"], policy, prepared["binding_hash"],
                           _json(record["reviews"][-1]["result"]), _json(record), observed, observed)
                _save(store, row, writer_key, policy, record["outcome"], draft, prepared, record, observed,
                      prepared_at=prepared_at, approval_key=key, approval_receipt=receipt)
                committed = store.commit_candidate(prepared, candidate, writer_key, now_iso(), approval_key=key,
                                                   policy_hash=policy, review_record=record, decision=action)
                if agreed_dup is not None and agreed_dup[1] == prepared["story_id"]:
                    _try_auto_merge(config, store, agreed_dup, propagate=False)
                return {**report, "status": committed["status"]}
            stage, candidate = action, value  # the next review: a verification or a release-label repair
            record["candidate"] = candidate
            _save(store, row, writer_key, policy, stage, draft, prepared, record, observed, prepared_at=prepared_at)
    except CompletionDeferred:
        return {**report, "status": "deferred", "budget_reached": True}
    except RetiredStory:
        return _ignore_retired()
    except (StaleCandidate, ReviewRequired):
        return {**report, "status": "stale"}
    finally:
        _prune(store, MAX_APPROVALS)


def _new_coverage(old_coverage, current_coverage) -> list[dict]:
    old_recent = old_coverage.get("recent") if isinstance(old_coverage, dict) else None
    seen = {(e["id"], e["updated_at"]) for e in (old_recent if isinstance(old_recent, list) else ())
            if isinstance(e, dict) and isinstance(e.get("id"), str) and isinstance(e.get("updated_at"), str)}
    return [{"id": e["id"], "title": e["title"], "updated_at": e["updated_at"]}
            for e in ((current_coverage or {}).get("recent") or ()) if (e["id"], e["updated_at"]) not in seen]


def _check_approval(config, store, item_id: str) -> tuple[dict, tuple | None]:
    def refuse(reason: str, editorial_failures=(), new_coverage=()):
        """Build an ineligible operator-approval check result with structured diagnostics."""
        return {"eligible": False, "reason": reason, "hash": None,
                "editorial_failures": list(editorial_failures), "new_coverage": list(new_coverage)}, None

    item_row = store.db.execute(
        """SELECT id,url,source_id,content_hash,cluster_key,status,attempts,rejections,
           next_attempt_at,last_error,story_id,first_seen,last_seen,priority_score,
           typeof(payload) AS payload_type,CAST(payload AS BLOB) AS payload_blob FROM items WHERE id=?""",
        (item_id,),
    ).fetchone()
    job = store.db.execute(
        """SELECT writer_key,policy_hash,stage,prepared_at,
           CASE WHEN typeof(draft_json)='text' THEN CAST(draft_json AS BLOB) END AS draft,
           CASE WHEN typeof(envelope_json)='text' THEN CAST(envelope_json AS BLOB) END AS envelope,
           CASE WHEN typeof(record_json)='text' THEN CAST(record_json AS BLOB) END AS record
           FROM review_jobs WHERE item_id=?""", (item_id,),
    ).fetchone()
    if item_row is None or item_row["status"] != "rejected" or job is None or job["stage"] != "held":
        return refuse("Only a held final review can be approved")
    payload_obj = saved_object(item_row["payload_blob"]) if item_row["payload_type"] == "text" else None
    draft, saved_env, record = (saved_object(job[key]) for key in ("draft", "envelope", "record"))
    if (payload_obj is None or draft is None or saved_env is None or record is None
            or not isinstance(job["writer_key"], str) or not job["writer_key"]
            or not isinstance(job["prepared_at"], str)
            or not isinstance(reviews := record.get("reviews"), list)):
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
        prepared = _prepare_candidate(store, row, draft, job["prepared_at"], _dirauth_users(config, store))
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
            or _dirauth_set(prepared.get("dirauth_users")) != _dirauth_set(saved_env.get("dirauth_users"))
            or prepared["candidate_hash"] != held_prepared.get("candidate_hash")
            or prepared["candidate_hash"] != saved_env.get("candidate_hash")
            or prepared["source_hash"] != held_prepared.get("source_hash")
            or prepared["source_hash"] != saved_env.get("source_hash")
            or any(prepared["binding"][key] != saved_binding.get(key)
                   for key in ("prior_story", "lock", "sources", "payload_hash",
                               *(["mode"] if "mode" in saved_binding else [])))):
        return refuse("Its story or sources changed since the review; retry it", editorial_failures, new_coverage)
    if any(entry.get("source_hash") != prepared["source_hash"] for entry in reviews):
        return refuse("An earlier review policy or packet reviewed it; retry it", editorial_failures, new_coverage)
    is_update = prepared.get("mode") == "update"
    try:
        validated = [review.validate_review(entry["result"], prepared["packet"],
                                            update=is_update, coverage=held_prepared.get("coverage"))
                     for entry in reviews]
    except (AnalysisError, ValueError, TypeError, KeyError):
        return refuse("Saved review record cannot be read", editorial_failures, new_coverage)
    if any(result["criteria"]["new_information"]["outcome"] != "pass" for result in validated):
        return refuse("A review failed new_information (already covered); dismiss it", editorial_failures, new_coverage)
    candidate = record.get("candidate")
    try:
        candidate_mod.validate_approved(prepared["candidate"], candidate, "update" if is_update else "story")
    except candidate_mod.ReviewRequired as exc:
        msg = ("No fresh verification reviewed this exact text"
               if "complete public candidate" in str(exc) else "Saved review record cannot be read")
        return refuse(msg, editorial_failures, new_coverage)
    candidate_hash = digest(candidate)
    reviews_of_text = [(entry, result) for entry, result in zip(reviews, validated) if entry.get("candidate_hash") == candidate_hash]
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
    if held := review.final_holds(candidate, prepared, known_attributions=review.attribution_names(prepared, record)):
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
    return {"eligible": True, "reason": None, "hash": approval_hash,
            "editorial_failures": editorial_failures, "new_coverage": new_coverage}, (
        prepared, candidate, job["writer_key"], record)


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
    audit["operator_approval"] = {"reason": reason, "approved_at": stamp,
                                  "approval_hash": approval_hash, "new_coverage": info["new_coverage"]}
    try:
        committed = store.commit_candidate(prepared, candidate, writer_key, stamp, review_record=audit, operator=True)
    except (candidate_mod.StaleCandidate, candidate_mod.ReviewRequired) as exc:
        raise ValueError(str(exc)) from None
    return {"item_id": item_id, "content_hash": prepared["row"]["content_hash"], "action": "approve",
            "status": committed["status"], "story_id": committed["story_id"],
            "analysis_key": committed["analysis_key"], "publication_pending": True}
