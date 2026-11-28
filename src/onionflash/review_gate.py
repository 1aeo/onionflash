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

from concurrent.futures import ThreadPoolExecutor
import copy
import inspect
import json
import re
import threading

from . import candidate as candidate_mod, decisions, editorial, review, source_packet
from .analyze import MIN_EVIDENCE_CHARS, cache_key
from .llm import AnalysisError, CompletionDeferred, RequestObserver, is_quoted_list_post, unquoted_mail_text
from .schema import CATEGORIES, CONFIDENCES, PRIORITIES, PRODUCTS, SHA256_RE, STATES
from .store import ITEM_SAFE_COLUMNS, decode_item_row, item_hash, item_hash_fields, set_job_stage
from .util import (
    _DIRAUTH_LABELS, _GITLAB_OWN, _PRODUCT_NAMES, after, cve_ids, digest,
    dirauth_user_set, effective_authority, folded_labels, gitlab_refs, has_invalid_text_chars,
    is_dirauth_item, is_hackerone_item, is_housekeeping_item, is_trove_item, item_cluster, LIST_ARCHIVE_HOST,
    mandatory_news_rule, normalize_evidence, now_iso, parse_utc, release_mentions,
    safe_canonical_url, saved_object, strict_json, thread_subject, tor_core_user_set, trove_ids,
)

REVIEW_STATE_VERSION = 2
MAX_APPROVALS = 2000  # cached approvals kept besides those unfinished jobs pin
# An item starts a new story only if its newest dated development is at most this many days older
# than the collection of its current revision: the same window the collector's lookback uses.
NEW_STORY_DAYS = 14
HIGH_SECURITY_SEVERITIES = frozenset({"severity::high", "severity::critical"})
# The repairs that may follow the first review, a release-label repair request counting as one, each
# checked by another fresh verification, plus at most one 3rd tiebreaker vote on news_value:
# an item gets at most MAX_VERIFY_REPAIRS + 3 review requests (or +3 beyond all waves under specialists).
MAX_VERIFY_REPAIRS = 5
MAX_REVIEW_REQUESTS = MAX_VERIFY_REPAIRS + 3
MAX_SPECIALIST_REVIEW_REQUESTS = (MAX_VERIFY_REPAIRS + 1) * len(review.SPECIALISTS) + 3
OFFICIAL_AUTHORITIES = frozenset({"official", "hackerone", "dirauth-operator"})
OUTCOME_STAGES = {"approve": "approved", "skip": "skipped", "hold": "held", "route": "routed"}
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
    "specialist_budget": "specialist verification could not complete all lenses",
    # review.final_holds, which holds a verified approval
    "completed_action": "the story reports a completed action that its sources do not",
    "compromise_headline": "the headline drops the sources' doubt about a compromise",
    "confirmed_source": "confirmed needs an official announcement or a merged merge request",
    "merge_state": "a story told only by merge requests must be marked merged",
    "release_state": "an issue-only candidate cannot be marked released",
    "shouting_caps": "the candidate contains unnormalized all-caps shouting",
    "malformed_version": "the candidate cites a nonexistent three-part C-Tor version",
    "untrusted_operator_claim": "an uncorroborated mailing-list incident claim needs a trusted source",
    "trove_category": "a verified TROVE advisory must be categorized as security",
}


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and bool(SHA256_RE.fullmatch(value))


def _prepare(store, config, row, draft, at):
    coll = config.get("collection") or {} if isinstance(config, dict) else {}
    kwargs = {}
    if "prepare_candidate" not in vars(store):
        kwargs["dirauth_users"] = coll.get("dirauth_gitlab_users")
        kwargs["tor_core_users"] = coll.get("tor_core_gitlab_users")
    return store.prepare_candidate(row, draft, at, **kwargs)


def initial_review_state():
    """Only newly created chains initialize these fields; saved chains require them."""
    return {"request_budget": {"reserved": 0, "inconsistent_requests": [], "validation_reask": None},
            "untrusted_proposals": []}


def _new_record(input_row: dict, writer=None, **extra) -> dict:
    return {"schema_version": REVIEW_STATE_VERSION, "writer": writer, "input_hash": input_row["content_hash"],
            "input_proof": 1, "input_row": input_row, "reviews": [], **initial_review_state(), **extra}


def _load_job(db, item_id: str):
    job = db.execute(
        """SELECT writer_key,policy_hash,stage,approval_key,prepared_at,
           draft_json IS NOT NULL AS has_draft,envelope_json IS NOT NULL AS has_envelope,
           CASE WHEN typeof(draft_json)='text' THEN CAST(draft_json AS BLOB) END AS draft,
           CASE WHEN typeof(envelope_json)='text' THEN CAST(envelope_json AS BLOB) END AS envelope,
           CASE WHEN typeof(record_json)='text' THEN CAST(record_json AS BLOB) END AS record
           FROM review_jobs WHERE item_id=?""",
        (item_id,),
    ).fetchone()
    if job is None:
        return None, None, None, None
    return job, *(saved_object(job[k]) for k in ("draft", "envelope", "record"))


def _max_review_requests(record=None, *, specialists: int = 1) -> int:
    if specialists == len(review.SPECIALISTS) or (
        isinstance(record, dict) and record.get("specialists") == len(review.SPECIALISTS)
    ):
        return MAX_SPECIALIST_REVIEW_REQUESTS
    return MAX_REVIEW_REQUESTS


def _carried_requests(record):
    """A different automatic review target invalidates proof, not spent requests."""
    ReviewRequests(record)
    extra = {"specialists": record["specialists"]} if record.get("specialists") == len(review.SPECIALISTS) else {}
    if type(record.get("specialist_upgrade_at")) is int and extra:
        extra["specialist_upgrade_at"] = record["specialist_upgrade_at"]
    return {**extra,
            "request_budget": copy.deepcopy(record["request_budget"]),
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


def _valid_timestamp(value: object) -> bool:
    try:
        parse_utc(value)
        return True
    except ValueError:
        return False


def _valid_saved_draft(draft: object) -> bool:
    if not isinstance(draft, dict) or draft.get("publish", True) is not True:
        return False
    evidence = draft.get("evidence")
    if not isinstance(evidence, list) or any(not isinstance(q, str) or has_invalid_text_chars(q) for q in evidence):
        return False
    fields = set(draft) - {"publish"}
    if "update" in draft:
        return (
            fields == {"update", "confidence", "state", "evidence"}
            and isinstance(draft["update"], str)
            and bool(draft["update"].strip())
            and not has_invalid_text_chars(draft["update"])
            and draft["confidence"] in CONFIDENCES
            and draft["state"] in STATES
        )
    return (
        fields == {*candidate_mod.SEMANTIC_FIELDS, "evidence"}
        and all(
            isinstance(draft[k], str) and (k == "why_it_matters" or bool(draft[k].strip())) and not has_invalid_text_chars(draft[k])
            for k in ("title", "summary", "why_it_matters")
        )
        and draft["category"] in CATEGORIES
        and draft["priority"] in PRIORITIES
        and draft["confidence"] in CONFIDENCES
        and draft["state"] in STATES
        and isinstance(draft["products"], list)
        and all(isinstance(p, str) and p in PRODUCTS for p in draft["products"])
        and isinstance(draft["tags"], list)
        and all(isinstance(t, str) and t in CATEGORIES for t in draft["tags"])
    )


def reset_review_work(store, item_id):
    """Explicit operator retry starts a new review, retaining its completed draft.

    The caller owns the transaction.
    """
    job, draft, saved_env, saved_record = _load_job(store.db, item_id)
    if job is None:
        return
    raw_row = store.db.execute(f"SELECT {ITEM_SAFE_COLUMNS} FROM items WHERE id=?", (item_id,)).fetchone()
    item, item_payload = decode_item_row(raw_row)
    valid_hashes = _valid_item_hashes(item_payload) if item_payload is not None else set()
    stale_source = (
        (
            isinstance(saved_record, dict)
            and (
                ((ih := saved_record.get("input_hash")) is not None and (not _is_sha256(ih) or ih not in valid_hashes))
                or ((ir := saved_record.get("input_row")) is not None and (not isinstance(ir, dict) or ir.get("content_hash") != item["content_hash"]))
            )
        )
        or (
            isinstance(saved_env, dict)
            and (er := saved_env.get("row")) is not None
            and (not isinstance(er, dict) or er.get("content_hash") != item["content_hash"])
        )
    ) if item is not None else True
    if (
        item_payload is None
        or stale_source
        or not _valid_saved_draft(draft)
        or not _is_sha256(job["writer_key"])
        or not _is_sha256(job["policy_hash"])
        or not _valid_timestamp(job["prepared_at"])
    ):
        store.db.execute("DELETE FROM review_jobs WHERE item_id=?", (item_id,))
        return
    record = _new_record(item, {"key": job["writer_key"]}, policy_hash=job["policy_hash"])
    store.db.execute(
        """UPDATE review_jobs SET stage='drafted',envelope_json=NULL,
        record_json=?,approval_key=NULL,updated_at=? WHERE item_id=?""",
        (strict_json(record), now_iso(), item_id),
    )


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
            (row["id"], writer_key, policy_hash, stage, strict_json(draft) if draft is not None else None,
             strict_json(prepared) if prepared is not None else None, strict_json(record), approval_key, prepared_at, observed))


def _policy_copies(record, policy):
    """Check retained policy metadata without interpreting older verdict schemas."""
    if not _is_sha256(policy):
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


def _valid_item_hashes(payload: dict) -> set[str]:
    """Return current and exact historical item_hash digests accepted for saved payloads."""
    hashes = {item_hash(payload)}
    if isinstance(payload.get("source_content"), str):
        hashes.add(item_hash({k: v for k, v in payload.items() if k != "source_content"}))
    if payload.get("dirauth_notes"):
        hashes.add(digest({**item_hash_fields(payload, include_sender_domain=False), "dirauth_notes": payload["dirauth_notes"]}))
    return hashes


def _valid_item_fingerprints(row: dict) -> set[str]:
    """Return current and transitional item_fingerprint digests accepted for saved envelopes."""
    payload = saved_object(row["payload"].encode("utf-8"))
    if payload is None:
        raise ValueError()
    meta = {key: row.get(key) for key in ("id", "url", "source_id", "content_hash", "cluster_key", "story_id", "status")}
    transitional_src = digest({key: payload.get(key) for key in (*source_packet.BASE_SOURCE_FIELDS, "author", "dirauth_notes")})
    return {candidate_mod.item_fingerprint(row), digest([meta, transitional_src])}


def _saved_job(store, row, config):
    """Validate saved identity before a mismatch can start a fresh automatic review."""
    job, draft, prepared, record = _load_job(store.db, row["id"])
    if job is None:
        return None, None, None, None, False
    try:
        if (record is None or (draft is not None) != bool(job["has_draft"])
                or (prepared is not None) != bool(job["has_envelope"])):
            raise ValueError()

        def _source_identity(value):
            if not isinstance(value, dict) or (payload := saved_object(value["payload"].encode("utf-8"))) is None:
                raise ValueError()
            if (value["id"] != row["id"] or payload.get("id") != value["id"]
                    or payload.get("url") != value["url"] or payload.get("source_id") != value["source_id"]
                    or not _is_sha256(value["content_hash"])
                    or value["content_hash"] not in _valid_item_hashes(payload)):
                raise ValueError()
            return value["content_hash"], payload

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
        if "input_hash" in record and not _is_sha256(record["input_hash"]):
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
        source_hash, proof_payload = _source_identity(proof_row)
        if "input_hash" in record and record["input_hash"] != source_hash:
            raise ValueError()
        for extra_row in (*([record["input_row"]] if "input_row" in record else ()), *([prepared["row"]] if prepared is not None else ())):
            if extra_row is not proof_row and (
                _source_identity(extra_row)[0] != source_hash
                or candidate_mod.item_fingerprint(extra_row) != candidate_mod.item_fingerprint(proof_row)
            ):
                raise ValueError()
        _, row_payload = _source_identity(row)
        same_source = item_hash(proof_payload) == item_hash(row_payload)
        if (not _is_sha256(job["writer_key"])
                or not _valid_timestamp(job["prepared_at"])
                or not isinstance(record.get("writer"), dict) or record["writer"].get("key") != job["writer_key"]):
            raise ValueError()
        if prepared is not None:
            if not isinstance(prepared["binding"].get("item"), str) or prepared["binding"]["item"] not in _valid_item_fingerprints(prepared["row"]):
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
_PROPOSAL_TOKEN = re.compile(r"\bproposal\s+\d{3,4}\b|\b(?:cve-\d{4}-\d+|trove-\d{4}-\d{3,5})\b", re.I)
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
    return {u for src in (story.get("sources") or ()) if isinstance(src, dict) and (u := safe_canonical_url(src.get("url")))}


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
    refs = set().union(*gitlab_refs({"url": "", "title": "", "content": "\n".join([*src_urls, text])}))
    projects = {
        (match.group(1), match.group(2).lower()): clean
        for raw_url in src_urls
        if (match := _GITLAB_OWN.match(clean := safe_canonical_url(raw_url)))
    }
    if len(projects) == 1:
        [context_url] = projects.values()
        refs.update(*gitlab_refs({"url": context_url, "title": "", "content": text}))
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
    if pa is None or pb is None:
        return None
    cka, ckb = rows[a_id]["cluster_key"], rows[b_id]["cluster_key"]
    if (pa.get("origin") == "network-health" or pb.get("origin") == "network-health"
            or cka.startswith("network:") or ckb.startswith("network:")
            or (cka.startswith("release:") and ckb.startswith("release:") and cka != ckb)
            or not _specific_story_overlap(pa, pb)):
        return None
    (surv_p, surv_id), (dup_p, dup_id) = sorted(
        ((pa, a_id), (pb, b_id)),
        key=lambda pair: (pair[0].get("added_at") or rows[pair[1]]["added_at"] or rows[pair[1]]["published_at"], rows[pair[1]]["published_at"], pair[1]),
    )
    if (pa.get("network") or pb.get("network")
            or dup_p.get("updates")
            or (dup_p.get("confidence") == "confirmed" and surv_p.get("confidence") != "confirmed")
            or len(_story_urls(dup_p) - _story_urls(surv_p)) > 1):
        return None
    return dup_id, surv_id


_DIRAUTH_TOPIC_RE = re.compile(
    r"\b(?:dirauth|directory authorit\w*|authorit(?:y|ies)|dirvote|consensus|voting|vote|bwauth|"
    r"bandwidth\s+authorit\w*|relay\s+descriptor|bridge\s+authorit\w*|dannenberg|moria1|serge|"
    r"maatuska|longclaw|gabelmoo|faravahar|bastet|sekhmet|dizum|tor26)\b",
    re.I,
)


def _dirauth_operational_relevant(item: dict) -> bool:
    if folded_labels(item) & _DIRAUTH_LABELS:
        return True
    title = item["title"] if isinstance(item.get("title"), str) else ""
    body = next((item[k] for k in ("source_content", "content") if isinstance(item.get(k), str)), "")
    return bool(_DIRAUTH_TOPIC_RE.search(f"{title}\n{body}"))


def _news(result, *, mandatory: bool = False) -> bool:
    new_info = result["criteria"]["new_information"]["outcome"] == "pass"
    return new_info and (mandatory or result["criteria"]["news_value"]["outcome"] == "pass")


def _can_route(candidate: dict, prepared: dict, result: dict, target_id) -> bool:
    """Route a new item only when its overlap and publication policy allow attachment."""
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
    release_hint = prepared["row"].get("cluster_key") or ""
    if (item.get("kind") == "feed" and item.get("authority") == "official"
            and release_hint.startswith("release:") and target.get("state") == "released"
            and result["criteria"]["new_information"]["outcome"] == "pass"):
        # New official announcement facts merit their own article after the release
        # is already covered; a positive novelty judgment must not become an update.
        return False
    if release_hint.startswith("release:") and target.get("state") in {"tagged", "released"}:
        if (candidate_mod.release_story_key("", target) or "") != release_hint:
            return False
    cand_products = set(candidate.get("products") or ())
    if isinstance(item.get("product"), str) and item["product"]:
        cand_products.add(item["product"])
    if cand_products & set(target.get("products") or ()) or target.get("related"):
        return True
    if set().union(*gitlab_refs(item)) & set().union(*gitlab_refs({"url": "", "title": "", "content": _story_text(target)})):
        return True
    target_text = _story_text(target)
    target_probe = {"title": target.get("title") or "", "content": target_text}
    if set(release_mentions(item)) & set(release_mentions(target_probe)):
        return True
    if (set(trove_ids(item)) & set(trove_ids(target_probe))) or (set(cve_ids(item)) & set(cve_ids(target_probe))):
        return True
    item_text = "\n".join(
        str(p or "")
        for p in (
            item.get("title"),
            item.get("source_content") if isinstance(item.get("source_content"), str) else item.get("content"),
            *(n.get("body") for n in (item.get("public_comments") or ()) if isinstance(n, dict)),
        )
        if p
    )
    cand_text = "\n".join(str(candidate.get(k) or "") for k in ("title", "summary", "why_it_matters"))
    combined_text = f"{item_text}\n{cand_text}"
    item_vers = {m.casefold() for m in _VERSION_TOKEN.findall(combined_text)}
    target_vers = {m.casefold() for m in _VERSION_TOKEN.findall(target_text)}
    if (shared_vers := item_vers & target_vers) and (
        target.get("state") in {"tagged", "released"} or target.get("category") == "release"
    ):
        target_prods = {p for p in (target.get("products") or ()) if p != "network"}
        if any(
            candidate_mod.item_mentions_product_version(combined_text, prod, ver)
            for prod in target_prods
            for ver in shared_vers
        ):
            return True
        if any(
            re.search(rf"\b{pat}\b" + (r"(?!\s+project\b)" if prod == "tor" else ""), combined_text, re.I)
            and any(
                not candidate_mod.version_claimed_by_other_product(combined_text, prod, ver)
                for ver in shared_vers
            )
            for prod in target_prods
            if (pat := _PRODUCT_NAMES.get(prod))
        ):
            return True
    item_subj, _ = thread_subject(item)
    target_subj, _ = thread_subject({"url": item.get("url"), "title": target.get("title")})
    return bool(item_subj and item_subj == target_subj)


def _is_official(item: dict, prepared: dict) -> bool:
    """Return whether `item` holds official, HackerOne, or relevant dirauth standing."""
    eff_auth = effective_authority(item, prepared.get("dirauth_users"), prepared.get("tor_core_users"))
    recent_dev = (
        developed_at(item) >= after(-NEW_STORY_DAYS * 86400, item["updated_at"])
        or _security_disclosure(item)
        or (prepared.get("coverage") or {}).get("prior_story") is not None
    )
    is_dirauth_rel = (
        (eff_auth == "dirauth-operator" or is_dirauth_item(item, prepared.get("dirauth_users")))
        and recent_dev
        and _dirauth_operational_relevant(item)
    )
    return (
        eff_auth in (OFFICIAL_AUTHORITIES - {"dirauth-operator"})
        or is_hackerone_item(item)
        or is_dirauth_rel
    ) and item.get("kind") != "tag"


def _is_editorial_news_tie(reviews: list[dict], *, mandatory: bool) -> bool:
    """Return True only when review and verification split strictly on news_value."""
    if mandatory or len(reviews) != 2:
        return False
    first, second = reviews
    if first.get("tiebreaker") or first.get("specialists") or second.get("tiebreaker"):
        return False
    if first.get("stage") != "review" or second.get("stage") != "verification":
        return False
    res0, res1 = first["result"], second["result"]
    failed0 = {name for name, check in res0["criteria"].items() if check["outcome"] != "pass"}
    failed1 = {name for name, check in res1["criteria"].items() if check["outcome"] != "pass"}
    if "new_information" in failed0 or "new_information" in failed1:
        return False
    if (
        second.get("specialists")
        and res0["verdict"] == "approve"
        and not failed0
        and res1["verdict"] == "hold"
        and failed1 == {"news_value"}
        and res1["criteria"]["news_value"]["outcome"] == "insufficient"
    ):
        return True
    if "hold" in (res0["verdict"], res1["verdict"]):
        return False
    pair = ((res0["verdict"], failed0), (res1["verdict"], failed1))
    return pair in (
        (("approve", set()), ("skip", {"news_value"})),
        (("skip", {"news_value"}), ("approve", set())),
    )


def next_step(reviews, candidate, prepared, *, specialists: int = 1):
    """What follows the latest review of `candidate`, decided from the chain of reviews alone.

    ("route", story_id) attaches an unmapped item to an existing story, ("verify", text) sends text
    to a fresh verification, ("tiebreak", text) asks a third verification pass to break a news_value
    tie, ("repair", text) asks a review to repair its release labels, ("approve" | "skip", candidate)
    commits, and ("hold", (stage, reason)) holds. The evaluation follows the same steps.
    """
    latest = reviews[-1]
    result, stage, later = latest["result"], latest["stage"], len(reviews) > 1
    item = json.loads(prepared["row"]["payload"])
    eff_auth = effective_authority(item, prepared.get("dirauth_users"), prepared.get("tor_core_users"))
    mandatory = mandatory_news_rule({**item, "authority": eff_auth}) is not None
    verdict = result["verdict"]
    failed = {name for name, check in result["criteria"].items() if check["outcome"] != "pass"}
    official = _is_official(item, prepared)
    cand_hash = latest.get("candidate_hash")
    needs_specialist_verify = (
        specialists > 1
        and stage == "verification"
        and not latest.get("specialists")
        and not (
            latest.get("tiebreaker")
            and any(
                entry.get("stage") == "verification"
                and entry.get("candidate_hash") == cand_hash
                and entry.get("specialists")
                for entry in reviews[:-1]
            )
        )
    )
    is_tiebreak_pair = _is_editorial_news_tie(reviews[:2], mandatory=mandatory)
    if len(reviews) == 3 and (latest.get("tiebreaker") or is_tiebreak_pair):
        new_info_ok = result["criteria"]["new_information"]["outcome"] == "pass"
        if not new_info_ok:
            if result.get("same_story") and _can_route(candidate, prepared, result, result.get("same_story")):
                return "route", result["same_story"]
            return "hold", ("verification", "disagreed_news")
        if result["criteria"]["news_value"]["outcome"] == "insufficient" and failed & review.EDITORIAL_CRITERIA == {"news_value"}:
            return "hold", ("verification", "disagreed_news")
        votes = sum(_news(entry["result"], mandatory=mandatory) for entry in reviews[:3])
        if votes <= 1:
            if official:
                return "hold", ("verification", "official_not_news")
            return "skip", candidate
    else:
        if len(reviews) == 2 and _is_editorial_news_tie(reviews, mandatory=mandatory):
            return "tiebreak", candidate
        has_tiebreak = len(reviews) > 3 and (reviews[2].get("tiebreaker") or is_tiebreak_pair)
        news_anchor = reviews[2] if has_tiebreak else reviews[0]
        if later and _news(result, mandatory=mandatory) != _news(news_anchor["result"], mandatory=mandatory):
            return "hold", (stage, "disagreed_news")
    if _can_route(candidate, prepared, result, result.get("same_story")):
        return "route", result["same_story"]
    if mandatory and failed == {"news_value"} and verdict in {"skip", "revise", "hold"}:
        if stage == "review" and not later:
            return "verify", candidate
        if stage == "verification":
            if not result["criteria"]["source_support"]["source_refs"]:
                return "hold", (stage, "model_hold")
            if held := review.final_holds(candidate, prepared):
                return "hold", ("final_check", held[0])
            if not review.release_labels_match_state(candidate):
                if latest.get("issue") or len(reviews) > MAX_VERIFY_REPAIRS:
                    return "hold", (stage, "release_labels")
                return "repair", candidate
            return ("verify" if needs_specialist_verify else "approve"), candidate
        return "hold", (stage, "model_hold")
    # An official item that fails only news value is the operator's to judge, once a fresh
    # verification has passed its facts; a duplicate still skips.
    disputed = official and failed & review.EDITORIAL_CRITERIA == {"news_value"}
    if disputed:
        if stage == "verification" and failed == {"news_value"}:
            return "hold", (stage, "official_not_news")
        if verdict != "revise":
            return ("hold", (stage, "model_hold")) if later else ("verify", candidate)
    elif verdict == "skip":
        if (
            result["criteria"]["news_value"]["outcome"] == "insufficient"
            and result["criteria"]["new_information"]["outcome"] != "fail"
        ):
            return "hold", (stage, "model_hold")
        if not official or (
            result["criteria"]["new_information"]["outcome"] == "fail"
            and (prepared.get("mode") == "update" or not result.get("same_story"))
        ):
            return (
                "verify"
                if (needs_specialist_verify or (stage == "review" and not later and _can_auto_merge_review(candidate, prepared, result)))
                else "skip"
            ), candidate
        if result.get("same_story") and stage == "review" and not later:
            return "verify", candidate
    if verdict == "approve":
        if stage == "verification" and (held := review.final_holds(candidate, prepared)):
            return "hold", ("final_check", held[0])
        if not review.release_labels_match_state(candidate):
            # A review told the problem may repair it, if the repair can still be verified within the limit.
            if latest.get("issue") or len(reviews) > MAX_VERIFY_REPAIRS:
                return "hold", (stage, "release_labels")
            return "repair", candidate
        return ("verify" if (stage == "review" or needs_specialist_verify) else "approve"), candidate
    if verdict != "revise" or (later and failed & review.EDITORIAL_CRITERIA and not disputed):
        return "hold", (stage, "release_labels" if latest.get("issue") else "model_hold")
    if _literal_tag(prepared):
        return "hold", (stage, "tag_repair")
    if len(reviews) > MAX_VERIFY_REPAIRS + 1:
        return "hold", (stage, "repairs_exhausted")
    try:
        repaired = review.apply_repair(candidate, result["repair"], update=prepared.get("mode") == "update")
    except review.ReviewError:
        # After a disputed official item's first review, the unchanged text goes to its fresh verification.
        return ("verify", candidate) if disputed and not later else ("hold", (stage, "unusable_repair"))
    if latest.get("issue") and not review.release_labels_match_state(repaired):
        return "hold", (stage, "release_labels")  # the repair request left the labels in place
    if digest(repaired) in {entry["candidate_hash"] for entry in reviews}:
        return "hold", (stage, "repeated_repair")  # every text of the chain was refused once already
    return "verify", repaired


def _next_step(reviews, candidate, prepared, *, specialists: int = 1):
    if specialists != 1 and _supports_kwarg(next_step, "specialists"):
        return next_step(reviews, candidate, prepared, specialists=specialists)
    return next_step(reviews, candidate, prepared)


class ReviewRequests:
    """Reserve endpoint attempts before sending; interruptions never replenish them."""

    def __init__(self, record, persist=lambda: None, *, specialists: int = 1):
        self.record, self.persist, self.actual = record, persist, 0
        if not isinstance(record, dict) or not isinstance(record.get("reviews"), list):
            raise AnalysisError("Saved review state is damaged", code="app.damaged_job")
        if "specialists" in record and (
            type(record["specialists"]) is not int or record["specialists"] != len(review.SPECIALISTS)
        ):
            raise AnalysisError("Saved review state is damaged", code="app.damaged_job")
        self.max_requests = _max_review_requests(record, specialists=specialists)
        if "request_budget" not in record or not isinstance(record.get("untrusted_proposals"), list):
            raise AnalysisError("Saved review ledger is missing", code="app.damaged_job")
        state = record["request_budget"]
        if (not isinstance(state, dict) or set(state) != {"reserved", "inconsistent_requests", "validation_reask"}
                or type(state.get("reserved")) is not int
                or not len(record["reviews"]) <= state["reserved"] <= self.max_requests
                or not isinstance(state.get("inconsistent_requests"), list)
                or any(type(n) is not int or not 1 <= n <= state["reserved"] for n in state["inconsistent_requests"])
                or state["inconsistent_requests"] != sorted(set(state["inconsistent_requests"]))):
            raise AnalysisError("Saved review request budget is damaged", code="app.damaged_job")
        if "specialist_upgrade_at" in record:
            upgrade_at = record["specialist_upgrade_at"]
            if (record.get("specialists") != len(review.SPECIALISTS)
                    or type(upgrade_at) is not int
                    or not 1 <= upgrade_at <= min(MAX_REVIEW_REQUESTS, state["reserved"])):
                raise AnalysisError("Saved review state is damaged", code="app.damaged_job")
        is_specialist = record.get("specialists") == len(review.SPECIALISTS)
        correction = state["validation_reask"]
        if correction is not None:
            if (not isinstance(correction, dict)
                    or set(correction) != {"trigger", "attempts", "response", "transport_failed"}
                    or type(correction.get("trigger")) is not int
                    or not 1 <= correction["trigger"] < self.max_requests
                    or correction["trigger"] > state["reserved"]):
                raise AnalysisError("Saved validation correction is damaged", code="app.damaged_job")
            attempts = correction.get("attempts")
            attempts_ok = (
                isinstance(attempts, list)
                and all(type(n) is int and correction["trigger"] < n <= state["reserved"] for n in attempts)
                and (
                    attempts == sorted(set(attempts))
                    if is_specialist
                    else all(n == correction["trigger"] + idx for idx, n in enumerate(attempts, 1))
                )
            )
            if (not attempts_ok
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
            """Track durable request slot reservations and transport outcomes for one call."""

            previous = None

            def __call__(self, delta):
                state = requests.state
                reask = state["validation_reask"] if correction else None
                if correction and (reask is None or reask["response"] is not None):
                    raise AnalysisError("Validation correction is not pending", code="app.damaged_job")
                if delta == 1:
                    if state["reserved"] >= requests.max_requests:
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
                """Persist receipt of a validation-reask HTTP response before JSON parsing."""
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
                """Mark a validation-reask transport failure eligible for retry."""
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


def _entry_stage(entry: dict) -> str:
    if entry.get("issue") == "release_labels":
        return "repair"
    if entry.get("tiebreaker"):
        return "tiebreak"
    return "verify" if entry["stage"] == "verification" else "review"


def _active_events(record: dict) -> list[tuple]:
    return ([(entry.get("request"), False, entry) for entry in record["reviews"]]
            + [(p["request"], True, p) for p in record["untrusted_proposals"] if p["disposition"] != "discarded_context"])


def _agreed_same_story(reviews: list[dict]) -> str | None:
    if len(reviews) >= 2 and reviews[-1]["stage"] == "verification":
        first, final = reviews[0]["result"].get("same_story"), reviews[-1]["result"].get("same_story")
        if isinstance(first, str) and first and first == final:
            return first
    return None


def _validate_reask(record, stage):
    """Bind correction slots to rejected replies and observed responses."""
    budget, proposals = record["request_budget"], record["untrusted_proposals"]
    correction = budget["validation_reask"]
    is_specialist = record.get("specialists") == len(review.SPECIALISTS)
    triggers = [proposal for proposal in proposals if proposal["reask_trigger"]]
    responses = [(entry, False) for entry in record["reviews"]]
    responses += [(proposal, True) for proposal in proposals]
    if any(type(entry.get("reask_response", False)) is not bool for entry, _ in responses):
        raise ValueError()
    upgrade_at = record.get("specialist_upgrade_at")
    if correction is None:
        if triggers or any(entry.get("reask_response", False) for entry, _ in responses):
            raise ValueError()
        for proposal in proposals:
            if proposal["accepted"]:
                continue
            gov_cap = (
                MAX_REVIEW_REQUESTS
                if type(upgrade_at) is int and proposal["request"] <= upgrade_at
                else _max_review_requests(record)
            )
            exhausted_at = budget["reserved"] if is_specialist else proposal["request"]
            if exhausted_at < gov_cap:
                raise ValueError()
        return
    if is_specialist:
        matching_triggers = [t for t in triggers if t["request"] == correction["trigger"]]
        if len(matching_triggers) != 1 or matching_triggers[0]["accepted"]:
            raise ValueError()
        trigger = matching_triggers[0]
    else:
        if len(triggers) != 1 or triggers[0]["request"] != correction["trigger"] or triggers[0]["accepted"]:
            raise ValueError()
        trigger = triggers[0]
    active = trigger["disposition"] != "discarded_context"
    observed = correction["response"]
    for entry, untrusted in responses:
        marked = entry.get("reask_response", False)
        req_num = entry.get("request")
        if is_specialist and isinstance(req_num, int) and req_num < trigger["request"]:
            continue
        if marked != (req_num == observed):
            raise ValueError()
        if req_num in correction["attempts"] and not marked:
            raise ValueError()  # A transport retry cannot follow a received semantic reply.
        if marked:
            actual_context = entry["context"] if untrusted else {key: entry.get(key) for key in trigger["context"]}
            actual_stage = entry["stage"] if untrusted else _entry_stage(entry)
            before_hash = entry["candidate_before_hash"] if untrusted else entry["candidate_hash"]
            if (actual_context != trigger["context"] or actual_stage != trigger["stage"]
                    or before_hash != trigger["candidate_before_hash"]
                    or (untrusted and entry["mode"] != trigger["mode"])):
                raise ValueError()
    wave = record.get("pending_specialist_wave") if is_specialist else None
    if active and observed is None:
        expected_reserved = correction["attempts"][-1] if correction["attempts"] else correction["trigger"]
        if isinstance(wave, dict):
            wave_reqs = [c["request"] for c in (wave.get("completed") or ()) if isinstance(c, dict) and isinstance(c.get("request"), int)]
            expected_reserved = max([correction["trigger"], *correction["attempts"], *wave_reqs])
        if budget["reserved"] != expected_reserved:
            raise ValueError()
    if (active and observed is not None and not any(entry.get("request") == observed for entry, _ in responses)
            and stage in {"approved", "skipped", "routed", "held", "locked"}
            and not (is_specialist and stage == "held" and record.get("hold_code") == "specialist_budget")):
        raise ValueError()


def _pending_reask(record, stage, candidate, prepared):
    """Resume only confirmed transport failures; an unknown or invalid reply is terminal."""
    _, is_proposal, latest = max(_active_events(record), default=(0, False, None), key=lambda event: event[0])
    if not is_proposal or latest["accepted"]:
        return False
    correction = record["request_budget"]["validation_reask"]
    if correction is None or correction["trigger"] != latest["request"]:
        raise review.InconsistentReview()
    if (latest["stage"] != stage or latest["mode"] != prepared.get("mode", "story")
            or latest["candidate_before_hash"] != digest(candidate)
            or latest["context"] != _context(prepared, record["policy_hash"])):
        raise AnalysisError("Validation correction target changed", code="app.damaged_job")
    if correction["response"] is not None:
        raise review.ReviewError("Validation correction did not yield a usable review")
    if correction["attempts"] and not correction["transport_failed"]:
        raise review.ReviewError("Interrupted validation correction cannot be repeated")
    return True


def _validate_specialist_entry(record: dict, entry: dict, proposals: list[dict]) -> None:
    """Validate one saved 3-specialist verification entry and cross-check it against its merged result."""
    if (record.get("specialists") != len(review.SPECIALISTS)
            or entry.get("stage") != "verification"
            or "tiebreaker" in entry or "issue" in entry
            or not isinstance(entry["specialists"], list)
            or [spec.get("specialist") for spec in entry["specialists"] if isinstance(spec, dict)] != list(review.SPECIALISTS)):
        raise ValueError()
    other_requests = (
        {e.get("request") for e in record["reviews"] if e is not entry}
        | {p.get("request") for p in proposals if p.get("disposition") != "discarded_context"}
    )
    spec_reqs: list[int] = []
    for spec in entry["specialists"]:
        if (not isinstance(spec, dict)
                or set(spec) != {"specialist", "request", "verdict", "same_story", "failed"}
                or type(spec["request"]) is not int or not 1 <= spec["request"] <= entry["request"]
                or spec["request"] in other_requests
                or spec["verdict"] not in review.VERDICTS
                or (spec["verdict"] == "approve") != (not spec["failed"])
                or (spec["same_story"] is not None
                    and (not isinstance(spec["same_story"], str) or not review.STORY_ID_RE.fullmatch(spec["same_story"])))
                or not isinstance(spec["failed"], list)
                or any(crit not in review.CRITERIA for crit in spec["failed"])):
            raise ValueError()
        spec_reqs.append(spec["request"])
    if len(set(spec_reqs)) != len(spec_reqs):
        raise ValueError()
    merged = entry["result"]
    merged_criteria = merged["criteria"]
    maj = 2 if len(entry["specialists"]) == 3 else len(entry["specialists"])
    for crit in review.FACTUAL_CRITERIA:
        in_domain_fail = any(crit in review.SPECIALIST_DOMAINS[spec["specialist"]] and crit in spec["failed"] for spec in entry["specialists"])
        majority_fail = sum(crit in spec["failed"] for spec in entry["specialists"]) >= maj
        if (in_domain_fail or majority_fail) and (merged_criteria[crit]["outcome"] == "pass" or merged["verdict"] == "approve"):
            raise ValueError()


def validate_review_state(record, stage, candidate, prepared, *, allow_cached=True):
    """Fail closed on damaged bookkeeping before it can reach a cached approval."""
    req_budget = ReviewRequests(record)
    budget = req_budget.state
    proposals = record["untrusted_proposals"]
    dispositions = {"pending", "superseded_unverified", "discarded_context", "unusable", "literal_tag", "labels", "repeated",
                    "checked_approve", "checked_revise", "checked_hold", "checked_skip"}
    fields = {"error", "request", "stage", "mode", "candidate_before_hash", "candidate_after_hash", "context", "changed_fields", "repair",
              "accepted", "disposition", "reask_trigger", "reask_response"}
    try:
        if stage == "drafted":
            if (prepared is not None or record["reviews"] or "candidate" in record
                    or any(p.get("disposition") != "discarded_context" for p in proposals)):
                raise ValueError()
        elif not isinstance(prepared, dict):
            raise ValueError()
        if len(proposals) > req_budget.max_requests:
            raise ValueError()
        for entry in record["reviews"]:
            if (not isinstance(entry, dict) or entry.get("stage") not in {"review", "verification"}
                    or not _is_sha256(entry.get("candidate_hash"))
                    or ("tiebreaker" in entry and (entry["tiebreaker"] is not True
                                                  or entry.get("stage") != "verification"
                                                  or "issue" in entry))):
                raise ValueError()
            review.validate_review(entry["result"], prepared["packet"],
                                   update=prepared.get("mode") == "update", coverage=prepared.get("coverage"))
            if "specialists" in entry:
                _validate_specialist_entry(record, entry, proposals)
        for proposal in proposals:
            if (not isinstance(proposal, dict) or set(proposal) != fields
                    or proposal["error"] != review.INCONSISTENT_VERDICT
                    or type(proposal["request"]) is not int or not 1 <= proposal["request"] <= budget["reserved"]
                    or proposal["stage"] not in {"review", "verify", "repair", "tiebreak"}
                    or proposal["mode"] not in {"story", "update"}
                    or not _is_sha256(proposal["candidate_before_hash"])
                    or (proposal["candidate_after_hash"] is not None and not _is_sha256(proposal["candidate_after_hash"]))
                    or type(proposal["accepted"]) is not bool or proposal["disposition"] not in dispositions
                    or type(proposal["reask_trigger"]) is not bool
                    or not isinstance(proposal["context"], dict)
                    or set(proposal["context"]) != {"source_hash", "coverage_hash", "binding_hash", "policy_hash"}
                    or not all(_is_sha256(value) for value in proposal["context"].values())
                    or not isinstance(proposal["changed_fields"], list)
                    or proposal["changed_fields"] != sorted(set(proposal["changed_fields"]))
                    or set(proposal["changed_fields"]) - set(candidate_mod.UPDATE_FIELDS if proposal["mode"] == "update" else review.EDITABLE)):
                raise ValueError()
            accepted = proposal["accepted"]
            if proposal["repair"] is not None:
                if review._repair_fields(proposal["repair"], update=proposal["mode"] == "update") != proposal["repair"]:
                    raise ValueError()
            if ((accepted and (proposal["candidate_after_hash"] is None or not proposal["changed_fields"]))
                    or (proposal["disposition"] != "discarded_context"
                        and accepted == (proposal["disposition"] in {"unusable", "literal_tag", "labels", "repeated"}))):
                raise ValueError()
            if proposal["disposition"].startswith("checked_"):
                verdict = proposal["disposition"].removeprefix("checked_")
                if not any(entry["stage"] == "verification"
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
        if "pending_specialist_wave" in record:
            wave = record["pending_specialist_wave"]
            correction = budget["validation_reask"]
            base_keys = {"trigger", "candidate_hash", "context", "failed_specialist", "completed"}
            multi_keys = base_keys | {"pending_specialists"}
            has_multi = isinstance(wave, dict) and set(wave) == multi_keys
            if (stage != "verify" or record.get("specialists") != len(review.SPECIALISTS)
                    or correction is None
                    or not isinstance(wave, dict)
                    or set(wave) not in (base_keys, multi_keys)
                    or wave["trigger"] != correction["trigger"]
                    or wave["candidate_hash"] != digest(candidate)
                    or wave["context"] != _context(prepared, record["policy_hash"])
                    or wave["failed_specialist"] not in review.SPECIALISTS
                    or not isinstance(wave["completed"], list)):
                raise ValueError()
            comp_specs = [c.get("specialist") for c in wave["completed"] if isinstance(c, dict)]
            if len(comp_specs) != len(wave["completed"]) or len(set(comp_specs)) != len(comp_specs):
                raise ValueError()
            if has_multi:
                pend_specs = wave["pending_specialists"]
                if (not isinstance(pend_specs, list)
                        or any(s not in review.SPECIALISTS for s in pend_specs)
                        or len(set(pend_specs)) != len(pend_specs)
                        or wave["failed_specialist"] in pend_specs
                        or wave["failed_specialist"] in comp_specs
                        or set(comp_specs) & set(pend_specs)
                        or set(comp_specs) | {wave["failed_specialist"]} | set(pend_specs) != set(review.SPECIALISTS)):
                    raise ValueError()
            elif comp_specs != [s for s in review.SPECIALISTS if s != wave["failed_specialist"]]:
                raise ValueError()
            other_requests = (
                {e.get("request") for e in record["reviews"]}
                | {p.get("request") for p in proposals if p.get("disposition") != "discarded_context"}
            )
            wave_reqs: list[int] = []
            max_comp_req = budget["reserved"] if has_multi else wave["trigger"] - 1
            for comp in wave["completed"]:
                if (not isinstance(comp, dict) or set(comp) != {"specialist", "request", "result"}
                        or type(comp["request"]) is not int or not 1 <= comp["request"] <= max_comp_req
                        or comp["request"] in other_requests):
                    raise ValueError()
                review.validate_review(comp["result"], prepared["packet"],
                                       update=prepared.get("mode") == "update", coverage=prepared.get("coverage"))
                wave_reqs.append(comp["request"])
            if len(set(wave_reqs)) != len(wave_reqs):
                raise ValueError()
        if "pending_hold" in record:
            if (stage != "verify" or record["pending_hold"] != "specialist_budget"
                    or record.get("specialists") != len(review.SPECIALISTS)
                    or budget["reserved"] < req_budget.max_requests
                    or "pending_specialist_wave" in record):
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
    events = _active_events(record)
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
                seen.add(digest(current))
        else:
            if (_entry_stage(entry) != expected_stage or entry["candidate_hash"] != digest(current)
                    or any(entry.get(key) != value for key, value in context.items())):
                raise ValueError()
            trusted.append(entry)
            action, value = _next_step(trusted, current, prepared, specialists=record.get("specialists", 1))
            last_action, last_value = action, value
            if action in {"verify", "repair", "tiebreak"}:
                if digest(value) != digest(current) and digest(value) in seen:
                    expected_stage = "held"
                else:
                    current, expected_stage = value, action
                    seen.add(digest(current))
            else:
                expected_stage = OUTCOME_STAGES[action]
    if (digest(current) != digest(candidate)
            or (not allow_cached and digest(record.get("candidate")) != digest(candidate))):
        raise ValueError()
    # A zero-call cache hit records its validated proof separately from the
    # current chain. It does not manufacture current-chain reviewer requests.
    cached_terminal = False
    if stage in {"approved", "skipped"} or "approval" in record:
        key = _approval_key(candidate, context, record["policy_hash"])
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
                      and (agreed := _agreed_same_story(trusted)) is not None
                      and agreed == record.get("routed_to")
                      and _can_auto_merge_review(candidate, prepared, trusted[-1]["result"]))
    if stage == "routed" and last_action == "route" and record.get("routed_to") != last_value:
        raise ValueError()
    if (stage != expected_stage and not guarded_approval and not cached_terminal and not merged_handoff
            and not (stage == "held" and record.get("hold_code") in {"missing_sources", "repeat_hold", "specialist_budget"})):
        raise ValueError()


def _literal_tag(prepared):
    payload = json.loads(prepared["row"]["payload"])
    if payload.get("tag_enriched") is True:
        return False
    kind = payload.get("kind") if prepared.get("mode") == "update" else prepared["payload"]["editorial_kind"]
    return kind == "tag"


def _allowed_proposal(before, after, prepared, repair):
    """Check proposed labels without reclassifying read-only update context."""
    update = prepared.get("mode") == "update"
    try:
        candidate_mod.validate_approved(before, after, "update" if update else "story")
    except candidate_mod.ReviewRequired:
        return False
    update_sources = (before.get("updates") or [{}])[-1].get("sources") if update else None
    limits = review.repair_limits(
        prepared["packet"], prepared.get("coverage"), update=update,
        candidate_sources=before.get("sources"), update_sources=update_sources,
    )
    return review.within_label_limits(repair, limits) and (update or review.within_label_limits(after, limits))


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
    return {"raw_inconsistency_count": len(proposals), "accepted_proposal_count": sum(p["accepted"] for p in proposals),
            "unresolved_inconsistency": unresolved}


def _handle_inconsistent_review(stage, candidate, prepared, record, requests, failed, seen, waiting, *, correction, on_reask=None):
    """Record an inconsistent review reply and return ('verify', repaired) or ('reask', candidate)."""
    event = {"error": review.INCONSISTENT_VERDICT, "request": requests.state["reserved"], "stage": stage,
             "mode": prepared.get("mode", "story"),
             "candidate_before_hash": digest(candidate), "candidate_after_hash": None,
             "context": _context(prepared, record["policy_hash"]), "changed_fields": [],
             "repair": None, "accepted": False, "disposition": "unusable",
             "reask_trigger": False, "reask_response": correction}
    requests.state["inconsistent_requests"].append(event["request"])
    record.setdefault("untrusted_proposals", []).append(event)
    try:
        if _literal_tag(prepared):
            event["disposition"] = "literal_tag"
            raise review.ReviewError("Literal tags cannot use untrusted edits")
        is_update = prepared.get("mode") == "update"
        proposed = review._repair_fields(failed.proposal, update=is_update)
        repaired = review.apply_repair(candidate, proposed, update=is_update)
        event["candidate_after_hash"] = digest(repaired)
        event["changed_fields"] = sorted(key for key in candidate if repaired.get(key) != candidate[key])
        event["repair"] = proposed
        if not _allowed_proposal(candidate, repaired, prepared, event["repair"]):
            event["disposition"] = "labels"
            raise review.ReviewError("Untrusted edit exceeds packet label limits")
        if event["candidate_after_hash"] in seen:
            event["disposition"] = "repeated"
            raise review.ReviewError("Untrusted edit repeats a reviewed candidate")
    except review.ReviewError:
        if requests.state["validation_reask"] is None and requests.state["reserved"] < requests.max_requests:
            event["reask_trigger"] = True
            requests.state["validation_reask"] = {"trigger": event["request"], "attempts": [],
                                                   "response": None, "transport_failed": False}
            if on_reask is not None:
                on_reask(event["request"])
            requests.persist()
            return "reask", candidate
        requests.persist()
        raise failed
    if waiting is not None:
        waiting["disposition"] = "superseded_unverified"
    event.update(accepted=True, disposition="pending")
    return "verify", repaired


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
    before, failed = requests.actual, None
    try:
        result = reviewer.review(candidate, prepared["packet"], coverage=prepared["coverage"],
                                 verification=stage in {"verify", "tiebreak"},
                                 issue=review.RELEASE_ISSUE if stage == "repair" else None,
                                 on_request=requests.callback(correction=correction),
                                 **({"validation_error": review.INCONSISTENT_VERDICT} if correction else {}),
                                 **({"update": True} if prepared.get("mode") == "update" else {}),
                                 **({"tiebreaker": True}
                                    if stage == "tiebreak" and _supports_kwarg(reviewer.review, "tiebreaker")
                                    else {}))
    except review.InconsistentReview as exc:
        if requests.actual == before:
            raise
        failed = exc
    if correction and requests.state["validation_reask"]["response"] != requests.state["reserved"]:
        raise AnalysisError("Validation response was not observed", code="app.damaged_job")
    if failed is not None:
        outcome = _handle_inconsistent_review(
            stage, candidate, prepared, record, requests, failed, seen, waiting, correction=correction,
        )
        if outcome[0] == "reask":
            # The correction keeps this exact stage and candidate. Invalid
            # criteria are still absent from the trusted review history.
            return advance_review(reviewer, stage, candidate, prepared, record, requests)
        # The caller persists this audit, exact candidate and verify stage before
        # requesting its next step. No invalid reply is appended to reviews.
        return outcome
    entry = {"stage": "verification" if stage in {"verify", "tiebreak"} else "review",
             **({"issue": "release_labels"} if stage == "repair" else {}),
             **({"tiebreaker": True} if stage == "tiebreak" else {}),
             **({"reask_response": True} if correction else {}),
             "candidate_hash": digest(candidate), "request": requests.state["reserved"], "result": result}
    if waiting is not None:
        if entry["stage"] != "verification" or entry["candidate_hash"] != waiting["candidate_after_hash"]:
            raise AnalysisError("Proposal verification identity changed", code="app.damaged_job")
        waiting["disposition"] = "checked_" + entry["result"]["verdict"]
    record["reviews"].append({**entry, **_context(prepared, record["policy_hash"])})
    action, value = _next_step(record["reviews"], candidate, prepared, specialists=record.get("specialists", 1))
    if action in {"verify", "repair"} and digest(value) != digest(candidate) and digest(value) in seen:
        return "hold", ("verification" if stage in {"verify", "tiebreak"} else "review", "repeated_repair")
    return action, value


def _verified(reviews) -> bool:
    """Whether the latest review is a fresh verification that passed every factual criterion and cites a source."""
    criteria = reviews[-1]["result"]["criteria"] if reviews and reviews[-1]["stage"] == "verification" else None
    return bool(criteria and criteria["source_support"]["source_refs"]) and all(
        check["outcome"] == "pass" for name, check in criteria.items() if name not in review.EDITORIAL_CRITERIA)


def _ignore_at_gate(store, row: dict, observed: str, error: str, code: str, *,
                    clear_story: bool = False, verified_pending: bool = False, before_log=None, **details) -> str:
    def _apply() -> str:
        if not verified_pending:
            store.require_pending_item(row, "Source item changed before gate skip")
        story_clause = ",story_id=NULL" if clear_story else ""
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
        return "ignored"

    if verified_pending:
        return _apply()
    try:
        with store.db:
            return _apply()
    except candidate_mod.StaleCandidate:
        return "stale"


def _attach_item(store, row: dict, draft: dict, writer_key: str, routed_record: dict, observed: str,
                 target_id: str, note: str, *, require_unmapped: bool = False) -> None:
    guard = " AND story_id IS NULL" if require_unmapped else ""
    updated = store.db.execute(
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
    record.pop("pending_specialist_wave", None)
    record.pop("pending_hold", None)
    record.update(outcome="held", hold_code=reason, hold_reason=HOLDS[reason],
                  verified_facts=not proposal_needs_check(record) and _verified(record["reviews"]))
    with store.db:
        store.require_pending_item(row, "Source item changed before hold completed")
        if not store.db.execute("""UPDATE items SET status='rejected',attempts=attempts+1,
            rejections=MAX(rejections,3),next_attempt_at=NULL,last_error=?
            WHERE id=? AND content_hash=? AND status='pending'""",
            ("Final review held: " + HOLDS[reason], row["id"], row["content_hash"])).rowcount:
            raise candidate_mod.StaleCandidate("Source item changed before hold completed")
        store.record_analysis(row, draft, writer_key, observed, review_record=record)
        set_job_stage(store.db, row["id"], "held", record, observed)
        decisions.record(store.db, row["id"], f"held.{stage}.{reason}", observed, review=record)


def _route(store, row, draft, writer_key, record, observed, target, _stage=None) -> str:
    """Attach an unmapped item to `target` once and clear its standalone draft for update review."""
    with store.db:
        store.require_pending_item(row, "Source item changed before routing")
        found = store.db.execute(
            """SELECT CASE WHEN typeof(s.payload)='text' THEN CAST(s.payload AS BLOB) END AS payload
               FROM stories s LEFT JOIN editorial_controls e ON e.story_id=s.id
               WHERE s.id=? AND COALESCE(e.retracted,0)=0""",
            (target,),
        ).fetchone()
        target_payload = saved_object(found["payload"] if found else None)
        if (
            target_payload is None
            or target_payload.get("origin") == "network-health"
            or editorial.retired(store.db, story_id=target) is not None
        ):
            raise candidate_mod.StaleCandidate("Target story changed before routing")
        routed_record = {**record, "outcome": "routed", "routed_to": target}
        _attach_item(store, row, draft, writer_key, routed_record, observed,
                     target, candidate_mod.UNVERIFIED_ROUTE, require_unmapped=True)
        record.update(outcome="routed", routed_to=target)
        return "routed"


def _try_auto_merge(config, store, pair: tuple[str, str], *, propagate: bool,
                    prepared: dict | None = None, draft: dict | None = None,
                    writer_key: str | None = None, record: dict | None = None,
                    observed: str | None = None) -> bool:
    dup_id, survivor_id = pair

    def _guard(db) -> None:
        if propagate:
            candidate_mod.verify_prepared_binding(db, prepared)
        if _auto_merge_pair(store, dup_id, survivor_id) != pair:
            raise candidate_mod.StaleCandidate("Duplicate stories changed before automatic merge")

    if propagate:
        routed_record = {**record, "candidate": record.get("candidate", prepared["candidate"]), "outcome": "routed", "routed_to": survivor_id, "merged_duplicate": dup_id}
        complete = lambda _db: _attach_item(
            store, prepared["row"], draft, writer_key, routed_record, observed,
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
            _guard=_guard,
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
    """Keep the exact old proof and budget until the routed item is prepared again."""
    if not set_job_stage(store.db, row["id"], "routed", record, observed):
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


_DUP_ISSUE_RE = re.compile(
    r"\b(?:closed\s+as\s+(?:a\s+)?duplicate(?:\s+of)?|duplicate\s+of|duplicates?)\s*:?\s*"
    r"(?:#\d+|[\w.-]+/[\w./-]+#\d+|https://gitlab\.torproject\.org/\S+)"
    r"|\bdup(?:licate)?\s+of\s+(?:#\d+|[\w.-]+/[\w./-]+#\d+|https://gitlab\.torproject\.org/\S+)",
    re.I,
)
_NOT_DUP_RE = re.compile(
    r"\b(?:(?:is|was|are|were)n['’]?t\s+(?:a\s+)?|not\s+(?:a\s+)?|no\s+|non[- ]?)duplicates?\b",
    re.I,
)
_DUP_LABELS = frozenset({"duplicate", "status::duplicate"})
_DUP_SECURITY_GUARD_RE = re.compile(
    r"\b(?:vulnerabilit\w*|exploit\w*|null[- ]?(?:pointer[- ]|ptr[- ])?deref\w*|use[- ]after[- ]free|buffer\s+overflow|"
    r"out[- ]of[- ]bounds|remote\s+code(?:\s+execution)?)\b",
    re.I,
)
_PURE_ACK_RE = re.compile(
    r"^(?:"
    r"(?:many\s+|hi[,.]?\s*)?(?:thanks?(?:\s+(?:a\s+lot|very\s+much|everyone|all))?|"
    r"thank\s+you(?:\s+(?:very\s+much|all))?|\+1|lgtm|ack|bumped?|ping|me\s+too|"
    r"same\s+here|agreed|works\s+for\s+me|verified|done|ok(?:ay)?|looks\s+good(?:\s+to\s+me)?|"
    r"no\s+(?:news|changes?|updates?|issues?)(?:\s+here)?|following|subscribed|bump|"
    r"test(?:ing)?(?:\s+post)?(?:\s*,?\s*please\s+ignore)?)"
    r"\s*[,!.:;)]*\s*"
    r")+(?:for\s+(?:the\s+)?(?:update|report|info|feedback|reply|testing)[!.,]*)?$",
    re.I,
)
_PROTECTED_LABELS = frozenset({"security", "regression", "critical", "severity::high", "severity::critical"})


def _retry_consumed_by_terminal(db, item_id: str, retry_at: str) -> bool:
    """Return whether a terminal decision logged after `retry_at` has consumed that retry exemption."""
    retry_dl = db.execute(
        """SELECT COALESCE(MAX(id),0) FROM decision_log
           WHERE item_id=? AND code IN ('operator.retried','operator.reconsidered') AND decided_at=?""",
        (item_id, retry_at),
    ).fetchone()[0]
    if retry_dl:
        terminal = db.execute(
            """SELECT 1 FROM decision_log
               WHERE item_id=?
                 AND (code GLOB 'published.*' OR code GLOB 'skipped.*' OR code GLOB 'held.*'
                      OR code GLOB 'failed.*' OR code='operator.dismissed')
                 AND (decided_at>? OR (decided_at=? AND id>?))
               LIMIT 1""",
            (item_id, retry_at, retry_at, retry_dl),
        ).fetchone()
    else:
        terminal = db.execute(
            """SELECT 1 FROM decision_log
               WHERE item_id=?
                 AND (code GLOB 'published.*' OR code GLOB 'skipped.*' OR code GLOB 'held.*'
                      OR code GLOB 'failed.*' OR code='operator.dismissed')
                 AND decided_at>?
               LIMIT 1""",
            (item_id, retry_at),
        ).fetchone()
    return terminal is not None


def _has_operator_retry(db, row: dict | None) -> bool:
    if not (isinstance(row, dict) and isinstance(item_id := row.get("id"), str) and item_id
            and isinstance(content_hash := row.get("content_hash"), str) and content_hash):
        return False
    exact = db.execute(
        "SELECT created_at FROM rejection_actions WHERE item_id=? AND content_hash=? AND action='retry' ORDER BY action_id DESC LIMIT 1",
        (item_id, content_hash),
    ).fetchone()
    if exact is not None:
        exact_at = exact["created_at"]
        if not isinstance(exact_at, str) or not exact_at:
            return True
        return not _retry_consumed_by_terminal(db, item_id, exact_at)
    latest = db.execute(
        "SELECT action,created_at FROM rejection_actions WHERE item_id=? ORDER BY action_id DESC LIMIT 1",
        (item_id,),
    ).fetchone()
    if latest is None or latest["action"] != "retry" or not isinstance(latest["created_at"], str):
        return False
    retry_at = latest["created_at"]
    raw_payload = row.get("payload")
    payload = (
        saved_object(raw_payload.encode("utf-8") if isinstance(raw_payload, str) else raw_payload)
        if isinstance(raw_payload, (str, bytes)) else None
    )
    checked_at = payload.get("comments_checked_at") if isinstance(payload, dict) and payload.get("kind") == "gitlab_issue" else None
    if not isinstance(checked_at, str) or not checked_at:
        return False
    try:
        if parse_utc(checked_at) < parse_utc(retry_at):
            return False
    except ValueError:
        return False
    return not _retry_consumed_by_terminal(db, item_id, retry_at)


def _security_disclosure(item: dict) -> bool:
    """A HackerOne disclosure, verified TROVE advisory, or high/critical security issue may become public long after filing."""
    if is_hackerone_item(item) or is_trove_item(item):
        return True
    if item.get("kind") != "gitlab_issue":
        return False
    labels = folded_labels(item)
    return "security" in labels and bool(labels & HIGH_SECURITY_SEVERITIES)


def _eval_deterministic_skip(
    db, item: dict, existing: dict | None, *, row: dict | None = None, dirauth_users=None, tor_core_users=None
) -> tuple[str, str] | None:
    if item.get("kind") == "tag" or item.get("origin") == "network-health" or _has_operator_retry(db, row):
        return None
    body = item.get("source_content") if isinstance(item.get("source_content"), str) else (item.get("content") or "")
    url = str(item.get("url") or "")
    quoted_list = is_quoted_list_post(url, body)
    unquoted = unquoted_mail_text(body) if quoted_list else body
    if quoted_list and len(normalize_evidence(unquoted)) < MIN_EVIDENCE_CHARS:
        return "skipped.gate.quoted_only", "Mailing-list reply contains no qualifying unquoted author text"
    labels = folded_labels(item)
    if (
        existing is None
        and item.get("kind") == "gitlab_issue"
        and "security" not in labels
        and not is_hackerone_item(item)
        and not is_trove_item(item)
        and not cve_ids(item)
        and not trove_ids(item)
    ):
        comments_text = "\n".join(str(n.get("body") or "") for n in (item.get("public_comments") or ()) if isinstance(n, dict))
        full_text = f"{item.get('title') or ''}\n{body}\n{comments_text}"
        if not _NOT_DUP_RE.search(full_text) and not _DUP_SECURITY_GUARD_RE.search(full_text):
            matches = list(_DUP_ISSUE_RE.finditer(full_text))
            target_refs: list[str] = []
            if matches:
                dup_snippet = "\n".join(m.group(0) for m in matches)
                closing, mentioned = gitlab_refs(
                    {**item, "title": "", "content": dup_snippet, "source_content": dup_snippet, "public_comments": []}
                )
                target_refs = [*closing, *mentioned]
            elif (labels & _DUP_LABELS) and item.get("upstream_state") == "closed":
                closing, mentioned = gitlab_refs(item)
                target_refs = [*closing, *mentioned]
            if target_refs and candidate_mod._stories_for_urls(db, target_refs):
                return "skipped.gate.duplicate_issue", "Duplicate GitLab issue referencing an already-covered story"
    auth = effective_authority(item, dirauth_users, tor_core_users)
    if mandatory_news_rule({**item, "authority": auth}) is not None:
        return None
    if (
        is_hackerone_item(item)
        or is_trove_item(item)
        or (is_dirauth_item(item, dirauth_users) and _dirauth_operational_relevant(item))
        or _security_disclosure(item)
        or cve_ids(item)
        or trove_ids(item)
        or (labels & _PROTECTED_LABELS)
    ):
        return None
    norm_body = re.sub(r"\s+", " ", unquoted).strip()
    if (
        norm_body
        and len(norm_body) <= 120
        and _PURE_ACK_RE.fullmatch(norm_body)
        and not item.get("public_comments")
        and not (existing is not None and item.get("upstream_state") == "closed")
    ):
        return "skipped.gate.housekeeping", "Routine acknowledgment or no-content reply"
    if (
        existing is None
        and not item.get("public_comments")
        and (housekeeping := is_housekeeping_item(item)) is not None
    ):
        return housekeeping
    return None


def _deterministic_skip(config, store, row, item, observed, *, existing=candidate_mod._UNSET) -> str | None:
    """Ignore quoted-only replies, housekeeping items, and covered duplicate GitLab issues before any model call."""
    coll = config.get("collection") or {} if isinstance(config, dict) else {}
    dirauth_users = coll.get("dirauth_gitlab_users")
    tor_core_users = coll.get("tor_core_gitlab_users")
    if existing is candidate_mod._UNSET:
        existing = candidate_mod.existing_story(store.db, row)
    if (
        _eval_deterministic_skip(
            store.db, item, existing, row=row, dirauth_users=dirauth_users, tor_core_users=tor_core_users
        )
        is None
    ):
        return None
    try:
        with store.db:
            current = store.require_pending_item(row, "Source item changed before deterministic gate skip")
            try:
                curr_item = json.loads(current["payload"])
            except (ValueError, TypeError):
                return "stale"
            curr_existing = candidate_mod.existing_story(store.db, current)
            hit = _eval_deterministic_skip(
                store.db, curr_item, curr_existing, row=current, dirauth_users=dirauth_users, tor_core_users=tor_core_users
            )
            if hit is None:
                return "stale"
            code, reason = hit
            return _ignore_at_gate(store, row, observed, reason, code, verified_pending=True)
    except candidate_mod.StaleCandidate:
        return "stale"


def _not_recent(config, store, row, item, observed, *, existing=candidate_mod._UNSET) -> str | None:
    """Ignore, before any model call, an item that would start a story from an old development."""
    def _skip_developed_at(r: dict, it: dict, story=candidate_mod._UNSET) -> str | None:
        if story is candidate_mod._UNSET:
            story = candidate_mod.existing_story(store.db, r)
        developed = developed_at(it)
        if (developed >= after(-NEW_STORY_DAYS * 86400, r["last_seen"])
                or _security_disclosure(it)
                or story is not None
                or _has_operator_retry(store.db, r)):
            return None
        return developed

    if _skip_developed_at(row, item, existing) is None:
        return None

    def _maybe_check_comments() -> None:
        if item.get("kind") == "gitlab_issue" and "comments_source_key" not in item:
            from .comments import request_check
            request_check(store.db, config, row, observed)

    try:
        with store.db:
            current = store.require_pending_item(row, "Source item changed before recency skip")
            try:
                current_developed = _skip_developed_at(current, json.loads(current["payload"]))
            except editorial.RetiredStory:
                raise
            except (ValueError, TypeError, KeyError):
                return "stale"
            if current_developed is None:
                return "stale"
            reason = f"Not recent: newest dated development {current_developed} is over {NEW_STORY_DAYS} days before collection"
            return _ignore_at_gate(store, row, observed, reason, "skipped.gate.not_recent",
                                   verified_pending=True, before_log=_maybe_check_comments,
                                   developed_at=current_developed, collected_at=current["last_seen"])
    except candidate_mod.StaleCandidate:
        return "stale"


class _WorkerRequestObserver(RequestObserver):
    """Thread-safe in-memory request observer backed by a pre-reserved pool."""

    def __init__(self, lock: threading.Lock, shared_used: list[int], max_pool: int):
        self._lock = lock
        self._shared_used = shared_used
        self._max_pool = max_pool
        self.used = 0
        self._can_refund = False

    def __call__(self, delta: int) -> None:
        with self._lock:
            if delta == 1:
                if self._shared_used[0] >= self._max_pool:
                    raise review.ReviewLimitReached("Review request budget exhausted")
                self._shared_used[0] += 1
                self.used += 1
                self._can_refund = True
            elif delta == -1 and self._can_refund:
                self._shared_used[0] -= 1
                self.used -= 1
                self._can_refund = False
            else:
                raise ValueError("Invalid review request accounting")

    def response_received(self) -> None:
        """Disallow post-response refunds once a completion response has been received."""
        with self._lock:
            self._can_refund = False

    def transport_failed(self) -> None:
        """Disallow refunds once a transport attempt has already been dispatched."""
        with self._lock:
            self._can_refund = False


def _supports_kwarg(fn, name: str) -> bool:
    try:
        params = inspect.signature(fn).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(param.name == name or param.kind == inspect.Parameter.VAR_KEYWORD for param in params)


def _writer_cache_options(writer) -> tuple[int, bool | None]:
    """Return `(best_of, quote_digest)` matching how `writer` builds drafts."""
    best_of = getattr(writer, "best_of", 1)
    if type(best_of) is not int or best_of < 1:
        best_of = 1
    quote_digest = True if getattr(writer, "quote_digest", None) is True else None
    return best_of, quote_digest


def _writer_metadata_impact(writer) -> bool:
    """Return whether `writer` explicitly runs the focused metadata and impact pass."""
    return getattr(writer, "metadata_impact_pass", False) is True


def _require_specialist_support(rev) -> None:
    if rev is None or not _supports_kwarg(rev.review, "specialist"):
        raise TypeError("Reviewer does not accept required 'specialist' keyword argument")


def _call_reviewer_worker(reviewer_factory, candidate, prepared, obs: _WorkerRequestObserver, *,
                          is_verify: bool, specialist: str | None = None, close_worker: bool = True):
    try:
        rev = reviewer_factory()
        kwargs = {
            "coverage": copy.deepcopy(prepared["coverage"]),
            "verification": is_verify,
            "on_request": obs,
            **({"update": True} if prepared.get("mode") == "update" else {}),
        }

        def _invoke():
            if specialist is not None:
                _require_specialist_support(rev)
                kwargs["specialist"] = specialist
            return rev.review(copy.deepcopy(candidate), copy.deepcopy(prepared["packet"]), **kwargs), None

        if close_worker and hasattr(rev, "__enter__") and hasattr(rev, "__exit__"):
            with rev:
                return _invoke()
        try:
            return _invoke()
        finally:
            if close_worker and hasattr(rev, "close"):
                rev.close()
    except Exception as exc:
        return None, exc


def _reask_specialist_worker(reviewer_factory, reviewer, candidate, prepared, requests, *, specialist: str):
    """Run one validation-reask call for the single failed specialist lens."""
    obs = requests.callback(correction=True)
    if reviewer_factory is not None:
        rev = reviewer_factory()
        close_after = True
    else:
        rev = reviewer
        close_after = False
    kwargs = {
        "coverage": copy.deepcopy(prepared["coverage"]),
        "verification": True,
        "specialist": specialist,
        "validation_error": review.INCONSISTENT_VERDICT,
        "on_request": obs,
        **({"update": True} if prepared.get("mode") == "update" else {}),
    }

    def _invoke():
        _require_specialist_support(rev)
        return rev.review(copy.deepcopy(candidate), copy.deepcopy(prepared["packet"]), **kwargs)

    try:
        if close_after and hasattr(rev, "__enter__") and hasattr(rev, "__exit__"):
            with rev:
                res = _invoke()
        else:
            try:
                res = _invoke()
            finally:
                if close_after and hasattr(rev, "close"):
                    rev.close()
    except review.InconsistentReview as exc:
        return None, exc
    except Exception:
        reask = requests.state["validation_reask"]
        if reask is not None and reask["response"] is not None and requests.record.pop("pending_specialist_wave", None) is not None:
            requests.persist()
        raise
    if requests.state["validation_reask"]["response"] != requests.state["reserved"]:
        raise AnalysisError("Validation response was not observed", code="app.damaged_job")
    return res, None


def _specialist_meta(spec_results: list[dict], s_used_list: list[int], base_offset: int, max_req: int, *,
                     failed_idx: int | None = None, reask_req: int | None = None) -> list[dict]:
    meta: list[dict | None] = [None] * len(review.SPECIALISTS)
    running = base_offset
    for idx, (specialist, used, res) in enumerate(zip(review.SPECIALISTS, s_used_list, spec_results)):
        if idx == failed_idx:
            continue
        running += used
        req_num = max(1, min(max_req, running))
        meta[idx] = {
            "specialist": specialist,
            "request": req_num,
            "verdict": res["verdict"],
            "same_story": res.get("same_story"),
            "failed": [crit for crit in review.CRITERIA if res["criteria"][crit]["outcome"] != "pass"],
        }
    if failed_idx is not None and reask_req is not None:
        res = spec_results[failed_idx]
        meta[failed_idx] = {
            "specialist": review.SPECIALISTS[failed_idx],
            "request": reask_req,
            "verdict": res["verdict"],
            "same_story": res.get("same_story"),
            "failed": [crit for crit in review.CRITERIA if res["criteria"][crit]["outcome"] != "pass"],
        }
    return [entry for entry in meta if entry is not None]


def _pending_specialist_wave_data(
    spec_results: list[dict], s_used_list: list[int], base_offset: int, trigger_req: int,
    failed_idx: int, cand_hash: str, ctx: dict,
) -> dict:
    running = base_offset
    completed: list[dict] = []
    upper = max(1, trigger_req - 1)
    for idx, (specialist, used, res) in enumerate(zip(review.SPECIALISTS, s_used_list, spec_results)):
        if idx == failed_idx:
            continue
        running += used
        req_num = max(1, min(upper, running))
        completed.append({"specialist": specialist, "request": req_num, "result": copy.deepcopy(res)})
    return {
        "trigger": trigger_req,
        "candidate_hash": cand_hash,
        "context": copy.deepcopy(ctx),
        "failed_specialist": review.SPECIALISTS[failed_idx],
        "completed": completed,
    }


def _finish_specialist_wave(by_spec: dict[str, tuple[int, dict]], candidate, prepared, record,
                            cand_hash: str, final_req: int, ctx: dict, waiting, *, reasked: bool):
    """Merge completed specialist replies into one trusted verification entry and choose next step."""
    spec_results = [by_spec[spec][1] for spec in review.SPECIALISTS]
    merged = review.merge_specialist_verdicts(
        spec_results, candidate, prepared["packet"],
        update=prepared.get("mode") == "update", coverage=prepared["coverage"],
    )
    meta = [
        {
            "specialist": spec,
            "request": by_spec[spec][0],
            "verdict": by_spec[spec][1]["verdict"],
            "same_story": by_spec[spec][1].get("same_story"),
            "failed": [crit for crit in review.CRITERIA if by_spec[spec][1]["criteria"][crit]["outcome"] != "pass"],
        }
        for spec in review.SPECIALISTS
    ]
    ver_entry = {
        "stage": "verification",
        **({"reask_response": True} if reasked else {}),
        "candidate_hash": cand_hash,
        "request": final_req,
        "result": merged,
        "specialists": meta,
        **ctx,
    }
    if waiting is not None:
        if ver_entry["candidate_hash"] != waiting["candidate_after_hash"]:
            raise AnalysisError("Proposal verification identity changed", code="app.damaged_job")
        waiting["disposition"] = "checked_" + merged["verdict"]
    record["reviews"].append(ver_entry)
    action, value = _next_step(record["reviews"], candidate, prepared, specialists=record.get("specialists", 1))
    if action in {"verify", "repair"} and digest(value) != cand_hash and digest(value) in _seen_candidates(record, candidate, prepared):
        return "hold", ("verification", "repeated_repair")
    return action, value


def _enter_specialist_budget_hold(record: dict, waiting: dict | None, requests: ReviewRequests):
    """Persist an explicit budget-hold transition so a resume completes the hold without calling `_pending_reask`."""
    record.pop("pending_specialist_wave", None)
    if waiting is not None:
        waiting["disposition"] = "superseded_unverified"
    record["pending_hold"] = "specialist_budget"
    requests.persist()
    return "hold", ("verification", "specialist_budget")


def _run_pending_specialist_reasks(reviewer_factory, reviewer, candidate, prepared, record, requests,
                                   *, waiting=None, cand_hash: str, ctx: dict):
    """Drain all queued inconsistent specialists in `pending_specialist_wave`, up to budget."""
    seen = _seen_candidates(record, candidate, prepared)
    while "pending_specialist_wave" in record:
        reask_state = requests.state["validation_reask"]
        if reask_state is not None and reask_state["response"] is not None:
            record.pop("pending_specialist_wave", None)
            if waiting is not None:
                waiting["disposition"] = "superseded_unverified"
            requests.persist()
            raise review.ReviewError("Validation correction did not yield a usable review")
        wave = record["pending_specialist_wave"]
        if requests.state["reserved"] >= requests.max_requests:
            return _enter_specialist_budget_hold(record, waiting, requests)
        trigger_req = wave["trigger"]
        failed_specialist = wave["failed_specialist"]
        reask_res, reask_exc = _reask_specialist_worker(
            reviewer_factory, reviewer, candidate, prepared, requests,
            specialist=failed_specialist,
        )
        if reask_exc is not None:
            record.pop("pending_specialist_wave", None)
            if requests.state["reserved"] > trigger_req:
                return _handle_inconsistent_review(
                    "verify", candidate, prepared, record, requests, reask_exc,
                    seen, waiting, correction=True,
                )
            requests.persist()
            raise reask_exc
        reask_req = requests.state["reserved"]
        wave["completed"].append({
            "specialist": failed_specialist,
            "request": reask_req,
            "result": copy.deepcopy(reask_res),
        })
        remaining = list(wave.get("pending_specialists") or ())
        if not remaining:
            by_spec = {entry["specialist"]: (entry["request"], entry["result"]) for entry in wave["completed"]}
            record.pop("pending_specialist_wave", None)
            return _finish_specialist_wave(
                by_spec, candidate, prepared, record, cand_hash, reask_req, ctx, waiting, reasked=True,
            )
        if requests.state["reserved"] >= requests.max_requests:
            return _enter_specialist_budget_hold(record, waiting, requests)
        wave["failed_specialist"] = remaining[0]
        wave["pending_specialists"] = remaining[1:]
        requests.state["validation_reask"] = {
            "trigger": trigger_req,
            "attempts": [],
            "response": None,
            "transport_failed": False,
        }
        requests.persist()
    raise AnalysisError("Pending specialist wave ended unexpectedly", code="app.damaged_job")


def _resume_specialist_reask(reviewer_factory, reviewer, candidate, prepared, record, requests):
    """Resume an interrupted specialist validation reask using saved sibling specialist replies."""
    wave = record.get("pending_specialist_wave")
    cand_hash = digest(candidate)
    ctx = _context(prepared, record["policy_hash"])
    if not isinstance(wave, dict) or wave.get("candidate_hash") != cand_hash or wave.get("context") != ctx:
        raise AnalysisError("Validation correction wave changed", code="app.damaged_job")
    waiting = pending_proposal(record)
    return _run_pending_specialist_reasks(
        reviewer_factory, reviewer, candidate, prepared, record, requests,
        waiting=waiting, cand_hash=cand_hash, ctx=ctx,
    )


def _resolve_specialist_wave(spec_outcomes, s_used_list: list[int], candidate, prepared, record, requests,
                             *, base_offset: int, cand_hash: str, ctx: dict, waiting=None,
                             on_non_inconsistent=None, reviewer_factory=None, reviewer=None):
    results, excs = zip(*spec_outcomes)
    non_inconsistent = [(idx, exc) for idx, exc in enumerate(excs)
                        if exc is not None and not isinstance(exc, review.InconsistentReview)]
    if non_inconsistent:
        if on_non_inconsistent is not None:
            on_non_inconsistent()
        else:
            requests.persist()
        raise non_inconsistent[0][1]

    inconsistent = [(idx, exc) for idx, exc in enumerate(excs)
                    if isinstance(exc, review.InconsistentReview) and s_used_list[idx] > 0]
    if not inconsistent:
        running = base_offset
        by_spec = {}
        max_req = requests.state["reserved"]
        for idx, (spec, used, res) in enumerate(zip(review.SPECIALISTS, s_used_list, results)):
            running += used
            by_spec[spec] = (max(1, min(max_req, running)), res)
        return _finish_specialist_wave(
            by_spec, candidate, prepared, record, cand_hash, max_req, ctx, waiting, reasked=False,
        )

    if len(inconsistent) == 1 and requests.state["validation_reask"] is None:
        failed_idx, inc_exc = inconsistent[0]
        seen = _seen_candidates(record, candidate, prepared)
        spec_results = list(results)

        def _attach_pending_wave(trigger_req_num: int) -> None:
            record["pending_specialist_wave"] = _pending_specialist_wave_data(
                spec_results, s_used_list, base_offset, trigger_req_num, failed_idx, cand_hash, ctx,
            )

        step = _handle_inconsistent_review(
            "verify", candidate, prepared, record, requests, inc_exc,
            seen, waiting, correction=False, on_reask=_attach_pending_wave,
        )
        if step[0] == "verify":
            return step
        return _run_pending_specialist_reasks(
            reviewer_factory, reviewer, candidate, prepared, record, requests,
            waiting=waiting, cand_hash=cand_hash, ctx=ctx,
        )

    running = base_offset
    wave_reqs: list[int] = []
    for used in s_used_list:
        running += used
        wave_reqs.append(max(1, min(requests.state["reserved"], running)))
    can_reask = requests.state["reserved"] < requests.max_requests
    trigger_pos = inconsistent[-1][0]
    proposals = record.setdefault("untrusted_proposals", [])
    for idx, _exc in inconsistent:
        req_num = wave_reqs[idx]
        requests.state["inconsistent_requests"].append(req_num)
        proposals.append({
            "error": review.INCONSISTENT_VERDICT,
            "request": req_num,
            "stage": "verify",
            "mode": prepared.get("mode", "story"),
            "candidate_before_hash": cand_hash,
            "candidate_after_hash": None,
            "context": copy.deepcopy(ctx),
            "changed_fields": [],
            "repair": None,
            "accepted": False,
            "disposition": "unusable",
            "reask_trigger": bool(can_reask and idx == trigger_pos),
            "reask_response": False,
        })
    if not can_reask:
        return _enter_specialist_budget_hold(record, waiting, requests)

    trigger_req = wave_reqs[trigger_pos]
    requests.state["validation_reask"] = {
        "trigger": trigger_req,
        "attempts": [],
        "response": None,
        "transport_failed": False,
    }
    failed_set = {idx for idx, _ in inconsistent}
    completed = [
        {
            "specialist": review.SPECIALISTS[idx],
            "request": wave_reqs[idx],
            "result": copy.deepcopy(results[idx]),
        }
        for idx in range(len(review.SPECIALISTS))
        if idx not in failed_set
    ]
    pending_specs = [review.SPECIALISTS[idx] for idx, _ in inconsistent]
    record["pending_specialist_wave"] = {
        "trigger": trigger_req,
        "candidate_hash": cand_hash,
        "context": copy.deepcopy(ctx),
        "failed_specialist": pending_specs[0],
        "completed": completed,
        "pending_specialists": pending_specs[1:],
    }
    requests.persist()
    return _run_pending_specialist_reasks(
        reviewer_factory, reviewer, candidate, prepared, record, requests,
        waiting=waiting, cand_hash=cand_hash, ctx=ctx,
    )


def _parallel_specialist_verify(reviewer_factory, candidate, prepared, record, requests, *,
                                reviewer=None, specialists: int = 3):
    """Run all specialist verification passes concurrently and synthesize their verdicts fail-closed."""
    if specialists != len(review.SPECIALISTS):
        raise ValueError("specialists must match review.SPECIALISTS")
    validate_review_state(record, "verify", candidate, prepared)
    waiting = pending_proposal(record)
    base_reserved = requests.state["reserved"]
    spec_count = len(review.SPECIALISTS)
    for _ in range(spec_count):
        requests.callback()(1)
    lock = threading.Lock()
    shared_used = [0]
    obs_specs = [_WorkerRequestObserver(lock, shared_used, spec_count) for _ in review.SPECIALISTS]
    cand_hash = digest(candidate)
    ctx = _context(prepared, record["policy_hash"])

    with ThreadPoolExecutor(max_workers=spec_count) as pool:
        futs = [
            pool.submit(_call_reviewer_worker, reviewer_factory, candidate, prepared, obs, is_verify=True, specialist=spec)
            for spec, obs in zip(review.SPECIALISTS, obs_specs)
        ]
        outcomes = [fut.result() for fut in futs]

    s_used_list = [obs.used for obs in obs_specs]
    total_s_used = sum(s_used_list)
    requests.actual += total_s_used - spec_count
    requests.state["reserved"] = base_reserved + total_s_used
    return _resolve_specialist_wave(
        outcomes, s_used_list, candidate, prepared, record, requests,
        base_offset=base_reserved, cand_hash=cand_hash, ctx=ctx, waiting=waiting,
        reviewer_factory=reviewer_factory, reviewer=reviewer,
    )


def _sequential_specialist_verify(reviewer, candidate, prepared, record, requests, *, specialists: int = 3):
    """Run all specialist verification passes sequentially using `reviewer` without closing it."""
    if specialists != len(review.SPECIALISTS):
        raise ValueError("specialists must match review.SPECIALISTS")
    validate_review_state(record, "verify", candidate, prepared)
    waiting = pending_proposal(record)
    base_reserved = requests.state["reserved"]
    spec_count = len(review.SPECIALISTS)
    for _ in range(spec_count):
        requests.callback()(1)
    lock = threading.Lock()
    shared_used = [0]
    obs_specs = [_WorkerRequestObserver(lock, shared_used, spec_count) for _ in review.SPECIALISTS]
    cand_hash = digest(candidate)
    ctx = _context(prepared, record["policy_hash"])
    outcomes = [
        _call_reviewer_worker(
            lambda: reviewer, candidate, prepared, obs, is_verify=True, specialist=spec, close_worker=False,
        )
        for spec, obs in zip(review.SPECIALISTS, obs_specs)
    ]
    s_used_list = [obs.used for obs in obs_specs]
    total_s_used = sum(s_used_list)
    requests.actual += total_s_used - spec_count
    requests.state["reserved"] = base_reserved + total_s_used
    return _resolve_specialist_wave(
        outcomes, s_used_list, candidate, prepared, record, requests,
        base_offset=base_reserved, cand_hash=cand_hash, ctx=ctx, waiting=waiting,
        reviewer=reviewer,
    )


def _parallel_initial_review(reviewer_factory, candidate, prepared, record, requests, *, on_verify, save_verify,
                             specialists: int = 1, reviewer=None):
    """Run initial review and speculative verification concurrently without SQLite calls in worker threads."""
    if specialists not in (1, len(review.SPECIALISTS)):
        raise ValueError("specialists must be 1 or 3")
    base_reserved = requests.state["reserved"]
    lock = threading.Lock()
    shared_used = [0]
    cand_hash = digest(candidate)
    ctx = _context(prepared, record["policy_hash"])

    if specialists == len(review.SPECIALISTS):
        total_slots = 1 + len(review.SPECIALISTS)
        for _ in range(total_slots):
            requests.callback()(1)
        obs_rev = _WorkerRequestObserver(lock, shared_used, total_slots)
        obs_specs = [_WorkerRequestObserver(lock, shared_used, total_slots) for _ in review.SPECIALISTS]
        with ThreadPoolExecutor(max_workers=total_slots) as pool:
            fut_rev = pool.submit(_call_reviewer_worker, reviewer_factory, candidate, prepared, obs_rev, is_verify=False)
            fut_specs = [
                pool.submit(_call_reviewer_worker, reviewer_factory, candidate, prepared, obs, is_verify=True, specialist=spec)
                for spec, obs in zip(review.SPECIALISTS, obs_specs)
            ]
            rev_res, rev_exc = fut_rev.result()
            spec_outcomes = [fut.result() for fut in fut_specs]

        r_used = obs_rev.used
        s_used_list = [obs.used for obs in obs_specs]
        total_s_used = sum(s_used_list)
        requests.actual += r_used + total_s_used - total_slots
        if rev_exc is not None:
            if isinstance(rev_exc, review.InconsistentReview) and r_used > 0:
                requests.state["reserved"] = base_reserved + total_s_used + r_used
                step = _handle_inconsistent_review(
                    "review", candidate, prepared, record, requests, rev_exc,
                    _seen_candidates(record, candidate, prepared), None, correction=False,
                )
                return ("review", candidate) if step[0] == "reask" else step
            requests.state["reserved"] = base_reserved + r_used + total_s_used
            requests.persist()
            raise rev_exc

        requests.state["reserved"] = base_reserved + r_used + total_s_used
        rev_entry = {"stage": "review", "candidate_hash": cand_hash,
                     "request": base_reserved + r_used, "result": rev_res, **ctx}
        record["reviews"].append(rev_entry)
        seen = _seen_candidates(record, candidate, prepared)
        action, value = _next_step(record["reviews"], candidate, prepared, specialists=specialists)
        if action in {"verify", "repair"} and digest(value) != cand_hash and digest(value) in seen:
            action, value = "hold", ("review", "repeated_repair")

        if not (action == "verify" and digest(value) == cand_hash):
            return action, value

        on_verify()
        return _resolve_specialist_wave(
            spec_outcomes, s_used_list, candidate, prepared, record, requests,
            base_offset=base_reserved + r_used, cand_hash=cand_hash, ctx=ctx,
            on_non_inconsistent=save_verify, reviewer_factory=reviewer_factory, reviewer=reviewer,
        )

    requests.callback()(1)
    requests.callback()(1)
    obs_rev = _WorkerRequestObserver(lock, shared_used, 2)
    obs_ver = _WorkerRequestObserver(lock, shared_used, 2)

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_rev = pool.submit(_call_reviewer_worker, reviewer_factory, candidate, prepared, obs_rev, is_verify=False)
        fut_ver = pool.submit(_call_reviewer_worker, reviewer_factory, candidate, prepared, obs_ver, is_verify=True)
        rev_res, rev_exc = fut_rev.result()
        ver_res, ver_exc = fut_ver.result()

    r_used, v_used = obs_rev.used, obs_ver.used
    requests.actual += r_used + v_used - 2
    if rev_exc is not None:
        if isinstance(rev_exc, review.InconsistentReview) and r_used > 0:
            requests.state["reserved"] = base_reserved + v_used + r_used
            step = _handle_inconsistent_review(
                "review", candidate, prepared, record, requests, rev_exc,
                _seen_candidates(record, candidate, prepared), None, correction=False,
            )
            return ("review", candidate) if step[0] == "reask" else step
        requests.state["reserved"] = base_reserved + r_used + v_used
        requests.persist()
        raise rev_exc

    requests.state["reserved"] = base_reserved + r_used + v_used
    rev_entry = {"stage": "review", "candidate_hash": cand_hash,
                 "request": base_reserved + r_used, "result": rev_res, **ctx}
    record["reviews"].append(rev_entry)
    seen = _seen_candidates(record, candidate, prepared)
    action, value = _next_step(record["reviews"], candidate, prepared, specialists=specialists)
    if action in {"verify", "repair"} and digest(value) != cand_hash and digest(value) in seen:
        action, value = "hold", ("review", "repeated_repair")

    if not (action == "verify" and digest(value) == cand_hash):
        return action, value

    on_verify()
    if ver_exc is not None:
        if isinstance(ver_exc, review.InconsistentReview) and v_used > 0:
            step = _handle_inconsistent_review(
                "verify", candidate, prepared, record, requests, ver_exc,
                _seen_candidates(record, candidate, prepared), None, correction=False,
            )
            return ("verify", candidate) if step[0] == "reask" else step
        save_verify()
        raise ver_exc

    ver_entry = {"stage": "verification", "candidate_hash": cand_hash,
                 "request": base_reserved + r_used + v_used, "result": ver_res, **ctx}
    record["reviews"].append(ver_entry)
    action, value = _next_step(record["reviews"], candidate, prepared, specialists=specialists)
    if action in {"verify", "repair"} and digest(value) != cand_hash and digest(value) in _seen_candidates(record, candidate, prepared):
        return "hold", ("verification", "repeated_repair")
    return action, value


def _has_specialist_evidence(rec: dict, cand_hash: str, required: int, *, verdict_name: str | None = None) -> bool:
    if required <= 1:
        return True
    if rec.get("specialists") != required:
        return False
    verifications = [
        entry for entry in rec.get("reviews", ())
        if isinstance(entry, dict)
        and entry.get("stage") == "verification"
        and entry.get("candidate_hash") == cand_hash
    ]
    if verdict_name == "approve" or verifications:
        if not verifications:
            return False
        def _valid_specs(entry: dict) -> bool:
            specs = entry.get("specialists")
            return isinstance(specs, list) and [
                s.get("specialist") for s in specs if isinstance(s, dict)
            ] == list(review.SPECIALISTS)

        if verifications[-1].get("tiebreaker") is True:
            if not any(not entry.get("tiebreaker") and _valid_specs(entry) for entry in verifications[:-1]):
                return False
        elif not _valid_specs(verifications[-1]):
            return False
    return True


def process_item(config, store, row, writer, reviewer, observed=None, *, allow_network=True,
                 parallel_verify=False, reviewer_factory=None, specialists: int = 1):
    """Resume writer → exact-candidate review → fresh verification of each approved or repaired text → commit.

    Transport errors leave the current stage durable and raise a retryable
    AnalysisError for the existing queue's backoff. An unusable reply keeps the
    stage too, but its AnalysisError counts toward the item's three failures, as
    a saved job that cannot be read does. next_step bounds the repairs; a hold
    marks the item rejected immediately.
    """
    if specialists not in (1, len(review.SPECIALISTS)):
        raise ValueError("specialists must be 1 or 3")
    observed = observed or now_iso()
    report = {"status": "pending", "writer_calls": 0, "review_calls": 0, "cache_hit": False}

    def _ignore_retired() -> dict:
        status_out = _ignore_at_gate(store, row, observed, "Retired story; never recreated",
                                     "skipped.gate.retired_story", clear_story=True)
        return {**report, "status": status_out}

    try:
        existing = candidate_mod.existing_story(store.db, row)
        if existing is None and editorial.retired(
                store.db, story_id=digest(row["cluster_key"])[:24], cluster_key=row["cluster_key"]) is not None:
            raise editorial.RetiredStory("Story is retired")
        job, saved_draft, saved_prepared, saved_record, same_source = _saved_job(store, row, config)
        item_payload = json.loads(row["payload"])
        skipped = _not_recent(config, store, row, item_payload, observed, existing=existing)
        if skipped:
            return {**report, "status": skipped}
        skipped_det = _deterministic_skip(config, store, row, item_payload, observed, existing=existing)
        if skipped_det:
            return {**report, "status": skipped_det}
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
    except editorial.RetiredStory:
        return _ignore_retired()
    except candidate_mod.StaleCandidate:
        return {**report, "status": "stale"}

    writer_best_of, writer_quote_digest = _writer_cache_options(writer)
    writer_metadata_impact = _writer_metadata_impact(writer)
    writer_key = cache_key(
        row, config["llm"], prior, best_of=writer_best_of, quote_digest=writer_quote_digest, item=writer_item,
        metadata_impact_pass=writer_metadata_impact,
    )
    locked_reuse = (job is not None and existing is not None and editorial.is_locked(store.db, existing["id"])
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
        record = _new_record(row, **(carry or {}))
        prepared_at = observed
    prepared = None

    def _save_job(stg: str, *, env: bool = True, **kw) -> None:
        _save(store, row, writer_key, policy, stg, draft, prepared if env else None,
              record, observed, prepared_at=prepared_at, **kw)

    def _hold_item(stg: str, reason: str, **extra) -> dict:
        _hold(store, row, draft, writer_key, record, observed, stg, reason)
        return {**report, "status": "held", **extra}

    def _commit_decision(decision: str, key: str, *, fresh: bool = False, **extra) -> dict:
        record["outcome"] = OUTCOME_STAGES[decision]
        receipt = None
        if fresh:
            record.update(candidate=candidate, approval_key=key)
            receipt_result = (
                record["reviews"][-1]["result"]
                if record["reviews"][-1]["result"]["verdict"] == decision
                else next(
                    (entry["result"] for entry in reversed(record["reviews"]) if entry["result"]["verdict"] == decision),
                    None,
                )
                if decision == "skip"
                else None
            )
            if decision == "skip" and receipt_result is None:
                last_res = record["reviews"][-1]["result"]
                if any(last_res["criteria"][name]["outcome"] == "fail" for name in review.EDITORIAL_CRITERIA):
                    receipt_result = {
                        **last_res,
                        "verdict": "skip",
                        "same_story": None,
                        "repair": None,
                        "model_verdict": last_res["verdict"],
                    }
            if decision == "skip" and receipt_result is not None and receipt_result.get("same_story") is not None:
                receipt_result = {**receipt_result, "same_story": None}
            if receipt_result is not None:
                receipt = (key, digest(candidate), prepared["source_hash"], policy, prepared["binding_hash"],
                           strict_json(receipt_result), strict_json(record), observed, observed)
        _save_job(record["outcome"], approval_key=key, approval_receipt=receipt)
        committed = store.commit_candidate(prepared, candidate, writer_key, now_iso(), approval_key=key,
                                           policy_hash=policy, review_record=record, decision=decision)
        return {**report, "status": committed["status"], **extra}

    try:
        if draft is None:
            is_literal_tag = item_payload["kind"] == "tag" and item_payload.get("tag_enriched") is not True
            if not allow_network and not is_literal_tag:
                return {**report, "status": "deferred"}
            report["writer_calls"] += not is_literal_tag
            draft = writer.analyze(writer_item) if prior is None else writer.analyze(writer_item, prior=prior)
            record["writer"] = {"key": writer_key}  # The draft itself is saved in the job, then in analyses.
            if getattr(writer, "clears", 0):  # writer validation cleared the draft's impact sentence
                record["writer"]["clears"] = writer.clears  # kept until an operator retry resets the record
            _save_job("drafted", env=False)
        prepared = _prepare(store, config, row, draft, prepared_at)
        same = (
            old is not None
            and job["policy_hash"] == policy
            and all(old[k] == prepared[k] for k in ("candidate_hash", "source_hash", "binding_hash"))
            and dirauth_user_set(old.get("dirauth_users")) == dirauth_user_set(prepared.get("dirauth_users"))
            and tor_core_user_set(old.get("tor_core_users")) == tor_core_user_set(prepared.get("tor_core_users"))
        )
        stage = job["stage"] if same else "review"
        fresh_prepared = {
            key: prepared[key]
            for key in ("mode", "candidate", "packet", "coverage", "candidate_hash", "source_hash", "coverage_hash", "binding_hash")
        }
        if "dirauth_users" in prepared:
            fresh_prepared["dirauth_users"] = prepared["dirauth_users"]
        if "tor_core_users" in prepared:
            fresh_prepared["tor_core_users"] = prepared["tor_core_users"]
        fresh = _new_record(row, record["writer"], policy_hash=policy, prepared=fresh_prepared)
        # A coverage change invalidates old reviews, not the request budget of
        # this source revision and policy. Explicit operator retry starts afresh.
        if (job is not None and job["policy_hash"] == policy) or carry is not None:
            fresh.update(_carried_requests(record))
        record = record if same else fresh
        candidate = record.get("candidate", prepared["candidate"])
        validate_review_state(record, stage, candidate, prepared)
        _save_job(stage, approval_key=job["approval_key"] if same else None)
        if prepared.get("locked"):
            record["outcome"] = "locked"
            store.commit_candidate(prepared, prepared["candidate"], writer_key, now_iso(), review_record=record)
            return {**report, "status": record["outcome"]}
        if prepared["packet"]["missing_sources"]:
            return _hold_item("gate", "missing_sources")
        if stage == "held":
            # The same candidate held before: a source reverted to a held revision,
            # or an item was requeued without reset_review_work. Do not review it again.
            return _hold_item("gate", "repeat_hold")
        effective_specialists = max(
            specialists,
            record.get("specialists", 1) if isinstance(record.get("specialists"), int) else 1,
        )
        key = _approval_key(candidate, prepared, policy)
        cached = None if proposal_needs_check(record) else store.db.execute(
            """SELECT CASE WHEN typeof(result_json)='text' THEN CAST(result_json AS BLOB) END AS result_blob,
               CASE WHEN typeof(review_record_json)='text' THEN CAST(review_record_json AS BLOB) END AS record_blob
               FROM review_approvals WHERE key=?""",
            (key,),
        ).fetchone()
        cached_proof = None
        cached_verdict = None
        if cached is not None:
            try:
                raw_verdict, proof = saved_object(cached["result_blob"]), saved_object(cached["record_blob"])
                if raw_verdict is None or proof is None:
                    raise ValueError()
                verdict = review.validate_review(raw_verdict, prepared["packet"],
                                                 update=prepared.get("mode") == "update", coverage=prepared["coverage"])
                eff_auth = effective_authority(item_payload, prepared.get("dirauth_users"), prepared.get("tor_core_users"))
                mandatory_skip = (
                    verdict["verdict"] == "skip"
                    and mandatory_news_rule({**item_payload, "authority": eff_auth}) is not None
                    and verdict["criteria"]["new_information"]["outcome"] == "pass"
                )
                if (proof.get("policy_hash") != policy
                        or verdict["verdict"] not in {"approve", "skip"} or verdict.get("same_story") is not None
                        or mandatory_skip):
                    raise ValueError()
                validate_review_state(proof, OUTCOME_STAGES[verdict["verdict"]], candidate, prepared, allow_cached=False)
            except (AnalysisError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
                with store.db:
                    store.db.execute("DELETE FROM review_approvals WHERE key=?", (key,))
            else:
                if _has_specialist_evidence(proof, digest(candidate), effective_specialists, verdict_name=verdict["verdict"]):
                    cached_proof = proof
                    cached_verdict = verdict
        if cached_proof is not None and cached_verdict is not None:
            record["approval"] = cached_proof
            record["approval_key"] = key
            if cached_verdict["verdict"] == "approve" and (held := review.final_holds(candidate, prepared)):
                return _hold_item("final_check", held[0], cache_hit=True)
            return _commit_decision(cached_verdict["verdict"], key, cache_hit=True)
        if (
            stage == "approved"
            and not proposal_needs_check(record)
            and not record.get("pending_hold")
            and record.get("outcome") == "approved"
            and record.get("approval_key") == key
            and job["approval_key"] == key
            and _has_specialist_evidence(record, digest(candidate), effective_specialists, verdict_name="approve")
            and record.get("reviews")
            and record["reviews"][-1]["result"]["verdict"] != "approve"
            and mandatory_news_rule({
                **item_payload,
                "authority": effective_authority(item_payload, prepared.get("dirauth_users"), prepared.get("tor_core_users")),
            }) is not None
            and _next_step(record["reviews"], candidate, prepared, specialists=record.get("specialists", 1)) == ("approve", candidate)
        ):
            if held := review.final_holds(candidate, prepared):
                return _hold_item("final_check", held[0])
            return _commit_decision("approve", key)
        if stage in {"approved", "skipped"}:  # without a usable receipt, review the writer's draft again
            stage, candidate, record = "review", prepared["candidate"], fresh
        if effective_specialists > 1 and record.get("specialists") != effective_specialists:
            upgrade_at = record["request_budget"]["reserved"]
            if (
                (stage == "tiebreak" or any(entry.get("tiebreaker") for entry in record["reviews"]))
                and not any(entry.get("specialists") for entry in record["reviews"])
            ):
                stage, candidate, record = "review", prepared["candidate"], fresh
            if upgrade_at > 0 and "specialist_upgrade_at" not in record:
                record["specialist_upgrade_at"] = upgrade_at
            record["specialists"] = effective_specialists
        requests = ReviewRequests(record, lambda: _save_job(stage), specialists=effective_specialists)

        def _enter_verify() -> None:
            nonlocal stage
            stage = "verify"
            record["candidate"] = candidate

        needed_initial = (len(review.SPECIALISTS) + 2) if effective_specialists > 1 else 3
        use_parallel = (
            parallel_verify
            and stage == "review"
            and not record["reviews"]
            and allow_network
            and reviewer_factory is not None
            and requests.state["reserved"] + needed_initial <= requests.max_requests
            and not proposal_needs_check(record)
            and not record.get("pending_hold")
        )
        while True:
            if not allow_network:
                return {**report, "status": "deferred"}
            try:
                if use_parallel:
                    use_parallel = False
                    action, value = _parallel_initial_review(
                        reviewer_factory, candidate, prepared, record, requests,
                        on_verify=_enter_verify,
                        save_verify=lambda: _save_job("verify"),
                        specialists=effective_specialists,
                        reviewer=reviewer,
                    )
                elif effective_specialists > 1 and stage == "verify":
                    if record.get("pending_hold") == "specialist_budget":
                        action, value = "hold", ("verification", "specialist_budget")
                    elif _pending_reask(record, stage, candidate, prepared):
                        reask_factory = reviewer_factory if (parallel_verify and reviewer_factory is not None) else None
                        if record.get("pending_specialist_wave"):
                            if (
                                requests.state["reserved"] < requests.max_requests
                                and (reask_factory is not None or _supports_kwarg(reviewer.review, "specialist"))
                            ):
                                action, value = _resume_specialist_reask(
                                    reask_factory, reviewer, candidate, prepared, record, requests,
                                )
                            else:
                                action, value = "hold", ("verification", "specialist_budget")
                        elif requests.state["reserved"] < requests.max_requests:
                            action, value = advance_review(reviewer, stage, candidate, prepared, record, requests)
                        else:
                            action, value = "hold", ("verification", "specialist_budget")
                    elif requests.state["reserved"] + len(review.SPECIALISTS) > requests.max_requests:
                        action, value = "hold", ("verification", "specialist_budget")
                    elif parallel_verify and reviewer_factory is not None:
                        action, value = _parallel_specialist_verify(
                            reviewer_factory, candidate, prepared, record, requests,
                            reviewer=reviewer, specialists=effective_specialists,
                        )
                    elif _supports_kwarg(reviewer.review, "specialist"):
                        action, value = _sequential_specialist_verify(
                            reviewer, candidate, prepared, record, requests,
                            specialists=effective_specialists,
                        )
                    else:
                        action, value = "hold", ("verification", "specialist_budget")
                else:
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
                if value == ("verification", "specialist_budget") and (waiting := pending_proposal(record)) is not None:
                    waiting["disposition"] = "superseded_unverified"
                return _hold_item(*value)
            if action in {"approve", "skip"}:
                agreed_same = _agreed_same_story(record["reviews"]) if prepared["coverage"].get("prior_story") is not None else None
                agreed_dup = _auto_merge_pair(store, prepared["story_id"], agreed_same) if agreed_same else None
                if (
                    agreed_dup is not None
                    and agreed_dup[0] == prepared["story_id"]
                    and _can_auto_merge_review(candidate, prepared, record["reviews"][-1]["result"])
                    and _try_auto_merge(
                        config, store, agreed_dup, propagate=True, prepared=prepared,
                        draft=draft, writer_key=writer_key, record=record, observed=observed,
                    )
                ):
                    return {**report, "status": "routed"}
                out = _commit_decision(action, _approval_key(candidate, prepared, policy), fresh=True)
                if agreed_dup is not None:
                    _try_auto_merge(config, store, agreed_dup, propagate=False)
                return out
            stage, candidate = action, value  # the next review: a verification or a release-label repair
            record["candidate"] = candidate
            _save_job(stage)
    except CompletionDeferred:
        return {**report, "status": "deferred", "budget_reached": True}
    except editorial.RetiredStory:
        return _ignore_retired()
    except (candidate_mod.StaleCandidate, candidate_mod.ReviewRequired):
        return {**report, "status": "stale"}
    finally:
        _prune(store, MAX_APPROVALS)


def _valid_coverage_entry(entry: object) -> bool:
    return (
        isinstance(entry, dict)
        and isinstance(entry.get("id"), str)
        and isinstance(entry.get("title"), str)
        and (bool(entry.get("retracted")) or isinstance(entry.get("updated_at"), str))
    )


def _new_coverage(old_coverage, current_coverage) -> list[dict]:
    old_recent = old_coverage.get("recent") if isinstance(old_coverage, dict) else None
    seen = {
        (e["id"], e.get("updated_at") if isinstance(e.get("updated_at"), str) else None, bool(e.get("retracted")))
        for e in (old_recent if isinstance(old_recent, list) else ())
        if _valid_coverage_entry(e)
    }
    curr_recent = current_coverage.get("recent") if isinstance(current_coverage, dict) else None
    out = []
    for e in (curr_recent if isinstance(curr_recent, list) else ()):
        if not _valid_coverage_entry(e):
            continue
        retracted = bool(e.get("retracted"))
        updated_at = e.get("updated_at") if isinstance(e.get("updated_at"), str) else None
        if (e["id"], updated_at, retracted) not in seen:
            out.append({"id": e["id"], "title": e["title"], "updated_at": updated_at, **({"retracted": True} if retracted else {})})
    return out


def _check_approval(config, store, item_id: str) -> tuple[dict, tuple | None]:
    def _refuse(reason: str, editorial_failures=(), new_coverage=()):
        return {"eligible": False, "reason": reason, "hash": None,
                "editorial_failures": list(editorial_failures), "new_coverage": list(new_coverage)}, None

    item_row = store.db.execute(f"SELECT {ITEM_SAFE_COLUMNS} FROM items WHERE id=?", (item_id,)).fetchone()
    job, draft, saved_env, record = _load_job(store.db, item_id)
    if item_row is None or item_row["status"] != "rejected" or job is None or job["stage"] != "held":
        return _refuse("Only a held final review can be approved")
    row, payload_obj = decode_item_row(item_row)
    if (payload_obj is None or draft is None or saved_env is None or record is None
            or not isinstance(job["writer_key"], str) or not job["writer_key"]
            or not isinstance(job["prepared_at"], str)
            or not isinstance(reviews := record.get("reviews"), list)):
        return _refuse("Saved review record cannot be read")
    try:
        if any(not isinstance(entry, dict) or entry["stage"] not in {"review", "verification"} for entry in reviews):
            return _refuse("Saved review record cannot be read")
        editorial_failures = [
            f"{entry['stage']}:{name}"
            for entry in reviews
            for name in ("news_value", "new_information")
            if entry["result"]["criteria"][name]["outcome"] != "pass"
        ]
    except (TypeError, KeyError, AttributeError):
        return _refuse("Saved review record cannot be read")
    policy = review.policy_hash(config)
    if (job["policy_hash"] != policy or record.get("policy_hash") != policy
            or any(entry.get("policy_hash") != policy for entry in reviews)):
        return _refuse("An earlier review policy or packet reviewed it; retry it", editorial_failures)
    try:
        prepared = _prepare(store, config, row, draft, job["prepared_at"])
    except Exception:
        return _refuse("Its story or sources changed since the review; retry it", editorial_failures)
    if prepared["locked"]:
        return _refuse("Its story is editorially locked", editorial_failures)
    held_prepared = record.get("prepared")
    if not isinstance(held_prepared, dict):
        return _refuse("Saved review record cannot be read", editorial_failures)
    new_coverage = _new_coverage(held_prepared.get("coverage"), prepared["coverage"])
    if prepared["packet"]["missing_sources"]:
        return _refuse("Final review held: " + HOLDS["missing_sources"], editorial_failures, new_coverage)
    saved_binding = saved_env.get("binding") if isinstance(saved_env.get("binding"), dict) else {}
    try:
        stale_binding = (
            prepared["story_id"] != saved_env.get("story_id")
            or dirauth_user_set(prepared.get("dirauth_users")) != dirauth_user_set(saved_env.get("dirauth_users"))
            or tor_core_user_set(prepared.get("tor_core_users")) != tor_core_user_set(saved_env.get("tor_core_users"))
            or any(prepared[k] != d.get(k) for d in (held_prepared, saved_env) for k in ("candidate_hash", "source_hash"))
            or any(prepared["binding"][key] != saved_binding.get(key)
                   for key in ("prior_story", "lock", "sources", "payload_hash",
                               *(["mode"] if "mode" in saved_binding else [])))
        )
    except (TypeError, KeyError, AttributeError):
        return _refuse("Saved review record cannot be read", editorial_failures, new_coverage)
    if stale_binding:
        return _refuse("Its story or sources changed since the review; retry it", editorial_failures, new_coverage)
    if any(entry.get("source_hash") != prepared["source_hash"] for entry in reviews):
        return _refuse("An earlier review policy or packet reviewed it; retry it", editorial_failures, new_coverage)
    is_update = prepared.get("mode") == "update"
    try:
        validated = [review.validate_review(entry["result"], prepared["packet"],
                                            update=is_update, coverage=held_prepared.get("coverage"))
                     for entry in reviews]
    except (AnalysisError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return _refuse("Saved review record cannot be read", editorial_failures, new_coverage)
    if any(result["criteria"]["new_information"]["outcome"] != "pass" for result in validated):
        return _refuse("A review failed new_information (already covered); dismiss it", editorial_failures, new_coverage)
    candidate = record.get("candidate")
    try:
        candidate_mod.validate_approved(prepared["candidate"], candidate, "update" if is_update else "story")
    except candidate_mod.ReviewRequired as exc:
        msg = ("No fresh verification reviewed this exact text"
               if "complete public candidate" in str(exc) else "Saved review record cannot be read")
        return _refuse(msg, editorial_failures, new_coverage)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return _refuse("Saved review record cannot be read", editorial_failures, new_coverage)
    candidate_hash = digest(candidate)
    reviews_of_text = [(entry, result) for entry, result in zip(reviews, validated) if entry.get("candidate_hash") == candidate_hash]
    if not any(entry.get("stage") == "verification" for entry, _ in reviews_of_text):
        return _refuse("No fresh verification reviewed this exact text", editorial_failures, new_coverage)
    failed_facts = [
        name for name in review.CRITERIA
        if name not in review.EDITORIAL_CRITERIA
        and any(result["criteria"][name]["outcome"] != "pass" for _, result in reviews_of_text)
    ]
    if failed_facts:
        return _refuse(f"A review failed {', '.join(failed_facts)}; dismiss or retry it", editorial_failures, new_coverage)
    try:
        if (record.get("verified_facts") is not True or not _verified(reviews)
                or any(not result["criteria"]["source_support"]["source_refs"] for _, result in reviews_of_text)):
            return _refuse("No fresh verification with cited sources approved the facts; retry or dismiss it",
                           editorial_failures, new_coverage)
        if held := review.final_holds(candidate, prepared):
            return _refuse("Final review held: " + HOLDS[held[0]], editorial_failures, new_coverage)
        if not review.release_labels_match_state(candidate):
            return _refuse("Final review held: " + HOLDS["release_labels"], editorial_failures, new_coverage)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return _refuse("Saved review record cannot be read", editorial_failures, new_coverage)
    if not editorial_failures:
        return _refuse("Only a held news-value dispute can be approved", editorial_failures, new_coverage)
    try:
        validate_review_state(record, "held", record.get("candidate", saved_env.get("candidate")), saved_env)
        needs_check = proposal_needs_check(record)
    except (AnalysisError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return _refuse("Saved proposal or review state cannot be read")
    if needs_check:
        return _refuse("An untrusted proposal still needs a fresh valid review")
    exact_entries = [entry for entry, _ in reviews_of_text]
    approval_hash = digest(["approve-as-reviewed", prepared["binding_hash"], candidate_hash, policy, digest(exact_entries)])
    return {"eligible": True, "reason": None, "hash": approval_hash,
            "editorial_failures": editorial_failures, "new_coverage": new_coverage}, (
        prepared, candidate, job["writer_key"], record)


def approval(config, store, item_id: str) -> dict:
    """Read-only eligibility and binding hash for `rejected approve`; never raises on damaged rows."""
    try:
        return _check_approval(config, store, item_id)[0]
    except (AnalysisError, ValueError, TypeError, KeyError, AttributeError, IndexError, UnicodeError, RecursionError):
        return {"eligible": False, "reason": "Saved review record cannot be read", "hash": None,
                "editorial_failures": [], "new_coverage": []}


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
    audit = copy.deepcopy(record)
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
