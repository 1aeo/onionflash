#!/usr/bin/env python3
"""Read-only harvester converting live Onion Flash SQLite state into sanitized evaluation datasets."""

from __future__ import annotations

import argparse
from contextlib import closing
import copy
import json
import os
from pathlib import Path
import re
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from onionflash import candidate as candidate_mod, editorial, refresh, render, source_packet
from onionflash.comments import analysis_context
from onionflash.schema import CATEGORIES, CONFIDENCES, FIELD_LIMITS, PRIORITIES, PRODUCTS, PUBLIC_STATES, STORY_ID_RE
from onionflash.util import canonical_url, digest, now_iso, plain_text, safe_canonical_url, saved_object

BUCKETS = (
    "held_review_jobs",
    "rejection_actions",
    "editorial_revisions",
    "high_comment_items",
    "multi_update_stories",
)
MIN_HIGH_COMMENTS = 8
MIN_MULTI_UPDATES = 3
DEFAULT_LIMIT = 100
DEFAULT_MAX_PER_BUCKET = 25

_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(authorization\s*:\s*bearer\s+)[^\s\"']+"),
    re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|glpat-[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{16,})\b"),
    re.compile(r"(?i)\b([A-Z0-9_]*?(?:API_KEY|SECRET|TOKEN|PASSWORD)=)([^\s\"']+)"),
)
_ALLOWED_ITEM_PAYLOAD_KEYS = (
    "id", "source_id", "url", "title", "content", "source_content", "kind", "product",
    "authority", "published_at", "updated_at", "labels", "upstream_state", "closed_at",
    "author", "sender_domain", "public_comments", "dirauth_notes", "comments_truncated",
    "thread_root",
)
_FALLBACK_DATE = "2026-11-10T12:00:00Z"


_SURROGATE_RE = re.compile(r"[\ud800-\udfff]")


def sanitize_text(value: object) -> str:
    """Redact credential-like patterns and strip control characters or lone surrogates from text."""
    if not isinstance(value, str):
        return ""
    cleaned = _SURROGATE_RE.sub("\ufffd", value)
    if any(ord(c) < 32 and c not in "\n\t" for c in cleaned):
        cleaned = plain_text(cleaned, max(len(cleaned), 1), html=False)
    for pat in _SECRET_PATTERNS:
        if pat.groups >= 2:
            cleaned = pat.sub(r"\1[redacted]", cleaned)
        else:
            cleaned = pat.sub("[redacted]", cleaned)
    return cleaned


def _sanitize_obj(obj):
    if isinstance(obj, str):
        return sanitize_text(obj)
    if isinstance(obj, list):
        return [_sanitize_obj(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _sanitize_obj(v) for k, v in obj.items() if isinstance(k, str)}
    return obj


def _safe_sanitized_url(value: object) -> str:
    """Redact credential patterns before normalizing `value` as a safe canonical URL."""
    if not isinstance(value, str) or not value:
        return ""
    return safe_canonical_url(sanitize_text(value))


def _sanitize_item_payload(payload: dict) -> dict:
    clean = {k: _sanitize_obj(payload[k]) for k in _ALLOWED_ITEM_PAYLOAD_KEYS if k in payload}
    if "url" in clean and isinstance(clean["url"], str):
        clean["url"] = _safe_sanitized_url(clean["url"]) or clean["url"]
    return clean


def _sanitize_item_row(row: sqlite3.Row, payload_obj: dict, *, story_id_override: str | None = None) -> dict:
    clean_payload = _sanitize_item_payload(payload_obj)
    clean_url = sanitize_text(row["url"])
    return {
        "id": row["id"],
        "url": safe_canonical_url(clean_url) or clean_url,
        "source_id": row["source_id"],
        "payload": json.dumps(clean_payload, ensure_ascii=False, allow_nan=False),
        "content_hash": row["content_hash"],
        "cluster_key": row["cluster_key"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "status": "pending",
        "attempts": 0,
        "rejections": 0,
        "next_attempt_at": None,
        "last_error": None,
        "priority_score": row["priority_score"],
        "story_id": story_id_override,
    }


def open_readonly(db_path: Path) -> sqlite3.Connection:
    """Open `db_path` strictly read-only (`?mode=ro`, `uri=True`) without touching credentials."""
    resolved = db_path.resolve(strict=True)
    conn = sqlite3.connect(f"{resolved.as_uri()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = ON")
    return conn


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return bool(conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone())


def _safe_blob_json(blob) -> dict | None:
    if blob is None:
        return None
    if isinstance(blob, str):
        blob = blob.encode("utf-8", errors="replace")
    return saved_object(blob, allow_surrogates=True)


def _packet_from_item(item_obj: dict) -> dict | None:
    url = _safe_sanitized_url(item_obj.get("url"))
    title = sanitize_text(item_obj.get("title") or "")
    if not url or not title:
        return None
    body, notes = analysis_context(item_obj, include_url=True)
    if not body and isinstance(item_obj.get("content"), str):
        body = item_obj["content"]
    size = source_packet.LIMITS["passage_chars"]
    passages: list[dict] = []
    for note in notes:
        note_body = sanitize_text(note.get("body") or "")
        for start in range(0, len(note_body), size):
            chunk = note_body[start : start + size]
            if chunk.strip():
                passages.append({
                    "author": sanitize_text(note.get("author") or "unknown"),
                    "created_at": str(note.get("created_at") or item_obj.get("updated_at") or _FALLBACK_DATE),
                    "url": _safe_sanitized_url(note.get("url")) or url,
                    "text": chunk,
                })
    body_text = sanitize_text(body or title)
    for start in range(0, min(len(body_text), source_packet.LIMITS["max_source_chars"]), size):
        chunk = body_text[start : start + size]
        if chunk.strip():
            passages.append({"text": chunk})
    if not passages:
        passages.append({"text": title})
    unit = {
        "url": url,
        "title": title,
        "kind": item_obj.get("kind") or "gitlab_issue",
        "authority": item_obj.get("authority") or "development",
        "product": item_obj.get("product") or "tor",
        "published_at": item_obj.get("published_at") or _FALLBACK_DATE,
        "updated_at": item_obj.get("updated_at") or item_obj.get("published_at") or _FALLBACK_DATE,
        "upstream_state": item_obj.get("upstream_state") or "",
        "labels": source_packet.normalize_labels(item_obj.get("labels")),
        "passages": passages,
    }
    for opt in ("author", "sender_domain", "closed_at"):
        if isinstance(item_obj.get(opt), str) and item_obj[opt]:
            unit[opt] = sanitize_text(item_obj[opt])
    return {"sources": [unit], "missing_sources": [], "truncated": False}


def _packet_to_eval_format(packet: dict) -> dict | None:
    """Convert a `source_packet.build_packet` output into `evaluate_review.expand()` packet shape."""
    if not isinstance(packet, dict) or not packet.get("sources"):
        return None
    eval_sources: list[dict] = []
    for src in packet["sources"]:
        url = _safe_sanitized_url(src.get("url"))
        title = sanitize_text(src.get("title") or "")
        if not url or not title:
            continue
        raw_passages = list(src.get("passages") or ())
        # evaluate_review._expand_source prepends `src["title"]` as S<i>:P1; strip matching title passage.
        if (
            raw_passages
            and isinstance(raw_passages[0], dict)
            and "author" not in raw_passages[0]
            and sanitize_text(raw_passages[0].get("text") or "").strip() == title.strip()
        ):
            raw_passages = raw_passages[1:]
        passages: list[dict] = []
        for p in raw_passages:
            if isinstance(p, str):
                if p.strip():
                    passages.append({"text": sanitize_text(p)})
            elif isinstance(p, dict) and isinstance(p.get("text"), str) and p["text"].strip():
                entry = {"text": sanitize_text(p["text"])}
                if "author" in p:
                    entry["author"] = sanitize_text(p.get("author") or "unknown")
                    entry["created_at"] = str(p.get("created_at") or src.get("updated_at") or _FALLBACK_DATE)
                    entry["url"] = _safe_sanitized_url(p.get("url")) or url
                passages.append(entry)
        if not passages:
            passages.append({"text": title})
        unit = {
            "url": url,
            "title": title,
            "kind": src.get("kind") or "gitlab_issue",
            "authority": src.get("authority") or "development",
            "product": src.get("product") or "tor",
            "published_at": src.get("published_at") or _FALLBACK_DATE,
            "updated_at": src.get("updated_at") or src.get("published_at") or _FALLBACK_DATE,
            "upstream_state": src.get("upstream_state") or "",
            "labels": source_packet.normalize_labels(src.get("labels")),
            "passages": passages,
        }
        for opt in ("author", "sender_domain", "closed_at", "mandatory_news_rule", "unquoted_content", "thread_context"):
            if opt in src and src[opt] is not None:
                unit[opt] = _sanitize_obj(src[opt])
        eval_sources.append(unit)
    if not eval_sources:
        return None
    return {
        "sources": eval_sources,
        "missing_sources": list(packet.get("missing_sources") or ()),
        "truncated": bool(packet.get("truncated", False)),
    }


def _fallback_candidate_from_item(item_obj: dict, story_id: str) -> dict:
    title = plain_text(sanitize_text(item_obj.get("title") or "Untitled item"), FIELD_LIMITS["title"], html=False) or "Untitled item"
    body = sanitize_text(item_obj.get("source_content") or item_obj.get("content") or title)
    summary = plain_text(body, FIELD_LIMITS["summary"], html=False) or title
    product = item_obj.get("product") if item_obj.get("product") in PRODUCTS else "tor"
    pub = item_obj.get("published_at") or _FALLBACK_DATE
    upd = max(pub, item_obj.get("updated_at") or pub)
    return {
        "id": story_id if STORY_ID_RE.fullmatch(story_id) else digest(story_id)[:24],
        "title": title,
        "summary": summary,
        "why_it_matters": "",
        "category": "network",
        "priority": "normal",
        "confidence": "reported",
        "state": "developing",
        "products": [product],
        "tags": ["network"],
        "published_at": pub,
        "updated_at": upd,
        "added_at": upd,
    }


def _sanitize_sources(raw_sources: object) -> list[dict]:
    if not isinstance(raw_sources, list):
        return []
    out: list[dict] = []
    for src in raw_sources:
        if not isinstance(src, dict):
            continue
        url = _safe_sanitized_url(src.get("url"))
        if not url:
            continue
        title = sanitize_text(src.get("title") or "") or url
        out.append({"url": url, "title": title})
    return out


def _sanitize_updates(raw_updates: object) -> list[dict]:
    if not isinstance(raw_updates, list):
        return []
    out: list[dict] = []
    for upd in raw_updates:
        if not isinstance(upd, dict):
            continue
        text = sanitize_text(upd.get("text") or "").strip()
        sources = _sanitize_sources(upd.get("sources"))
        at = upd.get("at")
        if text and sources and isinstance(at, str) and at:
            out.append({"at": at, "text": text, "sources": sources})
    return out


def _sanitize_story_ref(raw_story: object) -> dict | None:
    if not isinstance(raw_story, dict):
        return None
    sid = raw_story.get("id")
    if not isinstance(sid, str) or not STORY_ID_RE.fullmatch(sid):
        return None
    cleaned: dict = {"id": sid}
    for key in ("title", "summary", "why_it_matters", "latest_update"):
        if isinstance(raw_story.get(key), str):
            cleaned[key] = sanitize_text(raw_story[key])
    for key in ("category", "state", "confidence", "priority", "published_at", "updated_at", "added_at"):
        if isinstance(raw_story.get(key), str) and raw_story[key]:
            cleaned[key] = sanitize_text(raw_story[key])
    if isinstance(raw_story.get("retracted"), bool):
        cleaned["retracted"] = raw_story["retracted"]
    if isinstance(raw_story.get("products"), list):
        cleaned["products"] = [p for p in raw_story["products"] if p in PRODUCTS]
    if isinstance(raw_story.get("tags"), list):
        cleaned["tags"] = [t for t in raw_story["tags"] if t in CATEGORIES]
    if isinstance(raw_story.get("associated"), list):
        cleaned["associated"] = [sanitize_text(a) for a in raw_story["associated"] if isinstance(a, str) and a]
    if sources := _sanitize_sources(raw_story.get("sources")):
        cleaned["sources"] = sources
    if updates := _sanitize_updates(raw_story.get("updates")):
        cleaned["updates"] = updates
    return cleaned


def _sanitize_coverage(raw_cov: object) -> dict | None:
    if not isinstance(raw_cov, dict):
        return None
    out: dict = {}
    if raw_cov.get("prior_story") is not None:
        if (prior := _sanitize_story_ref(raw_cov["prior_story"])) is None:
            return None
        out["prior_story"] = prior
    else:
        out["prior_story"] = None
    recent_clean: list[dict] = []
    for entry in (raw_cov.get("recent") or ()):
        if (clean_entry := _sanitize_story_ref(entry)) is not None:
            recent_clean.append(clean_entry)
    out["recent"] = recent_clean
    out["truncated"] = bool(raw_cov.get("truncated", False))
    return out


def _normalize_case_candidate(raw_cand: dict | None, packet: dict, fallback_id: str, item_obj: dict | None = None) -> dict | None:
    sources = [{"url": s["url"], "title": s["title"]} for s in packet["sources"]]
    base = copy.deepcopy(raw_cand) if isinstance(raw_cand, dict) else _fallback_candidate_from_item(item_obj or {}, fallback_id)
    base["id"] = str(base.get("id") or fallback_id)
    if not STORY_ID_RE.fullmatch(base["id"]):
        base["id"] = digest(base["id"])[:24]
    if base.get("category") not in CATEGORIES:
        base["category"] = "network"
    if base.get("priority") not in PRIORITIES:
        base["priority"] = "normal"
    if base.get("confidence") not in CONFIDENCES:
        base["confidence"] = "reported"
    if base.get("state") not in PUBLIC_STATES:
        base["state"] = "developing"
    products = [p for p in (base.get("products") or []) if p in PRODUCTS]
    base["products"] = products or ["tor"]
    tags = [t for t in (base.get("tags") or []) if t in CATEGORIES]
    base["tags"] = tags or [base["category"]]
    base["sources"] = sources
    if "updates" in base:
        clean_updates = _sanitize_updates(base.get("updates"))
        if clean_updates:
            base["updates"] = clean_updates
        else:
            base.pop("updates", None)
    base["title"] = sanitize_text(base.get("title") or "")[: FIELD_LIMITS["title"]]
    base["summary"] = sanitize_text(base.get("summary") or "")[: FIELD_LIMITS["summary"]]
    base["why_it_matters"] = sanitize_text(base.get("why_it_matters") or "")[: FIELD_LIMITS["why_it_matters"]]
    if not base["title"] or not base["summary"]:
        if item_obj:
            fb = _fallback_candidate_from_item(item_obj, base["id"])
            base["title"] = base["title"] or fb["title"]
            base["summary"] = base["summary"] or fb["summary"]
        else:
            return None
    base.setdefault("published_at", packet["sources"][0].get("published_at") or _FALLBACK_DATE)
    base.setdefault("updated_at", packet["sources"][0].get("updated_at") or base["published_at"])
    base.setdefault("added_at", base["updated_at"])
    try:
        prepared = render.prepare_story(base, editorial=base.get("editorial"), allow_empty_sources=True)
    except (ValueError, TypeError, KeyError, AttributeError):
        return None
    if not prepared.get("sources"):
        return None
    return prepared


def _load_item_row_and_payload(conn: sqlite3.Connection, item_id: str) -> tuple[sqlite3.Row | None, dict | None]:
    row = conn.execute(
        "SELECT id,url,source_id,CAST(payload AS BLOB) AS payload_blob,content_hash,cluster_key,"
        "first_seen,last_seen,status,attempts,rejections,next_attempt_at,last_error,priority_score,story_id "
        "FROM items WHERE id=?",
        (item_id,),
    ).fetchone()
    if row is None:
        return None, None
    payload = _safe_blob_json(row["payload_blob"])
    if payload is None:
        return None, None
    return row, payload


def _load_seed_analyses(conn: sqlite3.Connection, item_id: str) -> list[dict]:
    if not _table_exists(conn, "analyses"):
        return []
    rows = conn.execute(
        "SELECT cache_key,result,created_at,CAST(source_payload AS BLOB) AS sp,source_item_id,CAST(review_record AS BLOB) AS rr "
        "FROM analyses WHERE source_item_id=? ORDER BY created_at ASC, rowid ASC LIMIT 10",
        (item_id,),
    ).fetchall()
    out: list[dict] = []
    for r in rows:
        sp_obj = _safe_blob_json(r["sp"])
        rr_obj = _safe_blob_json(r["rr"])
        out.append({
            "cache_key": r["cache_key"],
            "result": sanitize_text(r["result"]) if isinstance(r["result"], str) else "{}",
            "created_at": r["created_at"],
            "source_payload": json.dumps(_sanitize_item_payload(sp_obj), ensure_ascii=False) if sp_obj else None,
            "source_item_id": r["source_item_id"],
            "review_record": json.dumps(_sanitize_obj(rr_obj), ensure_ascii=False) if rr_obj else None,
        })
    return out


def _load_seed_rejections(conn: sqlite3.Connection, item_id: str) -> list[dict]:
    if not _table_exists(conn, "rejection_actions"):
        return []
    rows = conn.execute(
        "SELECT item_id,content_hash,action,reason,created_at,before_status,before_attempts,"
        "before_rejections,before_error,before_next_attempt_at "
        "FROM rejection_actions WHERE item_id=? ORDER BY action_id ASC LIMIT 10",
        (item_id,),
    ).fetchall()
    return [
        {
            "item_id": r["item_id"],
            "content_hash": r["content_hash"],
            "action": r["action"],
            "reason": sanitize_text(r["reason"]),
            "created_at": r["created_at"],
            "before_status": r["before_status"],
            "before_attempts": r["before_attempts"],
            "before_rejections": r["before_rejections"],
            "before_error": sanitize_text(r["before_error"]) if r["before_error"] is not None else None,
            "before_next_attempt_at": r["before_next_attempt_at"],
        }
        for r in rows
    ]


def _story_eval_packet(conn: sqlite3.Connection, story_payload: dict) -> dict | None:
    packet, _ = refresh.build_story_refresh_packet(conn, story_payload)
    if packet is not None:
        if eval_pkt := _packet_to_eval_format(packet):
            return eval_pkt
    # Fall back to loading any available source items directly so archived/compacted stories still harvest cleanly.
    sources: list[dict] = []
    for ref in story_payload.get("sources") or ():
        if not isinstance(ref, dict) or ref.get("network_key") or not isinstance(ref.get("url"), str):
            continue
        sid = ref.get("source_item_id", ref.get("id"))
        loaded = source_packet._load(conn, sid, ref["url"].split("#note_", 1)[0])
        if loaded is not None and isinstance(loaded[0], dict):
            if pkt := _packet_from_item(loaded[0]):
                sources.extend(pkt["sources"])
                if len(sources) >= source_packet.LIMITS["max_sources"]:
                    break
    if sources:
        return {"sources": sources[: source_packet.LIMITS["max_sources"]], "missing_sources": [], "truncated": True}
    return None


def harvest_database(
    db_path: Path,
    *,
    limit: int = DEFAULT_LIMIT,
    max_per_bucket: int = DEFAULT_MAX_PER_BUCKET,
    include_updates: bool = False,
) -> dict:
    """Harvest sanitized held/rejected/editorial/high-comment/multi-update examples read-only."""
    if limit <= 0 or max_per_bucket <= 0:
        raise ValueError("--limit and --max-per-bucket must be positive integers")

    with closing(open_readonly(db_path)) as conn:
        identities = {}
        if _table_exists(conn, "metadata"):
            for key in ("registry.tor_core_users", "registry.trusted_operator_domains"):
                row = conn.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
                if row is not None and isinstance(row["value"], str):
                    identities[key] = row["value"]

        buckets: dict[str, list[dict]] = {name: [] for name in BUCKETS}
        packets: dict[str, dict] = {}
        cases: list[dict] = []
        items: list[dict] = []
        coverage_sets: dict[str, dict] = {}
        seen_case_ids: set[str] = set()
        seen_suite_item_ids: set[str] = set()
        total_harvested = 0

        def _can_add(bucket: str) -> bool:
            return total_harvested < limit and len(buckets[bucket]) < max_per_bucket

        def _register_entry(
            *,
            bucket: str,
            subgroup: str | None,
            entry_id: str,
            packet_id: str,
            packet: dict,
            candidate_obj: dict,
            expected: str,
            item_row_obj: sqlite3.Row | None = None,
            item_payload_obj: dict | None = None,
            target_story_id: str | None = None,
            exclude_story_ids: list[str] | None = None,
            coverage: dict | None = None,
            scope: str = "story",
        ) -> bool:
            nonlocal total_harvested
            if not _can_add(bucket) or entry_id in seen_case_ids:
                return False
            resolved_packet_id = packet_id
            if resolved_packet_id in packets and packets[resolved_packet_id] != packet:
                resolved_packet_id = f"{packet_id}:{digest(packet)[:12]}"
            packets[resolved_packet_id] = packet
            case_entry = {
                "id": entry_id,
                "packet": resolved_packet_id,
                "scope": scope,
                "candidate": candidate_obj,
                "expected": expected,
            }
            if coverage is not None:
                cov_id = f"cov:{resolved_packet_id}"
                if cov_id in coverage_sets and coverage_sets[cov_id] != coverage:
                    cov_id = f"{cov_id}:{digest(coverage)[:12]}"
                coverage_sets[cov_id] = coverage
                case_entry["coverage_set"] = cov_id
            cases.append(case_entry)
            seen_case_ids.add(entry_id)

            bucket_rec = {
                "id": entry_id,
                "bucket": bucket,
                "subgroup": subgroup,
                "packet": resolved_packet_id,
                "scope": scope,
                "expected": expected,
                **({"item_id": item_row_obj["id"]} if item_row_obj is not None else {}),
                **({"target_story_id": target_story_id} if target_story_id else {}),
            }
            buckets[bucket].append(bucket_rec)
            total_harvested += 1

            if item_row_obj is not None and item_payload_obj is not None and item_row_obj["id"] not in seen_suite_item_ids:
                seen_suite_item_ids.add(item_row_obj["id"])
                replay_story_id = None if (target_story_id and target_story_id in (exclude_story_ids or ())) else target_story_id
                items.append({
                    "group": bucket,
                    "subgroup": subgroup,
                    "item_id": item_row_obj["id"],
                    "packet_id": resolved_packet_id,
                    "target_story_id": target_story_id,
                    "exclude_story_ids": list(exclude_story_ids or ()),
                    "item_row": _sanitize_item_row(item_row_obj, item_payload_obj, story_id_override=replay_story_id),
                    "seed_analyses": _load_seed_analyses(conn, item_row_obj["id"]),
                    "seed_rejection_actions": _load_seed_rejections(conn, item_row_obj["id"]),
                })
            return True

        # 1. Held review_jobs
        if _can_add("held_review_jobs") and _table_exists(conn, "review_jobs") and _table_exists(conn, "items"):
            held_cursor = conn.execute(
                "SELECT item_id, stage, CAST(draft_json AS BLOB) AS draft_blob, "
                "CAST(envelope_json AS BLOB) AS env_blob, CAST(record_json AS BLOB) AS rec_blob "
                "FROM review_jobs WHERE stage='held' ORDER BY updated_at DESC, item_id"
            )
            for hrow in held_cursor:
                if not _can_add("held_review_jobs"):
                    break
                irow, ipayload = _load_item_row_and_payload(conn, hrow["item_id"])
                if irow is None or ipayload is None:
                    continue
                rec = _safe_blob_json(hrow["rec_blob"]) or {}
                env = _safe_blob_json(hrow["env_blob"]) or {}
                draft = _safe_blob_json(hrow["draft_blob"]) or {}
                is_update_job = env.get("mode") == "update" or "update" in draft
                if not include_updates and is_update_job:
                    continue
                pkt = _packet_to_eval_format(env.get("packet") or (rec.get("prepared") or {}).get("packet")) or _packet_from_item(ipayload)
                if pkt is None:
                    continue
                raw_cand = rec.get("candidate") or env.get("candidate") or (rec.get("prepared") or {}).get("candidate") or (draft if "title" in draft else None)
                cand = _normalize_case_candidate(raw_cand, pkt, digest(["held", irow["id"]])[:24], ipayload)
                if cand is None:
                    continue
                cov = None
                scope = "story"
                if is_update_job:
                    cov = _sanitize_coverage(env.get("coverage") or (rec.get("prepared") or {}).get("coverage"))
                    if (
                        cov is None
                        or not isinstance(cov.get("prior_story"), dict)
                        or not cand.get("updates")
                    ):
                        continue
                    scope = "latest_update"
                hold_info = rec.get("hold")
                subgroup = ".".join(hold_info) if isinstance(hold_info, list) else (str(hold_info) if hold_info else "held")
                target_sid = irow["story_id"] or ((cov or {}).get("prior_story") or {}).get("id") or env.get("story_id")
                _register_entry(
                    bucket="held_review_jobs",
                    subgroup=subgroup,
                    entry_id=f"held:{irow['id']}",
                    packet_id=f"pkt:item:{irow['id']}",
                    packet=pkt,
                    candidate_obj=cand,
                    expected="hold",
                    item_row_obj=irow,
                    item_payload_obj=ipayload,
                    target_story_id=target_sid,
                    exclude_story_ids=[] if (is_update_job or not target_sid) else [target_sid],
                    coverage=cov,
                    scope=scope,
                )

        # 2. Rejection actions
        if _can_add("rejection_actions") and _table_exists(conn, "rejection_actions") and _table_exists(conn, "items"):
            ra_cursor = conn.execute(
                "SELECT action_id, item_id, action, before_status FROM rejection_actions ORDER BY action_id DESC"
            )
            seen_ra_items: set[str] = set()
            for rrow in ra_cursor:
                if not _can_add("rejection_actions"):
                    break
                if rrow["item_id"] in seen_ra_items:
                    continue
                seen_ra_items.add(rrow["item_id"])
                irow, ipayload = _load_item_row_and_payload(conn, rrow["item_id"])
                if irow is None or ipayload is None:
                    continue
                pkt = _packet_from_item(ipayload)
                if pkt is None:
                    continue
                cand = _normalize_case_candidate(None, pkt, digest(["rej", irow["id"]])[:24], ipayload)
                if cand is None:
                    continue
                _register_entry(
                    bucket="rejection_actions",
                    subgroup=f"{rrow['action']}:{rrow['before_status']}",
                    entry_id=f"rej:{irow['id']}",
                    packet_id=f"pkt:item:{irow['id']}",
                    packet=pkt,
                    candidate_obj=cand,
                    expected="hold",
                    item_row_obj=irow,
                    item_payload_obj=ipayload,
                    target_story_id=irow["story_id"],
                    exclude_story_ids=[irow["story_id"]] if irow["story_id"] else [],
                )

        # 3. Editorial revisions
        if _can_add("editorial_revisions") and _table_exists(conn, "editorial_revisions") and _table_exists(conn, "stories"):
            ed_cursor = conn.execute(
                "SELECT story_id, revision, action, CAST(before_public_json AS BLOB) AS before_blob, "
                "CAST(after_public_json AS BLOB) AS after_blob "
                "FROM editorial_revisions ORDER BY created_at DESC, story_id, revision DESC"
            )
            seen_ed_stories: set[str] = set()
            for erow in ed_cursor:
                if not _can_add("editorial_revisions"):
                    break
                sid = erow["story_id"]
                if sid in seen_ed_stories:
                    continue
                seen_ed_stories.add(sid)
                srow = conn.execute("SELECT CAST(payload AS BLOB) AS payload_blob FROM stories WHERE id=?", (sid,)).fetchone()
                spayload = _safe_blob_json(srow["payload_blob"]) if srow is not None else None
                before_pub = _safe_blob_json(erow["before_blob"])
                after_pub = _safe_blob_json(erow["after_blob"])
                story_for_pkt = spayload or after_pub or before_pub
                if story_for_pkt is None:
                    continue
                pkt = _story_eval_packet(conn, story_for_pkt)
                if pkt is None:
                    continue
                raw_cand = before_pub if (erow["action"] == "retract" and before_pub is not None) else (after_pub or before_pub)
                expected = "hold" if erow["action"] == "retract" else "approve"
                cand = _normalize_case_candidate(raw_cand, pkt, sid)
                if cand is None:
                    continue
                w_id, _, _ = candidate_mod.writer_info(story_for_pkt, conn)
                irow, ipayload = _load_item_row_and_payload(conn, w_id) if w_id else (None, None)
                _register_entry(
                    bucket="editorial_revisions",
                    subgroup=erow["action"],
                    entry_id=f"ed:{sid}:r{erow['revision']}",
                    packet_id=f"pkt:story:{sid}",
                    packet=pkt,
                    candidate_obj=cand,
                    expected=expected,
                    item_row_obj=irow,
                    item_payload_obj=ipayload,
                    target_story_id=sid,
                    exclude_story_ids=[sid],
                )

        # 4. High-comment items (>= 8 comments)
        if _can_add("high_comment_items") and _table_exists(conn, "items"):
            item_cursor = conn.execute(
                "SELECT id,url,source_id,CAST(payload AS BLOB) AS payload_blob,content_hash,cluster_key,"
                "first_seen,last_seen,status,attempts,rejections,next_attempt_at,last_error,priority_score,story_id "
                "FROM items ORDER BY last_seen DESC, id"
            )
            for irow in item_cursor:
                if not _can_add("high_comment_items"):
                    break
                ipayload = _safe_blob_json(irow["payload_blob"])
                if ipayload is None:
                    continue
                comments = ipayload.get("public_comments")
                if not isinstance(comments, list) or len(comments) < MIN_HIGH_COMMENTS:
                    continue
                pkt = _packet_from_item(ipayload)
                if pkt is None:
                    continue
                raw_cand = None
                if irow["story_id"]:
                    st = conn.execute("SELECT CAST(payload AS BLOB) AS pb FROM stories WHERE id=?", (irow["story_id"],)).fetchone()
                    raw_cand = _safe_blob_json(st["pb"]) if st is not None else None
                cand = _normalize_case_candidate(raw_cand, pkt, digest(["hc", irow["id"]])[:24], ipayload)
                if cand is None:
                    continue
                _register_entry(
                    bucket="high_comment_items",
                    subgroup=f"comments_{len(comments)}",
                    entry_id=f"hc:{irow['id']}",
                    packet_id=f"pkt:item:{irow['id']}",
                    packet=pkt,
                    candidate_obj=cand,
                    expected="approve" if irow["status"] == "published" else "hold",
                    item_row_obj=irow,
                    item_payload_obj=ipayload,
                    target_story_id=irow["story_id"],
                    exclude_story_ids=[irow["story_id"]] if irow["story_id"] else [],
                )

        # 5. Multi-update stories (>= 3 updates)
        if _can_add("multi_update_stories") and _table_exists(conn, "stories"):
            story_cursor = conn.execute(
                "SELECT s.id, s.cluster_key, s.published_at, s.updated_at, "
                "CAST(s.payload AS BLOB) AS payload_blob "
                "FROM stories s LEFT JOIN editorial_controls e ON e.story_id=s.id "
                "WHERE COALESCE(e.retracted, 0) != 1 "
                "ORDER BY s.updated_at DESC, s.id"
            )
            for srow in story_cursor:
                if not _can_add("multi_update_stories"):
                    break
                sid = srow["id"]
                if editorial.retired(conn, story_id=sid, cluster_key=srow["cluster_key"]) is not None:
                    continue
                spayload = _safe_blob_json(srow["payload_blob"])
                if spayload is None:
                    continue
                updates = spayload.get("updates")
                if not isinstance(updates, list) or len(updates) < MIN_MULTI_UPDATES:
                    continue
                pkt = _story_eval_packet(conn, spayload)
                if pkt is None:
                    continue
                cand = _normalize_case_candidate(spayload, pkt, sid)
                if cand is None:
                    continue
                w_id, _, _ = candidate_mod.writer_info(spayload, conn)
                irow, ipayload = _load_item_row_and_payload(conn, w_id) if w_id else (None, None)
                added = _register_entry(
                    bucket="multi_update_stories",
                    subgroup=f"updates_{len(updates)}",
                    entry_id=f"mu:{sid}",
                    packet_id=f"pkt:story:{sid}",
                    packet=pkt,
                    candidate_obj=cand,
                    expected="approve",
                    item_row_obj=irow,
                    item_payload_obj=ipayload,
                    target_story_id=sid,
                    exclude_story_ids=[sid],
                )
                if added and include_updates and cand.get("updates") and _can_add("multi_update_stories"):
                    prior_cov = {
                        "prior_story": {k: v for k, v in cand.items() if k in {
                            "id", "title", "summary", "why_it_matters", "category", "priority",
                            "confidence", "state", "products", "tags", "published_at", "updated_at", "added_at", "updates",
                        }},
                        "recent": [],
                        "truncated": False,
                    }
                    _register_entry(
                        bucket="multi_update_stories",
                        subgroup=f"latest_update_{len(updates)}",
                        entry_id=f"mu:{sid}:latest_update",
                        packet_id=f"pkt:story:{sid}",
                        packet=pkt,
                        candidate_obj=cand,
                        expected="approve",
                        coverage=prior_cov,
                        scope="latest_update",
                        target_story_id=sid,
                    )

        # Background stories/controls/items for isolated run_suite1.py replay.
        background_stories: list[dict] = []
        bg_story_ids: set[str] = set()
        if _table_exists(conn, "stories"):
            for r in conn.execute(
                "SELECT id, cluster_key, CAST(payload AS BLOB) AS pb, published_at, updated_at "
                "FROM stories ORDER BY updated_at DESC, id LIMIT 100"
            ).fetchall():
                sp = _safe_blob_json(r["pb"])
                if sp is not None:
                    bg_story_ids.add(r["id"])
                    background_stories.append({
                        "id": r["id"],
                        "cluster_key": r["cluster_key"],
                        "payload": json.dumps(_sanitize_obj(sp), ensure_ascii=False),
                        "published_at": r["published_at"],
                        "updated_at": r["updated_at"],
                    })

        background_controls: list[dict] = []
        if _table_exists(conn, "editorial_controls") and bg_story_ids:
            for r in conn.execute(
                "SELECT story_id, revision, locked, retracted, notice_action, notice_reason, notice_at, held_updates, last_held_at "
                "FROM editorial_controls"
            ).fetchall():
                if r["story_id"] in bg_story_ids:
                    background_controls.append({
                        "story_id": r["story_id"],
                        "revision": r["revision"],
                        "locked": r["locked"],
                        "retracted": r["retracted"],
                        "notice_action": sanitize_text(r["notice_action"]),
                        "notice_reason": sanitize_text(r["notice_reason"]),
                        "notice_at": r["notice_at"],
                        "held_updates": r["held_updates"],
                        "last_held_at": r["last_held_at"],
                    })

        background_items: list[dict] = []
        if _table_exists(conn, "items") and bg_story_ids:
            for r in conn.execute(
                "SELECT id,url,source_id,CAST(payload AS BLOB) AS pb,content_hash,cluster_key,"
                "first_seen,last_seen,status,attempts,rejections,next_attempt_at,last_error,priority_score,story_id "
                "FROM items WHERE story_id IS NOT NULL ORDER BY last_seen DESC, id LIMIT 200"
            ).fetchall():
                if r["story_id"] in bg_story_ids and (ip := _safe_blob_json(r["pb"])) is not None:
                    background_items.append(_sanitize_item_row(r, ip))

    return {
        "schema_version": 1,
        "generated_at": now_iso(),
        "defaults": {
            "why_it_matters": "",
            "priority": "normal",
            "confidence": "reported",
            "state": "developing",
            "products": ["tor"],
            "published_at": _FALLBACK_DATE,
            "updated_at": _FALLBACK_DATE,
            "added_at": _FALLBACK_DATE,
        },
        "buckets": buckets,
        "items": items,
        "packets": packets,
        "coverage_sets": coverage_sets,
        "cases": cases,
        "identities": identities,
        "background_stories": background_stories,
        "background_controls": background_controls,
        "background_items": background_items,
    }


def main(argv: list[str] | None = None) -> int:
    """Parse harvester CLI flags and write a sanitized read-only evaluation JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, type=Path, help="Path to source SQLite DB (read-only)")
    parser.add_argument("--output", required=True, type=Path, help="Output JSON dataset path")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="Max total harvested cases")
    parser.add_argument("--max-per-bucket", type=int, default=DEFAULT_MAX_PER_BUCKET, help="Max cases per bucket")
    parser.add_argument("--include-updates", action="store_true", help="Include update-scope and update items")
    args = parser.parse_args(argv)

    db_resolved = args.db.resolve(strict=True)
    out = args.output.resolve()
    if out == db_resolved or (args.output.exists() and os.path.samefile(args.output, db_resolved)):
        parser.error("--output must not identify or alias --db")

    os.umask(0o077)
    dataset = harvest_database(
        args.db,
        limit=args.limit,
        max_per_bucket=args.max_per_bucket,
        include_updates=args.include_updates,
    )
    out.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(dataset, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
    print(
        json.dumps(
            {
                "output": str(out),
                "cases": len(dataset["cases"]),
                "items": len(dataset["items"]),
                "packets": len(dataset["packets"]),
                "buckets": {k: len(v) for k, v in dataset["buckets"].items()},
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
