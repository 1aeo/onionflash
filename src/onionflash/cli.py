"""The small explicit collect → analyze → render pipeline."""

from __future__ import annotations

import argparse
from collections import deque
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
import contextlib
import copy
import fcntl
import inspect
import json
import logging
import os
from pathlib import Path
import sqlite3
import sys
import threading
import time
import traceback

from . import __version__, candidate as candidate_mod, decisions, doctor, editorial, refresh, registry, rejection, review, review_gate
from .analyze import AnalysisError, Analyzer, cache_key
from .collect import CollectionError, collect_source
from .comments import RUN_BUDGET_SECONDS as COMMENTS_BUDGET, enrich_comments, merge_cached_comments, status as comments_status
from .config import enabled_consensus_sources, load_config
from .llm import CompletionDeferred
from .publication import build
from .review import Reviewer, ReviewLimitReached
from .review_gate import process_item, status as review_status
from .store import Store, source_due
from .transport import HttpClient
from .util import after, digest, now_iso

MAX_CONCURRENT_LLM_ITEMS = 4
_ORIG_ANALYZER = Analyzer
_ORIG_REVIEWER = Reviewer
_ORIG_PROCESS_ITEM = process_item
_ORIG_REFRESHER = refresh.StoryRefresher
_ORIG_REFRESH_DUE_STORIES = refresh.refresh_due_stories

_OPERATOR_ACTION_ORDER = {
    "story": ("show", "history", "correct", "retract", "restore", "unlock", "merge"),
    "rejected": ("list", "show", "retry", "dismiss", "approve"),
    "decisions": ("summary", "list"),
}
OPERATOR_ACTIONS = {k: set(v) for k, v in _OPERATOR_ACTION_ORDER.items()}
READ_ONLY_ACTIONS = {"show", "history", "list", "summary"}


def _unexpected_error(exc: BaseException) -> str:
    frame = traceback.extract_tb(exc.__traceback__)[-1]
    return f"Unexpected {type(exc).__name__} at {Path(frame.filename).name}:{frame.lineno}"


@contextlib.contextmanager
def run_lock(database: str):
    """Acquire a non-blocking exclusive advisory file lock adjacent to `database`."""
    path = Path(database + ".lock")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        yield True
    finally:
        os.close(fd)


def _operator_parsers(commands, cfg_parent: argparse.ArgumentParser) -> None:
    """Register explicit inspection and guarded editorial or retry commands."""
    guarded = argparse.ArgumentParser(add_help=False)
    guarded.add_argument("--expect-hash", required=True)
    guarded.add_argument("--reason", required=True)

    story = commands.add_parser("story", help="Inspect, correct, merge, or retract a published story")
    actions = story.add_subparsers(dest="action", required=True)
    for name in _OPERATOR_ACTION_ORDER["story"]:
        parents = [cfg_parent] if name in READ_ONLY_ACTIONS else [cfg_parent, guarded]
        action = actions.add_parser(name, parents=parents)
        action.add_argument("--story", required=True, help="Stable story ID")
        if name == "merge":
            action.add_argument("--into", dest="into_story", required=True, help="Survivor story ID")
        elif name == "correct":
            action.add_argument("--patch", required=True, type=Path, help="JSON object containing changed public fields")
        elif name == "restore":
            action.add_argument("--revision", required=True, type=int, help="Revision to restore and lock")

    rejected = commands.add_parser("rejected", help="Inspect, retry, dismiss or approve held analyses")
    actions = rejected.add_subparsers(dest="action", required=True)
    for name in _OPERATOR_ACTION_ORDER["rejected"]:
        parents = [cfg_parent, guarded] if name in {"retry", "dismiss"} else [cfg_parent]
        action = actions.add_parser(name, parents=parents)
        if name == "list":
            action.add_argument("--status", choices=("rejected", "dismissed", "ignored"), default="rejected")
            action.add_argument("--limit", type=int, default=50)
            action.add_argument("--after", help="Continuation cursor returned by the previous list")
        else:
            action.add_argument("--item", required=True, help="Collected item ID")
        if name == "approve":
            action.add_argument("--approval-hash", required=True, help="final_review.approval.hash returned by rejected show")
            action.add_argument("--reason", required=True, help="Private operator reason for this action")

    log = commands.add_parser("decisions", help="Summarize or list recent private decisions")
    actions = log.add_subparsers(dest="action", required=True)
    for name in _OPERATOR_ACTION_ORDER["decisions"]:
        action = actions.add_parser(name, parents=[cfg_parent])
        action.add_argument("--since", default="7d", help="Hours or days before now, such as 7d, or a timestamp")
        if name == "list":
            action.add_argument("--code", help="A decision code or its dotted prefix, such as held.review")
            action.add_argument("--source", help="Source ID")
            action.add_argument("--limit", type=int, default=50)
            action.add_argument("--after", type=int, help="Continuation cursor returned by the previous list")


def _operator_command(args, store: Store, config: dict) -> dict:
    """Dispatch one inspection, or one operator action with its required hash and reason."""
    if args.command == "story":
        if args.action == "show":
            return editorial.show(store.db, args.story)
        if args.action == "history":
            return editorial.history(store.db, args.story)
        options = {"reason": args.reason, "expect_hash": args.expect_hash}
        if args.action == "merge":
            result = editorial.merge(store.db, args.story, args.into_story, base_url=config["site"]["base_url"], **options)
        elif args.action == "correct":
            result = editorial.correct(store.db, args.story, json.loads(args.patch.read_text(encoding="utf-8")), **options)
        elif args.action == "restore":
            result = editorial.restore(store.db, args.story, revision=args.revision, **options)
        else:
            result = getattr(editorial, args.action)(store.db, args.story, **options)
        return {**result, "publication_pending": True}
    if args.command == "decisions":
        since = decisions.window(args.since)
        if args.action == "summary":
            return decisions.summary(store.db, since)
        return decisions.list_entries(store.db, since, code=args.code, source=args.source, limit=args.limit, after=args.after)
    if args.action == "list":
        return rejection.list_items(store, status=args.status, limit=args.limit, after=args.after)
    if args.action == "show":
        return rejection.show_item(store, args.item, config=config)
    if args.action == "approve":
        return rejection.approve_item(config, store, args.item, args.approval_hash, args.reason)
    return getattr(rejection, args.action + "_item")(store, args.item, args.expect_hash, args.reason)


def _effective_config(config: dict, store: Store) -> tuple[dict, list[str]]:
    tor_core_users, trusted_domains = registry.effective_identities(config, store.db)
    eff_collection = {
        **config["collection"],
        "tor_core_gitlab_users": tor_core_users,
        "trusted_operator_domains": trusted_domains,
    }
    return {**config, "collection": eff_collection}, tor_core_users


def _draft_cache_options(analyzer=None) -> tuple[int, bool | None]:
    """Return `(best_of, quote_digest)` matching `_new_analyzer` or a supplied writer instance."""
    if analyzer is not None:
        return review_gate._writer_cache_options(analyzer)
    try:
        params = inspect.signature(Analyzer).parameters
    except (TypeError, ValueError):
        params = {}
    best_of = 3 if "best_of" in params else 1
    quote_digest: bool | None = True if "quote_digest" in params else None
    return best_of, quote_digest


def _new_analyzer(
    config: dict,
    *,
    deadline: float | None = None,
    request_semaphore: threading.Semaphore | None = None,
):
    """Construct `Analyzer`, opting into polish, best-of-3, and quote-digest when supported."""
    kwargs: dict[str, object] = {"deadline": deadline}
    try:
        params = inspect.signature(Analyzer).parameters
    except (TypeError, ValueError):
        params = {}
    if "editorial_polish" in params:
        kwargs["editorial_polish"] = True
    best_of, quote_digest = _draft_cache_options()
    if "best_of" in params:
        kwargs["best_of"] = best_of
    if "quote_digest" in params and quote_digest is not None:
        kwargs["quote_digest"] = quote_digest
    if request_semaphore is not None and "request_semaphore" in params:
        kwargs["request_semaphore"] = request_semaphore
    return Analyzer(config, **kwargs)


def _parallel_verify_kwargs(use_parallel: bool, reviewer_factory) -> dict:
    """Return opt-in parallel verification kwargs when `process_item` supports them."""
    if not use_parallel:
        return {}
    try:
        params = inspect.signature(process_item).parameters
    except (TypeError, ValueError):
        return {}
    if "parallel_verify" in params and "reviewer_factory" in params:
        kwargs: dict[str, object] = {"parallel_verify": True, "reviewer_factory": reviewer_factory}
        if "specialists" in params:
            kwargs["specialists"] = 3
        return kwargs
    return {}


def _classify_pending_row(
    run_config: dict,
    store: Store,
    row: dict,
    policy: str,
    *,
    execute_gates: bool,
    observed: str | None = None,
    best_of: int | None = None,
    quote_digest: bool | None = None,
) -> tuple[str, object]:
    """Run deterministic pre-draft triage; when `execute_gates` is true, commit skips/citations before drafting."""
    if row.get("damaged"):
        if execute_gates:
            store.reject(row["id"], "Stored source item is damaged", "failed.app.damaged_item", observed or now_iso())
            return "failed", None
        return "skip", None
    coll = run_config.get("collection") or {}
    dirauth_users = coll.get("dirauth_gitlab_users")
    tor_core_users = coll.get("tor_core_gitlab_users")
    try:
        item_payload = json.loads(row["payload"])
        existing = candidate_mod.existing_story(store.db, row)
        if (
            existing is None
            and editorial.retired(
                store.db, story_id=digest(row["cluster_key"])[:24], cluster_key=row["cluster_key"]
            )
            is not None
        ):
            if execute_gates:
                status_out = review_gate._ignore_at_gate(
                    store,
                    row,
                    observed or now_iso(),
                    "Retired story; never recreated",
                    "skipped.gate.retired_story",
                    clear_story=True,
                )
                return "done", {"status": status_out, "cache_hit": False}
            return "skip", None
        if item_payload.get("kind") == "tag":
            return ("ready", row) if execute_gates else ("skip", None)
        job, saved_draft, _saved_prepared, saved_record, same_source = review_gate._saved_job(
            store, row, run_config
        )
        if execute_gates:
            stamp = observed or now_iso()
            if skipped := review_gate._not_recent(run_config, store, row, item_payload, stamp, existing=existing):
                return "done", {"status": skipped, "cache_hit": False}
            if skipped_det := review_gate._deterministic_skip(
                run_config, store, row, item_payload, stamp, existing=existing
            ):
                return "done", {"status": skipped_det, "cache_hit": False}
            if existing is not None and candidate_mod.relation(json.loads(existing["payload"]), item_payload, store.db) == "citation":
                cited = store.add_citation(row, existing["id"], stamp)
                return "done", {"status": cited["status"], "cache_hit": False}
            own_state, writer_item = candidate_mod.own_update_input(store.db, row, item_payload, existing=existing)
            if own_state == "skip":
                status_out = review_gate._ignore_at_gate(
                    store, row, stamp, "No new content after story update", "skipped.gate.no_new_content"
                )
                return "done", {"status": status_out, "cache_hit": False}
        else:
            developed = review_gate.developed_at(item_payload)
            if not (
                developed >= after(-review_gate.NEW_STORY_DAYS * 86400, row["last_seen"])
                or review_gate._security_disclosure(item_payload)
                or existing is not None
                or review_gate._has_operator_retry(store.db, row)
            ):
                return "skip", None
            if (
                review_gate._eval_deterministic_skip(
                    store.db,
                    item_payload,
                    existing,
                    row=row,
                    dirauth_users=dirauth_users,
                    tor_core_users=tor_core_users,
                )
                is not None
            ):
                return "skip", None
            if (
                existing is not None
                and candidate_mod.relation(json.loads(existing["payload"]), item_payload, store.db) == "citation"
            ):
                return "skip", None
            own_state, writer_item = candidate_mod.own_update_input(
                store.db, row, item_payload, existing=existing
            )
            if own_state == "skip":
                return "skip", None
        prior = candidate_mod.update_target(store.db, row, existing=existing)
    except sqlite3.Error:
        raise
    except editorial.RetiredStory:
        if execute_gates:
            status_out = review_gate._ignore_at_gate(
                store,
                row,
                observed or now_iso(),
                "Retired story; never recreated",
                "skipped.gate.retired_story",
                clear_story=True,
            )
            return "done", {"status": status_out, "cache_hit": False}
        return "skip", None
    except candidate_mod.StaleCandidate:
        return ("done", {"status": "stale", "cache_hit": False}) if execute_gates else ("skip", None)
    except (AnalysisError, ValueError, TypeError, KeyError):
        return ("ready", row) if execute_gates else ("skip", None)

    if best_of is None:
        best_of, default_qd = _draft_cache_options()
        if quote_digest is None:
            quote_digest = default_qd
    writer_key = cache_key(row, run_config["llm"], prior, best_of=best_of, quote_digest=quote_digest)
    locked_reuse = (
        job is not None
        and existing is not None
        and editorial.is_locked(store.db, existing["id"])
        and same_source
        and saved_draft is not None
    )
    carry = None
    if (
        job is not None
        and job["policy_hash"] == policy
        and same_source
        and (job["writer_key"] != writer_key or job["stage"] == "routed")
    ):
        carry = review_gate._carried_requests(saved_record)
    if (
        job is not None
        and same_source
        and job["stage"] != "routed"
        and (job["writer_key"] == writer_key or locked_reuse)
        and saved_draft is not None
    ):
        return ("ready", row) if execute_gates else ("skip", None)
    dispatch_context = digest([existing["id"] if existing is not None else None, writer_key, writer_item])
    return "draft", (row, copy.deepcopy(writer_item), copy.deepcopy(prior), writer_key, carry, dispatch_context)


def _draft_one_task(
    run_config: dict,
    run_deadline: float,
    writer_item_copy: dict,
    prior_copy: dict | None,
    request_semaphore: threading.Semaphore | None = None,
):
    """Run one `Analyzer` draft in an isolated client without SQLite access."""
    with _new_analyzer(run_config, deadline=run_deadline, request_semaphore=request_semaphore) as worker:
        try:
            draft = (
                worker.analyze(writer_item_copy)
                if prior_copy is None
                else worker.analyze(writer_item_copy, prior=prior_copy)
            )
            return draft, worker.calls, getattr(worker, "clears", 0), None
        except BaseException as exc:
            return None, worker.calls, 0, exc


def _persist_draft_outcome(
    run_config: dict,
    store: Store,
    report: dict,
    policy: str,
    row: dict,
    writer_key: str,
    carry: dict | None,
    draft,
    clears: int,
    exc: BaseException | None,
    *,
    observed: str | None = None,
    endpoint_failures: int = 0,
    dispatch_context: str | None = None,
    best_of: int | None = None,
    quote_digest: bool | None = None,
) -> tuple[str, int]:
    """Persist a completed worker draft or record its failure on the main thread."""
    if exc is None:
        record = review_gate._new_record(row, **(carry or {}))
        record["writer"] = {"key": writer_key}
        if clears:
            record["writer"]["clears"] = clears
        saved_at = observed or now_iso()
        try:
            review_gate._save(
                store,
                row,
                writer_key,
                policy,
                "drafted",
                draft,
                None,
                record,
                saved_at,
                prepared_at=saved_at,
            )
        except candidate_mod.StaleCandidate:
            report["review_stale"] += 1
            return "handled", endpoint_failures
        return "ready", endpoint_failures
    if isinstance(exc, sqlite3.Error):
        raise exc
    if isinstance(exc, CompletionDeferred):
        return "budget_reached", endpoint_failures
    if not isinstance(exc, Exception):
        raise exc
    is_analysis = isinstance(exc, AnalysisError)
    retryable = is_analysis and exc.retryable
    if retryable and endpoint_failures >= 2:
        return "skipped_breaker", endpoint_failures
    if dispatch_context is not None:
        cur = store.db.execute(
            "SELECT id,url,source_id,payload,content_hash,cluster_key,first_seen,last_seen,"
            "status,attempts,rejections,next_attempt_at,last_error,priority_score,story_id "
            "FROM items WHERE id=? AND content_hash=? AND status='pending'",
            (row["id"], row["content_hash"]),
        ).fetchone()
        if cur is None:
            report["review_stale"] += 1
            return "handled", endpoint_failures + retryable
        cur_kind, cur_payload = _classify_pending_row(
            run_config, store, dict(cur), policy, execute_gates=False, best_of=best_of, quote_digest=quote_digest,
        )
        if cur_kind != "draft" or cur_payload[5] != dispatch_context:
            report["review_stale"] += 1
            return "handled", endpoint_failures + retryable
    deferred = store.defer(
        row["id"],
        str(exc) if is_analysis else _unexpected_error(exc),
        run_config["llm"],
        observed or now_iso(),
        terminal=not retryable,
        code=exc.code if is_analysis else "app.unexpected",
        expected_row=row,
    )
    report["analysis_failed"] += deferred
    report["review_stale"] += not deferred
    endpoint_failures += retryable
    return "handled", endpoint_failures


def _prefetch_drafts(
    run_config: dict,
    store: Store,
    pending_rows: list[dict],
    report: dict,
    observed: str | None = None,
    *,
    run_deadline: float,
    allow_network: bool = True,
    endpoint_failures: int = 0,
) -> tuple[int, int, set[str], bool]:
    """Draft eligible queued items concurrently without accessing SQLite from worker threads."""
    if not allow_network or endpoint_failures >= 2 or len(pending_rows) <= 1 or time.monotonic() >= run_deadline:
        return 0, endpoint_failures, set(), False

    policy = review.policy_hash(run_config)
    best_of, quote_digest = _draft_cache_options()
    tasks: list[tuple[dict, dict, dict | None, str, dict | None, str]] = []
    for row in pending_rows[: MAX_CONCURRENT_LLM_ITEMS * 2]:
        kind, payload = _classify_pending_row(
            run_config, store, row, policy, execute_gates=False, best_of=best_of, quote_digest=quote_digest,
        )
        if kind == "draft":
            tasks.append(payload)

    if len(tasks) < 2:
        return 0, endpoint_failures, set(), False

    prefetched_calls = 0
    handled_ids: set[str] = set()
    budget_reached = False
    draft_semaphore = threading.Semaphore(MAX_CONCURRENT_LLM_ITEMS)

    with ThreadPoolExecutor(max_workers=min(MAX_CONCURRENT_LLM_ITEMS, len(tasks))) as pool:
        submitted = [
            (
                (row, writer_key, carry, dispatch_context),
                pool.submit(_draft_one_task, run_config, run_deadline, writer_item_copy, prior_copy, draft_semaphore),
            )
            for row, writer_item_copy, prior_copy, writer_key, carry, dispatch_context in tasks
        ]
        for idx, ((row, writer_key, carry, dispatch_context), future) in enumerate(submitted):
            if future.cancelled():
                continue
            draft, calls, clears, exc = future.result()
            prefetched_calls += calls
            outcome, endpoint_failures = _persist_draft_outcome(
                run_config,
                store,
                report,
                policy,
                row,
                writer_key,
                carry,
                draft,
                clears,
                exc,
                observed=observed,
                endpoint_failures=endpoint_failures,
                dispatch_context=dispatch_context,
                best_of=best_of,
                quote_digest=quote_digest,
            )
            if outcome == "budget_reached":
                budget_reached = True
                for _, rem in submitted[idx + 1 :]:
                    rem.cancel()
            elif outcome == "handled":
                handled_ids.add(row["id"])
                if endpoint_failures >= 2:
                    for _, rem in submitted[idx + 1 :]:
                        rem.cancel()

    return prefetched_calls, endpoint_failures, handled_ids, budget_reached


def _apply_item_result(report: dict, result: dict) -> None:
    if result["status"] not in {"stale", "deferred"}:
        report["analyzed"] += 1
    report["review_cache_hits"] += bool(result.get("cache_hit"))
    report["review_stale"] += result["status"] == "stale"
    report["review_routed"] += result["status"] == "routed"


def _run_process_item(
    run_config: dict,
    store: Store,
    row: dict,
    analyzer,
    reviewer,
    report: dict,
    *,
    allow_network: bool,
    endpoint_failures: int,
    process_kwargs: dict,
) -> tuple[int, bool]:
    """Execute `process_item` for one ready row on the main thread with standard error accounting."""
    if row.get("damaged"):
        store.reject(row["id"], "Stored source item is damaged", "failed.app.damaged_item", now_iso())
        report["analysis_failed"] += 1
        return endpoint_failures, False
    try:
        result = process_item(
            run_config,
            store,
            row,
            analyzer,
            reviewer,
            now_iso(),
            allow_network=allow_network,
            **process_kwargs,
        )
        _apply_item_result(report, result)
        if result.get("budget_reached"):
            report["budget_reached"] = True
            return endpoint_failures, True
    except ReviewLimitReached:
        # The gate already checked the exact source and recorded this
        # terminal rejection; it must not become a second queue strike.
        report["analysis_failed"] += 1
    except CompletionDeferred:
        report["budget_reached"] = True
        return endpoint_failures, True
    except sqlite3.Error:
        raise
    except Exception as exc:
        is_analysis = isinstance(exc, AnalysisError)
        retryable = is_analysis and exc.retryable
        deferred = store.defer(
            row["id"],
            str(exc) if is_analysis else _unexpected_error(exc),
            run_config["llm"],
            now_iso(),
            terminal=not retryable,
            code=exc.code if is_analysis else "app.unexpected",
            expected_row=row,
        )
        report["analysis_failed"] += deferred
        report["review_stale"] += not deferred
        endpoint_failures += retryable
    return endpoint_failures, False


def _run_sliding_window(
    run_config: dict,
    store: Store,
    pending_rows: list[dict],
    analyzer,
    reviewer,
    report: dict,
    *,
    run_deadline: float,
    endpoint_failures: int,
    process_kwargs: dict,
) -> tuple[int, int]:
    """Overlap a bounded window of concurrent drafts with immediate main-thread review commits."""
    policy = review.policy_hash(run_config)
    best_of, quote_digest = _draft_cache_options(analyzer)
    pending_iter = iter(pending_rows)
    in_flight: dict[Future, tuple[dict, str, dict | None, str]] = {}
    ready_rows: deque[dict] = deque()
    prefetched_calls = 0
    budget_reached = False
    stopped_dispatch = False
    draft_semaphore = threading.Semaphore(MAX_CONCURRENT_LLM_ITEMS)

    def _fill_window() -> None:
        nonlocal budget_reached, stopped_dispatch
        while (
            not stopped_dispatch
            and not budget_reached
            and endpoint_failures < 2
            and len(in_flight) < MAX_CONCURRENT_LLM_ITEMS
        ):
            if time.monotonic() >= run_deadline:
                report["budget_reached"] = True
                budget_reached = True
                stopped_dispatch = True
                return
            try:
                row = next(pending_iter)
            except StopIteration:
                return
            kind, payload = _classify_pending_row(
                run_config, store, row, policy, execute_gates=True, observed=now_iso(),
                best_of=best_of, quote_digest=quote_digest,
            )
            if kind == "failed":
                report["analysis_failed"] += 1
            elif kind == "done":
                _apply_item_result(report, payload)
            elif kind == "ready":
                ready_rows.append(payload)
            elif kind == "draft":
                d_row, writer_item_copy, prior_copy, writer_key, carry, dispatch_context = payload
                fut = pool.submit(_draft_one_task, run_config, run_deadline, writer_item_copy, prior_copy, draft_semaphore)
                in_flight[fut] = (d_row, writer_key, carry, dispatch_context)

    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_LLM_ITEMS) as pool:
        _fill_window()
        while ready_rows or in_flight:
            while ready_rows and not budget_reached:
                if time.monotonic() >= run_deadline:
                    report["budget_reached"] = True
                    budget_reached = True
                    stopped_dispatch = True
                    break
                endpoint_failures, hit_budget = _run_process_item(
                    run_config,
                    store,
                    ready_rows.popleft(),
                    analyzer,
                    reviewer,
                    report,
                    allow_network=endpoint_failures < 2 and not budget_reached,
                    endpoint_failures=endpoint_failures,
                    process_kwargs=process_kwargs,
                )
                if hit_budget:
                    budget_reached = True
                    stopped_dispatch = True
                    break
                if endpoint_failures >= 2:
                    stopped_dispatch = True
                elif not stopped_dispatch:
                    _fill_window()
            if budget_reached:
                for rem_fut in list(in_flight):
                    rem_fut.cancel()
                break
            if not in_flight:
                break
            done, _ = wait(in_flight, return_when=FIRST_COMPLETED)
            for fut in done:
                d_row, writer_key, carry, dispatch_context = in_flight.pop(fut)
                if fut.cancelled():
                    continue
                draft, calls, clears, exc = fut.result()
                prefetched_calls += calls
                outcome, endpoint_failures = _persist_draft_outcome(
                    run_config,
                    store,
                    report,
                    policy,
                    d_row,
                    writer_key,
                    carry,
                    draft,
                    clears,
                    exc,
                    endpoint_failures=endpoint_failures,
                    dispatch_context=dispatch_context,
                    best_of=best_of,
                    quote_digest=quote_digest,
                )
                if outcome == "budget_reached":
                    budget_reached = True
                    report["budget_reached"] = True
                    stopped_dispatch = True
                elif outcome == "ready":
                    ready_rows.append(d_row)
                if endpoint_failures >= 2:
                    stopped_dispatch = True
            if budget_reached or endpoint_failures >= 2:
                for rem_fut in list(in_flight):
                    rem_fut.cancel()
            elif not stopped_dispatch:
                _fill_window()
        # Save any already-running drafts that completed during shutdown without double-deferring.
        for rem_fut in list(in_flight):
            if not rem_fut.cancelled():
                d_row, writer_key, carry, dispatch_context = in_flight[rem_fut]
                draft, calls, clears, exc = rem_fut.result()
                prefetched_calls += calls
                outcome, endpoint_failures = _persist_draft_outcome(
                    run_config,
                    store,
                    report,
                    policy,
                    d_row,
                    writer_key,
                    carry,
                    draft,
                    clears,
                    exc,
                    endpoint_failures=endpoint_failures,
                    dispatch_context=dispatch_context,
                    best_of=best_of,
                    quote_digest=quote_digest,
                )
                if outcome == "budget_reached":
                    report["budget_reached"] = True
    return prefetched_calls, endpoint_failures


def run(config: dict, store: Store) -> dict:
    """Collect and review pending items within one deadline, then build the site."""
    consensus_sources = enabled_consensus_sources(config["sources"], check_single=True)
    observed = now_iso()
    first = decisions.latest_id(store.db)
    report = {
        "sources_ok": 0, "sources_failed": 0, "items_changed": 0, "analyzed": 0,
        "analysis_failed": 0, "budget_reached": False, "entries_skipped": 0,
        "review_cache_hits": 0, "review_stale": 0, "review_routed": 0, "model_calls": 0,
    }
    started = time.monotonic()
    budget = config["collection"]["run_budget_seconds"]
    collection_window = budget * (1 - config["collection"]["analysis_reserve_fraction"])
    registry_budget = min(registry.RUN_BUDGET_SECONDS, collection_window / 2)
    try:
        report["registry"] = registry.refresh_if_due(config, store, observed, deadline=started + registry_budget)
    except Exception as exc:
        report["registry"] = {
            "enabled": bool((config.get("registry") or {}).get("enabled", False)),
            "due": True,
            "refreshed": False,
            "updated": {},
            "errors": [_unexpected_error(exc)],
        }
    run_config, tor_core_users = _effective_config(config, store)
    run_collection = run_config["collection"]
    comments_enabled = bool(run_config.get("comments", {}).get("enabled"))
    comments_budget = min(COMMENTS_BUDGET, collection_window / 2) if comments_enabled else 0
    collection_deadline = started + collection_window - comments_budget
    network_ingested = {"reports_new": 0, "rejected": 0}
    prev_tor_core = getattr(store, "tor_core_users", None)
    store.tor_core_users = tuple(tor_core_users)
    try:
        def record_items(source, items):
            """Normalize, enrich, and store collected entries for one source."""
            received = now_iso()
            if source.get("alert_format") == "consensus":
                added, rejected = doctor.ingest(store.db, source, list(items), received, run_collection["content_chars"])
                network_ingested["reports_new"] += added
                network_ingested["rejected"] += rejected
                return received
            dirauth_users = run_collection.get("dirauth_gitlab_users")
            if comments_enabled:
                items = (
                    merge_cached_comments(
                        store, item, source, received, dirauth_users=dirauth_users, tor_core_users=tor_core_users
                    )
                    for item in items
                )
            report["items_changed"] += sum(
                store.ingest(item, received, dirauth_users=dirauth_users, tor_core_users=tor_core_users) for item in items
            )
            return received

        with HttpClient(run_config["http"]) as client:
            for source in run_config["sources"]:
                if not source["enabled"]:
                    continue
                state = store.source(source)
                if not source_due(state, observed):
                    continue
                remaining = collection_deadline - time.monotonic()
                if remaining < 1:
                    report["budget_reached"] = True
                    break
                shared = remaining <= run_collection["source_budget_seconds"]
                client.deadline = time.monotonic() + min(remaining, run_collection["source_budget_seconds"])
                client.deadline_reached = False
                try:
                    try:
                        result = collect_source(client, source, state, run_collection, observed)
                        received = record_items(source, result["items"])
                        report["entries_skipped"] += result.get("skipped", 0)
                        store.source_success(source, result, received, schedule_from=observed)
                        report["sources_ok"] += 1
                    except CollectionError as exc:
                        received = record_items(source, exc.items)
                        out_of_time = shared and (client.deadline_reached or time.monotonic() >= collection_deadline)
                        store.source_failure(
                            source, str(exc), run_collection, received,
                            exc.watermark, exc.catching_up or out_of_time,
                        )
                        report["sources_failed"] += 1
                        if out_of_time:
                            report["budget_reached"] = True
                            break
                except Exception as exc:
                    store.source_failure(source, _unexpected_error(exc), run_collection, now_iso())
                    report["sources_failed"] += 1
        try:
            report["comments"] = enrich_comments(run_config, store, now_iso(), deadline=started + collection_window)
        except Exception as exc:
            report["comments"] = {
                "enabled": comments_enabled, "checked": 0, "changed": 0,
                "failed": 1, "skipped": 0, "budget_reached": False, "error": _unexpected_error(exc),
            }
        run_deadline = started + budget
        endpoint_failures = 0
        prefetched_calls = 0
        review_workers: list[Reviewer] = []
        review_workers_lock = threading.Lock()

        def _reviewer_factory():
            """Construct an isolated `Reviewer` for concurrent verification calls."""
            worker = Reviewer(run_config, deadline=run_deadline)
            with review_workers_lock:
                review_workers.append(worker)
            return worker

        with (
            _new_analyzer(run_config, deadline=run_deadline) as analyzer,
            Reviewer(run_config, deadline=run_deadline) as reviewer,
            doctor.LinkChecker(run_config, deadline=run_deadline) as linker,
        ):
            try:
                for consensus_source in consensus_sources:
                    try:
                        evaluated = doctor.evaluate(
                            run_config, store, consensus_source, linker, now_iso(), allow_network=endpoint_failures < 2,
                        )
                        endpoint_failures += evaluated.pop("endpoint_failures", 0)
                        if evaluated.pop("budget_reached", False):
                            report["budget_reached"] = True
                        report["network"] = {**network_ingested, **evaluated}
                    except sqlite3.Error:
                        raise
                    except Exception as exc:
                        report["network"] = {
                            **network_ingested, "incidents_open": 0, "stories_written": 0,
                            "updates_written": 0, "held": 0, "dry_run": not consensus_source.get("publish", False),
                            "error": _unexpected_error(exc),
                        }
                pending_rows = store.pending(run_config["llm"]["max_items_per_run"], now_iso())
                use_parallel = (
                    Analyzer is _ORIG_ANALYZER
                    and Reviewer is _ORIG_REVIEWER
                    and process_item is _ORIG_PROCESS_ITEM
                    and len(pending_rows) > 1
                    and endpoint_failures < 2
                    and time.monotonic() < run_deadline
                )
                process_kwargs = _parallel_verify_kwargs(use_parallel, _reviewer_factory)
                if use_parallel:
                    prefetched_calls, endpoint_failures = _run_sliding_window(
                        run_config,
                        store,
                        pending_rows,
                        analyzer,
                        reviewer,
                        report,
                        run_deadline=run_deadline,
                        endpoint_failures=endpoint_failures,
                        process_kwargs=process_kwargs,
                    )
                else:
                    for row in pending_rows:
                        if time.monotonic() >= run_deadline:
                            report["budget_reached"] = True
                            break
                        endpoint_failures, hit_budget = _run_process_item(
                            run_config,
                            store,
                            row,
                            analyzer,
                            reviewer,
                            report,
                            allow_network=endpoint_failures < 2,
                            endpoint_failures=endpoint_failures,
                            process_kwargs=process_kwargs,
                        )
                        if hit_budget:
                            break
                refresh_calls = 0
                if (
                    not report["budget_reached"]
                    and endpoint_failures < 2
                    and time.monotonic() < run_deadline
                    and (
                        bool(run_config["llm"]["base_url"])
                        or refresh.StoryRefresher is not _ORIG_REFRESHER
                        or refresh.refresh_due_stories is not _ORIG_REFRESH_DUE_STORIES
                    )
                ):
                    try:
                        review_params = (
                            inspect.signature(reviewer.review).parameters
                            if Reviewer is _ORIG_REVIEWER and hasattr(reviewer, "review")
                            else {}
                        )
                    except (AttributeError, TypeError, ValueError):
                        review_params = {}
                    refresh_specialists = (
                        3
                        if (
                            Reviewer is _ORIG_REVIEWER
                            and any(
                                p.name == "specialist" or p.kind == inspect.Parameter.VAR_KEYWORD
                                for p in review_params.values()
                            )
                            and hasattr(review, "SPECIALISTS")
                            and hasattr(review, "merge_specialist_verdicts")
                        )
                        else 1
                    )
                    refresh_stats = refresh.refresh_due_stories(
                        run_config,
                        store,
                        reviewer,
                        observed,
                        deadline=run_deadline,
                        max_refreshes=refresh.MAX_REFRESHES_PER_RUN,
                        allow_network=endpoint_failures < 2,
                        endpoint_failures=endpoint_failures,
                        reviewer_factory=_reviewer_factory if refresh_specialists > 1 else None,
                        specialists=refresh_specialists,
                    )
                    refresh_calls = refresh_stats["calls"]
                    endpoint_failures = refresh_stats["endpoint_failures"]
                    if refresh_stats["budget_reached"]:
                        report["budget_reached"] = True
                    if refresh_stats["attempted"]:
                        store.set_meta(
                            story_refresh_last=json.dumps(
                                {
                                    "at": observed,
                                    "attempted": refresh_stats["attempted"],
                                    "refreshed": refresh_stats["refreshed"],
                                    "held": refresh_stats["held"],
                                    "skipped": refresh_stats["skipped"],
                                },
                                sort_keys=True,
                            )
                        )
                report["model_calls"] = (
                    analyzer.calls
                    + prefetched_calls
                    + refresh_calls
                    + reviewer.calls
                    + sum(worker.calls for worker in review_workers)
                    + linker.calls
                )
            finally:
                for worker in review_workers:
                    worker.close()
        report["decisions"] = decisions.codes_after(store.db, first)
        report["pending_analysis"] = store.pending_count()
        report["rejected_analysis"] = store.rejected_count()
        report["final_review"] = review_status(store)
        report.update(build(run_config, store))
        return report
    finally:
        store.tor_core_users = prev_tor_core


def main(argv: list[str] | None = None) -> int:
    """Parse CLI arguments and dispatch `run`, `build`, `check`, `status`, or operator actions."""
    parser = argparse.ArgumentParser(description="Collect, analyze, and build the Onion Flash static news feed.")
    parser.add_argument("--version", action="version", version=__version__)
    cfg_parent = argparse.ArgumentParser(add_help=False)
    cfg_parent.add_argument("--config", required=True, type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("run", "Collect, analyze queued items, and build"),
        ("build", "Build from saved stories without network requests"),
        ("check", "Validate configuration without network requests"),
        ("status", "Show source and queue status"),
    ):
        command = commands.add_parser(name, parents=[cfg_parent], help=help_text)
        if name == "build":
            command.add_argument("--force", action="store_true", help="Queue a bounded rebuild of all published articles")
    _operator_parsers(commands, cfg_parent)
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        if args.command == "check":
            print(json.dumps({
                "configuration": "valid",
                "sources": sum(s["enabled"] for s in config["sources"]),
                "model": config["llm"]["model"],
                "review_model": config["review"]["model"] or config["llm"]["model"],
                "comments_enabled": config["comments"]["enabled"],
                "llm_endpoint_configured": bool(config["llm"]["base_url"]),
                "llm_credential_present": bool(os.environ.get(config["llm"]["api_key_env"])),
            }))
            return 0
        database = config["storage"]["database"]
        dirauth_users = config["collection"]["dirauth_gitlab_users"]
        tor_core_users = config["collection"]["tor_core_gitlab_users"]
        operator = args.command in OPERATOR_ACTIONS
        read_only = args.command == "status" or (operator and args.action in READ_ONLY_ACTIONS)
        guard = contextlib.nullcontext(True) if read_only else run_lock(database)
        with guard as acquired:
            if not acquired:
                print(json.dumps({"status": "already-running"}))
                return 0 if args.command == "run" else 75
            with Store(database, dirauth_users=dirauth_users, tor_core_users=tor_core_users) as store:
                if args.command == "status":
                    observed, published = now_iso(), store.get_meta("published_stories")
                    result = {
                        "pending_analysis": store.pending_count(),
                        "rejected_analysis": store.rejected_count(),
                        "published_stories": int(published) if published is not None else None,
                        "registry": registry.status(store.db, config),
                        "comments": {"enabled": config["comments"]["enabled"], **comments_status(store)},
                        "final_review": review_status(store),
                        "network_health": doctor.status(store.db, config["sources"]),
                        "decisions_24h": decisions.recent(store.db, observed),
                        "sources": store.health(config["sources"], config["collection"]["stale_after_seconds"], observed),
                    }
                elif operator:
                    eff_config, eff_tor_core = _effective_config(config, store)
                    store.tor_core_users = tuple(eff_tor_core)
                    result = _operator_command(args, store, eff_config)
                elif args.command == "run":
                    result = run(config, store)
                else:
                    eff_config, eff_tor_core = _effective_config(config, store)
                    store.tor_core_users = tuple(eff_tor_core)
                    result = build(eff_config, store, force=args.force)
            print(json.dumps(result, ensure_ascii=operator))
        return 0
    except (ValueError, OSError) as exc:
        print(f"onionflash: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"onionflash: processing failed ({type(exc).__name__})", file=sys.stderr)
        return 1
