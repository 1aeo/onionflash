"""The small explicit collect → analyze → render pipeline."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import contextlib
import copy
import fcntl
import inspect
import json
import os
from pathlib import Path
import sqlite3
import sys
import threading
import time
import traceback

from . import __version__, candidate as candidate_mod, decisions, doctor, editorial, registry, rejection, review, review_gate
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


def _new_analyzer(config: dict, *, deadline: float | None = None):
    """Construct `Analyzer`, opting into `editorial_polish=True` when supported."""
    kwargs: dict[str, object] = {"deadline": deadline}
    try:
        params = inspect.signature(Analyzer).parameters
    except (TypeError, ValueError):
        params = {}
    if "editorial_polish" in params:
        kwargs["editorial_polish"] = True
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
        return {"parallel_verify": True, "reviewer_factory": reviewer_factory}
    return {}


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

    coll = run_config.get("collection") or {}
    dirauth_users = coll.get("dirauth_gitlab_users")
    tor_core_users = coll.get("tor_core_gitlab_users")
    policy = review.policy_hash(run_config)
    tasks: list[tuple[dict, dict, dict | None, str, dict | None]] = []

    for row in pending_rows[: MAX_CONCURRENT_LLM_ITEMS * 2]:
        if row.get("damaged"):
            continue
        try:
            item_payload = json.loads(row["payload"])
            if item_payload.get("kind") == "tag":
                continue
            existing = candidate_mod.existing_story(store.db, row)
            if (
                existing is None
                and editorial.retired(
                    store.db, story_id=digest(row["cluster_key"])[:24], cluster_key=row["cluster_key"]
                )
                is not None
            ):
                continue
            job, saved_draft, _saved_prepared, saved_record, same_source = review_gate._saved_job(
                store, row, run_config
            )
            developed = review_gate.developed_at(item_payload)
            if not (
                developed >= after(-review_gate.NEW_STORY_DAYS * 86400, row["last_seen"])
                or review_gate._security_disclosure(item_payload)
                or existing is not None
                or review_gate._has_operator_retry(store.db, row)
            ):
                continue
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
                continue
            if (
                existing is not None
                and candidate_mod.relation(json.loads(existing["payload"]), item_payload, store.db) == "citation"
            ):
                continue
            own_state, writer_item = candidate_mod.own_update_input(
                store.db, row, item_payload, existing=existing
            )
            if own_state == "skip":
                continue
            prior = candidate_mod.update_target(store.db, row, existing=existing)
        except sqlite3.Error:
            raise
        except (
            AnalysisError,
            editorial.RetiredStory,
            candidate_mod.StaleCandidate,
            ValueError,
            TypeError,
            KeyError,
        ):
            continue

        writer_key = cache_key(row, run_config["llm"], prior)
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
            continue
        tasks.append((row, copy.deepcopy(writer_item), copy.deepcopy(prior), writer_key, carry))

    if len(tasks) < 2:
        return 0, endpoint_failures, set(), False

    def _draft_one(writer_item_copy: dict, prior_copy: dict | None):
        """Run one `Analyzer` draft in an isolated client without SQLite access."""
        with _new_analyzer(run_config, deadline=run_deadline) as worker:
            try:
                draft = (
                    worker.analyze(writer_item_copy)
                    if prior_copy is None
                    else worker.analyze(writer_item_copy, prior=prior_copy)
                )
                return draft, worker.calls, getattr(worker, "clears", 0), None
            except BaseException as exc:
                return None, worker.calls, 0, exc

    prefetched_calls = 0
    handled_ids: set[str] = set()
    budget_reached = False

    with ThreadPoolExecutor(max_workers=min(MAX_CONCURRENT_LLM_ITEMS, len(tasks))) as pool:
        submitted = [
            ((row, writer_key, carry), pool.submit(_draft_one, writer_item_copy, prior_copy))
            for row, writer_item_copy, prior_copy, writer_key, carry in tasks
        ]
        for idx, ((row, writer_key, carry), future) in enumerate(submitted):
            if future.cancelled():
                continue
            draft, calls, clears, exc = future.result()
            prefetched_calls += calls
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
                    handled_ids.add(row["id"])
                continue
            if isinstance(exc, sqlite3.Error):
                raise exc
            if isinstance(exc, CompletionDeferred):
                budget_reached = True
                for _, rem in submitted[idx + 1 :]:
                    rem.cancel()
                continue
            if not isinstance(exc, Exception):
                raise exc
            is_analysis = isinstance(exc, AnalysisError)
            retryable = is_analysis and exc.retryable
            if retryable and endpoint_failures >= 2:
                continue
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
            handled_ids.add(row["id"])
            if endpoint_failures >= 2:
                for _, rem in submitted[idx + 1 :]:
                    rem.cancel()

    return prefetched_calls, endpoint_failures, handled_ids, budget_reached


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
                handled_ids: set[str] = set()
                prefetch_budget_reached = False
                if use_parallel:
                    prefetched_calls, endpoint_failures, handled_ids, prefetch_budget_reached = _prefetch_drafts(
                        run_config,
                        store,
                        pending_rows,
                        report,
                        run_deadline=run_deadline,
                        allow_network=endpoint_failures < 2,
                        endpoint_failures=endpoint_failures,
                    )
                    if prefetch_budget_reached:
                        report["budget_reached"] = True
                process_kwargs = _parallel_verify_kwargs(use_parallel, _reviewer_factory)
                for row in pending_rows:
                    if prefetch_budget_reached:
                        break
                    if row["id"] in handled_ids:
                        continue
                    if time.monotonic() >= run_deadline:
                        report["budget_reached"] = True
                        break
                    if row.get("damaged"):
                        store.reject(row["id"], "Stored source item is damaged", "failed.app.damaged_item", now_iso())
                        report["analysis_failed"] += 1
                        continue
                    try:
                        result = process_item(
                            run_config,
                            store,
                            row,
                            analyzer,
                            reviewer,
                            now_iso(),
                            allow_network=endpoint_failures < 2,
                            **process_kwargs,
                        )
                        if result["status"] not in {"stale", "deferred"}:
                            report["analyzed"] += 1
                        report["review_cache_hits"] += bool(result["cache_hit"])
                        report["review_stale"] += result["status"] == "stale"
                        report["review_routed"] += result["status"] == "routed"
                        if result.get("budget_reached"):
                            report["budget_reached"] = True
                            break
                    except ReviewLimitReached:
                        # The gate already checked the exact source and recorded this
                        # terminal rejection; it must not become a second queue strike.
                        report["analysis_failed"] += 1
                    except CompletionDeferred:
                        report["budget_reached"] = True
                        break
                    except sqlite3.Error:
                        raise
                    except Exception as exc:
                        is_analysis = isinstance(exc, AnalysisError)
                        retryable = is_analysis and exc.retryable
                        deferred = store.defer(
                            row["id"], str(exc) if is_analysis else _unexpected_error(exc), run_config["llm"], now_iso(),
                            terminal=not retryable, code=exc.code if is_analysis else "app.unexpected", expected_row=row,
                        )
                        report["analysis_failed"] += deferred
                        report["review_stale"] += not deferred
                        endpoint_failures += retryable
                report["model_calls"] = (
                    analyzer.calls
                    + prefetched_calls
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
