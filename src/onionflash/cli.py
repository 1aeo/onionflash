"""The small explicit collect → analyze → render pipeline."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import sqlite3
import sys
import time
import traceback
from pathlib import Path

from . import __version__, decisions, doctor, editorial, rejection
from .analyze import AnalysisError, Analyzer
from .review import Reviewer
from .review_gate import process_item, status as review_status
from .collect import CollectionError, collect_source
from .comments import RUN_BUDGET_SECONDS as COMMENTS_BUDGET, enrich_comments, merge_cached_comments, status as comments_status
from .config import DEFAULTS, load_config
from .publication import build
from .store import Store, source_due
from .transport import HttpClient
from .util import now_iso


@contextlib.contextmanager
def run_lock(database: str):
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


def _operator_parsers(commands) -> None:
    """Register explicit inspection and guarded editorial or retry commands."""
    story = commands.add_parser("story", help="Inspect, correct, merge, or retract a published story")
    actions = story.add_subparsers(dest="action", required=True)
    for name in ("show", "history", "correct", "retract", "restore", "unlock", "merge"):
        action = actions.add_parser(name)
        action.add_argument("--config", required=True, type=Path)
        action.add_argument("--story", required=True, help="Stable story ID")
        if name == "merge":
            action.add_argument("--into", dest="into_story", required=True, help="Survivor story ID")
            action.add_argument("--expect-hash", required=True, help="Current hash returned by story show")
            action.add_argument("--reason", required=True, help="Private operator reason recorded with the merge")
        elif name not in {"show", "history"}:
            action.add_argument("--expect-hash", required=True, help="Current hash returned by story show")
            action.add_argument("--reason", required=True, help="Public reason for this editorial action")
        if name == "correct":
            action.add_argument("--patch", required=True, type=Path, help="JSON object containing changed public fields")
        if name == "restore":
            action.add_argument("--revision", required=True, type=int, help="Revision to restore and lock")

    rejected = commands.add_parser("rejected", help="Inspect, retry, dismiss or approve held analyses")
    actions = rejected.add_subparsers(dest="action", required=True)
    for name in ("list", "show", "retry", "dismiss", "approve"):
        action = actions.add_parser(name)
        action.add_argument("--config", required=True, type=Path)
        if name == "list":
            action.add_argument("--status", choices=("rejected", "dismissed", "ignored"), default="rejected")
            action.add_argument("--limit", type=int, default=50)
            action.add_argument("--after", help="Continuation cursor returned by the previous list")
        else:
            action.add_argument("--item", required=True, help="Collected item ID")
        if name in {"retry", "dismiss"}:
            action.add_argument("--expect-hash", required=True, help="Current content_hash returned by rejected show")
            action.add_argument("--reason", required=True, help="Private operator reason for this action")
        if name == "approve":
            action.add_argument("--approval-hash", required=True, help="final_review.approval.hash returned by rejected show")
            action.add_argument("--reason", required=True, help="Private operator reason for this action")

    log = commands.add_parser("decisions", help="Summarize or list recent private decisions")
    actions = log.add_subparsers(dest="action", required=True)
    for name in ("summary", "list"):
        action = actions.add_parser(name)
        action.add_argument("--config", required=True, type=Path)
        action.add_argument("--since", default="7d", help="Hours or days before now, such as 7d, or a timestamp")
        if name == "list":
            action.add_argument("--code", help="A decision code or its dotted prefix, such as held.review")
            action.add_argument("--source", help="Source ID")
            action.add_argument("--limit", type=int, default=50)
            action.add_argument("--after", type=int, help="Continuation cursor returned by the previous list")


def _operator_command(args, store: Store, config: dict | None = None) -> dict:
    """Dispatch one inspection, or one operator action with its required hash and reason."""
    if args.command == "story":
        if args.action == "show":
            return editorial.show(store.db, args.story)
        if args.action == "history":
            return editorial.history(store.db, args.story)
        options = {"reason": args.reason, "expect_hash": args.expect_hash}
        if args.action == "merge":
            base_url = (config or {}).get("site", {}).get("base_url", DEFAULTS["site"]["base_url"])
            result = editorial.merge(store.db, args.story, args.into_story, base_url=base_url, **options)
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


def run(config: dict, store: Store) -> dict:
    """Collect and review pending items within one deadline, then build the site."""
    observed = now_iso()
    report = {
        "sources_ok": 0,
        "sources_failed": 0,
        "items_changed": 0,
        "analyzed": 0,
        "analysis_failed": 0,
        "budget_reached": False,
        "entries_skipped": 0,
        "review_cache_hits": 0,
        "review_stale": 0,
        "review_routed": 0,
        "model_calls": 0,
    }
    started = time.monotonic()
    budget = config["collection"]["run_budget_seconds"]
    collection_window = budget * (1 - config["collection"]["analysis_reserve_fraction"])
    comments_enabled = bool(config.get("comments", {}).get("enabled"))
    # Comments share collection time, preserving the existing analysis reserve.
    # Keep at least half the collection window available for primary sources.
    comments_budget = min(COMMENTS_BUDGET, collection_window / 2) if comments_enabled else 0
    collection_deadline = started + collection_window - comments_budget
    network_ingested = {"reports_new": 0, "rejected": 0}

    def record_items(source, items):
        received = now_iso()
        if source.get("alert_format") == "consensus":
            added, rejected = doctor.ingest(
                store.db, source, list(items), received, config["collection"]["content_chars"]
            )
            network_ingested["reports_new"] += added
            network_ingested["rejected"] += rejected
            return received
        if comments_enabled:  # Once they are turned off, stored notes no longer reach new revisions.
            items = (merge_cached_comments(store, item, source, received) for item in items)
        report["items_changed"] += sum(store.ingest(item, received) for item in items)
        return received

    with HttpClient(config["http"]) as client:
        for source in config["sources"]:
            if not source["enabled"]:
                continue
            state = store.source(source)
            if not source_due(state, observed):
                continue
            remaining = collection_deadline - time.monotonic()
            if remaining < 1:
                report["budget_reached"] = True
                break
            # Requests stop at this deadline; a source cut off only by the shared
            # collection deadline is not penalized and resumes next run.
            shared = remaining <= config["collection"]["source_budget_seconds"]
            client.deadline = time.monotonic() + min(remaining, config["collection"]["source_budget_seconds"])
            client.deadline_reached = False
            try:
                try:
                    result = collect_source(client, source, state, config["collection"], observed)
                    received = record_items(source, result["items"])
                    report["entries_skipped"] += result.get("skipped", 0)
                    store.source_success(source, result, received, schedule_from=observed)
                    report["sources_ok"] += 1
                except CollectionError as exc:  # saving its partial items is covered by the handler below too
                    received = record_items(source, exc.items)
                    out_of_time = shared and (client.deadline_reached or time.monotonic() >= collection_deadline)
                    store.source_failure(
                        source,
                        str(exc),
                        config["collection"],
                        received,
                        exc.watermark,
                        exc.catching_up or out_of_time,
                    )
                    report["sources_failed"] += 1
                    if out_of_time:
                        report["budget_reached"] = True
                        break
            except Exception as exc:  # untrusted input must not stop the other sources
                # Record where it failed (file:line), never the exception text.
                frame = traceback.extract_tb(exc.__traceback__)[-1]
                where = f"{Path(frame.filename).name}:{frame.lineno}"
                store.source_failure(source, f"Unexpected {type(exc).__name__} at {where}", config["collection"], now_iso())
                report["sources_failed"] += 1
    try:
        report["comments"] = enrich_comments(config, store, now_iso(), deadline=started + collection_window)
    except Exception as exc:
        # Optional discussion enrichment must not stop primary sources or queued
        # analysis. Keep diagnostics useful without printing source/API contents.
        frame = traceback.extract_tb(exc.__traceback__)[-1]
        report["comments"] = {"enabled": comments_enabled, "checked": 0, "changed": 0,
                              "failed": 1, "skipped": 0, "budget_reached": False,
                              "error": f"Unexpected {type(exc).__name__} at {Path(frame.filename).name}:{frame.lineno}"}
    run_deadline = started + budget
    endpoint_failures = 0
    first = decisions.latest_id(store.db)
    consensus_sources = [s for s in config["sources"] if s.get("alert_format") == "consensus" and s["enabled"]]
    with (
        Analyzer(config, deadline=run_deadline) as analyzer,
        Reviewer(config, deadline=run_deadline) as reviewer,
        doctor.LinkChecker(config, deadline=run_deadline) as linker,
    ):
        for consensus_source in consensus_sources[:1]:
            try:
                evaluated = doctor.evaluate(
                    config,
                    store,
                    consensus_source,
                    linker,
                    now_iso(),
                    allow_network=endpoint_failures < 2,
                )
                endpoint_failures += evaluated.pop("endpoint_failures", 0)
                report["network"] = {**network_ingested, **evaluated}
            except sqlite3.Error:
                raise
            except Exception as exc:
                frame = traceback.extract_tb(exc.__traceback__)[-1]
                report["network"] = {
                    **network_ingested,
                    "incidents_open": 0,
                    "stories_written": 0,
                    "updates_written": 0,
                    "held": 0,
                    "dry_run": not consensus_source.get("publish", False),
                    "error": f"Unexpected {type(exc).__name__} at {Path(frame.filename).name}:{frame.lineno}",
                }
        for row in store.pending(config["llm"]["max_items_per_run"], now_iso()):
            if time.monotonic() >= run_deadline:
                report["budget_reached"] = True
                break
            if row.get("damaged"):  # never sent to a model; collecting the item again restores its copy
                store.reject(row["id"], "Stored source item is damaged", "failed.app.damaged_item", now_iso())
                report["analysis_failed"] += 1
                continue
            try:
                result = process_item(config, store, row, analyzer, reviewer, now_iso(),
                                      allow_network=endpoint_failures < 2)
                if result["status"] not in {"stale", "deferred"}:
                    report["analyzed"] += 1
                report["review_cache_hits"] += bool(result["cache_hit"])
                report["review_stale"] += result["status"] == "stale"
                report["review_routed"] += result["status"] == "routed"
            except AnalysisError as exc:
                # A request cut off by the run deadline is retryable: the item backs off.
                store.defer(row["id"], str(exc), config["llm"], now_iso(), terminal=not exc.retryable, code=exc.code)
                report["analysis_failed"] += 1
                if exc.retryable:
                    # After a second endpoint failure, skip further network
                    # analysis; one failing item alone does not stop the run.
                    # Completed cached decisions can still finish; unfinished
                    # stages, tag reviews included, resume next run.
                    endpoint_failures += 1
            except sqlite3.Error:
                raise  # a database problem is not the item's fault and must not be a strike
            except Exception as exc:  # e.g. a draft that cannot form a public story
                # One item must not stop the run before build: count a strike and
                # record where it failed (file:line), never the exception text.
                frame = traceback.extract_tb(exc.__traceback__)[-1]
                store.defer(row["id"], f"Unexpected {type(exc).__name__} at {Path(frame.filename).name}:{frame.lineno}",
                            config["llm"], now_iso(), terminal=True)
                report["analysis_failed"] += 1
        report["model_calls"] = analyzer.calls + reviewer.calls + linker.calls
    report["decisions"] = decisions.codes_after(store.db, first)
    report["pending_analysis"] = store.pending_count()
    report["rejected_analysis"] = store.rejected_count()
    report["final_review"] = review_status(store)
    report.update(build(config, store))
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Collect, analyze, and build the Onion Flash static news feed."
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in [
        ("run", "Collect, analyze queued items, and build"),
        ("build", "Build from saved stories without network requests"),
        ("check", "Validate configuration without network requests"),
        ("status", "Show source and queue status"),
    ]:
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--config", required=True, type=Path)
        if name == "build":
            command.add_argument("--force", action="store_true", help="Queue a bounded rebuild of all published articles")
    _operator_parsers(commands)
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        if args.command == "check":
            print(
                json.dumps(
                    {
                        "configuration": "valid",
                        "sources": sum(s["enabled"] for s in config["sources"]),
                        "model": config["llm"]["model"],
                        "review_model": config["review"]["model"] or config["llm"]["model"],
                        "comments_enabled": config["comments"]["enabled"],
                        "llm_endpoint_configured": bool(config["llm"]["base_url"]),
                        "llm_credential_present": bool(
                            os.environ.get(config["llm"]["api_key_env"])
                        ),
                    }
                )
            )
            return 0
        if args.command == "status":
            # Read-only, so it needs no lock and works while a run is in progress.
            with Store(config["storage"]["database"]) as store:
                print(json.dumps({
                    "pending_analysis": store.pending_count(),
                    "rejected_analysis": store.rejected_count(),
                    # Recorded by the last successful build; None until one has run.
                    "published_stories": None if store.get_meta("published_stories") is None
                    else int(store.get_meta("published_stories")),
                    "comments": {"enabled": config["comments"]["enabled"], **comments_status(store)},
                    "final_review": review_status(store),
                    "network_health": doctor.status(store.db, config["sources"]),
                    "decisions_24h": decisions.recent(store.db, now_iso()),
                    "sources": store.health(
                        config["sources"], config["collection"]["stale_after_seconds"], now_iso()
                    ),
                }, ensure_ascii=False))
            return 0
        operator = args.command in {"story", "rejected", "decisions"}
        if operator and args.action in {"show", "history", "list", "summary"}:
            with Store(config["storage"]["database"]) as store:
                # Explicit source inspection can contain arbitrary Unicode. JSON
                # escapes keep terminal control/bidi characters visibly inert.
                print(json.dumps(_operator_command(args, store, config), ensure_ascii=True))
            return 0
        with run_lock(config["storage"]["database"]) as acquired:
            if not acquired:
                print(json.dumps({"status": "already-running"}))
                # An overlapping scheduled run is normal; a build that did not happen
                # is reported as a temporary failure (EX_TEMPFAIL).
                return 0 if args.command == "run" else 75
            with Store(config["storage"]["database"]) as store:
                if operator:
                    result = _operator_command(args, store, config)
                elif args.command == "run":
                    result = run(config, store)
                else:
                    result = build(config, store, force=args.force)
                print(json.dumps(result, ensure_ascii=operator))
        return 0
    except (ValueError, OSError) as exc:
        print(f"onionflash: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        # Do not dump source text, credential headers, or provider responses into logs.
        print(f"onionflash: processing failed ({type(exc).__name__})", file=sys.stderr)
        return 1
