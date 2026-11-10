"""The small explicit collect → analyze → render pipeline."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import signal
import sys
import time
from pathlib import Path

from . import __version__
from .analyze import AnalysisError, Analyzer, cache_key
from .collect import CollectionError, collect_source
from .config import load_config
from .store import Store, source_due
from .transport import HttpClient
from .util import BudgetExceeded, now_iso


RunBudgetReached = BudgetExceeded


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


@contextlib.contextmanager
def time_budget(seconds: int):
    def expired(signum, frame):
        raise RunBudgetReached()

    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def build(config: dict, store: Store, *, force: bool = False) -> dict:
    from .publication import build as publish_build

    return publish_build(config, store, force=force)


def run(config: dict, store: Store) -> dict:
    observed = now_iso()
    if not store.get_meta("fetch_completion_clock_since"):
        store.set_meta(fetch_completion_clock_since=observed)
    report = {
        "sources_ok": 0,
        "sources_failed": 0,
        "items_changed": 0,
        "analyzed": 0,
        "analysis_failed": 0,
        "budget_reached": False,
    }
    started = time.monotonic()
    budget = config["collection"]["run_budget_seconds"]
    collection_deadline = started + budget * (
        1 - config["collection"]["analysis_reserve_fraction"]
    )

    def record_items(source, items):
        received = now_iso()
        if source.get("alert_format"):
            store.ingest_alerts(source, items, config["monitoring"], received)
            return received
        priority = config["collection"]["tag_priority_score"]
        report["items_changed"] += sum(
            store.ingest(item, received, tag_priority_score=priority) for item in items
        )
        return received

    with HttpClient(config["http"]) as client:
        for source in config["sources"]:
            if not source["enabled"]:
                continue
            state = store.source(source)
            if not source_due(source, state, config["collection"], observed):
                continue
            remaining = collection_deadline - time.monotonic()
            if remaining < 1:
                report["budget_reached"] = True
                break
            try:
                with time_budget(
                    min(remaining, config["collection"]["source_budget_seconds"])
                ):
                    result = collect_source(
                        client, source, state, config["collection"], observed
                    )
                received = record_items(source, result["items"])
                store.source_success(source, result, received, schedule_from=observed)
                report["sources_ok"] += 1
            except CollectionError as exc:
                received = record_items(source, exc.items)
                store.source_failure(
                    source,
                    str(exc),
                    config["collection"],
                    received,
                    exc.checkpoint,
                    exc.catching_up,
                )
                report["sources_failed"] += 1
            except RunBudgetReached:
                store.source_failure(
                    source,
                    "Source time budget exceeded",
                    config["collection"],
                    now_iso(),
                )
                report["sources_failed"] += 1
    remaining = budget - (time.monotonic() - started)
    active_row = None
    endpoint_failures = 0
    try:
        with time_budget(max(1, remaining)):
            with Analyzer(config) as analyzer:
                for row in store.pending(config["llm"]["max_items_per_run"], now_iso()):
                    key = cache_key(row, config["llm"])
                    try:
                        result = store.cached(key)
                        if result is None:
                            item = json.loads(row["payload"])
                            if endpoint_failures >= 2 and item["kind"] != "tag":
                                continue
                            active_row = row
                            result = analyzer.analyze(item)
                            active_row = None
                        store.finish(row, result, key, now_iso())
                        report["analyzed"] += 1
                    except AnalysisError as exc:
                        active_row = None
                        store.defer(row["id"], str(exc), config["llm"], now_iso(), terminal=not exc.retryable)
                        report["analysis_failed"] += 1
                        if exc.retryable:
                            # After a second endpoint failure, skip further network
                            # analysis; one failing item alone does not stop the run.
                            # Deterministic tags and cached results still publish.
                            endpoint_failures += 1
    except RunBudgetReached:
        report["budget_reached"] = True
        if active_row is not None:
            store.defer(
                active_row["id"],
                "Analysis run budget reached",
                config["llm"],
                now_iso(),
            )
    report["pending_analysis"] = store.pending_count()
    report["rejected_analysis"] = store.rejected_count()
    report["monitoring"] = store.monitoring_status(config["monitoring"], now_iso())
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
        ("backup", "Create a consistent private SQLite backup"),
    ]:
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--config", required=True, type=Path)
        if name == "build":
            command.add_argument("--force", action="store_true", help="Queue a bounded rebuild of all published articles")
        if name == "backup":
            command.add_argument("--output", required=True, type=Path)
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
                        "llm_endpoint_configured": bool(config["llm"]["base_url"]),
                        "llm_credential_present": bool(
                            os.environ.get(config["llm"]["api_key_env"])
                        ),
                    }
                )
            )
            return 0
        with run_lock(config["storage"]["database"]) as acquired:
            if not acquired:
                print(json.dumps({"status": "already-running"}))
                return 0
            with Store(config["storage"]["database"]) as store:
                if args.command == "run":
                    result = run(config, store)
                elif args.command == "build":
                    result = build(config, store, force=args.force)
                elif args.command == "status":
                    result = {
                        "pending_analysis": store.pending_count(),
                        "rejected_analysis": store.rejected_count(),
                        # Accepted catalog count from the last successful build; None until one has run.
                        "published_stories": None if store.get_meta("published_stories") is None
                        else int(store.get_meta("published_stories")),
                        "monitoring": store.monitoring_status(config["monitoring"], now_iso()),
                        "sources": store.health(
                            config["sources"],
                            config["collection"]["stale_after_seconds"],
                            now_iso(),
                        ),
                    }
                else:
                    store.backup(args.output)
                    result = {"backup": "created"}
                print(json.dumps(result, ensure_ascii=False))
        return 0
    except (ValueError, OSError) as exc:
        print(f"onionflash: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        # Do not dump source text, credential headers, or provider responses into logs.
        print(f"onionflash: processing failed ({type(exc).__name__})", file=sys.stderr)
        return 1
