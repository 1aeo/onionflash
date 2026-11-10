"""The small explicit collect → analyze → render pipeline."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import shutil
import sys
import tempfile
import time
import traceback
from pathlib import Path

from . import __version__
from .analyze import AnalysisError, Analyzer, cache_key
from .collect import CollectionError, collect_source
from .config import load_config
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


def build(config: dict, store: Store) -> dict:
    """Render every stored story into a fresh directory and swap it in atomically.

    Rendering is deterministic and cheap, so it runs every time; the deployment
    uploads only output whose hashes changed.
    """
    from .render import render_site

    stories = store.stories()
    health = store.health(
        config["sources"], config["collection"]["stale_after_seconds"], now_iso()
    )
    public_health = [
        {
            "id": s["id"],
            "name": s["name"],
            "website_url": s["website_url"],
            "stale": s["stale"],
        }
        for s in health
    ]
    output = Path(config["storage"]["output_dir"])
    # The marker's presence alone shows Onion Flash created the output, so moving
    # or restoring an installation keeps working.
    owner = output.parent / ("." + output.name + ".onionflash-owner")
    if output.is_symlink() or owner.is_symlink():
        raise ValueError("Public output and ownership marker must not be symlinks")
    if owner.exists() and not owner.is_file():
        raise ValueError("Output ownership marker must be a regular file")
    if output.exists() and not output.is_dir():
        raise ValueError("Public output must be a directory")
    if output.exists() and any(output.iterdir()) and not owner.exists():
        raise ValueError(
            "Refusing to replace a nonempty directory not owned by Onion Flash"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = Path(
        tempfile.mkdtemp(prefix="." + output.name + ".build-", dir=output.parent)
    )
    previous = output.parent / (temp.name + ".previous")
    replaced = False
    try:
        skipped = render_site(config, stories, public_health, temp)
        if not owner.exists():
            fd = os.open(
                owner,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            with os.fdopen(fd, "w") as stream:
                stream.write("Onion Flash generated output\n")
        if output.exists():
            os.replace(output, previous)
            replaced = True
        try:
            os.replace(temp, output)
        except BaseException:
            if replaced:
                os.replace(previous, output)
            raise
        store.set_meta(published_stories=str(len(stories) - skipped))
    finally:
        if temp.exists():
            shutil.rmtree(temp)
        if previous.exists() and output.exists():
            shutil.rmtree(previous)
    return {"published_stories": len(stories) - skipped, "stories_skipped": skipped}


def run(config: dict, store: Store) -> dict:
    observed = now_iso()
    report = {
        "sources_ok": 0,
        "sources_failed": 0,
        "items_changed": 0,
        "analyzed": 0,
        "analysis_failed": 0,
        "budget_reached": False,
        "entries_skipped": 0,
    }
    started = time.monotonic()
    budget = config["collection"]["run_budget_seconds"]
    collection_deadline = started + budget * (
        1 - config["collection"]["analysis_reserve_fraction"]
    )

    def record_items(source, items):
        received = now_iso()
        if source.get("alert_format"):
            report.setdefault("alerts", {})[source["id"]] = store.ingest_alerts(source, items, received)
            return received
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
                result = collect_source(client, source, state, config["collection"], observed)
                received = record_items(source, result["items"])
                report["entries_skipped"] += result.get("skipped", 0)
                store.source_success(source, result, received, schedule_from=observed)
                report["sources_ok"] += 1
            except CollectionError as exc:
                received = record_items(source, exc.items)
                out_of_time = shared and (client.deadline_reached or time.monotonic() >= collection_deadline)
                store.source_failure(
                    source,
                    str(exc),
                    config["collection"],
                    received,
                    exc.checkpoint,
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
    run_deadline = started + budget
    endpoint_failures = 0
    with Analyzer(config, deadline=run_deadline) as analyzer:
        for row in store.pending(config["llm"]["max_items_per_run"], now_iso()):
            if time.monotonic() >= run_deadline:
                report["budget_reached"] = True
                break
            key = cache_key(row, config["llm"])
            try:
                result = store.cached(key)
                if result is None:
                    item = json.loads(row["payload"])
                    if endpoint_failures >= 2 and item["kind"] != "tag":
                        continue
                    result = analyzer.analyze(item)
                store.finish(row, result, key, now_iso())
                report["analyzed"] += 1
            except AnalysisError as exc:
                # A request cut off by the run deadline is retryable: the item backs off.
                store.defer(row["id"], str(exc), config["llm"], now_iso(), terminal=not exc.retryable)
                report["analysis_failed"] += 1
                if exc.retryable:
                    # After a second endpoint failure, skip further network
                    # analysis; one failing item alone does not stop the run.
                    # Deterministic tags and cached results still publish.
                    endpoint_failures += 1
    report["pending_analysis"] = store.pending_count()
    report["rejected_analysis"] = store.rejected_count()
    report["monitoring"] = store.monitoring_status(now_iso())
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
        if args.command == "status":
            # Read-only, so it needs no lock and works while a run is in progress.
            with Store(config["storage"]["database"]) as store:
                print(json.dumps({
                    "pending_analysis": store.pending_count(),
                    "rejected_analysis": store.rejected_count(),
                    # Recorded by the last successful build; None until one has run.
                    "published_stories": None if store.get_meta("published_stories") is None
                    else int(store.get_meta("published_stories")),
                    "monitoring": store.monitoring_status(now_iso()),
                    "sources": store.health(
                        config["sources"], config["collection"]["stale_after_seconds"], now_iso()
                    ),
                }, ensure_ascii=False))
            return 0
        with run_lock(config["storage"]["database"]) as acquired:
            if not acquired:
                print(json.dumps({"status": "already-running"}))
                # An overlapping scheduled run is normal; a build that did not happen
                # is reported as a temporary failure (EX_TEMPFAIL).
                return 0 if args.command == "run" else 75
            with Store(config["storage"]["database"]) as store:
                result = run(config, store) if args.command == "run" else build(config, store)
                print(json.dumps(result, ensure_ascii=False))
        return 0
    except (ValueError, OSError) as exc:
        print(f"onionflash: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        # Do not dump source text, credential headers, or provider responses into logs.
        print(f"onionflash: processing failed ({type(exc).__name__})", file=sys.stderr)
        return 1
