#!/usr/bin/env python3
"""Evaluate the configured reviewer without collecting or publishing any news.

Load the same LLM environment as the application first. Reports are private,
new JSONL files outside the configured public output directory.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import time

from onionflash.analyze import AnalysisError
from onionflash.config import load_config
from onionflash.render import _prepare_story
from onionflash.review import Reviewer, apply_repair, policy_hash


class EvaluationReviewer(Reviewer):
    """Keep decoded diagnostic replies only in the explicitly private report."""
    def review(self, *args, **kwargs):
        self.last_decoded = None
        return super().review(*args, **kwargs)

    def complete(self, *args, **kwargs):
        result = super().complete(*args, **kwargs)
        self.last_decoded = result
        return result


def evaluate(config, cases, output, *, rounds=1, verify_repairs=False, deadline=None):
    output = Path(output).resolve()
    public = Path(config["storage"]["output_dir"]).resolve()
    if output == public or public in output.parents:
        raise ValueError("Evaluation reports must stay outside public output")
    if not 1 <= rounds <= 3 or not cases or len(cases) > 100:
        raise ValueError("Use 1–3 rounds and 1–100 cases")
    identities = set()
    for case in cases:
        if case["id"] in identities or case["expected"] not in {"approve", "not_approve"}:
            raise ValueError("Invalid or duplicate evaluation case")
        identities.add(case["id"])
        canonical = _prepare_story(case["candidate"], editorial=case["candidate"].get("editorial"))
        if canonical != case["candidate"]:
            raise ValueError("Evaluation candidate must match exact public rendering")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    totals = {"cases": 0, "matched": 0, "false_approvals": 0, "positive_rejections": 0,
              "errors": 0, "repairs_verified": 0, "repairs_held": 0, "incomplete": False}
    identity = policy_hash(config)
    with os.fdopen(descriptor, "w", encoding="utf-8") as report, EvaluationReviewer(config, deadline=deadline) as reviewer:
        for iteration in range(1, rounds + 1):
            for case in cases:
                if deadline is not None and time.monotonic() >= deadline:
                    totals["incomplete"] = True
                    break
                started = time.monotonic()
                record = {"case": case["id"], "round": iteration, "expected": case["expected"],
                          "policy_hash": identity, "candidate": case["candidate"], "packet": case["packet"]}
                totals["cases"] += 1
                try:
                    result = reviewer.review(case["candidate"], case["packet"])
                    approved = result["verdict"] == "approve"
                    matched = approved == (case["expected"] == "approve")
                    totals["matched"] += matched
                    totals["false_approvals"] += approved and case["expected"] == "not_approve"
                    totals["positive_rejections"] += not approved and case["expected"] == "approve"
                    record.update(result=result, matched=matched)
                    if verify_repairs and result["verdict"] == "revise":
                        repaired = apply_repair(case["candidate"], result["repair"])
                        verified = reviewer.review(repaired, case["packet"], verification=True)
                        record.update(repaired=repaired, verification=verified)
                        totals["repairs_verified" if verified["verdict"] == "approve" else "repairs_held"] += 1
                except (AnalysisError, ValueError, TypeError, KeyError) as exc:
                    totals["errors"] += 1
                    record["error"] = type(exc).__name__
                    if isinstance(exc, AnalysisError):
                        record["error_reason"] = str(exc)
                    if reviewer.last_decoded is not None:
                        record["decoded_diagnostic"] = reviewer.last_decoded
                    record.setdefault("matched", False)
                record["seconds"] = round(time.monotonic() - started, 2)
                encoded = json.dumps(record, ensure_ascii=False, allow_nan=False)
                credential = os.environ.get(config["llm"]["api_key_env"], "")
                if len(credential) >= 8:
                    encoded = encoded.replace(credential, "[redacted]")
                report.write(encoded + "\n")
                report.flush()
                print(json.dumps({key: record.get(key) for key in ("case", "round", "expected", "matched", "error", "seconds")}
                                 | {"verdict": record.get("result", {}).get("verdict"),
                                    "verification": record.get("verification", {}).get("verdict")}), flush=True)
            if totals["incomplete"]:
                break
        report.write(json.dumps({"summary": totals, "policy_hash": identity}) + "\n")
    print(json.dumps({"summary": totals}), flush=True)
    return totals


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--cases", type=Path, default=Path(__file__).resolve().parents[1] / "tests/fixtures/review_cases.json")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--case-id", action="append", default=[])
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--max-seconds", type=int, default=900)
    parser.add_argument("--verify-repairs", action="store_true")
    args = parser.parse_args(argv)
    os.umask(0o077)
    if not 1 <= args.max_seconds <= 7200 or args.cases.stat().st_size > 2097152:
        parser.error("Invalid evaluation time or case-file size")
    config = load_config(args.config)
    cases = json.loads(args.cases.read_text())["cases"]
    if args.case_id:
        selected = set(args.case_id)
        if selected - {case["id"] for case in cases}:
            parser.error("Unknown evaluation case")
        cases = [case for case in cases if case["id"] in selected]
    result = evaluate(config, cases, args.output, rounds=args.rounds,
                      verify_repairs=args.verify_repairs, deadline=time.monotonic() + args.max_seconds)
    return int(bool(result["false_approvals"] or result["positive_rejections"] or result["errors"] or result["incomplete"]))


if __name__ == "__main__":
    raise SystemExit(main())
