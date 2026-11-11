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


def expand(corpus: dict) -> list[dict]:
    """Rebuild each compact case as the exact candidate and numbered packet under review.

    Sources and passages are numbered by position, with each source title as its
    first passage, as build_packet emits them. The candidate is the public rendering
    of the corpus defaults, the packet's source links and the case's own fields.
    """
    cases = []
    for case in corpus["cases"]:
        packet, sources = corpus["packets"][case["packet"]], []
        for i, source in enumerate(packet["sources"], 1):
            texts = [source["title"], *source["passages"]]
            sources.append({"id": f"S{i}", **source,
                            "passages": [{"id": f"S{i}:P{j}", "text": text} for j, text in enumerate(texts, 1)]})
        story = {**corpus["defaults"], "sources": [{"url": s["url"], "title": s["title"]} for s in sources],
                 **case["candidate"]}
        cases.append({**case, "candidate": _prepare_story(story, editorial=story.get("editorial")),
                      "packet": {"sources": sources, "missing_sources": packet.get("missing_sources", []),
                                 "truncated": packet.get("truncated", False)},
                      "existing_coverage": corpus.get("coverage_sets", {}).get(case.get("coverage_set"),
                          {"prior_story": None, "recent": [], "truncated": False})})
    return cases


def kept_unsupported(case: dict, story: dict) -> list[str]:
    """Find flagged wording or classifications still present in a proposed publication."""
    text = "\n".join(story[key] for key in ("title", "summary", "why_it_matters")).casefold()
    kept = [phrase for phrase in case.get("unsupported", []) if phrase.casefold() in text]
    for field, forbidden in case.get("forbidden_classifications", {}).items():
        values = story.get(field, [])
        values = values if isinstance(values, list) else [values]
        kept.extend(f"{field}:{value}" for value in forbidden if value in values)
    return kept


def evaluate(config, cases, output, *, rounds=1, verify_repairs=True, deadline=None):
    """Score final reviewed candidates and save bounded evaluation evidence privately."""
    if not verify_repairs:
        raise ValueError("Final verification is mandatory")
    output = Path(output).resolve()
    public = Path(config["storage"]["output_dir"]).resolve()
    if output == public or public in output.parents:
        raise ValueError("Evaluation reports must stay outside public output")
    if not 1 <= rounds <= 3 or not cases or len(cases) > 100:
        raise ValueError("Use 1–3 rounds and 1–100 cases")
    identities = set()
    for case in cases:
        # A negative case without the wording its repair must remove would score any
        # verified repair as a correct refusal.
        if (case["id"] in identities or case["expected"] not in {"approve", "not_approve", "skip"}
                or (verify_repairs and case["expected"] == "not_approve" and not case.get("unsupported"))):
            raise ValueError("Invalid or duplicate evaluation case")
        identities.add(case["id"])
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    totals = {"cases": 0, "matched": 0, "false_approvals": 0, "positive_rejections": 0,
              "errors": 0, "editorial_misses": 0, "repairs_verified": 0, "repairs_held": 0, "repairs_skipped": 0, "incomplete": False}
    identity = policy_hash(config)
    with os.fdopen(descriptor, "w", encoding="utf-8") as report, EvaluationReviewer(config, deadline=deadline) as reviewer:
        for iteration in range(1, rounds + 1):
            for case in cases:
                if deadline is not None and time.monotonic() >= deadline:
                    totals["incomplete"] = True
                    break
                started = time.monotonic()
                record = {"case": case["id"], "round": iteration, "expected": case["expected"],
                          "policy_hash": identity, "candidate": case["candidate"], "packet": case["packet"],
                          "existing_coverage": case.get("existing_coverage")}
                totals["cases"] += 1
                try:
                    result = reviewer.review(case["candidate"], case["packet"], coverage=case.get("existing_coverage"))
                    record["result"] = result
                    final_verdict = result["verdict"]
                    published = final_verdict == "approve"
                    unsafe = published and case["expected"] != "approve"
                    if result["verdict"] in {"approve", "revise"}:
                        final_candidate = (apply_repair(case["candidate"], result["repair"])
                                           if result["verdict"] == "revise" else case["candidate"])
                        verified = reviewer.review(final_candidate, case["packet"],
                                                   coverage=case.get("existing_coverage"), verification=True)
                        record.update(verification=verified, kept_unsupported=kept_unsupported(case, final_candidate))
                        if result["verdict"] == "revise":
                            record["repaired"] = final_candidate
                            totals[{"approve": "repairs_verified", "skip": "repairs_skipped"}.get(verified["verdict"], "repairs_held")] += 1
                        final_verdict = verified["verdict"]
                        published = final_verdict == "approve"
                        unsafe = published and (case["expected"] == "skip" or
                            (case["expected"] == "not_approve" and bool(record["kept_unsupported"])))
                    matched = (published if case["expected"] == "approve" else
                               final_verdict == "skip" if case["expected"] == "skip" else not unsafe)
                    record["final_verdict"] = final_verdict
                    record["published_candidate"] = record.get("repaired", case["candidate"]) if published else None
                    totals["matched"] += matched
                    totals["false_approvals"] += unsafe
                    totals["positive_rejections"] += not published and case["expected"] == "approve"
                    totals["editorial_misses"] += final_verdict != "skip" and case["expected"] == "skip"
                    record["matched"] = matched
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
    """Validate evaluation options and return failure for incomplete or incorrect runs."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--cases", type=Path, default=Path(__file__).resolve().with_name("review_cases.json"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--case-id", action="append", default=[])
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--max-seconds", type=int, default=900)
    parser.add_argument("--verify-repairs", action="store_true", default=True,
                        help="Compatibility option; final verification always runs")
    args = parser.parse_args(argv)
    os.umask(0o077)
    if not 1 <= args.max_seconds <= 7200 or args.cases.stat().st_size > 2097152:
        parser.error("Invalid evaluation time or case-file size")
    config = load_config(args.config)
    cases = expand(json.loads(args.cases.read_text()))
    if args.case_id:
        selected = set(args.case_id)
        if selected - {case["id"] for case in cases}:
            parser.error("Unknown evaluation case")
        cases = [case for case in cases if case["id"] in selected]
    result = evaluate(config, cases, args.output, rounds=args.rounds,
                      verify_repairs=args.verify_repairs, deadline=time.monotonic() + args.max_seconds)
    return int(bool(result["false_approvals"] or result["positive_rejections"] or result["editorial_misses"] or result["errors"] or result["incomplete"]))


if __name__ == "__main__":
    raise SystemExit(main())
