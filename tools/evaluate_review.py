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

from onionflash.analyze import AnalysisError, Analyzer
from onionflash.config import load_config
from onionflash.render import _prepare_story
from onionflash.review import EDITABLE, Reviewer, final_holds, policy_hash
from onionflash.review_gate import call_review, next_step

CASE_FILES = ("review_cases.json", "review_cases_judged.json")
# A judged case names the flaw of its labeled wording or labels; one without a flaw is clean.
FLAWS = ("invented_impact", "dropped_hedge", "overclaim", "filler", "badge_misuse", "stale_fact")
CATCH_TARGET, FLAW_FLOOR, FLOOR_CASES, FALSE_ALARM_LIMIT = 0.90, 0.80, 10, 0.10
MAX_CASES, MAX_SECONDS, MAX_FILE_BYTES = 400, 43200, 2097152


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
    first passage, as build_packet emits them. An authored passage is a note: its
    author, date and link precede its text, and notes come before the description.
    The candidate is the public rendering of the corpus defaults, the packet's
    source links and the case's own fields.
    """
    cases = []
    for case in corpus["cases"]:
        packet, sources = corpus["packets"][case["packet"]], []
        for i, source in enumerate(packet["sources"], 1):
            texts = [source["title"], *source["passages"]]
            sources.append({"id": f"S{i}", **source, "passages": [
                {"id": f"S{i}:P{j}", **(text if isinstance(text, dict) else {"text": text})} for j, text in enumerate(texts, 1)]})
        story = {**corpus["defaults"], "sources": [{"url": s["url"], "title": s["title"]} for s in sources],
                 **case["candidate"]}
        cases.append({**case, "candidate": _prepare_story(story, editorial=story.get("editorial")),
                      "packet": {"sources": sources, "missing_sources": packet.get("missing_sources", []),
                                 "truncated": packet.get("truncated", False)},
                      "existing_coverage": corpus["coverage_sets"][case["coverage_set"]] if "coverage_set" in case
                                           else {"prior_story": None, "recent": [], "truncated": False}})
    return cases


def draft_cases(corpus: dict) -> list[dict]:
    """One case per packet and coverage set, for reviewing the writer's own draft.

    It merges the labels of the cases it replaces and expects their common label,
    else approve when any of them approves, else not_approve.
    """
    groups = {}
    for case in corpus["cases"]:
        groups.setdefault((case["packet"], case.get("coverage_set")), []).append(case)
    merged = []
    for (packet, coverage_set), group in groups.items():
        expected, forbidden = {case["expected"] for case in group}, {}
        for case in group:
            for field, values in case.get("forbidden_classifications", {}).items():
                forbidden[field] = list(dict.fromkeys([*forbidden.get(field, []), *values]))
        merged.append({"id": "draft:" + "/".join(filter(None, (packet, coverage_set))), "packet": packet,
                       "candidate": group[0]["candidate"], "forbidden_classifications": forbidden,
                       "expected": expected.pop() if len(expected) == 1 else "approve" if "approve" in expected else "not_approve",
                       **{key: list(dict.fromkeys(phrase for case in group for phrase in case.get(key, [])))
                          for key in ("unsupported", "required")},
                       **({"coverage_set": coverage_set} if coverage_set else {})})
    return expand({**corpus, "cases": merged})


def writer_item(source: dict) -> dict:
    """The stored item a writer drafts from: authored passages are its notes, the rest its content."""
    passages = source["passages"][1:]
    return {key: source.get(key) for key in ("title", "kind", "authority", "product", "published_at", "updated_at",
                                             "upstream_state")} | {
        "labels": [], "content": "\n\n".join(passage["text"] for passage in passages if "author" not in passage),
        "public_comments": [{"author": passage["author"], "created_at": passage["created_at"], "url": passage["url"],
                             "body": passage["text"]} for passage in passages if "author" in passage]}


def _wording(story: dict) -> str:
    return "\n".join(story[key] for key in ("title", "summary", "why_it_matters")).casefold()


def kept_unsupported(case: dict, story: dict) -> list[str]:
    """Find flagged wording or classifications still present in a proposed publication."""
    text = _wording(story)
    kept = [phrase for phrase in case.get("unsupported", []) if phrase.casefold() in text]
    for field, forbidden in case.get("forbidden_classifications", {}).items():
        values = story.get(field, [])
        values = values if isinstance(values, list) else [values]
        kept.extend(f"{field}:{value}" for value in forbidden if value in values)
    return kept


def omitted(case: dict, story: dict) -> list[str]:
    """Find required wording that a proposed publication leaves out."""
    text = _wording(story)
    return [phrase for phrase in case.get("required", []) if phrase.casefold() not in text]


def target_missed(judged: dict) -> list[str]:
    """Name each judged target a run missed: the paired catch rate overall and for every
    flaw with enough distinct cases, and the false-alarm rate. An empty set passes."""
    flagged = {flaw: row for flaw, row in judged.items() if flaw != "clean"}
    caught, total = sum(row["paired"] for row in flagged.values()), sum(row["cases"] for row in flagged.values())
    missed = ["catch"] if total and caught / total < CATCH_TARGET else []
    missed += [flaw for flaw, row in flagged.items()
               if row["unique"] >= FLOOR_CASES and row["paired"] / row["cases"] < FLAW_FLOOR]
    clean = judged.get("clean")
    if clean and (clean["cases"] - clean["ok"]) / clean["cases"] > FALSE_ALARM_LIMIT:
        missed.append("false_alarms")
    return missed


def _rate(part: int, whole: int) -> float | None:
    return round(part / whole, 3) if whole else None


def evaluate(config, cases, output, *, rounds=1, deadline=None, draft=False):
    """Score final reviewed candidates and save bounded evaluation evidence privately.

    In draft mode the writer drafts each packet once per round, and each case on
    that packet reviews the draft in place of its own candidate.
    """
    output = Path(output).resolve()
    public = Path(config["storage"]["output_dir"]).resolve()
    if output == public or public in output.parents:
        raise ValueError("Evaluation reports must stay outside public output")
    if not 1 <= rounds <= 3 or not cases or len(cases) > MAX_CASES:
        raise ValueError(f"Use 1–3 rounds and 1–{MAX_CASES} cases")
    identities = set()
    for case in cases:
        # A negative case without the wording or labels its repair must remove would
        # score any verified repair as a correct refusal.
        flagged = case.get("unsupported") or case.get("forbidden_classifications") or case.get("required")
        if (case["id"] in identities or case["expected"] not in {"approve", "not_approve", "skip", "hold"}
                or (case["expected"] == "not_approve" and not flagged)
                or ("flaw" in case and (case["flaw"] not in FLAWS or "audit" not in case))):
            raise ValueError("Invalid or duplicate evaluation case")
        identities.add(case["id"])
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    totals = {"cases": 0, "matched": 0, "false_approvals": 0, "positive_rejections": 0, "omissions": 0,
              "errors": 0, "editorial_misses": 0, "impact_cleared": 0, "draft_unsupported": 0, "repairs_verified": 0,
              "repairs_held": 0, "repairs_skipped": 0, "verification_repairs": 0, "holds": {}, "final_holds": 0,
              "published_after_checks": 0, "controlled_mismatches": 0, "incomplete": False}
    judged, outcomes, seen = {}, {}, set()
    identity = policy_hash(config)
    with (os.fdopen(descriptor, "w", encoding="utf-8") as report, EvaluationReviewer(config, deadline=deadline) as reviewer,
          Analyzer(config, deadline=deadline) as writer):
        for iteration in range(1, rounds + 1):
            drafts = {}
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
                    candidate = case["candidate"]
                    if draft:
                        key = json.dumps(case["packet"], sort_keys=True)
                        if key not in drafts:
                            try:
                                drafts[key] = writer.analyze(writer_item(case["packet"]["sources"][0]))
                            except AnalysisError as exc:  # one failed draft fails every case on its packet
                                drafts[key] = exc
                        if isinstance(drafts[key], AnalysisError):
                            raise drafts[key]
                        record["draft"] = drafts[key]
                        candidate = record["candidate"] = _prepare_story(
                            {**candidate, **{field: drafts[key][field] for field in EDITABLE}}, editorial=candidate.get("editorial"))
                        record["draft_kept_unsupported"] = kept_unsupported(case, candidate)
                        totals["draft_unsupported"] += bool(record["draft_kept_unsupported"])
                    # The reviews follow the gate's steps. The first source is the item that wrote the candidate,
                    # as in draft mode.
                    source = case["packet"]["sources"][0]
                    prepared = {"packet": case["packet"], "coverage": case.get("existing_coverage"),
                                "payload": {"editorial_kind": source["kind"]}, "row": {"payload": json.dumps(writer_item(source))}}
                    stage, text, record["reviews"] = "review", candidate, []
                    while True:
                        record["reviews"].append(call_review(reviewer, stage, text, prepared))
                        action, value = next_step(record["reviews"], text, prepared)
                        if action not in {"verify", "repair"}:
                            break
                        stage, text = action, value
                    first = record["reviews"][0]["result"]
                    last = next((entry["result"] for entry in reversed(record["reviews"]) if entry["stage"] == "verification"), None)
                    record.update(result=first, kept_unsupported=kept_unsupported(case, text))
                    if last:
                        record["verification"] = last
                    for field, reply in (("model_verdict", first), ("verification_model_verdict", last or {})):
                        if "model_verdict" in reply:  # the model's own verdict, where a fixed rule replaced it
                            record[field] = reply["model_verdict"]
                    # Scores treat a verified approval as published, so they measure the reviewer alone;
                    # the gate's final checks count apart.
                    checked = action == "hold" and value[0] == "final_check"
                    published = action == "approve" or checked
                    if action == "hold":
                        record["hold"] = code = ".".join(("held", *value))
                        totals["holds"][code] = totals["holds"].get(code, 0) + 1
                    if checked:
                        record["final_holds"] = final_holds(text, prepared)
                    totals["final_holds"] += checked
                    totals["published_after_checks"] += action == "approve"
                    record["verification_repairs"] = sum(entry["stage"] == "verification" and entry["result"]["verdict"] == "revise"
                                                         for entry in record["reviews"][:-1])
                    totals["verification_repairs"] += record["verification_repairs"]
                    if record["result"]["verdict"] == "revise":
                        totals["repairs_verified" if published else "repairs_skipped" if action == "skip" else "repairs_held"] += 1
                    final_verdict = "approve" if published else action
                    unsafe = published and (case["expected"] in {"skip", "hold"} or bool(record["kept_unsupported"]))
                    published_candidate = text if published else None
                    missing = omitted(case, published_candidate) if published else []
                    # not_approve marks news with a flawed draft: hold or a clean repair, never a skip.
                    missed = (final_verdict == "skip") != (case["expected"] == "skip") and case["expected"] != "approve"
                    matched = (published if case["expected"] == "approve" else not missed) and not unsafe and not missing
                    record.update(final_verdict=final_verdict, published_candidate=published_candidate, matched=matched)
                    if missing:
                        record["omitted"] = missing
                    totals["matched"] += matched
                    totals["false_approvals"] += unsafe
                    totals["omissions"] += bool(missing)
                    totals["positive_rejections"] += not published and case["expected"] == "approve"
                    totals["editorial_misses"] += missed
                    totals["impact_cleared"] += bool(case["expected"] == "approve" and published
                                                     and candidate["why_it_matters"] and not published_candidate["why_it_matters"])
                    if "audit" in case:
                        # A flagged case is caught when its flaw never publishes and the news is
                        # not skipped; a clean case must publish unchanged.
                        record["ok"] = ok = matched and ("flaw" in case or published_candidate == candidate)
                        row = judged.setdefault(case.get("flaw", "clean"), {"cases": 0, "ok": 0, "unique": 0,
                                                                            **({"paired": 0} if "flaw" in case else {})})
                        row["cases"] += 1
                        row["ok"] += ok
                        row["unique"] += case["id"] not in seen
                        seen.add(case["id"])
                        outcomes[iteration, case["id"]] = ok
                    else:
                        totals["controlled_mismatches"] += not matched
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
                print(json.dumps({key: record.get(key) for key in ("case", "round", "expected", "matched", "ok", "error", "seconds")}
                                 | {"verdict": record.get("result", {}).get("verdict"),
                                    "verification": record.get("verification", {}).get("verdict")}), flush=True)
            if totals["incomplete"]:
                break
        # A flagged case counts as a paired catch only when every clean case on its
        # packet was right in the same round, so refusing the item is no catch. A
        # refusal also needs one such case in the run; a flaw that must publish does not.
        flagged = {case["id"]: (case["flaw"], case["expected"] == "approve",
                                [twin["id"] for twin in cases if "audit" in twin and "flaw" not in twin
                                 and twin["packet"] == case["packet"]]) for case in cases if "flaw" in case}
        for (iteration, case_id), ok in outcomes.items():
            if case_id in flagged:
                flaw, publishes, twins = flagged[case_id]
                judged[flaw]["paired"] += ok and (publishes or bool(twins)) and all(
                    outcomes.get((iteration, twin), False) for twin in twins)
        rows = [row for flaw, row in judged.items() if flaw != "clean"]
        clean = judged.get("clean", {"cases": 0, "ok": 0})
        totals.update(judged=judged, target_missed=target_missed(judged),
                      catch_rate=_rate(sum(row["ok"] for row in rows), sum(row["cases"] for row in rows)),
                      paired_catch_rate=_rate(sum(row["paired"] for row in rows), sum(row["cases"] for row in rows)),
                      false_alarm_rate=_rate(clean["cases"] - clean["ok"], clean["cases"]))
        report.write(json.dumps({"summary": totals, "policy_hash": identity}) + "\n")
    print(json.dumps({"summary": totals}), flush=True)
    return totals


def main(argv=None):
    """Validate evaluation options and return failure for incomplete or incorrect runs."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--cases", type=Path, action="append", default=None,
                        help="a case file; repeat to combine files (default: the public case files)")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--case-id", action="append", default=[])
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--max-seconds", type=int, default=900)
    parser.add_argument("--draft", action="store_true", help="review the writer's own draft of each packet")
    args = parser.parse_args(argv)
    os.umask(0o077)
    files = args.cases or [Path(__file__).resolve().with_name(name) for name in CASE_FILES]
    if not 1 <= args.max_seconds <= MAX_SECONDS or any(path.stat().st_size > MAX_FILE_BYTES for path in files):
        parser.error("Invalid evaluation time or case-file size")
    config = load_config(args.config)
    cases = [case for path in files for case in (draft_cases if args.draft else expand)(json.loads(path.read_text()))]
    if len({case["id"] for case in cases}) != len(cases):
        parser.error("Duplicate evaluation case")
    if args.case_id:
        selected = set(args.case_id)
        if selected - {case["id"] for case in cases}:
            parser.error("Unknown evaluation case")
        cases = [case for case in cases if case["id"] in selected]
    result = evaluate(config, cases, args.output, rounds=args.rounds, deadline=time.monotonic() + args.max_seconds,
                      draft=args.draft)
    return int(bool(result["controlled_mismatches"] or result["target_missed"] or result["errors"] or result["incomplete"]))


if __name__ == "__main__":
    raise SystemExit(main())
