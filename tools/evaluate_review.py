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
from onionflash.llm import is_quoted_list_post, unquoted_mail_text
from onionflash.render import prepare_story
from onionflash.review import EDITABLE, Reviewer, final_holds, policy_hash
from onionflash.review_gate import OUTCOME_STAGES, ReviewRequests, advance_review, initial_review_state, recovery_status
from onionflash.schema import ITEM_ID_RE
from onionflash.source_packet import LIMITS, OPTIONAL_SOURCE_FIELDS, normalize_labels, number_sources
from onionflash.util import item_cluster, plain_text, safe_canonical_url, story_cluster

CASE_FILES = ("review_cases.json", "review_cases_judged.json", "review_cases_roles.json")
SCOPES = ("story", "latest_update")
# A judged case names the flaw of its labeled wording or labels; one without a flaw is clean.
FLAWS = ("invented_impact", "dropped_hedge", "overclaim", "filler", "badge_misuse", "stale_fact")
CATCH_TARGET, FLAW_FLOOR, FLOOR_CASES, FALSE_ALARM_LIMIT = 0.90, 0.80, 10, 0.10
MAX_CASES, MAX_SECONDS, MAX_FILE_BYTES = 400, 43200, 2097152


class EvaluationReviewer(Reviewer):
    """Keep decoded diagnostic replies only in the explicitly private report."""
    last_decoded = None

    def review(self, *args, **kwargs):
        """Reset diagnostic decode capture before running a review pass."""
        self.last_decoded = None
        return super().review(*args, **kwargs)

    def complete(self, *args, **kwargs):
        """Capture the decoded JSON response for private evaluation diagnostics."""
        result = super().complete(*args, **kwargs)
        self.last_decoded = result
        return result


def _expand_source(src: dict) -> tuple[dict, list]:
    unit = {**src, "labels": normalize_labels(src.get("labels"))}
    if "unquoted_content" not in unit:
        body = "\n\n".join(
            p["text"] if isinstance(p, dict) else p
            for p in src["passages"]
            if not (isinstance(p, dict) and "author" in p)
        )
        if is_quoted_list_post(src.get("url"), body) and (unquoted := unquoted_mail_text(body)):
            unit["unquoted_content"] = plain_text(unquoted, LIMITS["max_source_chars"], html=False)
    return unit, [src["title"], *src["passages"]]


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
        scope = case.get("scope", "story")
        if scope not in SCOPES:
            raise ValueError("Invalid evaluation scope")
        packet = corpus["packets"][case["packet"]]
        sources = number_sources([_expand_source(src) for src in packet["sources"]])
        story = {**corpus["defaults"], "sources": [{"url": s["url"], "title": s["title"]} for s in sources],
                 **case["candidate"]}
        candidate = prepare_story(story, editorial=story.get("editorial"))
        if scope == "latest_update" and (not candidate.get("updates")
                                         or len(candidate["updates"]) != len(story.get("updates") or ())):
            raise ValueError("Update-scope case requires at least one valid update")
        cases.append({**case, "scope": scope, "candidate": candidate,
                      "packet": {"sources": sources, "missing_sources": packet.get("missing_sources", []),
                                 "truncated": packet.get("truncated", False)},
                      "existing_coverage": corpus["coverage_sets"][case["coverage_set"]] if "coverage_set" in case
                                           else {"prior_story": None, "recent": [], "truncated": False}})
    return cases


def draft_cases(corpus: dict) -> list[dict]:
    """One case per packet and coverage set, for reviewing the writer's own draft.

    It merges the labels of the story-scope cases it replaces and expects their
    common label, else approve when any of them approves, else not_approve.
    """
    groups = {}
    for case in corpus["cases"]:
        if case.get("scope", "story") == "story":
            groups.setdefault((case["packet"], case.get("coverage_set")), []).append(case)
    merged = []
    for (packet, coverage_set), group in groups.items():
        expected, forbidden = {case["expected"] for case in group}, {}
        for case in group:
            for field, values in case.get("forbidden_classifications", {}).items():
                forbidden[field] = list(dict.fromkeys([*forbidden.get(field, []), *values]))
        routes = {case["expected_same_story"] for case in group} if all("expected_same_story" in case for case in group) else set()
        merged.append({"id": "draft:" + "/".join(filter(None, (packet, coverage_set))), "packet": packet,
                       "candidate": group[0]["candidate"], "forbidden_classifications": forbidden,
                       "expected": expected.pop() if len(expected) == 1 else "approve" if "approve" in expected else "not_approve",
                       **{key: list(dict.fromkeys(phrase for case in group for phrase in case.get(key, [])))
                          for key in ("unsupported", "required")},
                       **({"expected_same_story": next(iter(routes))} if len(routes) == 1 else {}),
                       **({"coverage_set": coverage_set} if coverage_set else {})})
    return expand({**corpus, "cases": merged})


def writer_item(source: dict) -> dict:
    """The stored item a writer drafts from: authored passages are its notes, the rest its content."""
    passages = source["passages"][1:]
    item = {key: source.get(key) for key in ("url", "title", "kind", "authority", "product", "published_at",
                                             "updated_at", "upstream_state")} | {
        "labels": normalize_labels(source.get("labels")),
        "content": "\n\n".join(passage["text"] for passage in passages if "author" not in passage),
        "public_comments": [{"author": passage["author"], "created_at": passage["created_at"], "url": passage["url"],
                             "body": passage["text"]} for passage in passages if "author" in passage]}
    for opt in OPTIONAL_SOURCE_FIELDS:
        if isinstance(source.get(opt), str) and source[opt]:
            item[opt] = source[opt]
    if "dirauth_notes" in source:
        item["dirauth_notes"] = source["dirauth_notes"]
    return item


def _base_url(raw_url: object) -> str:
    raw = str(raw_url or "").split("#", 1)[0]
    return safe_canonical_url(raw) or raw


def _wording(story: dict, scope: str = "story") -> str:
    if scope == "latest_update":
        updates = story.get("updates") or ()
        return updates[-1]["text"].casefold() if updates else ""
    return "\n".join(story[key] for key in ("title", "summary", "why_it_matters")).casefold()


def kept_unsupported(case: dict, story: dict) -> list[str]:
    """Find flagged wording or classifications still present in a proposed publication."""
    text = _wording(story, case.get("scope", "story"))
    kept = [phrase for phrase in case.get("unsupported", []) if phrase.casefold() in text]
    for field, forbidden in case.get("forbidden_classifications", {}).items():
        values = story.get(field, [])
        values = values if isinstance(values, list) else [values]
        kept.extend(f"{field}:{value}" for value in forbidden if value in values)
    return kept


def omitted(case: dict, story: dict) -> list[str]:
    """Find required wording that a proposed publication leaves out."""
    text = _wording(story, case.get("scope", "story"))
    return [phrase for phrase in case.get("required", []) if phrase.casefold() not in text]


def _rate(part: int, whole: int) -> float | None:
    return round(part / whole, 3) if whole else None


def _judged_metrics(judged: dict) -> dict:
    flagged = {flaw: row for flaw, row in judged.items() if flaw != "clean"}
    caught, paired, total = (sum(r.get(k, 0) for r in flagged.values()) for k in ("ok", "paired", "cases"))
    clean = judged.get("clean") or {"cases": 0, "ok": 0}
    alarms = clean["cases"] - clean["ok"]
    missed = [*((["catch"] if total and paired / total < CATCH_TARGET else ())),
              *(f for f, r in flagged.items() if r["unique"] >= FLOOR_CASES and r["paired"] / r["cases"] < FLAW_FLOOR),
              *((["false_alarms"] if clean["cases"] and alarms / clean["cases"] > FALSE_ALARM_LIMIT else ()))]
    return {"target_missed": missed, "catch_rate": _rate(caught, total),
            "paired_catch_rate": _rate(paired, total), "false_alarm_rate": _rate(alarms, clean["cases"])}


def target_missed(judged: dict) -> list[str]:
    """Name each judged target a run missed; an empty list passes."""
    return _judged_metrics(judged)["target_missed"]


def _validate_cases(cases: list[dict], *, draft: bool = False) -> None:
    identities = set()
    for case in cases:
        # A negative case without the wording or labels its repair must remove would
        # score any verified repair as a correct refusal.
        scope = case.get("scope", "story")
        coverage = case.get("existing_coverage") or {}
        recent_ids = {row["id"] for row in coverage.get("recent") or ()
                      if isinstance(row, dict) and not row.get("retracted")}
        expected_route = case.get("expected_same_story")
        valid_route = ("expected_same_story" not in case or expected_route is None
                       or (scope == "story" and coverage.get("prior_story") is None and case["expected"] == "skip"
                           and isinstance(expected_route, str) and bool(ITEM_ID_RE.fullmatch(expected_route))
                           and expected_route in recent_ids))
        flagged = case.get("unsupported") or case.get("forbidden_classifications") or case.get("required")
        if (case["id"] in identities or scope not in SCOPES or not valid_route
                or (scope == "latest_update" and (draft or not case["candidate"].get("updates")))
                or case["expected"] not in {"approve", "not_approve", "skip", "hold"}
                or (case["expected"] == "not_approve" and not flagged and not (draft and case["id"].startswith("draft:")))
                or ("flaw" in case and (case["flaw"] not in FLAWS or "audit" not in case))):
            raise ValueError("Invalid or duplicate evaluation case")
        identities.add(case["id"])


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
    _validate_cases(cases, draft=draft)
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    totals = {**dict.fromkeys(("cases", "matched", "false_approvals", "positive_rejections", "omissions", "errors",
                               "editorial_misses", "impact_cleared", "draft_unsupported", "repairs_verified",
                               "repairs_held", "repairs_skipped", "verification_repairs", "final_holds",
                               "published_after_checks", "route_cases", "matched_routes", "missed_routes",
                               "false_routes", "wrong_routes", "controlled_mismatches",
                               "raw_inconsistencies", "unresolved_inconsistencies"), 0),
              "holds": {}, "incomplete": False}
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
                scope = case.get("scope", "story")
                record = {"case": case["id"], "round": iteration, "scope": scope, "expected": case["expected"],
                          **({"expected_same_story": case["expected_same_story"]} if "expected_same_story" in case else {}),
                          "policy_hash": identity, "candidate": case["candidate"], "packet": case["packet"],
                          "existing_coverage": case.get("existing_coverage"), "reviews": [], **initial_review_state()}
                requests = ReviewRequests(record)
                totals["cases"] += 1
                reviewer.last_decoded = None
                try:
                    candidate = case["candidate"]
                    # The reviews follow the gate's steps. The first source is the item that wrote the candidate,
                    # as in draft mode.
                    source = case["packet"]["sources"][0]
                    item = writer_item(source)
                    if draft:
                        key = json.dumps(case["packet"], sort_keys=True)
                        if key not in drafts:
                            try:
                                drafts[key] = writer.analyze(item)
                            except AnalysisError as exc:  # one failed draft fails every case on its packet
                                drafts[key] = exc
                        if isinstance(drafts[key], AnalysisError):
                            raise drafts[key]
                        record["draft"] = drafts[key]
                        candidate = record["candidate"] = prepare_story(
                            {**candidate, **{field: drafts[key][field] for field in EDITABLE}}, editorial=candidate.get("editorial"))
                        record["draft_kept_unsupported"] = kept_unsupported(case, candidate)
                        totals["draft_unsupported"] += bool(record["draft_kept_unsupported"])
                    prior = (case.get("existing_coverage") or {}).get("prior_story")
                    prior_id = prior["id"] if prior else None
                    row_source = source
                    if scope == "latest_update":
                        by_base = {_base_url(s.get("url")): s for s in reversed(case["packet"]["sources"])}
                        for cited in candidate["updates"][-1].get("sources") or ():
                            if isinstance(cited, dict) and (matched_src := by_base.get(_base_url(cited.get("url")))) is not None:
                                row_source = matched_src
                                break
                    row_item = item if row_source is source else writer_item(row_source)
                    if row_source.get("closed_at"):
                        row_item = {**row_item, "closed_at": row_source["closed_at"]}
                    identity_item = {**row_item, "url": row_source["url"],
                                     "source_entry_id": row_source.get("source_entry_id", row_source["url"])}
                    prepared = {"packet": case["packet"], "coverage": case.get("existing_coverage"),
                                "review_scope": scope, "mode": "update" if scope == "latest_update" else "story",
                                "story_id": prior_id,
                                "cluster_key": story_cluster(identity_item),
                                "payload": {"editorial_kind": source["kind"]},
                                "dirauth_users": list(config["collection"]["dirauth_gitlab_users"]),
                                "row": {"url": row_source["url"], "story_id": prior_id,
                                        "cluster_key": item_cluster(identity_item),
                                        "payload": json.dumps(row_item)}}
                    stage, text = "review", candidate
                    while (step := advance_review(reviewer, stage, text, prepared, record, requests))[0] in {"verify", "repair"}:
                        stage, text = step
                    action, value = step
                    first = record["reviews"][0]["result"]
                    last = next((entry["result"] for entry in reversed(record["reviews"]) if entry["stage"] == "verification"), None)
                    actual_route = (value if action == "route" and isinstance(value, str) else
                                    next((entry["result"].get("same_story") for entry in record["reviews"]
                                          if entry["result"]["verdict"] in {"approve", "revise", "skip"}
                                          and entry["result"].get("same_story")), None))
                    record.update(result=first, same_story=actual_route, kept_unsupported=kept_unsupported(case, text))
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
                        record["hold_code"] = value[1]
                        totals["holds"][code] = totals["holds"].get(code, 0) + 1
                    record["outcome"] = OUTCOME_STAGES[action]
                    if checked:
                        record["final_holds"] = final_holds(text, prepared)
                    totals["final_holds"] += checked
                    totals["published_after_checks"] += action == "approve"
                    record["verification_repairs"] = sum(entry["stage"] == "verification" and entry["result"]["verdict"] == "revise"
                                                         for entry in record["reviews"][:-1])
                    totals["verification_repairs"] += record["verification_repairs"]
                    if record["result"]["verdict"] == "revise":
                        totals["repairs_verified" if published else "repairs_skipped" if action in {"skip", "route"} else "repairs_held"] += 1
                    final_verdict = "approve" if published else action
                    route_ok = True
                    if "expected_same_story" in case:
                        totals["route_cases"] += 1
                        expected_route = case["expected_same_story"]
                        route_ok = actual_route is None if expected_route is None else action == "route" and value == expected_route
                        if not route_ok:
                            totals["false_routes" if expected_route is None else "missed_routes" if actual_route is None else "wrong_routes"] += 1
                        elif expected_route is not None:
                            totals["matched_routes"] += 1
                    unsafe = published and (case["expected"] in {"skip", "hold"} or bool(record["kept_unsupported"]))
                    published_candidate = text if published else None
                    missing = omitted(case, published_candidate) if published else []
                    # not_approve marks news with a flawed draft: hold or a clean repair, never a skip.
                    missed = (final_verdict in {"skip", "route"}) != (case["expected"] == "skip") and case["expected"] != "approve"
                    matched = (published if case["expected"] == "approve" else not missed) and not unsafe and not missing and route_ok
                    record.update(final_verdict=final_verdict, published_candidate=published_candidate, matched=matched)
                    if missing:
                        record["omitted"] = missing
                    totals["matched"] += matched
                    totals["false_approvals"] += unsafe
                    totals["omissions"] += bool(missing)
                    totals["positive_rejections"] += not published and case["expected"] == "approve"
                    totals["editorial_misses"] += missed
                    totals["impact_cleared"] += bool(scope == "story" and case["expected"] == "approve" and published
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
                record["review_request_count"] = requests.actual
                record.update(recovery_status(record))
                totals["raw_inconsistencies"] += record["raw_inconsistency_count"]
                totals["unresolved_inconsistencies"] += int(record["unresolved_inconsistency"])
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
        totals.update(judged=judged, **_judged_metrics(judged))
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
    try:
        _validate_cases(cases, draft=args.draft)
    except ValueError as exc:
        parser.error(str(exc))
    if args.case_id:
        selected = set(args.case_id)
        if selected - {case["id"] for case in cases}:
            parser.error("Unknown evaluation case")
        cases = [case for case in cases if case["id"] in selected]
    result = evaluate(config, cases, args.output, rounds=args.rounds, deadline=time.monotonic() + args.max_seconds,
                      draft=args.draft)
    return int(bool(result["controlled_mismatches"] or result.get("false_routes") or result["target_missed"]
                    or result["errors"] or result["incomplete"]))


if __name__ == "__main__":
    raise SystemExit(main())
