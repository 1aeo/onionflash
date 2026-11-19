"""Public-safety and labeling lint for the judged reviewer corpus.

It reads tools/review_cases_judged.json and the evaluator beside it. REVIEW_EVAL_TOOLS (a
tools directory) and REVIEW_CASES_JUDGED (a case file) point it at another tree for a local
run. REVIEW_PRIVATE_DENYLIST may name a JSON file, kept outside the repository, of words that
must not appear ("anywhere") or must not appear outside quoted upstream text ("own_text");
without it, only the generic public-text rules run.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import unicodedata
from urllib.parse import urlsplit

from helpers import ROOT, ApprovingReviewer, load_evaluator
from onionflash.config import DEFAULTS
from onionflash.review import CRITERIA, _packet_refs, release_labels_match_state

TOOLS = Path(os.environ.get("REVIEW_EVAL_TOOLS") or ROOT / "tools")
JUDGED = Path(os.environ.get("REVIEW_CASES_JUDGED") or TOOLS / "review_cases_judged.json")

AUDITS = {"why-it-matters-1", "live-1"}
DENYLIST = json.loads(Path(os.environ["REVIEW_PRIVATE_DENYLIST"]).read_text()) if os.environ.get("REVIEW_PRIVATE_DENYLIST") else {}
DENIED_ANYWHERE = frozenset(word.casefold() for word in DENYLIST.get("anywhere", []))
DENIED_IN_OWN_TEXT = frozenset(word.casefold() for word in DENYLIST.get("own_text", []))
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
URL = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)
ABSOLUTE_PATH = re.compile(r"(?:^|[\s(\"'`=])(?:~/|/(?:Users|home|private|tmp|var|etc|opt|srv|root)/|[A-Za-z]:\\)")
NUMBER = re.compile(r"\d+(?:\.\d+)*")
HEX_ID = re.compile(r"(?<![0-9a-f])[0-9a-f]{24}(?![0-9a-f])")
DATE_KEYS = ("published_at", "updated_at", "added_at")
RUN_STATE = {"snapshot", "captured_at", "editorial"}


def strings(value, *, skip_ids=False):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            if not (skip_ids and key == "id"):
                yield from strings(item, skip_ids=skip_ids)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item, skip_ids=skip_ids)
    elif isinstance(value, str):
        yield value


def denied(texts, words):
    found = set()
    for text in texts:
        folded = unicodedata.normalize("NFKC", text).casefold()
        found |= {*re.findall(r"[a-z0-9]+", folded), *re.findall(r"[a-z]+", folded)} & words
    return found


def torproject_https(url):
    try:
        parts = urlsplit(url)
    except (TypeError, ValueError):
        return False
    host = (parts.hostname or "").lower()
    return parts.scheme == "https" and (host == "torproject.org" or host.endswith(".torproject.org"))


def numbers(text):
    return {".".join(str(int(part)) for part in match.split("."))
            for match in NUMBER.findall(unicodedata.normalize("NFKC", text))}


def upstream_numbers(packet):
    found = set()
    for number in numbers(json.dumps(packet, ensure_ascii=False)):
        parts = number.split(".")
        found.update(".".join(parts[:end]) for end in range(1, len(parts) + 1))
        found.update(parts)
    return found


def unexplained_numbers(text, known):
    return sorted(n for n in numbers(text)
                  if n not in known and f"0.{n}" not in known and not (n.startswith("0.") and n[2:] in known))


def test_judged_corpus_is_public_and_labeled(tmp_path, monkeypatch, capsys):
    module = load_evaluator(TOOLS, "review_eval_judged")
    kept, omitted = module.kept_unsupported, module.omitted
    assert JUDGED.stat().st_size <= module.MAX_FILE_BYTES
    raw = json.loads(JUDGED.read_text(encoding="utf-8"))
    controlled = json.loads((TOOLS / "review_cases.json").read_text(encoding="utf-8"))
    problems = []

    assert set(raw) == {"description", "defaults", "packets", "cases", "coverage_sets"}
    assert raw["defaults"] == controlled["defaults"]
    cases = module.expand(raw)
    assert module.draft_cases(raw) and 0 < len(cases) <= module.MAX_CASES
    ids = [case["id"] for case in cases]
    assert len(set(ids)) == len(ids) and not (set(ids) & {case["id"] for case in controlled["cases"]})

    everything = list(strings(raw))
    if found := denied(everything, DENIED_ANYWHERE):
        problems.append(f"deployment, owner or private names present: {sorted(found)}")
    for text in everything:
        for match in EMAIL.finditer(unicodedata.normalize("NFKC", text)):
            if match.group(1).lower() != "lists.torproject.org":
                problems.append(f"e-mail address outside the Tor lists: {match.group(0)!r}")
    for name, packet in raw["packets"].items():
        for source in packet["sources"]:
            if not torproject_https(source["url"]):
                problems.append(f"packet {name}: source is not https torproject.org: {source['url']}")
            notes = [p for p in source["passages"] if isinstance(p, dict)]
            problems.extend(f"packet {name}: note is not https torproject.org: {n['url']}"
                            for n in notes if not torproject_https(n["url"]))
            if RUN_STATE & set(source):
                problems.append(f"packet {name}: run-state field kept")

    own = [*raw["packets"], *strings({k: v for k, v in raw.items() if k != "packets"}, skip_ids=True)]
    if found := denied(own, DENIED_IN_OWN_TEXT | DENIED_ANYWHERE):
        problems.append(f"tool, model or labeling words in the corpus's own text: {sorted(found)}")
    for text in own:
        problems.extend(f"link outside torproject.org in own text: {u}" for u in URL.findall(text) if not torproject_https(u))
        if ABSOLUTE_PATH.search(text):
            problems.append(f"filesystem path in own text: {text[:80]!r}")
        if HEX_ID.search(text):
            problems.append(f"id-like hex string in own text: {text[:80]!r}")
    if re.search(r"\d", raw["description"]):
        problems.append("the description carries a count or date")

    audits = {}
    for raw_case, case in zip(raw["cases"], cases):
        cid, flaw, expected = case["id"], case.get("flaw"), case["expected"]
        candidate, coverage = case["candidate"], case["existing_coverage"]
        unsupported, forbidden, required = (case.get(k) for k in ("unsupported", "forbidden_classifications", "required"))
        if case.get("audit") not in AUDITS:
            problems.append(f"{cid}: audit {case.get('audit')!r} is not a known set")
        if flaw is not None and flaw not in module.FLAWS:
            problems.append(f"{cid}: unknown flaw {flaw!r}")
        audits.setdefault(case.get("audit"), set()).add("flagged" if flaw else "clean")
        if not case.get("coverage") or not set(case["coverage"]) <= set(CRITERIA):
            problems.append(f"{cid}: coverage must name rubric criteria")
        if raw_case["candidate"].get("id") != hashlib.sha256(cid.encode()).hexdigest()[:24]:
            problems.append(f"{cid}: candidate id is not sha256(case id)[:24]")
        if RUN_STATE & set(raw_case["candidate"]):
            problems.append(f"{cid}: candidate carries run state")
        if flaw == "stale_fact":
            if expected != "approve" or not coverage["prior_story"] or unsupported or forbidden or required:
                problems.append(f"{cid}: a stale fact is an unflagged approve update over a prior story")
        elif flaw:
            if expected != "not_approve" or not (unsupported or forbidden):
                problems.append(f"{cid}: a flagged case is not_approve with the wording or labels it flags")
            if not release_labels_match_state(candidate):
                problems.append(f"{cid}: release labels already hold it, so the reviewer is not measured")
            if not candidate["why_it_matters"]:
                problems.append(f"{cid}: an empty why_it_matters lets a no-op clear count as a catch")
        elif expected != "approve" or unsupported or forbidden or required:
            problems.append(f"{cid}: a clean case is approve with no flags")
        if expected == "approve" and not release_labels_match_state(candidate):
            problems.append(f"{cid}: release labels hold it, so it can never publish")
        flagged = kept(case, candidate)
        if not set(unsupported or []) <= set(flagged) or bool(flagged) != bool(unsupported or forbidden):
            problems.append(f"{cid}: its flagged wording or labels are not in its own candidate")
        if omitted(case, candidate) != (required or []):
            problems.append(f"{cid}: its required wording is not in its own candidate")
        payload = json.dumps({"candidate": candidate, "packet": case["packet"], "existing_coverage": coverage})
        problems.extend(f"{cid}: label {lbl!r} reaches the model payload"
                        for lbl in (cid, case.get("audit"), flaw) if lbl and lbl in payload)
        if not _packet_refs(case["packet"]):
            problems.append(f"{cid}: the packet has no references")
        for src in case["packet"]["sources"]:
            authored = ["author" in p for p in src["passages"][1:]]
            if authored != sorted(authored, reverse=True):
                problems.append(f"{cid}: notes do not precede the description")
        if any(set(r) != {"id", "title", "summary", "category", "state", "updated_at", "summary_truncated"}
               for r in coverage["recent"]):
            problems.append(f"{cid}: coverage rows lack the compact background keys")
        known = {v for src in case["packet"]["sources"] for v in
                 [src.get("published_at"), src.get("updated_at"), *(p.get("created_at") for p in src["passages"])] if v}
        known |= {raw["defaults"][k] for k in DATE_KEYS}
        stories = [candidate, *([coverage["prior_story"]] if coverage["prior_story"] else [])]
        problems.extend(f"{cid}: {k} {st[k]} is neither a default nor an upstream date"
                        for st in stories for k in DATE_KEYS if st.get(k) not in known)
        own_text = "\n".join(st[k] for st in stories for k in ("title", "summary", "why_it_matters"))
        for phrase in unsupported or []:
            own_text = re.sub(re.escape(phrase), " ", own_text, flags=re.I)
        if extra := unexplained_numbers(own_text, upstream_numbers(case["packet"])):
            problems.append(f"{cid}: numbers that the packet does not hold: {extra}")
        if coverage["prior_story"] and coverage["prior_story"]["id"] != candidate["id"]:
            problems.append(f"{cid}: the prior story is not the same article as the update")
        clean_twins = [t for t in cases if t["packet"] == case["packet"] and "flaw" not in t]
        if flaw and not clean_twins:
            problems.append(f"{cid}: no clean twin on its packet, so it can never be a paired catch")
        problems.extend(f"{cid}: its flagged wording or labels also occur in clean twin {t['id']}"
                        for t in clean_twins if t["id"] != cid and kept(case, t["candidate"]))
        problems.extend(f"{cid}: approve twin {t['id']} lacks its required wording"
                        for t in clean_twins if t["expected"] == "approve" and omitted(case, t["candidate"]))
        negated, confirms = re.subn(r"\bconfirms?\b", "does not confirm", candidate["summary"])
        if confirms and kept(case, {"title": "", "summary": negated, "why_it_matters": ""}):
            problems.append(f"{cid}: the smallest negating repair still keeps its flagged wording")
    problems.extend(f"audit set {a} lacks flagged or clean cases" for a, kinds in audits.items() if kinds != {"flagged", "clean"})
    assert not problems, "\n".join(problems)

    config = copy.deepcopy(DEFAULTS)
    config["storage"]["output_dir"] = str(tmp_path / "public")
    monkeypatch.setattr(module, "EvaluationReviewer", ApprovingReviewer)
    summary = module.evaluate(config, cases, tmp_path / "private/report.jsonl")
    capsys.readouterr()
    judged = summary["judged"]
    assert summary["errors"] == 0 and not summary["incomplete"]
    assert sum(row["cases"] for row in judged.values()) == len(cases)
    observations = [json.loads(line) for line in (tmp_path / "private/report.jsonl").read_text().splitlines()]
    clean_ids = {case["id"] for case in cases if "flaw" not in case}
    # Primary scores measure reviewer changes; original-input history stays explicit.
    assert judged["clean"]["ok"] == sum(
        row["matched"] and row["published_candidate"] == row["review_candidate"]
        for row in observations if row.get("case") in clean_ids
    )
    assert summary["legacy_raw_judged"]["clean"]["ok"] == sum(
        row["matched"] and row["published_candidate"] == row["candidate"]
        for row in observations if row.get("case") in clean_ids
    )
    assert judged.get("stale_fact", {"ok": 0, "cases": 0})["ok"] == judged.get("stale_fact", {"cases": 0})["cases"]
    flagged = {case["id"] for case in cases if case.get("flaw") not in {None, "stale_fact"}}
    assert all(not row["ok"] or row["published_candidate"] != row["candidate"]
               for row in observations if row.get("case") in flagged)
