"""Evaluation harness tests for controlled, judged, draft, update, and routing corpora."""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import unicodedata
from urllib.parse import urlsplit

import pytest

from helpers import DATE, ROOT, ApprovingReviewer, _ClientBase, _meter_request, load_evaluator, verdict
from onionflash import review_gate
from onionflash.config import DEFAULTS
from onionflash.review import CRITERIA, RELEASE_ISSUE, _packet_refs, final_holds, release_labels_match_state, validate_review
from onionflash.source_packet import build_packet

MOD = load_evaluator()
RAW_PUBLIC = json.loads((ROOT / "tools/review_cases.json").read_text())
CORPUS = [case for name in MOD.CASE_FILES for case in MOD.expand(json.loads((ROOT / "tools" / name).read_text()))]
BY_ID = {c["id"]: c for c in CORPUS}

AUDITS = {"why-it-matters-1", "live-1"}
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
URL = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)
ABSOLUTE_PATH = re.compile(r"(?:^|[\s(\"'`=])(?:~/|/(?:Users|home|private|tmp|var|etc|opt|srv|root)/|[A-Za-z]:\\)")
NUMBER = re.compile(r"\d+(?:\.\d+)*")
HEX_ID = re.compile(r"(?<![0-9a-f])[0-9a-f]{24}(?![0-9a-f])")
DATE_KEYS = ("published_at", "updated_at", "added_at")
RUN_STATE = {"snapshot", "captured_at", "editorial"}


@pytest.fixture
def evaluation(tmp_path):
    """Provide the loaded evaluator module paired with an isolated configuration."""
    config = copy.deepcopy(DEFAULTS)
    config["storage"]["output_dir"] = str(tmp_path / "public")
    return MOD, config


def _scripted_completion(reply):
    return lambda _self, *args, on_request=None, **kwargs: _meter_request(on_request, lambda: reply(*args, **kwargs))


def _scripted(reply, *, coverages=None, reason_target=None):
    class _Reviewer(_ClientBase):
        def __init__(self, *args, **kwargs):
            pass

        def review(self, candidate, packet, *, coverage=None, verification=False, update=False, on_request=None, **_kw):
            """Meter and validate the scripted reply or `(verdict, same_story)` tuple."""
            if on_request is not None:
                on_request(1)
            if coverages is not None:
                coverages.append(coverage)
            out = reply(candidate, verification)
            if isinstance(out, tuple):
                v_name, same = out
                raw = verdict(
                    v_name, update=update,
                    criterion="new_information" if v_name == "skip" else "operational_advice",
                    reason=f"Same event as {same or reason_target}." if v_name == "skip" else None,
                )
                return {**validate_review(raw, packet, update=update), "same_story": same}
            if "criteria" not in out:
                out = verdict(out["verdict"], repair=out.get("repair"), update=update,
                              criterion="news_value" if out["verdict"] == "skip" else "operational_advice")
            return validate_review(out, packet, update=update)

    return _Reviewer


def _stub_main(monkeypatch, module, config, tmp_path, *, calls=None, overrides=None):
    passed = {"controlled_mismatches": 0, "target_missed": [], "errors": 0, "incomplete": False, **(overrides or {})}
    monkeypatch.setattr(module, "load_config", lambda _: config)
    monkeypatch.setattr(
        module, "evaluate",
        lambda _cfg, cs, _out, **opt: (calls.append(([c["id"] for c in cs], opt["draft"])) if calls is not None else None) or passed,
    )
    return ["--config", str(tmp_path / "config.toml"), "--output", str(tmp_path / "report.jsonl")]


def _check_packet_roundtrip(raw_doc, packet_name):
    fields = ("url", "title", "kind", "authority", "product", "published_at", "updated_at", "upstream_state")
    src = raw_doc["packets"][packet_name]["sources"][0]
    extra = {"closed_at": src["closed_at"]} if "closed_at" in src else {}
    itm = {"id": "a" * 24, **{k: src[k] for k in fields}, **extra, "labels": list(src.get("labels", [])),
           "content": "\n\n".join(p for p in src["passages"] if isinstance(p, str)),
           "public_comments": [{"author": n["author"], "created_at": n["created_at"], "url": n["url"], "body": n["text"]}
                               for n in src["passages"] if isinstance(n, dict)]}
    built, _ = build_packet(None, itm, {"sources": [{"id": itm["id"], "url": itm["url"]}]}, {"sources": []}, itm["id"])
    expanded = next(c for c in MOD.expand(raw_doc) if c["packet"]["sources"][0]["url"] == src["url"])["packet"]["sources"][0]
    return itm, built["sources"][0], expanded


def _string_entries(value, path="$", *, skip_ids=False):
    if isinstance(value, dict):
        for idx, (key, item) in enumerate(value.items()):
            yield f"{path}.<key[{idx}]>", key
            child_path = f"{path}[{idx}]" if path in {"$.packets", "$.coverage_sets"} or not re.fullmatch(r"[a-z_]+", key) else f"{path}.{key}"
            if not (skip_ids and key == "id"):
                yield from _string_entries(item, child_path, skip_ids=skip_ids)
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            yield from _string_entries(item, f"{path}[{idx}]", skip_ids=skip_ids)
    elif isinstance(value, str):
        yield path, value


def _has_denied(text, words):
    if not words:
        return False
    folded = unicodedata.normalize("NFKC", text).casefold()
    return bool(({*re.findall(r"[a-z0-9]+", folded), *re.findall(r"[a-z]+", folded)}) & words)


def _torproject_https(url):
    try:
        parts = urlsplit(url)
    except (TypeError, ValueError):
        return False
    host = (parts.hostname or "").lower()
    return (
        parts.scheme == "https"
        and parts.username is None
        and parts.password is None
        and "@" not in parts.netloc
        and (host == "torproject.org" or host.endswith(".torproject.org"))
    )


def _judged_hygiene_problems(raw, denied_anywhere, denied_in_own_text):
    problems = []
    everything = list(_string_entries(raw))
    for loc, text in everything:
        if _has_denied(text, denied_anywhere):
            problems.append(f"{loc}: denied private name present")
        if any(m.group(1).lower() != "lists.torproject.org" for m in EMAIL.finditer(unicodedata.normalize("NFKC", text))):
            problems.append(f"{loc}: e-mail address outside the Tor lists")
    for p_idx, packet in enumerate(raw["packets"].values()):
        for s_idx, source in enumerate(packet["sources"]):
            if not _torproject_https(source["url"]):
                problems.append(f"$.packets[{p_idx}].sources[{s_idx}].url: non-torproject or credentialed URL")
            for n_idx, passage in enumerate(source["passages"]):
                if isinstance(passage, dict) and not _torproject_https(passage["url"]):
                    problems.append(f"$.packets[{p_idx}].sources[{s_idx}].passages[{n_idx}].url: non-torproject or credentialed URL")
            if RUN_STATE & set(source):
                problems.append(f"$.packets[{p_idx}].sources[{s_idx}]: run-state field kept")

    own = [
        *((f"$.packets.<key[{idx}]>", name) for idx, name in enumerate(raw["packets"])),
        *_string_entries({k: v for k, v in raw.items() if k != "packets"}, skip_ids=True),
    ]
    own_denied = denied_in_own_text | denied_anywhere
    for loc, text in own:
        if _has_denied(text, own_denied):
            problems.append(f"{loc}: denied tool, model, or private word in corpus own text")
        if any(not _torproject_https(u) for u in URL.findall(text)):
            problems.append(f"{loc}: non-torproject or credentialed link in corpus own text")
        if ABSOLUTE_PATH.search(text):
            problems.append(f"{loc}: filesystem path in corpus own text")
        if HEX_ID.search(text):
            problems.append(f"{loc}: id-like hex string in corpus own text")
    if re.search(r"\d", raw["description"]):
        problems.append("$.description: carries a count or date")
    return problems


def _numbers(text):
    return {".".join(str(int(part)) for part in match.split("."))
            for match in NUMBER.findall(unicodedata.normalize("NFKC", text))}


def _unexplained_numbers(text, packet):
    known = set()
    for number in _numbers(json.dumps(packet, ensure_ascii=False)):
        parts = number.split(".")
        known.update(".".join(parts[:end]) for end in range(1, len(parts) + 1))
        known.update(parts)
    return sorted(n for n in _numbers(text)
                  if n not in known and f"0.{n}" not in known and not (n.startswith("0.") and n[2:] in known))


def _unexplained_case_numbers(case):
    candidate, coverage = case["candidate"], case["existing_coverage"]
    candidate_text = "\n".join(candidate[k] for k in ("title", "summary", "why_it_matters")).casefold()
    for phrase in case.get("unsupported") or []:
        candidate_text = candidate_text.replace(phrase.casefold(), " ")
    prior_story = coverage.get("prior_story")
    prior_text = (
        "\n".join(prior_story[k] for k in ("title", "summary", "why_it_matters"))
        if prior_story else ""
    )
    own_text = f"{candidate_text}\n{prior_text}" if prior_text else candidate_text
    return _unexplained_numbers(own_text, case["packet"])


def _corpus_case_errors(module, case, corpus):
    errors = []
    cid = case["id"]
    candidate, packet, coverage = case["candidate"], case["packet"], case["existing_coverage"]
    kept, omitted = module.kept_unsupported, module.omitted
    unsupported, forbidden, required = (case.get(k) for k in ("unsupported", "forbidden_classifications", "required"))
    flagged = kept(case, candidate)
    if not set(unsupported or []) <= set(flagged) or bool(flagged) != bool(unsupported or forbidden):
        errors.append(f"{cid}: its flagged wording or labels are not in its own candidate")
    if omitted(case, candidate) != (required or []):
        errors.append(f"{cid}: its required wording is not in its own candidate")
    payload = json.dumps({"candidate": candidate, "packet": packet, "existing_coverage": coverage})
    errors.extend(f"{cid}: label {lbl!r} reaches the model payload"
                  for lbl in (cid, case.get("audit"), case.get("flaw")) if lbl and lbl in payload)
    if not _packet_refs(packet):
        errors.append(f"{cid}: the packet has no references")
    for src in packet["sources"]:
        authored = ["author" in p for p in src["passages"][1:]]
        if authored != sorted(authored, reverse=True):
            errors.append(f"{cid}: notes do not precede the description")
    twins = [t for t in corpus if t["packet"] == packet
             and not (t.get("flaw") or t.get("unsupported") or t.get("forbidden_classifications"))]
    errors.extend(f"{cid}: its flagged wording or labels also occur in clean twin {t['id']}"
                  for t in twins if t["id"] != cid and kept(case, t["candidate"]))
    errors.extend(f"{cid}: approve twin {t['id']} lacks its required wording"
                  for t in twins if t["expected"] == "approve" and omitted(case, t["candidate"]))
    negated, confirms = re.subn(r"\bconfirms?\b", "does not confirm", candidate["summary"])
    if confirms and kept(case, {"title": "", "summary": negated, "why_it_matters": ""}):
        errors.append(f"{cid}: the smallest negating repair still keeps its flagged wording")
    return errors


def test_judged_corpus_is_public_and_labeled(evaluation, tmp_path, monkeypatch, capsys):
    """Enforce public-text hygiene, provenance, pairing, and baseline scoring on the judged corpus."""
    module, config = evaluation
    tools_env = os.environ.get("REVIEW_EVAL_TOOLS")
    tools = Path(tools_env) if tools_env else ROOT / "tools"
    if tools_env:
        module = load_evaluator(tools, "review_eval_judged")
        controlled = json.loads((tools / "review_cases.json").read_text(encoding="utf-8"))
    else:
        controlled = RAW_PUBLIC
    judged_path = Path(os.environ.get("REVIEW_CASES_JUDGED") or tools / "review_cases_judged.json")
    denylist = json.loads(Path(os.environ["REVIEW_PRIVATE_DENYLIST"]).read_text()) if os.environ.get("REVIEW_PRIVATE_DENYLIST") else {}
    denied_anywhere = frozenset(word.casefold() for word in denylist.get("anywhere", []))
    denied_in_own_text = frozenset(word.casefold() for word in denylist.get("own_text", []))

    assert judged_path.stat().st_size <= module.MAX_FILE_BYTES
    raw = json.loads(judged_path.read_text(encoding="utf-8"))
    problems = []

    assert set(raw) == {"description", "defaults", "packets", "cases", "coverage_sets"}
    assert raw["defaults"] == controlled["defaults"]
    cases = module.expand(raw)
    assert module.draft_cases(raw) and 0 < len(cases) <= module.MAX_CASES
    ids = [case["id"] for case in cases]
    assert len(set(ids)) == len(ids) and not (set(ids) & {case["id"] for case in controlled["cases"]})

    problems.extend(_judged_hygiene_problems(raw, denied_anywhere, denied_in_own_text))

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
        problems.extend(_corpus_case_errors(module, case, cases))
        if any(set(r) != {"id", "title", "summary", "category", "state", "updated_at", "summary_truncated"}
               for r in coverage["recent"]):
            problems.append(f"{cid}: coverage rows lack the compact background keys")
        known = {v for src in case["packet"]["sources"] for v in
                 [src.get("published_at"), src.get("updated_at"), *(p.get("created_at") for p in src["passages"])] if v}
        known |= {raw["defaults"][k] for k in DATE_KEYS}
        stories = [candidate, *([coverage["prior_story"]] if coverage["prior_story"] else [])]
        problems.extend(f"{cid}: {k} {st[k]} is neither a default nor an upstream date"
                        for st in stories for k in DATE_KEYS if st.get(k) not in known)
        if extra := _unexplained_case_numbers(case):
            problems.append(f"{cid}: numbers that the packet does not hold: {extra}")
        if coverage["prior_story"] and coverage["prior_story"]["id"] != candidate["id"]:
            problems.append(f"{cid}: the prior story is not the same article as the update")
        if flaw and not any(t["packet"] == case["packet"] and "flaw" not in t for t in cases):
            problems.append(f"{cid}: no clean twin on its packet, so it can never be a paired catch")
    problems.extend(f"audit set {a} lacks flagged or clean cases" for a, kinds in audits.items() if kinds != {"flagged", "clean"})
    assert not problems, "\n".join(problems)

    monkeypatch.setattr(module, "EvaluationReviewer", ApprovingReviewer)
    summary = module.evaluate(config, cases, tmp_path / "private/report.jsonl")
    capsys.readouterr()
    judged = summary["judged"]
    assert summary["errors"] == 0 and not summary["incomplete"]
    assert sum(row["cases"] for row in judged.values()) == len(cases)
    assert judged["clean"]["ok"] == judged["clean"]["cases"]
    assert judged.get("stale_fact", {"ok": 0, "cases": 0})["ok"] == judged.get("stale_fact", {"cases": 0})["cases"]
    assert all(row["ok"] == 0 for flaw, row in judged.items() if flaw not in {"clean", "stale_fact"})


def test_controlled_corpus_rubric_coverage_and_coverage_sets():
    """Verify rubric criterion coverage, scope outcomes, and coverage_set references across the corpus."""
    assert len(BY_ID) == len(CORPUS)
    assert set(CRITERIA) <= {criterion for c in CORPUS for criterion in c["coverage"]}
    assert any(c["expected"] == "approve" and "operational_advice" in c["coverage"] for c in CORPUS)
    assert all(any(c["scope"] == "latest_update" and c["expected"] == out for c in CORPUS)
               for out in ("approve", "skip", "not_approve", "hold"))
    assert any(c.get("expected_same_story") for c in CORPUS)
    assert any("expected_same_story" in c and c["expected_same_story"] is None for c in CORPUS)
    assert any(row.get("retracted") for row in RAW_PUBLIC["coverage_sets"]["busy"]["recent"])
    assert any(row.get("related") for row in RAW_PUBLIC["coverage_sets"]["busy"]["recent"])
    with pytest.raises(KeyError):
        MOD.expand({**RAW_PUBLIC, "cases": [{**RAW_PUBLIC["cases"][0], "coverage_set": "missing"}]})


@pytest.mark.parametrize("case", CORPUS, ids=[c["id"] for c in CORPUS])
def test_controlled_corpus_case_is_blinded_and_matches_detectors(case):
    """Ensure every corpus case is blinded and aligns with unsupported, required, and twin checks."""
    compact_req = {"id", "title", "summary", "category", "state", "updated_at", "summary_truncated"}
    compact_opt = {"latest_update", "products", "related"}
    assert not _corpus_case_errors(MOD, case, CORPUS)
    assert all((set(r) == {"id", "title", "retracted"} and r["retracted"] is True)
               or (compact_req <= set(r) <= compact_req | compact_opt)
               for r in case["existing_coverage"]["recent"])
    unsupported, forbidden, required = (case.get(k) for k in ("unsupported", "forbidden_classifications", "required"))
    assert case["expected"] in {"skip", "hold"} or bool(unsupported or forbidden or required) == (case["expected"] == "not_approve")


@pytest.mark.parametrize("change", [{"unsupported": []}, {"flaw": "invented_impact"}, {"audit": "test", "flaw": "unknown"}])
def test_invalid_evaluation_case_rejected(evaluation, tmp_path, change):
    """Reject malformed case flags and unknown flaw names before running `evaluate`."""
    module, config = evaluation
    with pytest.raises(ValueError, match="Invalid or duplicate evaluation case"):
        module.evaluate(config, [{**copy.deepcopy(BY_ID["bastet-original"]), **change}], tmp_path / "bad.jsonl")


def test_evaluation_scoring_repairs_holds_and_private_output(evaluation, tmp_path, monkeypatch, capsys):
    """Score false approvals, verified repairs, unusable repairs, and 0600 private output paths."""
    module, config = evaluation
    sel = [BY_ID["bastet-original"], BY_ID["legitimate-custom-config"], BY_ID["new-version-tag"]]
    monkeypatch.setattr(module, "EvaluationReviewer", _scripted(lambda _c, _v: {"verdict": "approve"}))
    out = tmp_path / "private/report.jsonl"
    res = module.evaluate(config, sel, out)
    assert res["false_approvals"] == 1 and res["matched"] == 2 and stat.S_IMODE(out.stat().st_mode) == 0o600
    assert json.loads(out.read_text().splitlines()[-1])["summary"] == res
    with pytest.raises(FileExistsError):
        module.evaluate(config, sel, out)
    with pytest.raises(ValueError, match="outside public"):
        module.evaluate(config, sel, tmp_path / "public/private-evidence.jsonl")
    assert "candidate" not in capsys.readouterr().out

    for repair, kept, fa in (({"priority": "high"}, ["update their configurations"], 1), ({"why_it_matters": ""}, [], 0)):
        monkeypatch.setattr(module, "EvaluationReviewer",
                            _scripted(lambda _c, v: {"verdict": "approve"} if v else {"verdict": "revise", "repair": repair}))
        o2 = tmp_path / f"fa-{fa}.jsonl"
        r2 = module.evaluate(config, [BY_ID["bastet-original"]], o2)
        assert (r2["repairs_verified"], r2["false_approvals"], r2["matched"]) == (1, fa, 1 - fa)
        assert json.loads(o2.read_text().splitlines()[0])["kept_unsupported"] == kept

    tightened = "The issue says bastet's keys can no longer be trusted."
    monkeypatch.setattr(
        module, "EvaluationReviewer",
        _scripted(lambda _c, v: {"verdict": "approve"} if v else {"verdict": "revise", "repair": {"why_it_matters": tightened}}),
    )
    o_tight = tmp_path / "tightened-wim.jsonl"
    r_tight = module.evaluate(config, [BY_ID["bastet-original"]], o_tight)
    assert (r_tight["repairs_verified"], r_tight["false_approvals"], r_tight["impact_cleared"], r_tight["matched"]) == (1, 0, 0, 1)
    assert json.loads(o_tight.read_text().splitlines()[0])["published_candidate"]["why_it_matters"] == tightened

    pos_sel = [c for c in CORPUS if c["id"] in {"bastet-corrected", "new-release-news", "new-version-tag"}]
    for verified, repair, verdicts, cleared in (("approve", {"priority": "high"}, ["approve", "approve", "hold"], 0),
                                                 ("hold", {"priority": "high"}, ["hold", "hold", "hold"], 0),
                                                 ("approve", {"why_it_matters": ""}, ["approve", "hold", "hold"], 1)):
        monkeypatch.setattr(module, "EvaluationReviewer",
                            _scripted(lambda _c, v: {"verdict": verified} if v else {"verdict": "revise", "repair": repair}))
        o3 = tmp_path / f"{verified}-{cleared}.jsonl"
        r3 = module.evaluate(config, pos_sel, o3)
        matched = verdicts.count("approve")
        assert (r3["matched"], r3["positive_rejections"], r3["false_approvals"], r3["repairs_held"], r3["impact_cleared"]) == (
            matched, 3 - matched, 0, 3 - matched, cleared)
        assert [json.loads(line)["final_verdict"] for line in o3.read_text().splitlines()[:-1]] == verdicts

    unusable_sel = [BY_ID["bastet-original"], BY_ID["empty-context-release"]]
    for repair in (None, {"why_it_matters": ""}):
        monkeypatch.setattr(module, "EvaluationReviewer", _scripted(lambda _c, _v: {"verdict": "revise", "repair": repair}))
        ru = module.evaluate(config, unusable_sel, tmp_path / f"unusable-{repair is None}.jsonl")
        assert (ru["errors"], ru["repairs_held"], ru["matched"], ru["positive_rejections"]) == (0, 2, 1, 1)

    monkeypatch.setattr(module, "EvaluationReviewer", _scripted(lambda _c, _v: {"verdict": "hold"}))
    assert module.evaluate(config, [BY_ID["bastet-confirmed-badge"]], tmp_path / "badge.jsonl")["matched"] == 1


def test_editorial_skips_misses_coverage_verification_and_final_checks(evaluation, tmp_path, monkeypatch):
    """Score editorial skips, coverage propagation, verification holds, and deterministic final holds."""
    module, config = evaluation
    skip_case = next(c for c in CORPUS if c["expected"] == "skip" and not c.get("unsupported"))
    for outcome, misses, false in (("skip", 0, 0), ("hold", 1, 0), ("approve", 1, 1)):
        monkeypatch.setattr(module, "EvaluationReviewer", _scripted(lambda _c, _v: {"verdict": outcome}))
        r = module.evaluate(config, [skip_case], tmp_path / f"sk-{outcome}.jsonl")
        assert (r["editorial_misses"], r["false_approvals"]) == (misses, false)
    monkeypatch.setattr(module, "EvaluationReviewer",
                        _scripted(lambda _c, v: {"verdict": "approve"} if v else {"verdict": "revise", "repair": {"summary": "A supported but redundant statement."}}))
    r_rep = module.evaluate(config, [skip_case], tmp_path / "sk-rep.jsonl")
    assert r_rep["false_approvals"] == r_rep["editorial_misses"] == 1

    pair = [BY_ID["bastet-original"], BY_ID["bastet-corrected"]]
    for outcome, misses in (("skip", 1), ("hold", 0)):
        monkeypatch.setattr(module, "EvaluationReviewer", _scripted(lambda _c, _v: {"verdict": outcome}))
        rp = module.evaluate(config, pair, tmp_path / f"nw-{outcome}.jsonl")
        assert (rp["editorial_misses"], rp["matched"], rp["positive_rejections"]) == (misses, 1 - misses, 1)

    cov_case = next(c for c in CORPUS if c.get("existing_coverage", {}).get("recent"))
    seen = []
    monkeypatch.setattr(
        module, "EvaluationReviewer",
        _scripted(lambda _c, v: ("skip", None) if v else {"verdict": "revise", "repair": {"summary": "A source-supported statement."}}, coverages=seen),
    )
    cov_out = tmp_path / "coverage.jsonl"
    rcov = module.evaluate(config, [cov_case], cov_out)
    assert rcov["repairs_skipped"] == 0 and rcov["repairs_held"] == 1 and rcov["holds"] == {"held.verification.disagreed_news": 1}
    assert seen == [cov_case["existing_coverage"], cov_case["existing_coverage"]]
    assert json.loads(cov_out.read_text().splitlines()[0])["existing_coverage"] == cov_case["existing_coverage"]

    app_case = next(c for c in CORPUS if c["expected"] == "approve")
    monkeypatch.setattr(module, "EvaluationReviewer", _scripted(lambda _c, v: {"verdict": "hold"} if v else {"verdict": "approve"}))
    fh_out = tmp_path / "final-hold.jsonl"
    rfh = module.evaluate(config, [app_case], fh_out)
    assert rfh["positive_rejections"] == 1 and rfh["matched"] == 0
    rec_fh = json.loads(fh_out.read_text().splitlines()[0])
    assert rec_fh["published_candidate"] is None and rec_fh["final_verdict"] == "hold"

    monkeypatch.setattr(module, "EvaluationReviewer", _scripted(lambda _c, _v: {"verdict": "approve"}))
    chk_out = tmp_path / "checks.jsonl"
    rchk = module.evaluate(config, [BY_ID["bastet-removed-as-done"], BY_ID["bastet-corrected"]], chk_out)
    assert (rchk["false_approvals"], rchk["matched"], rchk["final_holds"], rchk["published_after_checks"]) == (1, 1, 1, 1)
    recs = {r["case"]: r for r in map(json.loads, chk_out.read_text().splitlines()[:-1])}
    assert recs["bastet-removed-as-done"]["final_holds"] == ["completed_action"] and "final_holds" not in recs["bastet-corrected"]
    assert not [c["id"] for c in MOD.expand(RAW_PUBLIC) if c["expected"] == "approve" and final_holds(c["candidate"], {
        "packet": c["packet"], "payload": {"editorial_kind": c["packet"]["sources"][0]["kind"]}})]
    corpus_holds = {
        c["id"]: (c.get("audit"), holds)
        for c in CORPUS
        if c["expected"] == "approve"
        and (holds := final_holds(c["candidate"], {"packet": c["packet"], "payload": {"editorial_kind": c["packet"]["sources"][0]["kind"]}}))
    }
    assert all(
        (audit == "why-it-matters-1" and holds == ["untrusted_operator_claim"])
        or (cid == "live-circuit-marking-corrected" and audit == "live-1" and holds == ["release_state"])
        for cid, (audit, holds) in corpus_holds.items()
    )

    bf = BY_ID["bugfix-is-not-security-fix"]
    rep = {**bf["candidate"], "title": "Browser update", "summary": "An Android bugfix was released."}
    assert module.kept_unsupported(bf, rep) == ["tags:security"]
    assert module.kept_unsupported(bf, {**rep, "tags": ["release"]}) == []


def test_authored_passages_match_build_packet():
    """Match expanded authored passages, labels, and closed_at metadata against `build_packet`."""
    fields = ("url", "title", "kind", "authority", "product", "published_at", "updated_at", "upstream_state", "labels", "content", "public_comments")
    for packet_name, expected_labels in (("scope-correction", []), ("tor-41412-cross-cancellation-edited", ["Security", "Severity::medium"])):
        itm, built_src, expanded = _check_packet_roundtrip(RAW_PUBLIC, packet_name)
        assert expanded["labels"] == built_src["labels"] == expected_labels
        assert [list(p.items()) for p in expanded["passages"]] == [list(p.items()) for p in built_src["passages"]]
        assert MOD.writer_item(expanded) == {k: itm[k] for k in fields}

    closed_raw = copy.deepcopy(RAW_PUBLIC)
    closed_raw["packets"]["tor-41412-cross-cancellation-edited"]["sources"][0]["closed_at"] = "2026-10-07T17:16:54Z"
    _, c_built, c_exp = _check_packet_roundtrip(closed_raw, "tor-41412-cross-cancellation-edited")
    assert c_exp["closed_at"] == c_built["closed_at"] == "2026-10-07T17:16:54Z"
    assert "closed_at" not in MOD.writer_item(c_exp)


def test_draft_mode_drafts_once_and_isolates_writer_diagnostics(evaluation, tmp_path, monkeypatch):
    """Draft once per unique packet per round in `--draft` mode and isolate writer/reviewer errors."""
    module, config = evaluation
    groups = {"draft:bastet", "draft:issue-update/prior-issue", "draft:issue-update/related-issue",
              "draft:new-version-tag", "draft:refactor-with-disclosure"}
    cases = [c for c in module.draft_cases(RAW_PUBLIC) if c["id"] in groups]
    assert {c["id"]: c["expected"] for c in cases} == {
        "draft:bastet": "approve", "draft:issue-update/prior-issue": "approve",
        "draft:issue-update/related-issue": "skip", "draft:new-version-tag": "approve",
        "draft:refactor-with-disclosure": "approve",
    }
    requests = []

    class _DraftWriter(module.Analyzer):
        def complete(self, _prompt, payload, _schema, _name):
            """Return a deterministic draft payload keyed by packet title."""
            requests.append(payload)
            summary = ("Operators must update their configurations." if "bastet" in payload["title"]
                       else "A fix is proposed." if "crash fix" in payload["title"] else "A faithful summary of the report.")
            return {"publish": True, "title": payload["title"], "summary": summary, "why_it_matters": "",
                    "category": "security", "priority": "normal", "confidence": "reported", "state": "developing",
                    "products": [payload["product"]], "tags": ["security"], "evidence": [payload["title"]]}

    orig_eval_reviewer = module.EvaluationReviewer
    monkeypatch.setattr(module, "Analyzer", _DraftWriter)
    monkeypatch.setattr(module, "EvaluationReviewer", _scripted(lambda _c, _v: {"verdict": "approve"}))
    out = tmp_path / "drafts.jsonl"
    res = module.evaluate(config, cases, out, rounds=2, draft=True)
    assert sorted(p["title"] for p in requests) == sorted(
        2 * [s["sources"][0]["title"] for n, s in RAW_PUBLIC["packets"].items() if n in {"bastet", "issue-update", "refactor-with-disclosure"}])
    note = next(p for p in requests if "public_comments" in p)["public_comments"]
    assert note == [{k: p[k] for k in ("author", "created_at")} | {"body": p["text"]}
                    for p in RAW_PUBLIC["packets"]["refactor-with-disclosure"]["sources"][0]["passages"] if isinstance(p, dict)]
    assert (res["draft_unsupported"], res["false_approvals"], res["omissions"], res["missed_routes"], res["matched"]) == (4, 6, 2, 2, 2)
    records = [json.loads(l) for l in out.read_text().splitlines()[:-1]]
    assert all(r["candidate"]["summary"] == r["draft"]["summary"] for r in records)
    flagged = {"draft:bastet": ["update their configurations"], "draft:issue-update/prior-issue": ["fix is proposed"]}
    assert [r["draft_kept_unsupported"] for r in records] == [flagged.get(r["case"], []) for r in records]

    wanted = ["draft:bastet", "draft:refactor-with-disclosure", "draft:issue-update/prior-issue", "draft:issue-update/related-issue"]
    by_id = {c["id"]: c for c in module.draft_cases(RAW_PUBLIC) if c["id"] in wanted}
    req_text = " ".join(by_id["draft:refactor-with-disclosure"].get("required") or [])

    class _FlakyWriter(module.Analyzer):
        def complete(self, _prompt, payload, _schema, _name):
            """Raise `AnalysisError` on selected packets and draft cleanly on others."""
            if "bastet" in payload["title"] or "crash fix" in payload["title"]:
                raise module.AnalysisError("LLM request failed (HTTP 500)")
            return {"publish": True, "title": payload["title"], "summary": f"A faithful summary: {req_text}.",
                    "why_it_matters": "", "category": "security", "priority": "normal", "confidence": "reported",
                    "state": "developing", "products": [payload["product"]], "tags": ["security"], "evidence": [payload["title"]]}

    replies = iter([{"invalid": True}, verdict("approve"), verdict("approve")])
    monkeypatch.setattr(module, "EvaluationReviewer", orig_eval_reviewer)
    monkeypatch.setattr(module, "Analyzer", _FlakyWriter)
    monkeypatch.setattr(module.Reviewer, "complete", _scripted_completion(lambda *a: next(replies)))
    with module.EvaluationReviewer(config) as fresh_reviewer:
        assert fresh_reviewer.last_decoded is None
    err_out = tmp_path / "draft-errors.jsonl"
    err_res = module.evaluate(config, [by_id[cid] for cid in wanted], err_out, rounds=2, draft=True)
    assert (err_res["cases"], err_res["errors"], err_res["matched"]) == (8, 7, 1)
    by_cr = {(r["case"], r["round"]): r for r in map(json.loads, err_out.read_text().splitlines()[:-1])}
    assert by_cr["draft:refactor-with-disclosure", 1]["decoded_diagnostic"] == {"invalid": True}
    assert by_cr["draft:refactor-with-disclosure", 2]["final_verdict"] == "approve"
    for rnum in (1, 2):
        for fid in ("draft:bastet", "draft:issue-update/prior-issue", "draft:issue-update/related-issue"):
            assert by_cr[fid, rnum]["error"] == "AnalysisError" and "decoded_diagnostic" not in by_cr[fid, rnum]


def test_omissions_holds_model_verdict_release_repairs_and_fix_loop(evaluation, tmp_path, monkeypatch):
    """Score omissions, official-skip holds, verification repairs, and release-label fix loops."""
    module, config = evaluation
    om_case = BY_ID["draft-omits-disclosure"]
    for out_v, om, miss, match in (("approve", 1, 0, 0), ("skip", 0, 1, 0), ("hold", 0, 0, 1)):
        monkeypatch.setattr(module, "EvaluationReviewer", _scripted(lambda _c, _v: {"verdict": out_v}))
        r = module.evaluate(config, [om_case], tmp_path / f"om-{out_v}.jsonl")
        assert (r["omissions"], r["editorial_misses"], r["matched"], r["false_approvals"], r["controlled_mismatches"]) == (
            om, miss, match, 0, 1 - match)

    off_case = BY_ID["official-routine-post"]
    comm_case = copy.deepcopy(off_case)
    comm_case["packet"]["sources"][0]["authority"] = "community"
    for name, sel, out_v, match, fa, miss, holds in (
        ("hold", off_case, "hold", 1, 0, 0, {"held.review.model_hold": 1}),
        ("approve", off_case, "approve", 0, 1, 0, {}),
        ("official-skip", off_case, "skip", 1, 0, 0, {"held.verification.official_not_news": 1}),
        ("community-skip", comm_case, "skip", 0, 0, 1, {}),
    ):
        monkeypatch.setattr(module, "EvaluationReviewer", _scripted(lambda _c, _v: {"verdict": out_v}))
        r = module.evaluate(config, [sel], tmp_path / f"{name}.jsonl")
        assert (r["matched"], r["false_approvals"], r["editorial_misses"], r["holds"]) == (match, fa, miss, holds)

    replies_iter = iter([{"verdict": "approve"}, {"verdict": "revise", "repair": {"why_it_matters": ""}}, {"verdict": "approve"}])
    monkeypatch.setattr(module, "EvaluationReviewer", _scripted(lambda _c, _v: next(replies_iter)))
    loop_out = tmp_path / "loop.jsonl"
    rloop = module.evaluate(config, [BY_ID["bastet-original"]], loop_out)
    rec_loop = json.loads(loop_out.read_text().splitlines()[0])
    assert (rloop["matched"], rloop["false_approvals"], rloop["verification_repairs"]) == (1, 0, 1)
    assert [(e["stage"], e["result"]["verdict"]) for e in rec_loop["reviews"]] == [
        ("review", "approve"), ("verification", "revise"), ("verification", "approve")]
    assert rec_loop["published_candidate"]["why_it_matters"] == "" and rec_loop["final_verdict"] == "approve"

    monkeypatch.undo()
    monkeypatch.setattr(module.Reviewer, "complete", _scripted_completion(lambda *a: verdict("skip", criterion="source_support")))
    conv_out = tmp_path / "converted.jsonl"
    assert module.evaluate(config, [BY_ID["bastet-original"]], conv_out)["matched"] == 1
    rec_conv = json.loads(conv_out.read_text().splitlines()[0])
    assert (rec_conv["model_verdict"], rec_conv["result"]["verdict"], rec_conv["final_verdict"]) == ("skip", "hold", "hold")
    assert rec_conv["reviews"][0]["result"]["model_verdict"] == "skip" and "verification" not in rec_conv

    payloads = []
    monkeypatch.setattr(module.Reviewer, "complete", _scripted_completion(lambda _prompt, payload, *a: (payloads.append(payload), next(rel_replies))[1]))
    fixed = verdict("revise", repair={"title": "Opt-in exit proxying merged", "category": "feature", "tags": ["feature"]}, criterion="status")
    for name, rel_replies, holds, pub in (("unfixed", iter([verdict(), verdict()]), {"held.review.release_labels": 1}, None),
                                          ("fixed", iter([verdict(), fixed, verdict()]), {}, "Opt-in exit proxying merged")):
        payloads.clear()
        o = tmp_path / f"rel-{name}.jsonl"
        res = module.evaluate(config, [BY_ID["merged-is-not-release"]], o)
        rec = json.loads(o.read_text().splitlines()[0])
        assert (res["matched"], res["holds"], (rec["published_candidate"] or {}).get("title")) == (1, holds, pub)
        assert [e["stage"] for e in rec["reviews"]] == ["review", "review", "verification"][:len(payloads)]
        assert [p.get("application_issue") for p in payloads] == [None, RELEASE_ISSUE, None][:len(payloads)]
        assert rec["reviews"][1]["issue"] == "release_labels"


@pytest.mark.parametrize("flaws,clean,expected", [
    (None, None, []),
    ({"overclaim": (20, 10, 18)}, (10, 10), []),
    ({"overclaim": (20, 10, 17)}, (10, 10), ["catch"]),
    ({"overclaim": (10, 10, 7), "filler": (90, 90, 90)}, (10, 10), ["overclaim"]),
    ({"badge_misuse": (18, 9, 0), "filler": (200, 200, 200)}, (10, 10), []),
    ({"filler": (10, 10, 10)}, (100, 89), ["false_alarms"]),
    ({"filler": (10, 10, 10)}, (100, 90), []),
])
def test_target_missed_thresholds(flaws, clean, expected):
    """Enforce aggregate catch, per-flaw, and false-alarm target thresholds in `target_missed`."""
    if flaws is None:
        assert MOD.target_missed({}) == expected
    else:
        payload = {f: {"cases": c, "ok": c, "unique": u, "paired": p} for f, (c, u, p) in flaws.items()}
        payload["clean"] = {"cases": clean[0], "ok": clean[1], "unique": clean[0]}
        assert MOD.target_missed(payload) == expected


@pytest.mark.parametrize("failure", [{"target_missed": ["catch"]}, {"controlled_mismatches": 1}, {"false_routes": 1}, {"errors": 1}, {"incomplete": True}])
def test_main_cli_failure_returns_one(evaluation, tmp_path, monkeypatch, failure):
    """Return exit code 1 from `main` whenever any quality gate or completeness flag fails."""
    module, config = evaluation
    assert module.main(_stub_main(monkeypatch, module, config, tmp_path, overrides=failure)) == 1


def test_judged_scoring_thresholds_and_cli_main(evaluation, tmp_path, monkeypatch):
    """Verify paired/overall judged catch rates, false-alarm rates, and CLI argument validation."""
    module, config = evaluation
    pick = {c["id"]: c for c in RAW_PUBLIC["cases"]}
    judged_fn = lambda cid, src, **f: {**pick[src], "id": cid, "audit": "test", **f}
    cases = module.expand({**RAW_PUBLIC, "cases": [
        judged_fn("sentence", "bastet-original", flaw="invented_impact"),
        judged_fn("badge", "bastet-confirmed-badge", flaw="badge_misuse"),
        judged_fn("stale", "material-existing-update", flaw="stale_fact"),
        judged_fn("shell", "bastet-corrected", candidate={**pick["bastet-corrected"]["candidate"], "why_it_matters": ""}),
        judged_fn("grounded", "bastet-corrected"),
    ]})

    discerning = _scripted(
        lambda cand, _: {"verdict": "hold" if ("update their configurations" in cand["why_it_matters"] or cand["confidence"] == "confirmed") else "approve"}
    )
    rows = lambda s, b, st, cl, rounds=1: {
        "invented_impact": dict(zip(("ok", "paired"), s), cases=rounds, unique=1),
        "badge_misuse": dict(zip(("ok", "paired"), b), cases=rounds, unique=1),
        "stale_fact": dict(zip(("ok", "paired"), st), cases=rounds, unique=1),
        "clean": {"cases": 2 * rounds, "ok": cl, "unique": 2},
    }
    clearing = _scripted(lambda _c, v: {"verdict": "approve"} if v else {"verdict": "revise", "repair": {"why_it_matters": ""}})
    for name, rev_cls, rounds, j_exp, missed in (
        ("approve", _scripted(lambda _c, _v: {"verdict": "approve"}), 1, rows((0, 0), (0, 0), (1, 1), 2), ["catch"]),
        ("clear", clearing, 1, rows((1, 0), (0, 0), (0, 0), 0), ["catch", "false_alarms"]),
        ("skip", _scripted(lambda _c, _v: {"verdict": "skip"}), 1, rows((0, 0), (0, 0), (0, 0), 0), ["catch", "false_alarms"]),
        ("discerning", discerning, 2, rows((2, 2), (2, 2), (2, 2), 4, rounds=2), []),
    ):
        monkeypatch.setattr(module, "EvaluationReviewer", rev_cls)
        res = module.evaluate(config, cases, tmp_path / f"{name}.jsonl", rounds=rounds)
        assert (res["judged"], res["target_missed"], res["controlled_mismatches"]) == (j_exp, missed, 0), name
    assert (res["catch_rate"], res["paired_catch_rate"], res["false_alarm_rate"]) == (1.0, 1.0, 0.0)
    res_fl = module.evaluate(config, [c for c in cases if "flaw" in c], tmp_path / "flagged.jsonl")
    assert (res_fl["judged"], res_fl["target_missed"]) == ({k: v for k, v in rows((1, 0), (1, 0), (1, 1), 0).items() if k != "clean"}, ["catch"])
    assert (res_fl["catch_rate"], res_fl["paired_catch_rate"], res_fl["false_alarm_rate"]) == (1.0, 0.333, None)

    calls = []
    base = _stub_main(monkeypatch, module, config, tmp_path, calls=calls)
    default, public = [c["id"] for c in CORPUS], ROOT / "tools/review_cases.json"
    synthetic = [c["id"] for c in module.expand(RAW_PUBLIC)]
    extra, large = tmp_path / "extra.json", tmp_path / "large.json"
    extra.write_text(json.dumps({**RAW_PUBLIC, "cases": [{**RAW_PUBLIC["cases"][0], "id": "extra-case"}]}))
    large.write_text(" " * (module.MAX_FILE_BYTES + 1))
    assert module.main(base) == 0 and calls[-1] == (default, False) and len(default) > len(synthetic)
    assert module.main([*base, "--cases", str(public)]) == 0 and calls[-1] == (synthetic, False)
    assert module.main([*base, "--cases", str(public), "--cases", str(extra)]) == 0 and calls[-1] == (synthetic + ["extra-case"], False)
    assert module.main([*base, "--draft", "--case-id", "draft:bastet"]) == 0 and calls[-1] == (["draft:bastet"], True)
    for opts in (["--cases", str(public), "--cases", str(public)], ["--cases", str(large)],
                 ["--cases", str(public), "--cases", str(large)], ["--max-seconds", str(module.MAX_SECONDS + 1)]):
        with pytest.raises(SystemExit):
            module.main([*base, *opts])
    assert len(calls) == 4


@pytest.mark.parametrize("bad_mut", [
    lambda b: {**b, "scope": "paragraph"},
    lambda b: {**b, "candidate": {k: v for k, v in b["candidate"].items() if k != "updates"}},
    lambda b: {**b, "candidate": {**b["candidate"], "updates": [{"at": "bad", "text": "", "sources": []}]}},
])
def test_invalid_update_case_rejected(bad_mut):
    """Reject `latest_update` cases with invalid scopes or missing/malformed update lists."""
    base_raw = next(c for c in RAW_PUBLIC["cases"] if c["id"] == "update-fix-merged")
    with pytest.raises(ValueError):
        MOD.expand({**RAW_PUBLIC, "cases": [bad_mut(copy.deepcopy(base_raw))]})


def test_latest_update_scope_scans_only_new_entry_and_excludes_draft_mode(evaluation, tmp_path, monkeypatch):
    """Restrict `latest_update` detectors to the newest update entry and exclude them from draft mode."""
    module, config = evaluation
    by_id = {c["id"]: c for c in module.expand(RAW_PUBLIC)}
    wrong_state = copy.deepcopy(by_id["update-wrong-state"])
    srcs = wrong_state["candidate"]["updates"][-1]["sources"]
    story_with_prior = {
        **wrong_state["candidate"], "title": "Earlier headline shipped in a stable release",
        "summary": "Earlier summary shipped in a stable release.", "why_it_matters": "Earlier note shipped in a stable release.",
        "state": "merged",
        "updates": [{"at": "2026-11-09T10:00:00Z", "text": "Earlier update shipped in a stable release.", "sources": srcs},
                    {"at": "2026-11-10T11:00:00Z", "text": "Maintainers merged !91901 into main; required qualifier kept.", "sources": srcs}],
    }
    assert module.kept_unsupported(wrong_state, story_with_prior) == []
    assert module.kept_unsupported(wrong_state, {**story_with_prior, "state": "released"}) == ["state:released"]
    assert module.kept_unsupported(wrong_state, {**story_with_prior, "updates": [story_with_prior["updates"][0], {
        **story_with_prior["updates"][1], "text": "Maintainers shipped in a stable release."}]}) == ["shipped in a stable release"]

    req_case = {**wrong_state, "required": ["required qualifier"]}
    assert module.omitted(req_case, story_with_prior) == []
    assert module.omitted(req_case, {**story_with_prior, "summary": "Summary has required qualifier.", "updates": [
        story_with_prior["updates"][0], {**story_with_prior["updates"][1], "text": "Maintainers merged !91901 into main."}]}) == ["required qualifier"]

    upd_raw = {k: v for k, v in next(c for c in RAW_PUBLIC["cases"] if c["id"] == "update-speculative-cause").items() if k != "coverage_set"}
    mixed = {**RAW_PUBLIC, "cases": [next(c for c in RAW_PUBLIC["cases"] if c["id"] == "bastet-corrected"),
                                     {**upd_raw, "id": "update-on-story-packet", "packet": "bastet",
                                      "unsupported": ["phrase-only-in-update-case"], "required": ["required-only-in-update-case"],
                                      "forbidden_classifications": {"priority": ["normal"]}}]}
    drafted = module.draft_cases(mixed)
    assert [c["id"] for c in drafted] == ["draft:bastet"] and drafted[0]["unsupported"] == [] and drafted[0]["required"] == []
    assert drafted[0]["forbidden_classifications"] == {} and drafted[0]["expected"] == "approve"
    assert not [c["id"] for c in module.draft_cases(RAW_PUBLIC) if c["scope"] == "latest_update"]
    disagreed = module.draft_cases({**RAW_PUBLIC, "cases": [
        {"id": "s1", "packet": "bastet", "candidate": RAW_PUBLIC["cases"][0]["candidate"], "expected": "skip"},
        {"id": "h1", "packet": "bastet", "candidate": RAW_PUBLIC["cases"][0]["candidate"], "expected": "hold"},
    ]})
    assert disagreed[0]["expected"] == "not_approve"
    module._validate_cases(disagreed, draft=True)
    with pytest.raises(ValueError, match="Invalid or duplicate evaluation case"):
        module._validate_cases([{**disagreed[0], "id": "authored-flagless"}], draft=True)

    with pytest.raises(ValueError, match="Invalid or duplicate evaluation case"):
        module.evaluate(config, [by_id["update-fix-merged"]], tmp_path / "draft-upd.jsonl", draft=True)
    with pytest.raises(ValueError, match="Invalid or duplicate evaluation case"):
        no_updates = {**by_id["update-fix-merged"], "candidate": {k: v for k, v in by_id["update-fix-merged"]["candidate"].items() if k != "updates"}}
        module.evaluate(config, [no_updates], tmp_path / "empty-upd.jsonl")

    seen_scopes, orig_call = [], module.advance_review
    monkeypatch.setattr(module, "advance_review", lambda rev, stage, text, prep, state, requests: (
        seen_scopes.append((prep["review_scope"], prep["mode"])) or orig_call(rev, stage, text, prep, state, requests)))
    monkeypatch.setattr(module, "EvaluationReviewer", _scripted(lambda _c, _v: {"verdict": "approve"}))
    assert module.evaluate(config, [by_id["update-fix-merged"], by_id["bastet-corrected"]], tmp_path / "scopes.jsonl")["matched"] == 2
    assert seen_scopes == [("latest_update", "update"), ("latest_update", "update"), ("story", "story"), ("story", "story")]


@pytest.mark.parametrize("mutate", [
    lambda p, _t, _r, _b: {**p, "expected_same_story": "f" * 24},
    lambda p, _t, r, _b: {**p, "expected_same_story": r},
    lambda p, _t, _r, _b: {**p, "expected_same_story": "not-24-hex"},
    lambda p, _t, _r, _b: {**p, "expected_same_story": False},
    lambda p, _t, _r, _b: {**p, "expected": "approve"},
    lambda _p, t, _r, b: {**b["material-existing-update"], "expected": "skip", "expected_same_story": t},
    lambda _p, t, _r, b: {**b["update-rephrases-opening"], "expected_same_story": t},
])
def test_invalid_expected_same_story_case_rejected(evaluation, tmp_path, mutate):
    """Reject `expected_same_story` targets that are missing, retracted, malformed, or on update cases."""
    module, config = evaluation
    pos = copy.deepcopy(BY_ID["same-story-issue-mentions-covered-release"])
    target_id = pos["expected_same_story"]
    retracted_id = next(r["id"] for r in pos["existing_coverage"]["recent"] if r.get("retracted"))
    with pytest.raises(ValueError, match="Invalid or duplicate evaluation case"):
        module.evaluate(config, [mutate(pos, target_id, retracted_id, BY_ID)], tmp_path / "bad-route.jsonl")


def test_expected_same_story_scores_matched_missed_wrong_unroutable_and_false_routes(evaluation, tmp_path, monkeypatch):
    """Score matched, missed, wrong, unroutable network-health, and false `same_story` routes."""
    module, config = evaluation
    pos, neg, hold_neg = BY_ID["same-story-issue-mentions-covered-release"], BY_ID["same-story-neg-different-tor-version"], BY_ID["retracted-report-mirror"]
    target_id = pos["expected_same_story"]
    other_id = next(r["id"] for r in pos["existing_coverage"]["recent"] if r["id"] != target_id and not r.get("retracted"))

    monkeypatch.setattr(module, "EvaluationReviewer", _scripted(
        lambda cand, _: ("skip", target_id) if cand["id"] == pos["candidate"]["id"]
        else ("hold", None) if cand["id"] == hold_neg["candidate"]["id"] else ("approve", None),
        reason_target=target_id,
    ))
    out_ok = tmp_path / "routes-ok.jsonl"
    res_ok = module.evaluate(config, [pos, neg, hold_neg], out_ok)
    assert (res_ok["route_cases"], res_ok["matched_routes"], res_ok["missed_routes"], res_ok["false_routes"],
            res_ok["wrong_routes"], res_ok["matched"], res_ok["controlled_mismatches"]) == (3, 1, 0, 0, 0, 3, 0)
    recs_ok = {r["case"]: r for r in map(json.loads, out_ok.read_text().splitlines()[:-1])}
    assert recs_ok[pos["id"]]["same_story"] == target_id and recs_ok[neg["id"]]["same_story"] is None

    repost = BY_ID["same-story-official-release-only-repeat"]
    monkeypatch.setattr(module, "EvaluationReviewer", _scripted(lambda _c, _v: ("skip", repost["expected_same_story"]), reason_target=repost["expected_same_story"]))
    routed = module.evaluate(config, [repost], tmp_path / "release-repost.jsonl")
    assert (routed["matched_routes"], routed["matched"], routed["controlled_mismatches"]) == (1, 1, 0)

    for fn, exp_key in ((lambda _c, _v: ("skip", None), "missed_routes"), (lambda _c, _v: ("skip", other_id), "wrong_routes")):
        monkeypatch.setattr(module, "EvaluationReviewer", _scripted(fn, reason_target=target_id))
        res = module.evaluate(config, [pos], tmp_path / f"{exp_key}.jsonl")
        assert (res["route_cases"], res["matched_routes"], res[exp_key], res["matched"]) == (1, 0, 1, 0)

    monkeypatch.setattr(module, "EvaluationReviewer", _scripted(lambda _c, _v: ("skip", target_id), reason_target=target_id))
    res_false = module.evaluate(config, [neg], tmp_path / "routes-false.jsonl")
    assert (res_false["route_cases"], res_false["false_routes"], res_false["matched_routes"], res_false["matched"]) == (1, 1, 0, 0)

    nh_id, nh_url = "a" * 24, "https://gitlab.torproject.org/tpo/core/tor/-/work_items/321"
    nh_case = {
        "id": "route-to-network-health-blocked", "expected": "skip", "expected_same_story": nh_id,
        "candidate": {"title": "Authority bastet unreachable", "summary": "Operators noticed authority bastet unreachable.",
                      "why_it_matters": "", "category": "network", "priority": "normal", "confidence": "reported",
                      "state": "developing", "products": ["network-health"], "tags": ["network"], "sources": [{"url": nh_url, "title": "Issue 321"}]},
        "packet": {"sources": [{"id": "S1", "url": nh_url, "title": "Issue 321", "kind": "gitlab_issue", "authority": "development",
                                "product": "network-health", "published_at": DATE, "updated_at": DATE,
                                "passages": [{"id": "S1.P1", "text": "Operators noticed authority bastet unreachable."}]}]},
        "existing_coverage": {"prior_story": None, "recent": [{"id": nh_id, "origin": "network-health",
            "title": "Directory authority bastet missing from consensus", "summary": "DocTor reported bastet missing.",
            "category": "network", "state": "developing", "published_at": DATE, "updated_at": DATE, "sources": []}]},
    }
    monkeypatch.setattr(module, "EvaluationReviewer", _scripted(lambda _c, _v: ("skip", nh_id), reason_target=target_id))
    nh_res = module.evaluate(config, [nh_case], tmp_path / "eval_out.jsonl")
    assert (nh_res["matched_routes"], nh_res["wrong_routes"], nh_res["matched"]) == (0, 1, 0)

    with monkeypatch.context() as mp:
        mp.setattr(module, "EvaluationReviewer", _scripted(lambda _c, _v: ("approve", target_id), reason_target=target_id))
        mp.setattr(review_gate, "next_step", lambda reviews, text, prepared: ("route", target_id))
        out_gate = tmp_path / "routes-gate.jsonl"
        res_gate = module.evaluate(config, [pos], out_gate)
        rec_gate = json.loads(out_gate.read_text().splitlines()[0])
        assert (res_gate["matched_routes"], res_gate["matched"], res_gate["false_approvals"]) == (1, 1, 0)
        assert rec_gate["final_verdict"] == "route" and rec_gate["published_candidate"] is None


def test_expand_and_writer_item_preserve_unquoted_content_url_sender_and_official_holds(evaluation, tmp_path, monkeypatch):
    """Populate `unquoted_content` in `expand()` and preserve `url`/`author`/`sender_domain` in `writer_item()`."""
    module, config = evaluation
    quoted_case = BY_ID["third-party-entrymap-module-update"]
    assert "unquoted_content" in quoted_case["packet"]["sources"][0]
    quoted_pkt_name = next(c["packet"] for c in RAW_PUBLIC["cases"] if c["id"] == "third-party-entrymap-module-update")
    _, built_quoted, exp_quoted = _check_packet_roundtrip(RAW_PUBLIC, quoted_pkt_name)
    assert exp_quoted["unquoted_content"] == built_quoted["unquoted_content"]

    rich_src = {
        "id": "S1", "url": "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/M1/",
        "title": "[tor-relays] Re: Guard bandwidth drop", "kind": "feed", "authority": "community", "product": "tor",
        "published_at": DATE, "updated_at": DATE, "upstream_state": "", "labels": [],
        "author": "alice", "sender_domain": "1aeo.com",
        "dirauth_notes": [{"id": "gid://gitlab/Note/1", "author": "stefani", "created_at": DATE}],
        "passages": [{"id": "S1:P1", "text": "[tor-relays] Re: Guard bandwidth drop"},
                     {"id": "S1:P2", "text": "2026-11-08 measurement shows guard bandwidth recovered.\n> Prior quote line."}],
    }
    w_item = module.writer_item(rich_src)
    assert (w_item["url"], w_item["author"], w_item["sender_domain"], w_item["dirauth_notes"]) == (
        rich_src["url"], "alice", "1aeo.com", rich_src["dirauth_notes"],
    )

    seen_writer_payloads = []

    class _QuotedCommunityWriter(module.Analyzer):
        def complete(self, _prompt, payload, _schema, _name):
            """Record writer payload and return a community draft with non-empty `why_it_matters`."""
            seen_writer_payloads.append(copy.deepcopy(payload))
            return {
                "publish": True, "title": "Guard bandwidth recovery measured",
                "summary": "A reply reports that 2026-11-08 measurement shows guard bandwidth recovered.",
                "why_it_matters": "Community impact text that must be cleared.",
                "category": "relay", "priority": "normal", "confidence": "reported",
                "state": "developing", "products": ["tor"], "tags": ["relay"],
                "evidence": ["2026-11-08 measurement shows guard bandwidth recovered."],
            }

    mini_corpus = {
        "defaults": RAW_PUBLIC["defaults"],
        "packets": {"quoted-community": {"sources": [
            {k: v for k, v in rich_src.items() if k not in {"id", "sender_domain", "dirauth_notes", "passages"}}
            | {"passages": [p["text"] for p in rich_src["passages"][1:]]}
        ]}},
        "cases": [{"id": "quoted-community-case", "packet": "quoted-community", "expected": "approve",
                   "candidate": {"id": "a" * 24, "title": "Placeholder", "summary": "Placeholder.", "why_it_matters": "",
                                 "category": "relay", "priority": "normal", "confidence": "reported",
                                 "state": "developing", "products": ["tor"], "tags": ["relay"],
                                 "published_at": DATE, "updated_at": DATE,
                                 "sources": [{"url": rich_src["url"], "title": rich_src["title"]}]}}],
    }
    [draft_case] = module.draft_cases(mini_corpus)
    monkeypatch.setattr(module, "Analyzer", _QuotedCommunityWriter)
    monkeypatch.setattr(module, "EvaluationReviewer", _scripted(lambda _c, _v: ("approve", None)))
    draft_out = tmp_path / "draft-quoted.jsonl"
    assert module.evaluate(config, [draft_case], draft_out, draft=True)["matched"] == 1
    assert seen_writer_payloads[0]["unquoted_content"] == "2026-11-08 measurement shows guard bandwidth recovered."
    draft_rec = json.loads(draft_out.read_text().splitlines()[0])
    assert draft_rec["published_candidate"]["why_it_matters"] == ""

    monkeypatch.setattr(module, "EvaluationReviewer", _scripted(lambda _c, _v: {"verdict": "skip"}))
    for cid, src_extra in (
        ("dirauth-dev-hold", {"url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/49901",
                              "kind": "gitlab_issue", "author": "linus"}),
        ("h1-dev-hold", {"url": "https://hackerone.com/reports/3961620", "kind": "feed"}),
    ):
        hold_src = {
            "id": "S1", "title": "Minor authority formatting note", "authority": "development",
            "product": "tor", "published_at": DATE, "updated_at": DATE, "upstream_state": "opened", "labels": [],
            "passages": [{"id": "S1:P1", "text": "Minor authority formatting note"},
                         {"id": "S1:P2", "text": "Minor formatting note observed during check."}],
            **src_extra,
        }
        hold_case = {
            "id": cid, "expected": "hold",
            "candidate": {"id": "b" * 24, "title": "Minor authority formatting note",
                          "summary": "Minor formatting note observed during check.", "why_it_matters": "",
                          "category": "network", "priority": "normal", "confidence": "reported",
                          "state": "developing", "products": ["tor"], "tags": ["network"],
                          "published_at": DATE, "updated_at": DATE,
                          "sources": [{"url": hold_src["url"], "title": hold_src["title"]}]},
            "packet": {"sources": [hold_src], "missing_sources": [], "truncated": False},
            "existing_coverage": {"prior_story": None, "recent": []},
        }
        hold_out = tmp_path / f"{cid}.jsonl"
        res_hold = module.evaluate(config, [hold_case], hold_out)
        rec_hold = json.loads(hold_out.read_text().splitlines()[0])
        assert res_hold["matched"] == 1 and rec_hold["final_verdict"] == "hold" and rec_hold["hold_code"] == "official_not_news"

    closed_src = {
        "id": "S1",
        "url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/49905",
        "title": "Minor authority cleanup ticket",
        "kind": "gitlab_issue",
        "authority": "development",
        "author": "linus",
        "product": "tor",
        "published_at": "2026-10-01T12:00:00Z",
        "updated_at": DATE,
        "upstream_state": "closed",
        "closed_at": "2026-11-07T12:00:00Z",
        "labels": [],
        "passages": [
            {"id": "S1:P1", "text": "Minor authority cleanup ticket"},
            {"id": "S1:P2", "text": "Closed after routine directory authority check."},
        ],
    }
    closed_case = {
        "id": "dirauth-closed-recent-hold",
        "expected": "hold",
        "candidate": {
            "id": "c" * 24,
            "title": "Minor authority cleanup ticket",
            "summary": "Closed after routine directory authority check.",
            "why_it_matters": "",
            "category": "network",
            "priority": "normal",
            "confidence": "reported",
            "state": "resolved",
            "products": ["tor"],
            "tags": ["network"],
            "published_at": "2026-10-01T12:00:00Z",
            "updated_at": DATE,
            "sources": [{"url": closed_src["url"], "title": closed_src["title"]}],
        },
        "packet": {"sources": [closed_src], "missing_sources": [], "truncated": False},
        "existing_coverage": {"prior_story": None, "recent": []},
    }
    closed_out = tmp_path / "closed-dirauth.jsonl"
    assert module.evaluate(config, [closed_case], closed_out)["matched"] == 1
    closed_rec = json.loads(closed_out.read_text().splitlines()[0])
    assert closed_rec["hold"] == "held.verification.official_not_news"

    mr_src = {
        "id": "S1",
        "url": "https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/950",
        "title": "Merge feature into main",
        "kind": "gitlab_mr",
        "authority": "development",
        "product": "tor",
        "published_at": DATE,
        "updated_at": DATE,
        "upstream_state": "merged",
        "labels": [],
        "passages": [{"id": "S1:P1", "text": "Merge feature into main"}, {"id": "S1:P2", "text": "Merged feature."}],
    }
    later_ts = "2026-11-09T12:00:00Z"
    tag_src = {
        "id": "S2",
        "url": "https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-0.4.9.6",
        "title": "tor-0.4.9.6",
        "kind": "tag",
        "authority": "official",
        "product": "tor",
        "published_at": later_ts,
        "updated_at": later_ts,
        "upstream_state": "",
        "labels": [],
        "passages": [{"id": "S2:P1", "text": "tor-0.4.9.6"}],
    }
    tag_upd_case = {
        "id": "multi-source-tag-update-repair-hold",
        "scope": "latest_update",
        "expected": "hold",
        "candidate": {
            "id": "d" * 24,
            "title": "Feature merged into main",
            "summary": "Maintainers merged the feature into main.",
            "why_it_matters": "",
            "category": "feature",
            "priority": "normal",
            "confidence": "confirmed",
            "state": "tagged",
            "products": ["tor"],
            "tags": ["feature"],
            "published_at": DATE,
            "updated_at": later_ts,
            "sources": [{"url": mr_src["url"], "title": mr_src["title"]}, {"url": tag_src["url"], "title": tag_src["title"]}],
            "updates": [{
                "at": later_ts,
                "text": "The upstream feed lists the tag “tor-0.4.9.6”.",
                "sources": [{"url": tag_src["url"], "title": tag_src["title"]}],
            }],
        },
        "packet": {"sources": [mr_src, tag_src], "missing_sources": [], "truncated": False},
        "existing_coverage": {
            "prior_story": {"id": "d" * 24, "confidence": "confirmed", "state": "merged", "updated_at": DATE},
            "recent": [],
        },
    }
    monkeypatch.setattr(
        module, "EvaluationReviewer",
        _scripted(lambda _c, _v: {"verdict": "revise", "repair": {"update": "Reworded literal tag update."}}),
    )
    tag_upd_out = tmp_path / "tag-upd-hold.jsonl"
    assert module.evaluate(config, [tag_upd_case], tag_upd_out)["matched"] == 1
    tag_upd_rec = json.loads(tag_upd_out.read_text().splitlines()[0])
    assert tag_upd_rec["hold"] == "held.review.tag_repair"


def test_latest_update_matches_note_citation_by_exact_url_before_base_fallback(evaluation, tmp_path, monkeypatch):
    """Select an exact note source entry before falling back to its parent base URL in `evaluate`."""
    module, config = evaluation
    issue_url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/49910"
    note_url = f"{issue_url}#note_42"
    later_ts = "2026-11-09T12:00:00Z"
    parent_src = {
        "id": "S1", "url": issue_url, "title": "Parent issue #49910",
        "kind": "gitlab_issue", "authority": "development", "product": "tor",
        "published_at": DATE, "updated_at": DATE, "upstream_state": "opened", "labels": [],
        "source_entry_id": "parent-entry",
        "passages": [{"id": "S1:P1", "text": "Parent issue #49910"}, {"id": "S1:P2", "text": "Initial issue report."}],
    }
    note_src = {
        "id": "S2", "url": note_url, "title": "Tag note on #49910",
        "kind": "tag", "authority": "official", "product": "tor",
        "published_at": later_ts, "updated_at": later_ts, "upstream_state": "", "labels": [],
        "source_entry_id": "note-entry-42",
        "passages": [{"id": "S2:P1", "text": "Tag note on #49910"}, {"id": "S2:P2", "text": "Note evidence text."}],
    }
    base_case = {
        "id": "exact-note-url-match",
        "scope": "latest_update",
        "expected": "approve",
        "candidate": {
            "id": "e" * 24,
            "title": "Parent issue #49910",
            "summary": "Initial issue report.",
            "why_it_matters": "",
            "category": "network",
            "priority": "normal",
            "confidence": "reported",
            "state": "developing",
            "products": ["tor"],
            "tags": ["network"],
            "published_at": DATE,
            "updated_at": later_ts,
            "sources": [{"url": issue_url, "title": parent_src["title"]}, {"url": note_url, "title": note_src["title"]}],
            "updates": [{"at": later_ts, "text": "A follow-up note updated the ticket.", "sources": [{"url": note_url, "title": note_src["title"]}]}],
        },
        "packet": {"sources": [parent_src, note_src], "missing_sources": [], "truncated": False},
        "existing_coverage": {"prior_story": {"id": "e" * 24, "confidence": "reported", "state": "developing", "updated_at": DATE}, "recent": []},
    }
    seen_rows = []
    orig_advance = module.advance_review

    def _capture_advance(rev, stage, text, prep, state, requests):
        seen_rows.append(prep["row"]["url"])
        return orig_advance(rev, stage, text, prep, state, requests)

    monkeypatch.setattr(module, "advance_review", _capture_advance)
    monkeypatch.setattr(module, "EvaluationReviewer", _scripted(lambda _c, _v: {"verdict": "approve"}))
    assert module.evaluate(config, [base_case], tmp_path / "exact-note.jsonl")["matched"] == 1
    assert seen_rows == [note_url, note_url]

    # When only an unlisted note fragment is cited, fall back to the parent base-URL entry.
    seen_rows.clear()
    fallback_case = copy.deepcopy(base_case)
    fallback_case["id"] = "base-url-fallback-match"
    fallback_case["candidate"]["updates"][-1]["sources"] = [{"url": f"{issue_url}#note_99", "title": "Other note"}]
    assert module.evaluate(config, [fallback_case], tmp_path / "fallback-note.jsonl")["matched"] == 1
    assert seen_rows == [issue_url, issue_url]


def test_corpus_hygiene_helpers_reject_credentials_redact_private_text_and_scope_exemptions():
    """Verify credential rejection, redacted hygiene diagnostics, prior-story number checks, and callback errors."""
    assert _torproject_https("https://torproject.org/")
    assert _torproject_https("https://lists.torproject.org/mailman3/lists/tor-relays.lists.torproject.org/")
    for bad_url in (
        "https://user:secret@lists.torproject.org/path",
        "https://alice@torproject.org/path",
        "https://@lists.torproject.org/path",
        "http://torproject.org/",
    ):
        assert not _torproject_https(bad_url)

    def _buggy(_cand, _ver):
        raise TypeError("callback bug sentinel")

    with pytest.raises(TypeError, match="callback bug sentinel"):
        _scripted(_buggy)().review({}, {"sources": []})

    private_doc = {
        "description": "Public description",
        "defaults": RAW_PUBLIC["defaults"],
        "packets": {
            "secretpacket": {
                "sources": [{
                    "url": "https://user:topsecret@lists.torproject.org/m/1",
                    "title": "Contact private.person@example.org about secretword",
                    "passages": [
                        {"url": "https://evil.example/leak", "text": "See /Users/privateuser/notes.txt"},
                    ],
                }]
            }
        },
        "cases": [{
            "id": "case-1",
            "candidate": {"summary": "Visit https://user:topsecret@lists.torproject.org/m/1 or /Users/privateuser/file."},
        }],
        "coverage_sets": {},
    }
    problems = _judged_hygiene_problems(private_doc, frozenset({"secretword", "secretpacket"}), frozenset())
    assert len(problems) >= 6
    joined = "\n".join(problems)
    for sensitive in ("private.person@example.org", "secretword", "secretpacket", "topsecret", "evil.example", "/Users/privateuser"):
        assert sensitive not in joined

    shared_phrase = "upgrade to version 73"
    case_with_prior = {
        "unsupported": [shared_phrase],
        "candidate": {"title": "Update", "summary": f"Operators must {shared_phrase}.", "why_it_matters": ""},
        "existing_coverage": {
            "prior_story": {"title": "Earlier story", "summary": f"Earlier text says {shared_phrase}.", "why_it_matters": ""},
            "recent": [],
        },
        "packet": {"sources": [{"id": "S1", "title": "Update", "passages": [{"id": "S1:P1", "text": "No version here."}]}]},
    }
    assert _unexplained_case_numbers(case_with_prior) == ["73"]
    case_candidate_only = copy.deepcopy(case_with_prior)
    case_candidate_only["existing_coverage"]["prior_story"]["summary"] = "Earlier text with no number."
    assert _unexplained_case_numbers(case_candidate_only) == []


def test_evaluate_review_specialists_initial_reask_and_low_budget_hold(evaluation, tmp_path, monkeypatch):
    """Continue when initial parallel review returns `'review'` reask and hold fail-closed when specialist verify lacks budget."""
    import threading
    from onionflash import review as review_mod, review_gate as gate_mod

    module, config = evaluation
    clean_case = copy.deepcopy(BY_ID["bastet-corrected"])

    # 1) Initial review throws InconsistentReview (without repair) -> returns ('review', cand) -> loop continues cleanly.
    lock = threading.Lock()
    calls = []

    class _InitialReaskReviewer(_ClientBase):
        """Raise InconsistentReview on first initial review, then approve on validation reask and specialists."""

        last_decoded = None

        def __init__(self, *args, **kwargs):
            """Accept standard evaluation reviewer initialization args."""
            pass

        def review(self, cand, packet, *, coverage=None, verification=False, issue=None, update=False,
                   specialist=None, validation_error=None, on_request=None):
            """Handle initial reask and specialist verification calls."""
            if on_request:
                on_request(1)
            with lock:
                calls.append((verification, specialist, validation_error))
            if not verification and validation_error is None:
                raise review_mod.InconsistentReview()
            if validation_error is not None and on_request and hasattr(on_request, "response_received"):
                on_request.response_received()
            return verdict("approve", update=update)

    monkeypatch.setattr(module, "EvaluationReviewer", _InitialReaskReviewer)
    res_reask = module.evaluate(config, [clean_case], tmp_path / "reask.jsonl", specialists=3)
    assert res_reask["errors"] == 0 and res_reask["matched"] == 1
    assert any(err == review_mod.INCONSISTENT_VERDICT for _, _, err in calls)

    # 2) If stage=='verify' in specialist mode cannot fit all specialists within MAX_SPECIALIST_REVIEW_REQUESTS, hold fail-closed.
    class _LoopingRepairReviewer(_ClientBase):
        """Force one verify repair so the next verify wave lacks specialist budget."""

        last_decoded = None

        def __init__(self, *args, **kwargs):
            """Accept standard evaluation reviewer initialization args."""
            pass

        def review(self, cand, packet, *, coverage=None, verification=False, issue=None, update=False,
                   specialist=None, validation_error=None, on_request=None):
            """Return majority verify revision on first wave so follow-up wave hits specialist budget cap."""
            if on_request:
                on_request(1)
            if not verification:
                return verdict("approve", update=update)
            if specialist in {"grounding_status", "attribution_scope_advice"}:
                return verdict(
                    "revise",
                    criterion="scope_timing",
                    reason="Refine summary detail.",
                    repair={"why_it_matters": "Operator note revision."},
                )
            return verdict("approve", update=update)

    monkeypatch.setattr(gate_mod, "MAX_SPECIALIST_REVIEW_REQUESTS", 6)
    monkeypatch.setattr(module, "MAX_SPECIALIST_REVIEW_REQUESTS", 6, raising=False)
    monkeypatch.setattr(module, "EvaluationReviewer", _LoopingRepairReviewer)
    res_low = module.evaluate(config, [clean_case], tmp_path / "low_budget.jsonl", specialists=3)
    assert res_low["errors"] == 0 and res_low["matched"] == 0
    assert res_low["holds"].get("held.verification.specialist_budget") == 1
