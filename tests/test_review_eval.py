"""Evaluation harness tests for controlled, judged, draft, update, and routing corpora."""

import copy
import json
import re
import stat

import pytest

from helpers import DATE, ROOT, FakeLLM, analysis, completion, item, load_evaluator, scripted_completion, verdict
from onionflash import personal_attribution, review_gate
from onionflash.analyze import AnalysisError, Analyzer
from onionflash.config import DEFAULTS
from onionflash.review import CRITERIA, RELEASE_ISSUE, _packet_refs, final_holds, validate_review
from onionflash.source_packet import build_packet

MOD = load_evaluator()
RAW_PUBLIC = json.loads((ROOT / "tools/review_cases.json").read_text())
CORPUS = [case for name in MOD.CASE_FILES for case in MOD.expand(json.loads((ROOT / "tools" / name).read_text()))]
BY_ID = {c["id"]: c for c in CORPUS}


def evaluator():
    return MOD


def corpus():
    return [copy.deepcopy(c) for c in CORPUS]


@pytest.fixture
def evaluation(tmp_path):
    config = copy.deepcopy(DEFAULTS)
    config["storage"]["output_dir"] = str(tmp_path / "public")
    return MOD, config


def full(reply, packet, *, update=False):
    if "criteria" not in reply:
        reply = verdict(reply["verdict"], repair=reply.get("repair"), update=update,
                        criterion="news_value" if reply["verdict"] == "skip" else "operational_advice")
    return validate_review(reply, packet, update=update)


def scripted(reply):
    class Reviewer:
        last_decoded = None
        def __init__(self, *args, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def review(self, candidate, packet, *, coverage=None, verification=False, issue=None, update=False, on_request=None):
            if on_request is not None:
                on_request(1)
            return full(reply(verification), packet, update=update)
    return Reviewer


def test_controlled_corpus_rubric_coverage_and_coverage_sets():
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
    kept, omitted = MOD.kept_unsupported, MOD.omitted
    compact_req = {"id", "title", "summary", "category", "state", "updated_at", "summary_truncated"}
    compact_opt = {"latest_update", "products", "related"}
    payload = {"candidate": case["candidate"], "packet": case["packet"], "existing_coverage": case["existing_coverage"]}
    assert not [l for l in (case["id"], case.get("audit"), case.get("flaw")) if l and l in json.dumps(payload)]
    assert _packet_refs(case["packet"])
    for src in case["packet"]["sources"]:
        authored = ["author" in p for p in src["passages"][1:]]
        assert authored == sorted(authored, reverse=True)
    assert all((set(r) == {"id", "title", "retracted"} and r["retracted"] is True)
               or (compact_req <= set(r) <= compact_req | compact_opt)
               for r in case["existing_coverage"]["recent"])
    unsupported, forbidden, required = (case.get(k) for k in ("unsupported", "forbidden_classifications", "required"))
    assert case["expected"] in {"skip", "hold"} or bool(unsupported or forbidden or required) == (case["expected"] == "not_approve")
    flagged = kept(case, case["candidate"])
    assert set(unsupported or []) <= set(flagged) and bool(flagged) == bool(unsupported or forbidden)
    assert omitted(case, case["candidate"]) == (required or [])
    twins = [t for t in CORPUS if t["packet"] == case["packet"] and not (t.get("unsupported") or t.get("forbidden_classifications"))]
    assert not any(kept(case, t["candidate"]) for t in twins)
    assert not any(omitted(case, t["candidate"]) for t in twins if t["expected"] == "approve")
    negated, confirms = re.subn(r"\bconfirms?\b", "does not confirm", case["candidate"]["summary"])
    assert not confirms or not kept(case, {"title": "", "summary": negated, "why_it_matters": ""})


@pytest.mark.parametrize("change", [{"unsupported": []}, {"flaw": "invented_impact"}, {"audit": "test", "flaw": "unknown"}])
def test_invalid_evaluation_case_rejected(evaluation, tmp_path, change):
    module, config = evaluation
    with pytest.raises(ValueError, match="Invalid or duplicate evaluation case"):
        module.evaluate(config, [{**copy.deepcopy(BY_ID["bastet-original"]), **change}], tmp_path / "bad.jsonl")


def test_evaluation_scoring_repairs_holds_and_private_output(evaluation, tmp_path, monkeypatch, capsys):
    module, config = evaluation
    by_id = {c["id"]: c for c in corpus()}
    sel = [by_id["bastet-original"], by_id["legitimate-custom-config"], by_id["new-version-tag"]]
    monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda _: {"verdict": "approve"}))
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
                            scripted(lambda v: {"verdict": "approve"} if v else {"verdict": "revise", "repair": repair}))
        o2 = tmp_path / f"fa-{fa}.jsonl"
        r2 = module.evaluate(config, [by_id["bastet-original"]], o2)
        assert (r2["repairs_verified"], r2["false_approvals"], r2["matched"]) == (1, fa, 1 - fa)
        assert json.loads(o2.read_text().splitlines()[0])["kept_unsupported"] == kept

    pos_sel = [c for c in corpus() if c["id"] in {"bastet-corrected", "new-release-news", "new-version-tag"}]
    for verified, repair, verdicts, cleared in (("approve", {"priority": "high"}, ["approve", "approve", "hold"], 0),
                                                 ("hold", {"priority": "high"}, ["hold", "hold", "hold"], 0),
                                                 ("approve", {"why_it_matters": ""}, ["approve", "hold", "hold"], 1)):
        monkeypatch.setattr(module, "EvaluationReviewer",
                            scripted(lambda v: {"verdict": verified} if v else {"verdict": "revise", "repair": repair}))
        o3 = tmp_path / f"{verified}-{cleared}.jsonl"
        r3 = module.evaluate(config, pos_sel, o3)
        matched = verdicts.count("approve")
        assert (r3["matched"], r3["positive_rejections"], r3["false_approvals"], r3["repairs_held"], r3["impact_cleared"]) == (
            matched, 3 - matched, 0, 3 - matched, cleared)
        assert [json.loads(line)["final_verdict"] for line in o3.read_text().splitlines()[:-1]] == verdicts

    unusable_sel = [by_id["bastet-original"], by_id["empty-context-release"]]
    for repair in (None, {"why_it_matters": ""}):
        monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda _: {"verdict": "revise", "repair": repair}))
        ru = module.evaluate(config, unusable_sel, tmp_path / f"unusable-{repair is None}.jsonl")
        assert (ru["errors"], ru["repairs_held"], ru["matched"], ru["positive_rejections"]) == (0, 2, 1, 1)

    monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda _: {"verdict": "hold"}))
    assert module.evaluate(config, [by_id["bastet-confirmed-badge"]], tmp_path / "badge.jsonl")["matched"] == 1


def test_editorial_skips_misses_coverage_verification_and_final_checks(evaluation, tmp_path, monkeypatch):
    module, config = evaluation
    by_id = {c["id"]: c for c in corpus()}
    skip_case = next(c for c in corpus() if c["expected"] == "skip" and not c.get("unsupported"))
    for outcome, misses, false in (("skip", 0, 0), ("hold", 1, 0), ("approve", 1, 1)):
        monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda _: {"verdict": outcome}))
        r = module.evaluate(config, [skip_case], tmp_path / f"sk-{outcome}.jsonl")
        assert (r["editorial_misses"], r["false_approvals"]) == (misses, false)
    monkeypatch.setattr(module, "EvaluationReviewer",
                        scripted(lambda v: {"verdict": "approve"} if v else {"verdict": "revise", "repair": {"summary": "A supported but redundant statement."}}))
    r_rep = module.evaluate(config, [skip_case], tmp_path / "sk-rep.jsonl")
    assert r_rep["false_approvals"] == r_rep["editorial_misses"] == 1

    pair = [by_id["bastet-original"], by_id["bastet-corrected"]]
    for outcome, misses in (("skip", 1), ("hold", 0)):
        monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda _: {"verdict": outcome}))
        rp = module.evaluate(config, pair, tmp_path / f"nw-{outcome}.jsonl")
        assert (rp["editorial_misses"], rp["matched"], rp["positive_rejections"]) == (misses, 1 - misses, 1)

    cov_case = next(c for c in corpus() if c.get("existing_coverage", {}).get("recent"))
    seen = []
    class Inspector(scripted(lambda _: {"verdict": "skip"})):
        def review(self, candidate, packet, *, coverage=None, verification=False, issue=None, on_request=None):
            if on_request is not None:
                on_request(1)
            seen.append(coverage)
            return full({"verdict": "skip"} if verification else {"verdict": "revise", "repair": {"summary": "A source-supported statement."}}, packet)
    monkeypatch.setattr(module, "EvaluationReviewer", Inspector)
    cov_out = tmp_path / "coverage.jsonl"
    rcov = module.evaluate(config, [cov_case], cov_out)
    assert rcov["repairs_skipped"] == 0 and rcov["repairs_held"] == 1 and rcov["holds"] == {"held.verification.disagreed_news": 1}
    assert seen == [cov_case["existing_coverage"], cov_case["existing_coverage"]]
    assert json.loads(cov_out.read_text().splitlines()[0])["existing_coverage"] == cov_case["existing_coverage"]

    app_case = next(c for c in corpus() if c["expected"] == "approve")
    monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda v: {"verdict": "hold"} if v else {"verdict": "approve"}))
    fh_out = tmp_path / "final-hold.jsonl"
    rfh = module.evaluate(config, [app_case], fh_out)
    assert rfh["positive_rejections"] == 1 and rfh["matched"] == 0
    rec_fh = json.loads(fh_out.read_text().splitlines()[0])
    assert rec_fh["published_candidate"] is None and rec_fh["final_verdict"] == "hold"

    monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda _: {"verdict": "approve"}))
    chk_out = tmp_path / "checks.jsonl"
    rchk = module.evaluate(config, [by_id["bastet-removed-as-done"], by_id["bastet-corrected"]], chk_out)
    assert (rchk["false_approvals"], rchk["matched"], rchk["final_holds"], rchk["published_after_checks"]) == (1, 1, 1, 1)
    recs = {r["case"]: r for r in map(json.loads, chk_out.read_text().splitlines()[:-1])}
    assert recs["bastet-removed-as-done"]["final_holds"] == ["completed_action"] and "final_holds" not in recs["bastet-corrected"]
    assert not [c["id"] for c in MOD.expand(RAW_PUBLIC) if c["expected"] == "approve" and final_holds(personal_attribution.normalize(c["candidate"], update=c.get("scope") == "latest_update"), {
        "packet": c["packet"], "mode": "update" if c.get("scope") == "latest_update" else "story", "payload": {"editorial_kind": c["packet"]["sources"][0]["kind"]}})]
    corpus_holds = {
        c["id"]: (c.get("audit"), holds)
        for c in CORPUS
        if c["expected"] == "approve"
        and (holds := final_holds(personal_attribution.normalize(c["candidate"], update=c.get("scope") == "latest_update"), {"packet": c["packet"], "mode": "update" if c.get("scope") == "latest_update" else "story", "payload": {"editorial_kind": c["packet"]["sources"][0]["kind"]}}))
    }
    assert all(audit == "why-it-matters-1" and holds == ["untrusted_operator_claim"] for audit, holds in corpus_holds.values())

    bf = by_id["bugfix-is-not-security-fix"]
    rep = {**bf["candidate"], "title": "Browser update", "summary": "An Android bugfix was released."}
    assert module.kept_unsupported(bf, rep) == ["tags:security"]
    assert module.kept_unsupported(bf, {**rep, "tags": ["release"]}) == []


def test_authored_passages_match_build_packet():
    fields = ("url", "title", "kind", "authority", "product", "published_at", "updated_at", "upstream_state")
    for packet_name, expected_labels in (("scope-correction", []), ("tor-41412-cross-cancellation-edited", ["Security", "Severity::medium"])):
        src = RAW_PUBLIC["packets"][packet_name]["sources"][0]
        itm = {"id": "a" * 24, **{k: src[k] for k in fields}, "labels": list(src.get("labels", [])),
               "content": "\n\n".join(p for p in src["passages"] if isinstance(p, str)),
               "public_comments": [{"author": n["author"], "created_at": n["created_at"], "url": n["url"], "body": n["text"]}
                                   for n in src["passages"] if isinstance(n, dict)]}
        built, _ = build_packet(None, itm, {"sources": [{"id": itm["id"], "url": itm["url"]}]}, {"sources": []}, itm["id"])
        expanded = next(c for c in MOD.expand(RAW_PUBLIC) if c["packet"]["sources"][0]["url"] == src["url"])["packet"]["sources"][0]
        assert expanded["labels"] == built["sources"][0]["labels"] == expected_labels
        assert [list(p.items()) for p in expanded["passages"]] == [list(p.items()) for p in built["sources"][0]["passages"]]
        assert MOD.writer_item(expanded) == {k: itm[k] for k in (*fields, "labels", "content", "public_comments")}

    closed_raw = copy.deepcopy(RAW_PUBLIC)
    closed_raw["packets"]["tor-41412-cross-cancellation-edited"]["sources"][0]["closed_at"] = "2026-10-07T17:16:54Z"
    c_src = closed_raw["packets"]["tor-41412-cross-cancellation-edited"]["sources"][0]
    c_itm = {"id": "a" * 24, **{k: c_src[k] for k in fields}, "closed_at": c_src["closed_at"],
             "labels": list(c_src["labels"]), "content": "\n\n".join(p for p in c_src["passages"] if isinstance(p, str)),
             "public_comments": [{"author": n["author"], "created_at": n["created_at"], "url": n["url"], "body": n["text"]}
                                 for n in c_src["passages"] if isinstance(n, dict)]}
    c_built, _ = build_packet(None, c_itm, {"sources": [{"id": c_itm["id"], "url": c_itm["url"]}]}, {"sources": []}, c_itm["id"])
    c_exp = next(c for c in MOD.expand(closed_raw) if c["packet"]["sources"][0]["url"] == c_src["url"])["packet"]["sources"][0]
    assert c_exp["closed_at"] == c_built["sources"][0]["closed_at"] == "2026-10-07T17:16:54Z"
    assert "closed_at" not in MOD.writer_item(c_exp)


@pytest.mark.parametrize("quoted_only", [False, True])
def test_draft_evaluation_preserves_native_mailing_list_reply_input(monkeypatch, quoted_only):
    reply = "The new measurement covers a smaller sample than the earlier report."
    quoted = "> The earlier participant reported failures across every measured relay."
    incoming = item(
        id="a" * 24, kind="feed", authority="project-sender", title="Re: Relay measurements",
        url="https://lists.torproject.org/mailman3/hyperkitty/list/tor-dev/thread/EXAMPLE/",
        author="casey", sender_domain="example.org",
        content=f"{reply}\n\nOn Monday, an earlier participant wrote:\n{quoted}",
    )
    packet, _ = build_packet(None, incoming, {"sources": [{"id": incoming["id"], "url": incoming["url"]}]},
                             {"sources": []}, incoming["id"])
    evaluated = MOD.writer_item(packet["sources"][0])
    draft = analysis(title="A reply narrows the measurement sample", summary=reply,
                     why_it_matters="", evidence=[quoted if quoted_only else reply])
    config = copy.deepcopy(DEFAULTS)
    config["llm"].update(base_url="https://model.example/v1", fallback_base_urls=[])
    monkeypatch.setenv("ONIONFLASH_LLM_API_KEY", "synthetic-fixture-key")
    payloads = []
    for supplied in (incoming, evaluated):
        with Analyzer(config) as writer:
            writer.client = FakeLLM(completion(draft))
            if quoted_only:
                with pytest.raises(AnalysisError) as caught:
                    writer.analyze(supplied)
                assert caught.value.code == "writer.quoted_only_evidence"
            else:
                assert writer.analyze(supplied)["summary"] == reply
            payloads.append(json.loads(writer.client.requests[0][1]["messages"][-1]["content"]))
    assert payloads[0] == payloads[1]
    assert payloads[1]["author"] == "casey" and payloads[1]["sender_domain"] == "example.org"
    assert payloads[1]["unquoted_content"] == reply and quoted not in payloads[1]["unquoted_content"]


def test_draft_mode_drafts_once_and_isolates_writer_diagnostics(evaluation, tmp_path, monkeypatch):
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

    class DraftWriter(module.Analyzer):
        def complete(self, prompt, payload, schema, name):
            requests.append(payload)
            summary = ("Operators must update their configurations." if "bastet" in payload["title"]
                       else "A fix is proposed." if "crash fix" in payload["title"] else "A faithful summary of the report.")
            return {"publish": True, "title": payload["title"], "summary": summary, "why_it_matters": "",
                    "category": "security", "priority": "normal", "confidence": "reported", "state": "developing",
                    "products": [payload["product"]], "tags": ["security"], "evidence": [payload["title"]]}

    orig_eval_reviewer = module.EvaluationReviewer
    monkeypatch.setattr(module, "Analyzer", DraftWriter)
    monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda _: {"verdict": "approve"}))
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

    class FlakyWriter(module.Analyzer):
        def complete(self, prompt, payload, schema, name):
            if "bastet" in payload["title"] or "crash fix" in payload["title"]:
                raise module.AnalysisError("LLM request failed (HTTP 500)")
            return {"publish": True, "title": payload["title"], "summary": f"A faithful summary: {req_text}.",
                    "why_it_matters": "", "category": "security", "priority": "normal", "confidence": "reported",
                    "state": "developing", "products": [payload["product"]], "tags": ["security"], "evidence": [payload["title"]]}

    replies = iter([{"invalid": True}, verdict("approve"), verdict("approve")])
    monkeypatch.setattr(module, "EvaluationReviewer", orig_eval_reviewer)
    monkeypatch.setattr(module, "Analyzer", FlakyWriter)
    monkeypatch.setattr(module.Reviewer, "complete", scripted_completion(lambda *a: next(replies)))
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
    module, config = evaluation
    by_id = {c["id"]: c for c in corpus()}
    om_case = by_id["draft-omits-disclosure"]
    for out_v, om, miss, match in (("approve", 1, 0, 0), ("skip", 0, 1, 0), ("hold", 0, 0, 1)):
        monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda _: {"verdict": out_v}))
        r = module.evaluate(config, [om_case], tmp_path / f"om-{out_v}.jsonl")
        assert (r["omissions"], r["editorial_misses"], r["matched"], r["false_approvals"], r["controlled_mismatches"]) == (
            om, miss, match, 0, 1 - match)

    off_case = by_id["official-routine-post"]
    comm_case = copy.deepcopy(off_case)
    comm_case["packet"]["sources"][0]["authority"] = "community"
    for name, sel, out_v, match, fa, miss, holds in (
        ("hold", off_case, "hold", 1, 0, 0, {"held.review.model_hold": 1}),
        ("approve", off_case, "approve", 0, 1, 0, {}),
        ("official-skip", off_case, "skip", 1, 0, 0, {"held.verification.official_not_news": 1}),
        ("community-skip", comm_case, "skip", 0, 0, 1, {}),
    ):
        monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda _: {"verdict": out_v}))
        r = module.evaluate(config, [sel], tmp_path / f"{name}.jsonl")
        assert (r["matched"], r["false_approvals"], r["editorial_misses"], r["holds"]) == (match, fa, miss, holds)

    replies_iter = iter([{"verdict": "approve"}, {"verdict": "revise", "repair": {"why_it_matters": ""}}, {"verdict": "approve"}])
    monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda _: next(replies_iter)))
    loop_out = tmp_path / "loop.jsonl"
    rloop = module.evaluate(config, [by_id["bastet-original"]], loop_out)
    rec_loop = json.loads(loop_out.read_text().splitlines()[0])
    assert (rloop["matched"], rloop["false_approvals"], rloop["verification_repairs"]) == (1, 0, 1)
    assert [(e["stage"], e["result"]["verdict"]) for e in rec_loop["reviews"]] == [
        ("review", "approve"), ("verification", "revise"), ("verification", "approve")]
    assert rec_loop["published_candidate"]["why_it_matters"] == "" and rec_loop["final_verdict"] == "approve"

    monkeypatch.undo()
    monkeypatch.setattr(module.Reviewer, "complete", scripted_completion(lambda *a: verdict("skip", criterion="source_support")))
    conv_out = tmp_path / "converted.jsonl"
    assert module.evaluate(config, [by_id["bastet-original"]], conv_out)["matched"] == 1
    rec_conv = json.loads(conv_out.read_text().splitlines()[0])
    assert (rec_conv["model_verdict"], rec_conv["result"]["verdict"], rec_conv["final_verdict"]) == ("skip", "hold", "hold")
    assert rec_conv["reviews"][0]["result"]["model_verdict"] == "skip" and "verification" not in rec_conv

    payloads = []
    monkeypatch.setattr(module.Reviewer, "complete", scripted_completion(lambda prompt, payload, *a: (payloads.append(payload), next(rel_replies))[1]))
    fixed = verdict("revise", repair={"title": "Opt-in exit proxying merged", "category": "feature", "tags": ["feature"]}, criterion="status")
    for name, rel_replies, holds, pub in (("unfixed", iter([verdict(), verdict()]), {"held.review.release_labels": 1}, None),
                                          ("fixed", iter([verdict(), fixed, verdict()]), {}, "Opt-in exit proxying merged")):
        payloads.clear()
        o = tmp_path / f"rel-{name}.jsonl"
        res = module.evaluate(config, [by_id["merged-is-not-release"]], o)
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
    if flaws is None:
        assert MOD.target_missed({}) == expected
    else:
        payload = {f: {"cases": c, "ok": c, "unique": u, "paired": p} for f, (c, u, p) in flaws.items()}
        payload["clean"] = {"cases": clean[0], "ok": clean[1], "unique": clean[0]}
        assert MOD.target_missed(payload) == expected


@pytest.mark.parametrize("failure", [{"target_missed": ["catch"]}, {"controlled_mismatches": 1}, {"false_routes": 1}, {"errors": 1}, {"incomplete": True}])
def test_main_cli_failure_returns_one(evaluation, tmp_path, monkeypatch, failure):
    module, config = evaluation
    passed = {"controlled_mismatches": 0, "target_missed": [], "errors": 0, "incomplete": False}
    monkeypatch.setattr(module, "load_config", lambda _: config)
    monkeypatch.setattr(module, "evaluate", lambda cfg, cs, out, **opt: passed | failure)
    assert module.main(["--config", str(tmp_path / "config.toml"), "--output", str(tmp_path / "report.jsonl")]) == 1


def test_judged_scoring_thresholds_and_cli_main(evaluation, tmp_path, monkeypatch):
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

    class Discerning(scripted(None)):
        def review(self, candidate, packet, *, coverage=None, verification=False, issue=None, update=False, on_request=None):
            if on_request is not None:
                on_request(1)
            flawed = "update their configurations" in candidate["why_it_matters"] or candidate["confidence"] == "confirmed"
            return full({"verdict": "hold" if flawed else "approve"}, packet, update=update)

    rows = lambda s, b, st, cl, rounds=1: {
        "invented_impact": dict(zip(("ok", "paired"), s), cases=rounds, unique=1),
        "badge_misuse": dict(zip(("ok", "paired"), b), cases=rounds, unique=1),
        "stale_fact": dict(zip(("ok", "paired"), st), cases=rounds, unique=1),
        "clean": {"cases": 2 * rounds, "ok": cl, "unique": 2},
    }
    clearing = scripted(lambda v: {"verdict": "approve"} if v else {"verdict": "revise", "repair": {"why_it_matters": ""}})
    for name, rev_cls, rounds, j_exp, missed in (
        ("approve", scripted(lambda _: {"verdict": "approve"}), 1, rows((0, 0), (0, 0), (1, 1), 2), ["catch"]),
        ("clear", clearing, 1, rows((1, 0), (0, 0), (0, 0), 0), ["catch", "false_alarms"]),
        ("skip", scripted(lambda _: {"verdict": "skip"}), 1, rows((0, 0), (0, 0), (0, 0), 0), ["catch", "false_alarms"]),
        ("discerning", Discerning, 2, rows((2, 2), (2, 2), (2, 2), 4, rounds=2), []),
    ):
        monkeypatch.setattr(module, "EvaluationReviewer", rev_cls)
        res = module.evaluate(config, cases, tmp_path / f"{name}.jsonl", rounds=rounds)
        assert (res["judged"], res["target_missed"], res["controlled_mismatches"]) == (j_exp, missed, 0), name
    assert (res["catch_rate"], res["paired_catch_rate"], res["false_alarm_rate"]) == (1.0, 1.0, 0.0)
    res_fl = module.evaluate(config, [c for c in cases if "flaw" in c], tmp_path / "flagged.jsonl")
    assert (res_fl["judged"], res_fl["target_missed"]) == ({k: v for k, v in rows((1, 0), (1, 0), (1, 1), 0).items() if k != "clean"}, ["catch"])
    assert (res_fl["catch_rate"], res_fl["paired_catch_rate"], res_fl["false_alarm_rate"]) == (1.0, 0.333, None)

    calls, passed = [], {"controlled_mismatches": 0, "target_missed": [], "errors": 0, "incomplete": False}
    monkeypatch.setattr(module, "load_config", lambda _: config)
    monkeypatch.setattr(module, "evaluate", lambda cfg, cs, out, **opt: calls.append(([c["id"] for c in cs], opt["draft"])) or passed)
    base = ["--config", str(tmp_path / "config.toml"), "--output", str(tmp_path / "report.jsonl")]
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
    base_raw = next(c for c in RAW_PUBLIC["cases"] if c["id"] == "update-fix-merged")
    with pytest.raises(ValueError):
        MOD.expand({**RAW_PUBLIC, "cases": [bad_mut(copy.deepcopy(base_raw))]})


def test_latest_update_scope_scans_only_new_entry_and_excludes_draft_mode(evaluation, tmp_path, monkeypatch):
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
    monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda _: {"verdict": "approve"}))
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
    module, config = evaluation
    pos = copy.deepcopy(BY_ID["same-story-issue-mentions-covered-release"])
    target_id = pos["expected_same_story"]
    retracted_id = next(r["id"] for r in pos["existing_coverage"]["recent"] if r.get("retracted"))
    with pytest.raises(ValueError, match="Invalid or duplicate evaluation case"):
        module.evaluate(config, [mutate(pos, target_id, retracted_id, BY_ID)], tmp_path / "bad-route.jsonl")


def test_expected_same_story_scores_matched_missed_wrong_unroutable_and_false_routes(evaluation, tmp_path, monkeypatch):
    module, config = evaluation
    by_id = {c["id"]: c for c in corpus()}
    pos, neg, hold_neg = by_id["same-story-issue-mentions-covered-release"], by_id["same-story-neg-different-tor-version"], by_id["retracted-report-mirror"]
    target_id = pos["expected_same_story"]
    other_id = next(r["id"] for r in pos["existing_coverage"]["recent"] if r["id"] != target_id and not r.get("retracted"))

    def routed_reviewer(reply_fn):
        class RoutedReviewer:
            last_decoded = None
            def __init__(self, *args, **kwargs): pass
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def review(self, candidate, packet, *, coverage=None, verification=False, issue=None, update=False, on_request=None):
                if on_request is not None:
                    on_request(1)
                v_name, same = reply_fn(candidate, verification)
                base = verdict(v_name, update=update, criterion="new_information" if v_name == "skip" else "operational_advice")
                if v_name == "skip":
                    base["criteria"]["new_information"]["reason"] = f"Same event as {same or target_id}."
                return {**validate_review(base, packet, update=update), "same_story": same}
        return RoutedReviewer

    monkeypatch.setattr(module, "EvaluationReviewer", routed_reviewer(
        lambda cand, _: ("skip", target_id) if cand["id"] == pos["candidate"]["id"]
        else ("hold", None) if cand["id"] == hold_neg["candidate"]["id"] else ("approve", None)))
    out_ok = tmp_path / "routes-ok.jsonl"
    res_ok = module.evaluate(config, [pos, neg, hold_neg], out_ok)
    assert (res_ok["route_cases"], res_ok["matched_routes"], res_ok["missed_routes"], res_ok["false_routes"],
            res_ok["wrong_routes"], res_ok["matched"], res_ok["controlled_mismatches"]) == (3, 1, 0, 0, 0, 3, 0)
    recs_ok = {r["case"]: r for r in map(json.loads, out_ok.read_text().splitlines()[:-1])}
    assert recs_ok[pos["id"]]["same_story"] == target_id and recs_ok[neg["id"]]["same_story"] is None

    repost = by_id["same-story-official-release-only-repeat"]
    monkeypatch.setattr(module, "EvaluationReviewer", routed_reviewer(lambda *_: ("skip", repost["expected_same_story"])))
    routed = module.evaluate(config, [repost], tmp_path / "release-repost.jsonl")
    assert (routed["matched_routes"], routed["matched"], routed["controlled_mismatches"]) == (1, 1, 0)

    for fn, exp_key in ((lambda *_: ("skip", None), "missed_routes"), (lambda *_: ("skip", other_id), "wrong_routes")):
        monkeypatch.setattr(module, "EvaluationReviewer", routed_reviewer(fn))
        res = module.evaluate(config, [pos], tmp_path / f"{exp_key}.jsonl")
        assert (res["route_cases"], res["matched_routes"], res[exp_key], res["matched"]) == (1, 0, 1, 0)

    monkeypatch.setattr(module, "EvaluationReviewer", routed_reviewer(lambda *_: ("skip", target_id)))
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
    monkeypatch.setattr(module, "EvaluationReviewer", routed_reviewer(lambda *_: ("skip", nh_id)))
    nh_res = module.evaluate(config, [nh_case], tmp_path / "eval_out.jsonl")
    assert (nh_res["matched_routes"], nh_res["wrong_routes"], nh_res["matched"]) == (0, 1, 0)

    with monkeypatch.context() as mp:
        mp.setattr(module, "EvaluationReviewer", routed_reviewer(lambda *_: ("approve", target_id)))
        mp.setattr(review_gate, "next_step", lambda reviews, text, prepared: ("route", target_id))
        out_gate = tmp_path / "routes-gate.jsonl"
        res_gate = module.evaluate(config, [pos], out_gate)
        rec_gate = json.loads(out_gate.read_text().splitlines()[0])
        assert (res_gate["matched_routes"], res_gate["matched"], res_gate["false_approvals"]) == (1, 1, 0)
        assert rec_gate["final_verdict"] == "route" and rec_gate["published_candidate"] is None
