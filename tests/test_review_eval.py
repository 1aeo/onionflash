import copy
import importlib.util
import json
import re
import stat
from pathlib import Path

import pytest

from approval_helpers import verdict
from onionflash.config import DEFAULTS
from onionflash.review import CRITERIA, RELEASE_ISSUE, _packet_refs, final_holds, validate_review
from onionflash.source_packet import build_packet


ROOT = Path(__file__).resolve().parents[1]


def evaluator():
    spec = importlib.util.spec_from_file_location("review_eval_tool", ROOT / "tools/evaluate_review.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def evaluation(tmp_path):
    """The evaluator module and a configuration whose public output is under tmp_path."""
    config = copy.deepcopy(DEFAULTS)
    config["storage"]["output_dir"] = str(tmp_path / "public")
    return evaluator(), config


def corpus():
    module = evaluator()
    return [case for name in module.CASE_FILES for case in module.expand(json.loads((ROOT / "tools" / name).read_text()))]


def full(reply, packet):
    """A reply validated as the reviewer validates one. Shorthand such as {"verdict": "skip"} becomes a complete
    verdict, in which a skip fails news value and any other refusal operational advice."""
    if "criteria" not in reply:
        reply = verdict(reply["verdict"], repair=reply.get("repair"),
                        criterion="news_value" if reply["verdict"] == "skip" else "operational_advice")
    return validate_review(reply, packet)


def scripted(reply):
    """A reviewer stand-in whose reply comes from reply(verification)."""
    class Reviewer:
        last_decoded = None
        def __init__(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def review(self, candidate, packet, *, coverage=None, verification=False, issue=None):
            return full(reply(verification), packet)
    return Reviewer


def test_controlled_corpus_is_blinded_and_covers_rubric():
    """Keep evaluation labels out of model input and cover every review criterion."""
    module = evaluator()
    kept, omitted = module.kept_unsupported, module.omitted
    cases = corpus()
    assert len({c["id"] for c in cases}) == len(cases)
    assert set(CRITERIA) <= {criterion for c in cases for criterion in c["coverage"]}
    assert any(c["expected"] == "approve" and "operational_advice" in c["coverage"] for c in cases)
    raw = json.loads((ROOT / "tools/review_cases.json").read_text())
    with pytest.raises(KeyError):  # an unknown coverage set fails to load
        evaluator().expand({**raw, "cases": [{**raw["cases"][0], "coverage_set": "missing"}]})
    for case in cases:
        payload = {"candidate": case["candidate"], "packet": case["packet"], "existing_coverage": case["existing_coverage"]}
        assert not [label for label in (case["id"], case.get("audit"), case.get("flaw")) if label and label in json.dumps(payload)]
        assert _packet_refs(case["packet"])
        # Notes come right after each title and before the description, as build_packet orders them.
        for source in case["packet"]["sources"]:
            authored = ["author" in passage for passage in source["passages"][1:]]
            assert authored == sorted(authored, reverse=True), case["id"]
        # Recent rows have the compact keys that coverage_background sends.
        assert all(set(row) == {"id", "title", "summary", "category", "state", "updated_at", "summary_truncated"}
                   for row in case["existing_coverage"]["recent"]), case["id"]
        # A flawed draft flags wording or labels that it contains and its faithful twins do not,
        # or omits required wording that its approved twins contain.
        unsupported, forbidden, required = (case.get(key) for key in ("unsupported", "forbidden_classifications", "required"))
        assert case["expected"] in {"skip", "hold"} or bool(unsupported or forbidden or required) == (case["expected"] == "not_approve")
        flagged = kept(case, case["candidate"])
        assert set(unsupported or []) <= set(flagged)
        assert bool(flagged) == bool(unsupported or forbidden)
        assert omitted(case, case["candidate"]) == (required or [])
        twins = [twin for twin in cases if twin["packet"] == case["packet"]
                 and not (twin.get("unsupported") or twin.get("forbidden_classifications"))]
        assert not any(kept(case, twin["candidate"]) for twin in twins), case["id"]
        assert not any(omitted(case, twin["candidate"]) for twin in twins if twin["expected"] == "approve"), case["id"]
        # Nor does the smallest faithful repair of "the source confirms that X": "... does not confirm that X".
        negated, confirms = re.subn(r"\bconfirms?\b", "does not confirm", case["candidate"]["summary"])
        assert not confirms or not kept(case, {"title": "", "summary": negated, "why_it_matters": ""}), case["id"]


def test_evaluation_records_false_approvals_and_writes_private_new_file(evaluation, tmp_path, monkeypatch, capsys):
    module, config = evaluation
    # An approved tag notice publishes; the gate holds only a repair of one.
    selected = [c for c in corpus() if c["id"] in {"bastet-original", "legitimate-custom-config", "new-version-tag"}]
    monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda verification: {"verdict": "approve"}))
    output = tmp_path / "private/report.jsonl"
    result = module.evaluate(config, selected, output)
    assert result["false_approvals"] == 1 and result["matched"] == 2
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert json.loads(output.read_text().splitlines()[-1])["summary"] == result
    with pytest.raises(FileExistsError):
        module.evaluate(config, selected, output)
    with pytest.raises(ValueError, match="outside public"):
        module.evaluate(config, selected, tmp_path / "public/private-evidence.jsonl")
    assert "candidate" not in capsys.readouterr().out


def test_verified_repair_that_keeps_flagged_wording_is_a_false_approval(evaluation, tmp_path, monkeypatch):
    module, config = evaluation
    selected = [c for c in corpus() if c["id"] == "bastet-original"]
    # A priority-only repair keeps the unsupported operator advice; clearing why_it_matters removes it.
    for repair, kept, false_approvals in (({"priority": "high"}, ["update their configurations"], 1),
                                          ({"why_it_matters": ""}, [], 0)):
        monkeypatch.setattr(module, "EvaluationReviewer", scripted(
            lambda verification: {"verdict": "approve"} if verification else {"verdict": "revise", "repair": repair}))
        output = tmp_path / f"{false_approvals}.jsonl"
        result = module.evaluate(config, selected, output)
        assert (result["repairs_verified"], result["false_approvals"], result["matched"]) == (1, false_approvals, 1 - false_approvals)
        assert json.loads(output.read_text().splitlines()[0])["kept_unsupported"] == kept


def test_verified_repair_of_a_positive_case_is_an_approval(evaluation, tmp_path, monkeypatch):
    module, config = evaluation
    selected = [c for c in corpus() if c["id"] in {"bastet-corrected", "new-release-news", "new-version-tag"}]
    # The gate publishes a repaired story only if verification approves it, and never repairs a tag notice.
    # Clearing a supported impact sentence still publishes, but is counted; a story without one has none
    # to clear, so its approval is not counted and clearing it is a no-op that holds.
    for verified, repair, verdicts, cleared in (("approve", {"priority": "high"}, ["approve", "approve", "hold"], 0),
                                                 ("hold", {"priority": "high"}, ["hold", "hold", "hold"], 0),
                                                 ("approve", {"why_it_matters": ""}, ["approve", "hold", "hold"], 1)):
        monkeypatch.setattr(module, "EvaluationReviewer", scripted(
            lambda verification: {"verdict": verified} if verification else {"verdict": "revise", "repair": repair}))
        output = tmp_path / f"{verified}-{cleared}.jsonl"
        result = module.evaluate(config, selected, output)
        matched = verdicts.count("approve")
        assert (result["matched"], result["positive_rejections"], result["false_approvals"], result["repairs_held"],
                result["impact_cleared"]) == (matched, 3 - matched, 0, 3 - matched, cleared)
        assert [json.loads(line)["final_verdict"] for line in output.read_text().splitlines()[:-1]] == verdicts


def test_unusable_repair_is_scored_as_the_gate_hold(evaluation, tmp_path, monkeypatch):
    """A null or no-op repair holds in the gate, so it is neither an error nor a publication."""
    module, config = evaluation
    selected = [c for c in corpus() if c["id"] in {"bastet-original", "empty-context-release"}]
    for repair in (None, {"why_it_matters": ""}):
        monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda verification: {"verdict": "revise", "repair": repair}))
        result = module.evaluate(config, selected, tmp_path / f"{repair is None}.jsonl")
        assert (result["errors"], result["repairs_held"], result["matched"], result["positive_rejections"]) == (0, 2, 1, 1)


def test_repair_verification_refuses_a_negative_case_without_its_unsupported_wording(evaluation, tmp_path, monkeypatch):
    module, config = evaluation
    cases = {c["id"]: c for c in corpus()}
    # A flaw needs a labeled set and a known name.
    for change in ({"unsupported": []}, {"flaw": "invented_impact"}, {"audit": "test", "flaw": "unknown"}):
        with pytest.raises(ValueError, match="Invalid or duplicate evaluation case"):
            module.evaluate(config, [{**cases["bastet-original"], **change}], tmp_path / "report.jsonl")
    # Forbidden labels alone flag a badge flaw; no placeholder phrase is needed.
    monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda verification: {"verdict": "hold"}))
    assert module.evaluate(config, [cases["bastet-confirmed-badge"]], tmp_path / "badge.jsonl")["matched"] == 1


def test_editorial_skip_requires_skip_and_never_counts_repaired_publication_as_success(evaluation, tmp_path, monkeypatch):
    """Count publication of a negative editorial case as a failure even after repair."""
    module, config = evaluation
    case = next(c for c in corpus() if c["expected"] == "skip" and not c.get("unsupported"))
    for outcome, misses, false in (("skip", 0, 0), ("hold", 1, 0), ("approve", 1, 1)):
        monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda verification: {"verdict": outcome}))
        result = module.evaluate(config, [case], tmp_path / (outcome + ".jsonl"))
        assert result["editorial_misses"] == misses
        assert result["false_approvals"] == false
    monkeypatch.setattr(module, "EvaluationReviewer", scripted(
        lambda verification: {"verdict": "approve"} if verification else
        {"verdict": "revise", "repair": {"summary": "A supported but redundant statement."}}))
    result = module.evaluate(config, [case], tmp_path / "repaired.jsonl")
    assert result["false_approvals"] == result["editorial_misses"] == 1


def test_skipping_newsworthy_negative_is_an_editorial_miss(evaluation, tmp_path, monkeypatch):
    """A not_approve case is news with a flawed draft: it may hold, but never skip. A skipped approval is a rejection, not a miss."""
    module, config = evaluation
    selected = [c for c in corpus() if c["id"] in {"bastet-original", "bastet-corrected"}]
    for outcome, misses in (("skip", 1), ("hold", 0)):
        monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda verification: {"verdict": outcome}))
        result = module.evaluate(config, selected, tmp_path / (outcome + ".jsonl"))
        assert (result["editorial_misses"], result["matched"], result["positive_rejections"]) == (misses, 1 - misses, 1)


def test_coverage_background_is_passed_to_both_reviews_and_saved_privately(evaluation, tmp_path, monkeypatch):
    """Keep both stages and the private report bound to the same coverage context."""
    module, config = evaluation
    case = next(c for c in corpus() if c.get("existing_coverage", {}).get("recent"))
    seen = []
    class Inspector(scripted(lambda verification: {"verdict": "skip"})):
        def review(self, candidate, packet, *, coverage=None, verification=False, issue=None):
            """Capture each background and simulate a repair followed by a skip, which disagrees with the first review."""
            seen.append(coverage)
            return full({"verdict": "skip"} if verification else
                        {"verdict": "revise", "repair": {"summary": "A source-supported statement."}}, packet)
    monkeypatch.setattr(module, "EvaluationReviewer", Inspector)
    output = tmp_path / "coverage.jsonl"
    result = module.evaluate(config, [case], output)
    assert result["repairs_skipped"] == 0 and result["repairs_held"] == 1
    assert result["holds"] == {"held.verification.disagreed_news": 1}
    assert seen == [case["existing_coverage"], case["existing_coverage"]]
    assert json.loads(output.read_text().splitlines()[0])["existing_coverage"] == case["existing_coverage"]


def test_first_approval_is_not_publication_without_final_verification(evaluation, tmp_path, monkeypatch):
    """Score the final refusal instead of treating initial approval as publication."""
    module, config = evaluation
    case = next(c for c in corpus() if c["expected"] == "approve")
    monkeypatch.setattr(module, "EvaluationReviewer", scripted(
        lambda verification: {"verdict": "hold"} if verification else {"verdict": "approve"}))
    result = module.evaluate(config, [case], tmp_path / "final-hold.jsonl")
    assert result["positive_rejections"] == 1 and result["matched"] == 0
    record = json.loads((tmp_path / "final-hold.jsonl").read_text().splitlines()[0])
    assert record["published_candidate"] is None and record["final_verdict"] == "hold"


def test_final_checks_count_apart_from_the_reviewer_scores(evaluation, tmp_path, monkeypatch):
    """Scores measure the reviewer alone: an approval the gate's final checks would hold is still a false approval."""
    module, config = evaluation
    selected = [c for c in corpus() if c["id"] in {"bastet-removed-as-done", "bastet-corrected"}]
    monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda verification: {"verdict": "approve"}))
    output = tmp_path / "checks.jsonl"
    result = module.evaluate(config, selected, output)
    assert (result["false_approvals"], result["matched"], result["final_holds"], result["published_after_checks"]) == (1, 1, 1, 1)
    records = {record["case"]: record for record in map(json.loads, output.read_text().splitlines()[:-1])}
    assert records["bastet-removed-as-done"]["final_holds"] == ["completed_action"]
    assert "final_holds" not in records["bastet-corrected"]
    # No case that must publish is held by a final check.
    assert not [case["id"] for case in corpus() if case["expected"] == "approve" and final_holds(case["candidate"], {
        "packet": case["packet"], "payload": {"editorial_kind": case["packet"]["sources"][0]["kind"]}})]


def test_evaluation_detects_unsupported_labels_after_text_is_repaired():
    """Removing a headline claim cannot hide its surviving misleading classification."""
    module = evaluator()
    case = next(c for c in corpus() if c["id"] == "bugfix-is-not-security-fix")
    repaired = {**case["candidate"], "title": "Browser update", "summary": "An Android bugfix was released."}
    assert module.kept_unsupported(case, repaired) == ["tags:security"]
    repaired["tags"] = ["release"]
    assert module.kept_unsupported(case, repaired) == []


def test_authored_passages_match_build_packet():
    """An authored passage has a stored note's keys and place, and drafts back to the same note and labels."""
    module = evaluator()
    raw = json.loads((ROOT / "tools/review_cases.json").read_text())
    fields = ("url", "title", "kind", "authority", "product", "published_at", "updated_at", "upstream_state")
    for packet_name, expected_labels in (("scope-correction", []),
                                         ("tor-41412-cross-cancellation-edited", ["Security", "Severity::medium"])):
        source = raw["packets"][packet_name]["sources"][0]
        item = {"id": "a" * 24, **{key: source[key] for key in fields},
                "labels": list(source.get("labels", [])),
                "content": "\n\n".join(passage for passage in source["passages"] if isinstance(passage, str)),
                "public_comments": [{"author": note["author"], "created_at": note["created_at"], "url": note["url"], "body": note["text"]}
                                    for note in source["passages"] if isinstance(note, dict)]}
        built, _ = build_packet(None, item, {"sources": [{"id": item["id"], "url": item["url"]}]}, {"sources": []}, item["id"])
        expanded = next(c for c in module.expand(raw) if c["packet"]["sources"][0]["url"] == source["url"])["packet"]["sources"][0]
        assert expanded["labels"] == built["sources"][0]["labels"] == expected_labels
        assert [list(passage.items()) for passage in expanded["passages"]] == [list(passage.items()) for passage in built["sources"][0]["passages"]]
        assert module.writer_item(expanded) == {key: item[key] for key in (*fields[1:], "labels", "content", "public_comments")}


def test_draft_mode_drafts_each_packet_once_and_scores_draft_and_publication(evaluation, tmp_path, monkeypatch):
    """One writer request per packet and round reviews under every coverage set; a tag notice needs none."""
    module, config = evaluation
    raw = json.loads((ROOT / "tools/review_cases.json").read_text())
    groups = {"draft:bastet", "draft:issue-update/prior-issue", "draft:issue-update/related-issue", "draft:new-version-tag",
              "draft:refactor-with-disclosure"}
    cases = [case for case in module.draft_cases(raw) if case["id"] in groups]
    assert len(cases) == len(groups)
    # Each group has an approved draft, so each expects approval, even where it also has flawed ones.
    assert {case["expected"] for case in cases} == {"approve"}
    requests = []

    class Writer(module.Analyzer):
        def complete(self, prompt, payload, schema, name):
            requests.append(payload)
            summary = ("Operators must update their configurations." if "bastet" in payload["title"]
                       else "A fix is proposed." if "crash fix" in payload["title"] else "A faithful summary of the report.")
            return {"publish": True, "title": payload["title"], "summary": summary, "why_it_matters": "",
                    "category": "security", "priority": "normal", "confidence": "reported", "state": "developing",
                    "products": [payload["product"]], "tags": ["security"], "evidence": [payload["title"]]}
    monkeypatch.setattr(module, "Analyzer", Writer)
    monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda verification: {"verdict": "approve"}))
    output = tmp_path / "drafts.jsonl"
    result = module.evaluate(config, cases, output, rounds=2, draft=True)
    assert sorted(payload["title"] for payload in requests) == sorted(
        2 * [source["sources"][0]["title"] for name, source in raw["packets"].items()
             if name in {"bastet", "issue-update", "refactor-with-disclosure"}])
    note = next(payload for payload in requests if "public_comments" in payload)["public_comments"]
    assert note == [{key: passage[key] for key in ("author", "created_at")} | {"body": passage["text"]}
                    for passage in raw["packets"]["refactor-with-disclosure"]["sources"][0]["passages"] if isinstance(passage, dict)]
    # A flagged draft publishes as a false approval, also where its group's own candidate is clean, and each
    # case scores the draft against its own flags; the draft that omits the disclosure is an omission.
    assert (result["draft_unsupported"], result["false_approvals"], result["omissions"], result["matched"]) == (4, 4, 2, 4)
    records = [json.loads(line) for line in output.read_text().splitlines()[:-1]]
    assert all(record["candidate"]["summary"] == record["draft"]["summary"] for record in records)
    flagged = {"draft:bastet": ["update their configurations"], "draft:issue-update/prior-issue": ["fix is proposed"]}
    assert [record["draft_kept_unsupported"] for record in records] == [flagged.get(record["case"], []) for record in records]


def test_missing_required_wording_is_an_omission_not_a_false_approval(evaluation, tmp_path, monkeypatch):
    module, config = evaluation
    case = next(c for c in corpus() if c["id"] == "draft-omits-disclosure")
    for outcome, omissions, misses, matched in (("approve", 1, 0, 0), ("skip", 0, 1, 0), ("hold", 0, 0, 1)):
        monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda verification: {"verdict": outcome}))
        result = module.evaluate(config, [case], tmp_path / f"{outcome}.jsonl")
        assert (result["omissions"], result["editorial_misses"], result["matched"], result["false_approvals"],
                result["controlled_mismatches"]) == (omissions, misses, matched, 0, 1 - matched)


def test_hold_case_matches_only_a_hold(evaluation, tmp_path, monkeypatch):
    """Publishing a case that must be held is a false approval, and skipping it is an editorial miss. The gate
    verifies an official item that both reviews find not newsworthy, then holds it instead of skipping it."""
    module, config = evaluation
    case = next(c for c in corpus() if c["id"] == "official-routine-post")
    community = copy.deepcopy(case)
    community["packet"]["sources"][0]["authority"] = "community"
    for name, selected, outcome, matched, false, misses, holds in (
            ("hold", case, "hold", 1, 0, 0, {"held.review.model_hold": 1}), ("approve", case, "approve", 0, 1, 0, {}),
            ("official-skip", case, "skip", 1, 0, 0, {"held.verification.official_not_news": 1}),
            ("community-skip", community, "skip", 0, 0, 1, {})):
        monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda verification: {"verdict": outcome}))
        result = module.evaluate(config, [selected], tmp_path / f"{name}.jsonl")
        assert (result["matched"], result["false_approvals"], result["editorial_misses"], result["holds"]) == (
            matched, false, misses, holds), name


def test_model_verdict_keeps_the_reply_that_validation_replaced(evaluation, tmp_path, monkeypatch):
    """A skip that fails no editorial criterion holds; the report keeps the model's own verdict."""
    module, config = evaluation
    case = next(c for c in corpus() if c["id"] == "bastet-original")
    monkeypatch.setattr(module.Reviewer, "complete", lambda self, *args: verdict("skip", criterion="source_support"))
    output = tmp_path / "converted.jsonl"
    assert module.evaluate(config, [case], output)["matched"] == 1
    record = json.loads(output.read_text().splitlines()[0])
    assert (record["model_verdict"], record["result"]["verdict"], record["final_verdict"]) == ("skip", "hold", "hold")
    assert record["reviews"][0]["result"]["model_verdict"] == "skip" and "verification" not in record


def test_release_labels_get_a_repair_request_that_names_the_problem(evaluation, tmp_path, monkeypatch):
    """Like the gate, the evaluation asks a review to repair release labels on an unreleased change, then verifies
    the repair; labels the request leaves in place hold."""
    module, config = evaluation
    case = next(c for c in corpus() if c["id"] == "merged-is-not-release")
    payloads = []

    def complete(self, prompt, payload, *args):
        payloads.append(payload)
        return next(replies)
    monkeypatch.setattr(module.Reviewer, "complete", complete)
    fixed = verdict("revise", repair={"title": "Opt-in exit proxying merged", "category": "feature", "tags": ["feature"]},
                    criterion="status")
    for name, replies, holds, published in (("unfixed", iter([verdict(), verdict()]), {"held.review.release_labels": 1}, None),
                                            ("fixed", iter([verdict(), fixed, verdict()]), {}, "Opt-in exit proxying merged")):
        payloads.clear()
        output = tmp_path / f"{name}.jsonl"
        result = module.evaluate(config, [case], output)
        record = json.loads(output.read_text().splitlines()[0])
        assert (result["matched"], result["holds"], (record["published_candidate"] or {}).get("title")) == (1, holds, published)
        assert [entry["stage"] for entry in record["reviews"]] == ["review", "review", "verification"][:len(payloads)]
        assert [payload.get("application_issue") for payload in payloads] == [None, RELEASE_ISSUE, None][:len(payloads)]
        assert record["reviews"][1]["issue"] == "release_labels"


def test_evaluation_follows_the_gate_fix_loop(evaluation, tmp_path, monkeypatch):
    """A verification's own repair is verified afresh; the case scores the repaired publication."""
    module, config = evaluation
    case = next(c for c in corpus() if c["id"] == "bastet-original")
    replies = iter([{"verdict": "approve"}, {"verdict": "revise", "repair": {"why_it_matters": ""}}, {"verdict": "approve"}])
    monkeypatch.setattr(module, "EvaluationReviewer", scripted(lambda verification: next(replies)))
    output = tmp_path / "loop.jsonl"
    result = module.evaluate(config, [case], output)
    record = json.loads(output.read_text().splitlines()[0])
    assert (result["matched"], result["false_approvals"], result["verification_repairs"]) == (1, 0, 1)
    assert [(entry["stage"], entry["result"]["verdict"]) for entry in record["reviews"]] == [
        ("review", "approve"), ("verification", "revise"), ("verification", "approve")]
    assert record["published_candidate"]["why_it_matters"] == "" and record["final_verdict"] == "approve"


def judged_cases(raw):
    """Judged twins on one packet (a flawed sentence, a flawed badge, a bare shell and a grounded sentence) and a stale update."""
    pick = {case["id"]: case for case in raw["cases"]}

    def judged(case_id, source, **fields):
        return {**pick[source], "id": case_id, "audit": "test", **fields}
    return evaluator().expand({**raw, "cases": [
        judged("sentence", "bastet-original", flaw="invented_impact"),
        judged("badge", "bastet-confirmed-badge", flaw="badge_misuse"),
        judged("stale", "material-existing-update", flaw="stale_fact"),
        judged("shell", "bastet-corrected", candidate={**pick["bastet-corrected"]["candidate"], "why_it_matters": ""}),
        judged("grounded", "bastet-corrected")]})


def test_judged_scoring_counts_catches_and_false_alarms(evaluation, tmp_path, monkeypatch):
    """A flaw is caught only while its clean twins publish unchanged in the same round."""
    module, config = evaluation
    cases = judged_cases(json.loads((ROOT / "tools/review_cases.json").read_text()))

    class Discerning(scripted(None)):
        def review(self, candidate, packet, *, coverage=None, verification=False, issue=None):
            flawed = "update their configurations" in candidate["why_it_matters"] or candidate["confidence"] == "confirmed"
            return full({"verdict": "hold" if flawed else "approve"}, packet)

    def rows(sentence, badge, stale, clean, rounds=1):
        return {"invented_impact": dict(zip(("ok", "paired"), sentence), cases=rounds, unique=1),
                "badge_misuse": dict(zip(("ok", "paired"), badge), cases=rounds, unique=1),
                "stale_fact": dict(zip(("ok", "paired"), stale), cases=rounds, unique=1),
                "clean": {"cases": 2 * rounds, "ok": clean, "unique": 2}}
    clearing = scripted(lambda verification: {"verdict": "approve"} if verification else
                        {"verdict": "revise", "repair": {"why_it_matters": ""}})
    for name, reviewer, rounds, judged, missed in (
            ("approve", scripted(lambda verification: {"verdict": "approve"}), 1, rows((0, 0), (0, 0), (1, 1), 2), ["catch"]),
            # Clearing every impact sentence removes the flawed one, so the catch is not paired.
            ("clear", clearing, 1, rows((1, 0), (0, 0), (0, 0), 0), ["catch", "false_alarms"]),
            ("skip", scripted(lambda verification: {"verdict": "skip"}), 1, rows((0, 0), (0, 0), (0, 0), 0), ["catch", "false_alarms"]),
            ("discerning", Discerning, 2, rows((2, 2), (2, 2), (2, 2), 4, rounds=2), [])):
        monkeypatch.setattr(module, "EvaluationReviewer", reviewer)
        result = module.evaluate(config, cases, tmp_path / f"{name}.jsonl", rounds=rounds)
        assert (result["judged"], result["target_missed"], result["controlled_mismatches"]) == (judged, missed, 0), name
    assert (result["catch_rate"], result["paired_catch_rate"], result["false_alarm_rate"]) == (1.0, 1.0, 0.0)
    # Without its clean twins in the run, a held flaw is caught but not paired; the stale update, which must publish, needs none.
    result = module.evaluate(config, [case for case in cases if "flaw" in case], tmp_path / "flagged.jsonl")
    assert (result["judged"], result["target_missed"]) == (
        {flaw: row for flaw, row in rows((1, 0), (1, 0), (1, 1), 0).items() if flaw != "clean"}, ["catch"])
    assert (result["catch_rate"], result["paired_catch_rate"], result["false_alarm_rate"]) == (1.0, 0.333, None)


def test_target_missed_thresholds():
    target = evaluator().target_missed

    def run(flagged, clean=(10, 10)):
        # Every flagged case is caught, but only paired catches count toward the targets.
        judged = {flaw: {"cases": cases, "ok": cases, "unique": unique, "paired": paired}
                  for flaw, (cases, unique, paired) in flagged.items()}
        return target(judged | {"clean": {"cases": clean[0], "ok": clean[1], "unique": clean[0]}})
    assert target({}) == []
    assert run({"overclaim": (20, 10, 18)}) == []  # 90% overall passes
    assert run({"overclaim": (20, 10, 17)}) == ["catch"]
    assert run({"overclaim": (10, 10, 7), "filler": (90, 90, 90)}) == ["overclaim"]  # a flaw with 10 cases at 70%
    assert run({"badge_misuse": (18, 9, 0), "filler": (200, 200, 200)}) == []  # 9 distinct cases are reported only
    assert run({"filler": (10, 10, 10)}, clean=(100, 89)) == ["false_alarms"]
    assert run({"filler": (10, 10, 10)}, clean=(100, 90)) == []


def test_main_reads_repeated_case_files(evaluation, tmp_path, monkeypatch):
    """The default reads every public case file once; explicit files replace it and combine, never doubled.
    A missed target, a mismatched case, an error or an incomplete run fails."""
    module, config = evaluation
    calls, passed = [], {"controlled_mismatches": 0, "target_missed": [], "errors": 0, "incomplete": False}
    monkeypatch.setattr(module, "load_config", lambda path: config)
    monkeypatch.setattr(module, "evaluate", lambda config, cases, output, **options: calls.append(
        ([case["id"] for case in cases], options["draft"])) or passed)
    base = ["--config", str(tmp_path / "config.toml"), "--output", str(tmp_path / "report.jsonl")]
    default, public = [case["id"] for case in corpus()], ROOT / "tools/review_cases.json"
    raw = json.loads(public.read_text())
    synthetic = [case["id"] for case in module.expand(raw)]
    extra, large = tmp_path / "extra.json", tmp_path / "large.json"
    extra.write_text(json.dumps({**raw, "cases": [{**raw["cases"][0], "id": "extra-case"}]}))
    large.write_text(" " * (module.MAX_FILE_BYTES + 1))
    assert module.main(base) == 0 and calls[-1] == (default, False) and len(default) > len(synthetic)
    assert module.main([*base, "--cases", str(public)]) == 0 and calls[-1] == (synthetic, False)
    assert module.main([*base, "--cases", str(public), "--cases", str(extra)]) == 0 and calls[-1] == (synthetic + ["extra-case"], False)
    assert module.main([*base, "--draft", "--case-id", "draft:bastet"]) == 0 and calls[-1] == (["draft:bastet"], True)
    for options in (["--cases", str(public), "--cases", str(public)], ["--cases", str(large)],
                    ["--cases", str(public), "--cases", str(large)], ["--max-seconds", str(module.MAX_SECONDS + 1)]):
        with pytest.raises(SystemExit):
            module.main([*base, *options])
    assert len(calls) == 4
    for failure in ({"target_missed": ["catch"]}, {"controlled_mismatches": 1}, {"errors": 1}, {"incomplete": True}):
        monkeypatch.setattr(module, "evaluate", lambda config, cases, output, **options: passed | failure)
        assert module.main(base) == 1, failure
