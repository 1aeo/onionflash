"""Exact-candidate review protocol, immutable repairs and fresh verification."""

import copy
import json

import pytest

from approval_helpers import verdict
from onionflash import analyze, review
from onionflash.analyze import AnalysisError
from onionflash.config import DEFAULTS
from onionflash.render import _prepare_story
from onionflash.transport import FetchError, Response
from test_analyze import FakeLLM, completion
from test_render import STORY


def config():
    result = copy.deepcopy(DEFAULTS)
    result["llm"]["base_url"] = "https://llm.example/v1"
    return result


def candidate(**changes):
    return _prepare_story({**copy.deepcopy(STORY), **changes})


def packet():
    return {"sources": [{"id": "S1", "url": STORY["sources"][0]["url"], "title": "Release notes",
                         "kind": "rss", "authority": "official", "product": "tor",
                         "published_at": STORY["published_at"], "updated_at": STORY["updated_at"],
                         "labels": [],
                         "passages": [{"id": "S1:P1", "text": "The release includes improvements for relay operators."}]}],
            "missing_sources": [], "truncated": False}


def reviewer(monkeypatch, *responses, settings=None):
    monkeypatch.setenv("ONIONFLASH_LLM_API_KEY", "unit-test-secret")
    result = review.Reviewer(settings or config())
    result.client = FakeLLM(*responses)
    return result


def test_review_and_its_fresh_verification_send_exact_candidate_packet_and_bounds(monkeypatch):
    public = candidate(why_it_matters="Operators must edit their configuration to exclude the compromised node.")
    checker = reviewer(monkeypatch, completion(verdict("revise", repair={"why_it_matters": ""})), completion(verdict()))
    result = checker.review(public, packet())
    assert result["repair"] == {"why_it_matters": ""}  # The reply's null fields are not edits.
    repaired = review.apply_repair(public, result["repair"])
    assert checker.review(repaired, packet(), verification=True)["verdict"] == "approve"
    first, second = (body for _, body in checker.client.requests)
    for check in first["response_format"]["json_schema"]["schema"]["properties"]["criteria"]["properties"].values():
        assert check["properties"]["source_refs"]["items"]["enum"] == sorted(review._packet_refs(packet()))
    assert "enum" not in review.REFS["items"]  # A request cannot contaminate another packet's schema.
    assert json.loads(first["messages"][1]["content"]) == {"candidate": public, "packet": packet(),
                                                       "label_bounds": analyze.label_limits(packet()["sources"])}
    # Verification starts afresh: its own prompt and the repaired text, never the earlier reply.
    assert len(second["messages"]) == 2 and second["messages"][0]["content"] == review.VERIFY_PROMPT
    assert json.loads(second["messages"][1]["content"]) == {"candidate": repaired, "packet": packet(),
                                                        "label_bounds": analyze.label_limits(packet()["sources"])}


@pytest.mark.parametrize("bad", ["source-ref", "issues", "model-verdict", "failed-criterion", "changed-text", "missing-criterion", "missing-refs", "score", "unknown-verdict"])
def test_malformed_or_ambiguous_approval_is_rejected(monkeypatch, bad):
    response = verdict()
    if bad == "source-ref":
        response["criteria"]["source_support"]["source_refs"] = ["S2:P99"]
    elif bad == "issues":
        response["issues"] = []
    elif bad == "model-verdict":
        response["model_verdict"] = "hold"  # only the application records a replaced verdict
    elif bad == "failed-criterion":
        response["criteria"]["source_support"]["outcome"] = "fail"
    elif bad == "changed-text":
        response["repair"] = {key: None for key in review.EDITABLE}
    elif bad == "missing-criterion":
        del response["criteria"]["new_information"]
    elif bad == "missing-refs":
        response["criteria"]["source_support"]["source_refs"] = []
    elif bad == "score":
        response["score"] = 10
    else:
        response["verdict"] = "probably"
    checker = reviewer(monkeypatch, completion(response))
    with pytest.raises(review.ReviewError):
        checker.review(candidate(), packet())
    assert len(checker.client.requests) == 1


def test_approval_is_not_rewritten_or_reclassified(monkeypatch):
    public = candidate(confidence="suspected", state="developing", category="security", tags=["security"], why_it_matters="")
    before = copy.deepcopy(public)
    response = reviewer(monkeypatch, completion(verdict())).review(public, packet())
    assert response["verdict"] == "approve" and public == before


@pytest.mark.parametrize("state", ["released", "tagged"])
@pytest.mark.parametrize("verification", [False, True])
def test_release_metadata_allows_announced_and_tagged_states(monkeypatch, state, verification):
    """Coherent release metadata preserves the model's approval at either stage."""
    result = reviewer(monkeypatch, completion(verdict())).review(candidate(state=state), packet(), verification=verification)
    assert result["verdict"] == "approve"


def test_release_labels_on_a_merged_change_are_left_to_the_gate_which_names_the_problem(monkeypatch):
    """The review returns the model's approval; the gate asks a review to repair the labels, naming the problem
    beside the candidate (review_gate.next_step decides when)."""
    public = candidate(state="merged", category="release", tags=["release"])
    checker = reviewer(monkeypatch, completion(verdict()))
    result = checker.review(public, packet(), issue=review.RELEASE_ISSUE)
    assert result == review.validate_review(verdict(), packet()) and "model_verdict" not in result
    body = checker.client.requests[0][1]
    assert body["messages"][0]["content"] == review.SYSTEM_PROMPT
    assert json.loads(body["messages"][1]["content"]) == {"candidate": public, "packet": packet(),
                                                          "label_bounds": analyze.label_limits(packet()["sources"]),
                                                          "application_issue": review.RELEASE_ISSUE}


def unit(kind, *texts, authority="development", state=""):
    """A packet source whose first text is its title."""
    return {"kind": kind, "authority": authority, "upstream_state": state, "title": texts[0],
            "passages": [{"text": text} for text in texts]}


# A public Tor issue, and the merged merge request that later made its change.
ISSUE = unit("gitlab_issue", "dirauth: Remove bastet from list",
             "Last night, bastet's operator notified us that the machine is very plausibly compromised.",
             "In any kind of scenario here, the keys can’t be trusted anymore and bastet will generate a new identity soon.",
             "In the meantime, remove bastet from source as we can't trust it anymore.", state="opened")
MERGED = unit("gitlab_mr", "Remove bastet's keys from default dirauth list", state="merged")
FEED = unit("feed", "Tor Browser 16.0.2 is released", "Tor Browser 16.0.2 is now available for Android.", authority="official")
CRASH = unit("gitlab_issue", "Fix the crash in the parser", state="opened")
COMPROMISED = unit("gitlab_issue", "Bastet", "The machine was compromised.", state="opened")
DONE, HEADLINE, CONFIRMED, MERGE = ["completed_action"], ["compromise_headline"], ["confirmed_source"], ["merge_state"]
FINAL_CASES = [  # (id, writer kind, sources, story fields, expected holds)
    ("removed-headline", "gitlab_issue", [ISSUE], {"title": "Tor Directory Authority 'bastet' Removed Following Suspected Compromise"}, DONE),
    ("removed-from-source", "gitlab_issue", [ISSUE], {"title": "Tor authority bastet removed from source after reported compromise",
     "summary": "A public issue says bastet has been removed from the source code as its keys can no longer be trusted."}, DONE),
    ("removes", "gitlab_issue", [ISSUE], {"summary": "Tor removes bastet from the authority list."}, DONE),
    ("revoked", "gitlab_issue", [ISSUE], {"title": "Bastet's keys revoked after reported compromise"}, DONE),
    ("ships", "gitlab_issue", [CRASH], {"summary": "Tor ships a fix for the reported crash."}, DONE),
    ("patched", "gitlab_issue", [CRASH], {"summary": "Developers patched the crash."}, DONE),
    ("impact-patched", "gitlab_issue", [CRASH], {"why_it_matters": "Developers patched the crash."}, DONE),
    ("planned-deployment", "gitlab_issue", [unit("gitlab_issue", "Crash", "The fix will be deployed next week.")],
     {"summary": "The fix was deployed."}, DONE),
    ("negated-in-source", "gitlab_issue", [unit("gitlab_issue", "Crash", "This wasn’t fixed in 2.7.0.")],
     {"summary": "The crash was fixed in 2.7.0."}, DONE),
    ("compound-in-source", "gitlab_issue", [unit("gitlab_issue", "Crash", "The parser uses a fixed-size buffer and crashes on long input.")],
     {"summary": "The crash was fixed."}, DONE),
    ("requested", "gitlab_issue", [ISSUE], {"title": "Tor authority bastet to be removed from source after reported compromise"}, []),
    ("asked", "gitlab_issue", [ISSUE], {"summary": "The issue asks that bastet be removed."}, []),
    ("not-yet", "gitlab_issue", [ISSUE], {"summary": "Bastet has not been removed yet."}, []),
    ("contractions", "gitlab_issue", [ISSUE], {"summary": "Bastet wasn't removed yet, and its keys haven’t been rotated."}, []),
    ("no-fixed-release", "gitlab_issue", [ISSUE], {"summary": "No fixed release has been identified."}, []),
    ("adjective", "gitlab_issue", [ISSUE], {"summary": "The parser uses a fixed-size buffer."}, []),
    ("stated-elsewhere", "gitlab_issue", [unit("gitlab_issue", "Fix the crash in the parser", "The crash is fixed in main.")],
     {"summary": "Developers fixed the crash."}, []),
    ("stated-in-comment", "gitlab_issue", [unit("gitlab_issue", "Protover parser differential", "This was fixed in 2.7.0. Closing.")],
     {"summary": "This was fixed in Arti 2.7.0."}, []),
    ("noun", "gitlab_issue", [ISSUE], {"title": "Arti 2.8.0 released with low-severity security fixes"}, []),
    ("not-issue-written", "feed", [ISSUE], {"summary": "Tor removes bastet from the authority list."}, []),
    ("merged-title", "gitlab_issue", [ISSUE, MERGED], {"summary": "Bastet's keys were removed from the default authority list."}, []),
    ("merged-title-other-change", "gitlab_issue", [ISSUE, MERGED], {"summary": "Bastet's keys were revoked."}, DONE),
    ("unmerged-title", "gitlab_issue", [ISSUE, {**MERGED, "upstream_state": "opened"}],
     {"summary": "Bastet's keys were removed from the default authority list."}, DONE),
    ("compromised", "gitlab_issue", [ISSUE], {"title": "Bastet directory authority compromised"}, HEADLINE),
    ("hacked", "gitlab_issue", [ISSUE], {"title": "Tor directory authority bastet hacked"}, HEADLINE),
    ("breach", "gitlab_issue", [ISSUE], {"title": "Bastet authority breach forces key change"}, HEADLINE),
    ("possibly", "gitlab_issue", [unit("gitlab_issue", "Bastet", "It was possibly compromised.")], {"title": "Bastet compromised"}, HEADLINE),
    ("hedged-by-second-source", "gitlab_issue", [COMPROMISED, unit("feed", "Bastet", "It may have been compromised.")],
     {"title": "Bastet compromised"}, HEADLINE),
    ("qualified", "gitlab_issue", [ISSUE], {"title": "Bastet reported plausibly compromised"}, []),
    ("may-have-been", "gitlab_issue", [ISSUE], {"title": "Bastet may have been compromised"}, []),
    ("unhedged-source", "gitlab_issue", [COMPROMISED], {"title": "Bastet compromised"}, []),
    ("issue-confirmed", "gitlab_issue", [ISSUE], {"confidence": "confirmed"}, CONFIRMED),
    ("tag-and-issue-confirmed", "gitlab_issue", [unit("tag", "arti-v2.7.0", authority="official"), ISSUE], {"confidence": "confirmed"}, CONFIRMED),
    ("unmerged-request-confirmed", "gitlab_mr", [{**MERGED, "upstream_state": ""}], {"confidence": "confirmed", "state": "merged"}, CONFIRMED),
    ("merged-request-confirmed", "gitlab_mr", [MERGED], {"confidence": "confirmed", "state": "merged"}, []),
    ("official-feed-confirmed", "feed", [FEED], {"confidence": "confirmed", "state": "released"}, []),
    ("official-feed-and-issue-confirmed", "feed", [FEED, ISSUE], {"confidence": "confirmed"}, []),
    ("release-shape-confirmed", "feed", [unit("tag", "tor-0.4.9.16", authority="official"), FEED,
                                         unit("metrics_timeline", "Relay versions", authority="telemetry")],
     {"confidence": "confirmed", "state": "released"}, []),
    ("merge-request-released", "gitlab_mr", [MERGED], {"title": "Tor releases a parser fix", "state": "released"}, MERGE),
    ("merge-request-and-issue-fixed", "gitlab_mr", [MERGED, ISSUE], {"state": "fixed"}, []),
    ("operator-only-state", "gitlab_issue", [ISSUE], {"state": "no-longer-listed"}, []),
]


@pytest.mark.parametrize("writer,sources,fields,expected", [case[1:] for case in FINAL_CASES], ids=[case[0] for case in FINAL_CASES])
def test_final_holds_on_real_cases(writer, sources, fields, expected):
    """Fixed checks of a verified approval, over texts written for real public sources."""
    story = candidate(**{"title": "Bastet reported plausibly compromised", "why_it_matters": "", "category": "security",
                         "tags": ["security"], "summary": "A public issue reports that bastet's machine is very plausibly compromised.",
                         "confidence": "reported", "state": "developing", **fields})
    assert review.final_holds(story, {"packet": {"sources": sources}, "payload": {"editorial_kind": writer}}) == expected


@pytest.mark.parametrize("source,confidence,state", [
    (ISSUE, ["reported", "suspected", "observed-anomaly"], analyze.STATES), (MERGED, analyze.CONFIDENCES, ["merged"]),
    (FEED, analyze.CONFIDENCES, analyze.STATES)], ids=["issue", "merged-request", "official-feed"])
def test_repair_schema_offers_only_labels_the_packet_allows(monkeypatch, source, confidence, state):
    evidence = {"sources": [{**source, "id": "S1", "passages": [{"id": "S1:P1", **source["passages"][0]}]}],
                "missing_sources": [], "truncated": False}
    checker = reviewer(monkeypatch, completion(verdict()), completion(verdict()))
    checker.review(candidate(), evidence)
    checker.review(candidate(), evidence, verification=True)
    for _, request in checker.client.requests:
        repair = request["response_format"]["json_schema"]["schema"]["properties"]["repair"]["anyOf"][1]["properties"]
        assert (repair["confidence"]["anyOf"][0]["enum"], repair["state"]["anyOf"][0]["enum"]) == (confidence, state)
    assert review.FIELDS["confidence"]["enum"] == analyze.CONFIDENCES  # another packet keeps its own limits


@pytest.mark.parametrize("sources, expected_confidence, expected_state, weaker_state", [
    ([unit("gitlab_issue", "An attributed report", authority="development", state="opened")],
     ["reported", "suspected", "observed-anomaly"], analyze.STATES, "developing"),
    ([unit("gitlab_mr", "A completed change", authority="development", state="merged")],
     analyze.CONFIDENCES, ["merged"], "merged"),
    ([unit("feed", "An official attributed report", authority="official")],
     analyze.CONFIDENCES, analyze.STATES, "developing"),
    ([unit("tag", "An observed version tag", authority="official")],
     ["reported", "suspected", "observed-anomaly"], analyze.STATES, "tagged"),
    ([unit("feed", "A proposal for comment", authority="project-sender")],
     ["reported", "suspected", "observed-anomaly"], analyze.STATES, "developing"),
    ([unit("gitlab_mr", "A completed change", authority="development", state="merged"),
      unit("gitlab_issue", "A related open report", authority="development", state="opened")],
     analyze.CONFIDENCES, analyze.STATES, "developing"),
])
def test_review_payload_and_repair_schema_share_bounds_without_upgrading_weaker_labels(
        monkeypatch, sources, expected_confidence, expected_state, weaker_state):
    evidence = {"sources": [{**source, "id": f"S{index}",
                            "passages": [{"id": f"S{index}:P1", **source["passages"][0]}]}
                           for index, source in enumerate(sources, 1)],
                "missing_sources": [], "truncated": False}
    public = candidate(confidence="reported", state=weaker_state, why_it_matters="")
    before = copy.deepcopy(public)
    checker = reviewer(monkeypatch, completion(verdict()), completion(verdict()))
    for verification in (False, True):
        result = checker.review(public, evidence, verification=verification)
        assert result["verdict"] == "approve" and result["repair"] is None
    assert public == before and public["confidence"] == "reported"
    expected = {"confidence": expected_confidence, "state": expected_state}
    for _, request in checker.client.requests:
        sent = json.loads(request["messages"][1]["content"])
        assert sent == {"candidate": public, "packet": evidence, "label_bounds": expected}
        repair = request["response_format"]["json_schema"]["schema"]["properties"]["repair"]["anyOf"][1]["properties"]
        for label in ("confidence", "state"):
            assert repair[label]["anyOf"][0]["enum"] == sent["label_bounds"][label]


def test_supplying_label_bounds_keeps_existing_final_guard_for_a_bad_approval(monkeypatch):
    source = unit("gitlab_issue", "An attributed report", authority="development", state="opened")
    evidence = {"sources": [{**source, "id": "S1", "passages": [{"id": "S1:P1", "text": "An attributed report"}]}],
                "missing_sources": [], "truncated": False}
    public = candidate(title="An attributed report", summary="A source reports a possible issue.",
                       confidence="confirmed", state="developing", category="security", tags=["security"], why_it_matters="")
    checker = reviewer(monkeypatch, completion(verdict()))
    assert checker.review(public, evidence)["verdict"] == "approve"  # the fake model ignores its input bounds
    sent = json.loads(checker.client.requests[0][1]["messages"][1]["content"])
    assert "confirmed" not in sent["label_bounds"]["confidence"]
    assert "confirmed_source" in review.final_holds(public, {"packet": evidence, "payload": {"editorial_kind": "gitlab_issue"}})


def test_inconsistent_release_metadata_does_not_prevent_editorial_skip(monkeypatch):
    """Non-news can still be skipped without repairing metadata that will not publish."""
    result = reviewer(monkeypatch, completion(verdict("skip", criterion="news_value"))).review(
        candidate(state="merged"), packet())
    assert result["verdict"] == "skip"


def test_repairs_can_clear_but_cannot_generate_an_impact_paragraph(monkeypatch):
    """Model repairs may remove legacy commentary without creating new advice."""
    public = candidate(why_it_matters="Existing commentary")
    assert review.apply_repair(public, {"why_it_matters": ""})["why_it_matters"] == ""
    with pytest.raises(review.ReviewError):
        review.apply_repair(public, {"why_it_matters": "Operators must upgrade immediately."})
    checker = reviewer(monkeypatch, completion(verdict()))
    checker.review(public, packet())
    schema = checker.client.requests[0][1]["response_format"]["json_schema"]["schema"]
    field = schema["properties"]["repair"]["anyOf"][1]["properties"]["why_it_matters"]
    assert field["anyOf"][0]["enum"] == [""] and field["anyOf"][1] == {"type": "null"}


def test_editorial_coverage_is_background_and_never_an_evidence_reference(monkeypatch):
    """Keep coverage separate from the packet IDs allowed as factual evidence."""
    public = candidate()
    background = {"prior_story": None, "recent": [{"id": "B1", "title": "Earlier coverage"}], "truncated": False}
    checker = reviewer(monkeypatch, completion(verdict()), completion(verdict()))
    checker.review(public, packet(), coverage=background)
    checker.review(public, packet(), coverage=background, verification=True)
    for _, request in checker.client.requests:
        assert json.loads(request["messages"][1]["content"]) == {
            "candidate": public, "packet": packet(), "coverage_background": background,
            "label_bounds": analyze.label_limits(packet()["sources"])}
        fields = request["response_format"]["json_schema"]["schema"]["properties"]["criteria"]["properties"]
        assert set(fields) == set(review.CRITERIA)
        assert "news_value" in fields and "new_information" in fields
        for check in fields.values():
            assert check["properties"]["source_refs"]["items"]["enum"] == ["S1", "S1:P1"]
    forged = verdict("skip", criterion="new_information", ref="B1")
    with pytest.raises(review.ReviewError, match="source reference"):
        reviewer(monkeypatch, completion(forged)).review(public, packet(), coverage=background)


COVERED = "0123456789abcdef01234567"
COVERAGE = {"prior_story": None, "recent": [{"id": COVERED, "title": "Earlier coverage"}], "truncated": False}
PRIOR = {"prior_story": {"id": COVERED, "title": "Earlier coverage"}, "recent": [], "truncated": False}


@pytest.mark.parametrize("criterion,outcome,expected", [
    ("news_value", "fail", "skip"), ("new_information", "fail", "skip"),
    ("news_value", "insufficient", "hold"), ("new_information", "insufficient", "hold"),
    ("source_support", "fail", "hold"),  # a factual failure alone is not an editorial skip
])
@pytest.mark.parametrize("verification", [False, True])
def test_a_skip_stands_only_on_a_failed_editorial_criterion(monkeypatch, criterion, outcome, expected, verification):
    """An uncertain or factual-only skip holds, and the record keeps the model's own verdict."""
    reply = verdict("skip", criterion=criterion)
    reply["criteria"][criterion].update(outcome=outcome, reason=f"Story {COVERED} reports the same event.")
    result = reviewer(monkeypatch, completion(reply)).review(candidate(), packet(), coverage=COVERAGE,
                                                             verification=verification)
    assert (result["verdict"], result["repair"], result["criteria"]) == (expected, None, reply["criteria"])
    assert result.get("model_verdict") == (None if expected == "skip" else "skip")
    assert review.validate_review(result, packet()) == result  # the saved review stays valid
    if expected == "hold":  # a saved skip of this kind is damaged
        with pytest.raises(review.ReviewError, match="editorial criterion"):
            review.validate_review(reply, packet())


@pytest.mark.parametrize("coverage,reason,expected", [
    (COVERAGE, "Earlier coverage reports the same event.", "hold"),
    (COVERAGE, f"Story {COVERED} reports the same event.", "skip"),
    (PRIOR, f"The existing story {COVERED} already reports this.", "skip"),
    (None, f"Story {COVERED} reports the same event.", "hold"),
], ids=["unnamed", "recent", "prior", "no-coverage"])
def test_a_skip_for_new_information_alone_names_a_story_from_coverage(monkeypatch, coverage, reason, expected):
    """Duplication is decided only from the coverage background, so the reason names the story."""
    reply = verdict("skip", criterion="new_information")
    reply["criteria"]["new_information"]["reason"] = reason
    result = reviewer(monkeypatch, completion(reply)).review(candidate(), packet(), coverage=coverage)
    assert result["verdict"] == expected
    # A failed news_value is enough by itself.
    reply["criteria"]["news_value"]["outcome"] = "fail"
    assert reviewer(monkeypatch, completion(reply)).review(candidate(), packet(), coverage=coverage)["verdict"] == "skip"


def test_reply_reasons_before_outcomes_and_verdict(monkeypatch):
    """The schema orders the generated reply: each reason before its outcome, every criterion before the verdict."""
    checker = reviewer(monkeypatch, completion(verdict()))
    checker.review(candidate(), packet())
    schema = checker.client.requests[0][1]["response_format"]["json_schema"]["schema"]
    assert list(schema["properties"]) == schema["required"] == ["criteria", "verdict", "repair"]
    for check in schema["properties"]["criteria"]["properties"].values():
        assert list(check["properties"]) == check["required"] == ["reason", "source_refs", "outcome"]
        assert check["properties"]["reason"]["maxLength"] == 240  # room for a 25-word reason


def test_skip_can_record_factual_defects_without_polishing_non_news():
    response = verdict("skip", criterion="new_information")
    response["criteria"]["source_support"]["outcome"] = "fail"
    assert review.validate_review(response, packet())["verdict"] == "skip"


def test_skip_cannot_repair_text():
    response = verdict("skip", criterion="news_value", repair={"summary": "Different text"})
    with pytest.raises(review.ReviewError, match="Only a revise"):
        review.validate_review(response, packet())


@pytest.mark.parametrize("criterion", ["news_value", "new_information"])
def test_all_nine_criteria_are_required_for_approval(criterion):
    response = verdict("skip", criterion=criterion)
    response["verdict"] = "approve"
    with pytest.raises(review.ReviewError, match="all criteria"):
        review.validate_review(response, packet())


def test_repairs_cannot_modify_immutable_or_private_fields():
    with pytest.raises(review.ReviewError, match="immutable"):
        review.apply_repair(candidate(), {"sources": "changed"})


def test_repair_is_normalized_before_verification_and_preserves_public_metadata():
    public = candidate()
    repaired = review.apply_repair(public, {"summary": "  More   precise source wording.  ", "why_it_matters": ""})
    assert repaired["summary"] == "More precise source wording." and repaired["why_it_matters"] == ""
    assert all(repaired[key] == value for key, value in public.items() if key not in review.EDITABLE)
    with pytest.raises(review.ReviewError, match="does not change"):
        review.apply_repair(public, {"title": public["title"]})


@pytest.mark.parametrize("patch", [{"title": ""}, {"summary": 1}, {"products": ["unknown"]}, {"state": "approved"}])
def test_invalid_semantic_repairs_fail_closed(patch):
    with pytest.raises(review.ReviewError):
        review.apply_repair(candidate(), patch)


def test_final_verification_nonapproval_is_an_explicit_verdict_for_the_gate(monkeypatch):
    checker = reviewer(monkeypatch, completion(verdict("revise", repair={"why_it_matters": ""})))
    public = candidate()
    revised = checker.review(public, packet(), verification=True)
    assert revised["verdict"] == "revise" and public == candidate()
    # The durable gate applies this repair and sends the result to another fresh verification.
    held = reviewer(monkeypatch, completion(verdict("hold"))).review(candidate(), packet(), verification=True)
    assert held["verdict"] == "hold" and held["repair"] is None


def test_cached_api_response_validation_checks_refs_and_sparse_repairs():
    response = verdict("revise", repair={"why_it_matters": ""})
    response["repair"] = {"why_it_matters": ""}
    assert review.validate_review(response, packet())["repair"] == {"why_it_matters": ""}
    response["criteria"]["operational_advice"]["source_refs"] = ["S9"]
    with pytest.raises(review.ReviewError, match="source reference"):
        review.validate_review(response, packet())


def test_reviewer_sends_app_built_packet_text_without_rechecking_it(monkeypatch):
    # Rows stored before line endings were normalized can still carry a carriage return.
    evidence = packet()
    evidence["sources"][0]["passages"][0]["text"] += "\r\nA second line."
    assert reviewer(monkeypatch, completion(verdict())).review(candidate(), evidence)["verdict"] == "approve"
    evidence["sources"][0]["passages"][0]["text"] = "\ud800"
    checker = reviewer(monkeypatch)
    with pytest.raises(AnalysisError, match="UTF-8"):  # the request's own check still applies
        checker.review(candidate(), evidence)
    assert checker.client.requests == []


def test_duplicate_verdict_and_truncated_review_are_never_approved(monkeypatch):
    encoded = json.dumps(verdict()).replace('"verdict":', '"verdict":"hold","verdict":', 1)
    raw = {"choices": [{"finish_reason": "stop", "message": {"content": encoded}}]}
    checker = reviewer(monkeypatch, Response(200, json.dumps(raw).encode(), {}, "https://llm.example/v1"))
    with pytest.raises(AnalysisError, match="invalid JSON") as caught:
        checker.review(candidate(), packet())
    assert not caught.value.retryable  # a strike against the item, as for the writer
    checker = reviewer(monkeypatch, completion(verdict(), finish_reason="length"))
    with pytest.raises(AnalysisError, match="truncated") as caught:
        checker.review(candidate(), packet())
    assert not caught.value.retryable


def test_review_reuses_endpoint_fallback_and_the_writer_timeout(monkeypatch):
    cfg = config()
    cfg["llm"].update(fallback_base_urls=["https://fallback.example/v1"], timeout_seconds=180)
    cfg["review"]["model"] = "review-model"
    checker = reviewer(monkeypatch, FetchError("unavailable", status=503), completion(verdict()), settings=cfg)
    assert checker.review(candidate(), packet())["verdict"] == "approve"
    assert [url for url, _ in checker.client.requests] == ["https://llm.example/v1/chat/completions", "https://fallback.example/v1/chat/completions"]
    assert checker.client.requests[-1][1]["model"] == "review-model"
    assert checker.client.requests[-1][1]["max_tokens"] == review.OUTPUT_TOKENS
    # An operator's longer llm.timeout_seconds reaches review too, and the attempt total covers it.
    assert (checker.http_settings["timeout_seconds"], checker.http_settings["total_timeout_seconds"]) == (180, 190)
    assert checker.http_settings["retry_attempts"] == 1


def test_review_client_receives_shared_absolute_deadline(monkeypatch):
    monkeypatch.setenv("ONIONFLASH_LLM_API_KEY", "unit-test-secret")
    fake = FakeLLM(completion(verdict()))
    monkeypatch.setattr(analyze, "HttpClient", lambda *args, **kwargs: fake)
    with review.Reviewer(config(), deadline=123.5) as checker:
        checker.review(candidate(), packet())
        assert fake.deadline == 123.5


def test_policy_hash_binds_effective_model_and_endpoint_but_not_credentials(monkeypatch):
    cfg = config()
    initial = review.policy_hash(cfg)
    monkeypatch.setenv("ONIONFLASH_LLM_API_KEY", "a-different-secret")
    assert review.policy_hash(cfg) == initial
    for section, key, value in [("llm", "model", "another-model"), ("llm", "base_url", "https://other.example/v1"),
                                ("llm", "fallback_base_urls", ["https://fallback.example/v1"]), ("review", "model", "review-only")]:
        changed = copy.deepcopy(cfg)
        changed[section][key] = value
        assert review.policy_hash(changed) != initial
    monkeypatch.setattr(review, "RELEASE_ISSUE", "changed")
    assert review.policy_hash(cfg) != initial
