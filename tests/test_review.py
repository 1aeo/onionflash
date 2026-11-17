"""Exact-candidate review protocol, immutable repairs, config, and fresh verification."""

import copy
import json

import pytest

from helpers import LATER, STORY, FakeLLM, completion, item, verdict
from onionflash import analyze, review
from onionflash.analyze import AnalysisError
from onionflash.config import DEFAULTS, load_config
from onionflash.render import prepare_story
from onionflash.transport import FetchError, Response


def cfg_llm():
    """Return default configuration with a placeholder LLM endpoint URL."""
    result = copy.deepcopy(DEFAULTS)
    result["llm"]["base_url"] = "https://llm.example/v1"
    return result


def candidate(**changes):
    """Build a normalized public story candidate with optional overrides."""
    return prepare_story({**copy.deepcopy(STORY), **changes})


def packet():
    """Return a minimal single-source numbered review packet."""
    return {
        "sources": [{"id": "S1", "url": STORY["sources"][0]["url"], "title": "Release notes",
                     "kind": "rss", "authority": "official", "product": "tor",
                     "published_at": STORY["published_at"], "updated_at": STORY["updated_at"], "labels": [],
                     "passages": [{"id": "S1:P1", "text": "The release includes improvements for relay operators."}]}],
        "missing_sources": [], "truncated": False,
    }


def reviewer(monkeypatch, *responses, settings=None):
    """Instantiate a Reviewer wired to scripted FakeLLM responses."""
    monkeypatch.setenv("ONIONFLASH_LLM_API_KEY", "unit-test-secret")
    result = review.Reviewer(settings or cfg_llm())
    result.client = FakeLLM(*responses)
    return result


def unit(kind, *texts, authority="development", state=""):
    """Construct an unnumbered source packet unit with passage texts."""
    return {"kind": kind, "authority": authority, "upstream_state": state, "title": texts[0],
            "passages": [{"text": text} for text in texts]}


ISSUE = unit("gitlab_issue", "dirauth: Remove bastet from list",
             "Last night, bastet's operator notified us that the machine is very plausibly compromised.",
             "In any kind of scenario here, the keys can’t be trusted anymore and bastet will generate a new identity soon.",
             "In the meantime, remove bastet from source as we can't trust it anymore.", state="opened")
MERGED = unit("gitlab_mr", "Remove bastet's keys from default dirauth list", state="merged")
FEED = unit("feed", "Tor Browser 16.0.2 is released", "Tor Browser 16.0.2 is now available for Android.", authority="official")
CRASH = unit("gitlab_issue", "Fix the crash in the parser", state="opened")
COMPROMISED = unit("gitlab_issue", "Bastet", "The machine was compromised.", state="opened")
DONE, HEADLINE, CONFIRMED, MERGE = ["completed_action"], ["compromise_headline"], ["confirmed_source"], ["merge_state"]
FINAL_CASES = [
    ("removed-headline", "gitlab_issue", [ISSUE], {"title": "Tor Directory Authority 'bastet' Removed Following Suspected Compromise"}, DONE),
    ("removed-from-source", "gitlab_issue", [ISSUE], {"title": "Tor authority bastet removed from source after reported compromise",
     "summary": "A public issue says bastet has been removed from the source code as its keys can no longer be trusted."}, DONE),
    ("removes", "gitlab_issue", [ISSUE], {"summary": "Tor removes bastet from the authority list."}, DONE),
    ("revoked", "gitlab_issue", [ISSUE], {"title": "Bastet's keys revoked after reported compromise"}, DONE),
    ("ships", "gitlab_issue", [CRASH], {"summary": "Tor ships a fix for the reported crash."}, DONE),
    ("patched", "gitlab_issue", [CRASH], {"summary": "Developers patched the crash."}, DONE),
    ("impact-patched", "gitlab_issue", [CRASH], {"why_it_matters": "Developers patched the crash."}, DONE),
    ("planned-deployment", "gitlab_issue", [unit("gitlab_issue", "Crash", "The fix will be deployed next week.")], {"summary": "The fix was deployed."}, DONE),
    ("negated-in-source", "gitlab_issue", [unit("gitlab_issue", "Crash", "This wasn’t fixed in 2.7.0.")], {"summary": "The crash was fixed in 2.7.0."}, DONE),
    ("compound-in-source", "gitlab_issue", [unit("gitlab_issue", "Crash", "The parser uses a fixed-size buffer and crashes on long input.")], {"summary": "The crash was fixed."}, DONE),
    ("requested", "gitlab_issue", [ISSUE], {"title": "Tor authority bastet to be removed from source after reported compromise"}, []),
    ("asked", "gitlab_issue", [ISSUE], {"summary": "The issue asks that bastet be removed."}, []),
    ("not-yet", "gitlab_issue", [ISSUE], {"summary": "Bastet has not been removed yet."}, []),
    ("contractions", "gitlab_issue", [ISSUE], {"summary": "Bastet wasn't removed yet, and its keys haven’t been rotated."}, []),
    ("no-fixed-release", "gitlab_issue", [ISSUE], {"summary": "No fixed release has been identified."}, []),
    ("adjective", "gitlab_issue", [ISSUE], {"summary": "The parser uses a fixed-size buffer."}, []),
    ("stated-elsewhere", "gitlab_issue", [unit("gitlab_issue", "Fix the crash in the parser", "The crash is fixed in main.")], {"summary": "Developers fixed the crash."}, []),
    ("stated-in-comment", "gitlab_issue", [unit("gitlab_issue", "Protover parser differential", "This was fixed in 2.7.0. Closing.")], {"summary": "This was fixed in Arti 2.7.0."}, []),
    ("noun", "gitlab_issue", [ISSUE], {"title": "Arti 2.8.0 released with low-severity security fixes"}, []),
    ("not-issue-written", "feed", [ISSUE], {"summary": "Tor removes bastet from the authority list."}, []),
    ("merged-title", "gitlab_issue", [ISSUE, MERGED], {"summary": "Bastet's keys were removed from the default authority list."}, []),
    ("merged-title-other-change", "gitlab_issue", [ISSUE, MERGED], {"summary": "Bastet's keys were revoked."}, DONE),
    ("unmerged-title", "gitlab_issue", [ISSUE, {**MERGED, "upstream_state": "opened"}], {"summary": "Bastet's keys were removed from the default authority list."}, DONE),
    ("compromised", "gitlab_issue", [ISSUE], {"title": "Bastet directory authority compromised"}, HEADLINE),
    ("hacked", "gitlab_issue", [ISSUE], {"title": "Tor directory authority bastet hacked"}, HEADLINE),
    ("breach", "gitlab_issue", [ISSUE], {"title": "Bastet authority breach forces key change"}, HEADLINE),
    ("possibly", "gitlab_issue", [unit("gitlab_issue", "Bastet", "It was possibly compromised.")], {"title": "Bastet compromised"}, HEADLINE),
    ("hedged-by-second-source", "gitlab_issue", [COMPROMISED, unit("feed", "Bastet", "It may have been compromised.")], {"title": "Bastet compromised"}, HEADLINE),
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
                                         unit("metrics_timeline", "Relay versions", authority="telemetry")], {"confidence": "confirmed", "state": "released"}, []),
    ("merge-request-released", "gitlab_mr", [MERGED], {"title": "Tor releases a parser fix", "state": "released"}, MERGE),
    ("merge-request-and-issue-fixed", "gitlab_mr", [MERGED, ISSUE], {"state": "fixed"}, []),
    ("operator-only-state", "gitlab_issue", [ISSUE], {"state": "no-longer-listed"}, []),
]
NON_TAG_STATES = [v for v in analyze.STATES if v != "tagged"]
NON_RELEASE_CATEGORIES = [v for v in analyze.CATEGORIES if v != "release"]
COVERED = "0123456789abcdef01234567"
COVERAGE = {"prior_story": None, "recent": [{"id": COVERED, "title": "Earlier coverage"}], "truncated": False}
PRIOR = {"prior_story": {"id": COVERED, "title": "Earlier coverage"}, "recent": [], "truncated": False}


def test_review_preserves_legacy_model_config_and_rejects_unknown_settings(tmp_path):
    """Accept supported review settings while rejecting unknown keys."""
    def configured(name, extra):
        """Load a temporary TOML configuration with extra settings."""
        p = tmp_path / name
        p.write_text('[[sources]]\nid="test"\nurl="https://example.org/feed.xml"\n' + extra)
        return load_config(p)

    cfg = configured("c1.toml", '[llm]\ntimeout_seconds=45\n[review]\nmodel="critic-model"\n')
    assert cfg["review"] == {"model": "critic-model", "reasoning": False}
    with review.Reviewer(cfg) as rev:
        assert rev.llm["model"] == "critic-model" and rev.llm["max_output_tokens"] == review.OUTPUT_TOKENS
        assert (rev.http_settings["timeout_seconds"], rev.http_settings["total_timeout_seconds"]) == (45, 180)
    with pytest.raises(ValueError, match="review.model"):
        configured("c2.toml", "[review]\nmodel=[]\n")
    for unknown_key in ("max_passages=1", "max_repairs=0", "timeout_seconds=300"):
        with pytest.raises(ValueError, match="Unknown review settings"):
            configured("c3.toml", f"[review]\n{unknown_key}\n")
    inh = copy.deepcopy(DEFAULTS)
    inh["llm"]["model"] = "configured-local-model"
    with review.Reviewer(inh) as rev:
        assert rev.llm["model"] == "configured-local-model"


@pytest.mark.parametrize("st", ["released", "tagged"])
@pytest.mark.parametrize("ver", [False, True])
def test_released_and_tagged_candidates_pass_review_and_verification(monkeypatch, st, ver):
    """Approve released and tagged candidates in both review and verification stages."""
    assert reviewer(monkeypatch, completion(verdict())).review(candidate(state=st), packet(), verification=ver)["verdict"] == "approve"


def test_review_protocol_fresh_verification_and_application_issue(monkeypatch):
    """Verify schema constraints, repair application, fresh verification, and application_issue payloads."""
    public = candidate(why_it_matters="Operators must edit their configuration to exclude the compromised node.")
    checker = reviewer(monkeypatch, completion(verdict("revise", repair={"why_it_matters": ""})), completion(verdict()))
    result = checker.review(public, packet())
    assert result["repair"] == {"why_it_matters": ""}
    repaired = review.apply_repair(public, result["repair"])
    assert checker.review(repaired, packet(), verification=True)["verdict"] == "approve"
    first, second = (body for _, body in checker.client.requests)
    for check in first["response_format"]["json_schema"]["schema"]["properties"]["criteria"]["properties"].values():
        assert check["properties"]["source_refs"]["items"]["enum"] == sorted(review._packet_refs(packet()))
    assert "enum" not in review.REFS["items"]
    first_payload = json.loads(first["messages"][1]["content"])
    first_context = first_payload.pop("evidence_context")
    assert first_payload == {"candidate": public, "packet": packet()}
    assert first_context["source_date_comparisons"] == review.source_date_comparisons(packet())
    assert "why_it_matters" in {field["field"] for field in first_context["fields"]}
    assert all(passage in packet()["sources"][0]["passages"] for passage in first_context["passages"])
    assert len(second["messages"]) == 2
    assert second["messages"][0]["content"] == review.VERIFY_PROMPT + "\n\n" + review.SOURCE_DATE_CONTEXT_PROMPT
    second_payload = json.loads(second["messages"][1]["content"])
    second_context = second_payload.pop("evidence_context")
    assert second_payload == {"candidate": repaired, "packet": packet()}
    assert second_context["source_date_comparisons"] == first_context["source_date_comparisons"]
    assert "why_it_matters" not in {field["field"] for field in second_context["fields"]}

    schema = first["response_format"]["json_schema"]["schema"]
    assert list(schema["properties"]) == schema["required"] == ["criteria", "verdict", "same_story", "repair"]
    for check in schema["properties"]["criteria"]["properties"].values():
        assert list(check["properties"]) == check["required"] == ["reason", "source_refs", "outcome"]
        assert check["properties"]["reason"]["maxLength"] == 360

    untouched = candidate(confidence="suspected", state="developing", category="security", tags=["security"], why_it_matters="")
    snap = copy.deepcopy(untouched)
    assert reviewer(monkeypatch, completion(verdict())).review(untouched, packet())["verdict"] == "approve" and untouched == snap

    rel_pub = candidate(state="merged", category="release", tags=["release"])
    rel_chk = reviewer(monkeypatch, completion(verdict()))
    rel_res = rel_chk.review(rel_pub, packet(), issue=review.RELEASE_ISSUE)
    assert rel_res == review.validate_review(verdict(), packet()) and "model_verdict" not in rel_res
    assert rel_chk.client.requests[0][1]["messages"][0]["content"] == review.SYSTEM_PROMPT + "\n\n" + review.SOURCE_DATE_CONTEXT_PROMPT
    issue_payload = json.loads(rel_chk.client.requests[0][1]["messages"][1]["content"])
    issue_payload.pop("evidence_context")
    assert issue_payload == {
        "candidate": rel_pub, "packet": packet(), "application_issue": review.RELEASE_ISSUE}


@pytest.mark.parametrize("length", [240, 241, 360])
def test_evidence_comparison_reason_bound_accepts_existing_and_longer_records(length):
    response = verdict()
    response["criteria"]["source_support"]["reason"] = (
        "The passage supports the claim with the stated audience and conditions. " * 6
    )[:length]
    checked = review.validate_review(response, packet())
    assert checked["criteria"]["source_support"]["reason"] == response["criteria"]["source_support"]["reason"]


def test_evidence_comparison_reason_bound_rejects_one_character_over_limit():
    response = verdict()
    response["criteria"]["source_support"]["reason"] = (
        "The passage supports the claim with the stated audience and conditions. " * 6
    )[:361]
    with pytest.raises(review.ReviewError):
        review.validate_review(response, packet())


@pytest.mark.parametrize("verification", [False, True])
@pytest.mark.parametrize("update", [False, True])
def test_native_review_delivers_evidence_order_without_a_new_response_protocol(monkeypatch, verification, update):
    public = candidate(why_it_matters="The source describes an effect with stated conditions.")
    if update:
        public["updates"] = [{"at": public["updated_at"], "text": "The source reports an additional observation.",
                              "sources": public["sources"]}]
    checker = reviewer(monkeypatch, completion(verdict(update=update)))
    checker.review(public, packet(), update=update, verification=verification)
    body = checker.client.requests[0][1]
    prompt = body["messages"][0]["content"]
    assert review._SHARED_VERDICT_RULES in prompt
    assert "check a nonempty why_it_matters FIRST" in prompt
    assert "actual\n  source.authority metadata value" in prompt
    assert "passage order is not chronology" in prompt
    assert "retain the underlying-story rule" in prompt
    schema = body["response_format"]["json_schema"]["schema"]
    assert list(schema["properties"]) == ["criteria", "verdict", "same_story", "repair"]
    assert all(check["properties"]["reason"]["maxLength"] == 360
               for check in schema["properties"]["criteria"]["properties"].values())
    assert body["max_tokens"] == 2200
    payload = json.loads(body["messages"][-1]["content"])
    assert payload["packet"] == packet()
    assert payload["candidate"] == public


def test_evidence_reason_prompt_and_bound_are_both_in_review_policy(monkeypatch):
    original = review.policy_hash(DEFAULTS)
    monkeypatch.setattr(review, "SYSTEM_PROMPT", review.SYSTEM_PROMPT + " Additional evidence comparison.")
    assert review.policy_hash(DEFAULTS) != original
    monkeypatch.undo()
    changed = copy.deepcopy(review.SCHEMA)
    changed["properties"]["criteria"]["properties"]["source_support"]["properties"]["reason"]["maxLength"] = 240
    monkeypatch.setattr(review, "SCHEMA", changed)
    assert review.policy_hash(DEFAULTS) != original


@pytest.mark.parametrize("bad", [
    "source-ref", "issues", "model-verdict", "failed-criterion", "changed-text",
    "missing-criterion", "missing-refs", "score", "unknown-verdict",
    "failed-news-value-approve", "failed-new-information-approve",
])
def test_malformed_or_ambiguous_approval_is_rejected(monkeypatch, bad):
    """Reject malformed, extra-field, or inconsistent approval responses."""
    resp = verdict()
    if bad == "source-ref": resp["criteria"]["source_support"]["source_refs"] = ["S2:P99"]
    elif bad == "issues": resp["issues"] = []
    elif bad == "model-verdict": resp["model_verdict"] = "hold"
    elif bad == "failed-criterion": resp["criteria"]["source_support"]["outcome"] = "fail"
    elif bad == "changed-text": resp["repair"] = {k: None for k in review.EDITABLE}
    elif bad == "missing-criterion": del resp["criteria"]["new_information"]
    elif bad == "missing-refs": resp["criteria"]["source_support"]["source_refs"] = []
    elif bad == "score": resp["score"] = 10
    elif bad == "failed-news-value-approve":
        resp = verdict("skip", criterion="news_value"); resp["verdict"] = "approve"
    elif bad == "failed-new-information-approve":
        resp = verdict("skip", criterion="new_information"); resp["verdict"] = "approve"
    else:
        resp["verdict"] = "probably"
    checker = reviewer(monkeypatch, completion(resp))
    with pytest.raises(review.ReviewError):
        checker.review(candidate(), packet())
    assert len(checker.client.requests) == 1


@pytest.mark.parametrize("writer,sources,fields,expected", [c[1:] for c in FINAL_CASES], ids=[c[0] for c in FINAL_CASES])
def test_final_holds_on_real_cases(writer, sources, fields, expected):
    """Verify deterministic final_holds reasons across issue, MR, and feed cases."""
    story = candidate(**{"title": "Bastet reported plausibly compromised", "why_it_matters": "", "category": "security",
                         "tags": ["security"], "summary": "A public issue reports that bastet's machine is very plausibly compromised.",
                         "confidence": "reported", "state": "developing", **fields})
    assert review.final_holds(story, {"packet": {"sources": sources}, "payload": {"editorial_kind": writer}}) == expected


@pytest.mark.parametrize("sources,confidence,state,categories", [
    ([ISSUE], ["reported", "suspected", "observed-anomaly"], NON_TAG_STATES, analyze.CATEGORIES),
    ([MERGED], analyze.CONFIDENCES, ["merged"], NON_RELEASE_CATEGORIES),
    ([FEED], analyze.CONFIDENCES, NON_TAG_STATES, analyze.CATEGORIES),
    ([unit("tag", "tor-0.4.9.16", authority="official"), FEED], analyze.CONFIDENCES, analyze.STATES, analyze.CATEGORIES),
], ids=["issue", "merged-request", "official-feed", "tagged-release"])
def test_repair_schema_offers_only_labels_the_packet_allows(monkeypatch, sources, confidence, state, categories):
    """Constrain repair enum choices to packet-supported confidence, state, and category labels."""
    evidence = {"sources": [{**s, "id": f"S{i}", "passages": [{"id": f"S{i}:P1", **s["passages"][0]}]}
                            for i, s in enumerate(sources, 1)], "missing_sources": [], "truncated": False}
    checker = reviewer(monkeypatch, completion(verdict()), completion(verdict()))
    checker.review(candidate(), evidence)
    checker.review(candidate(), evidence, verification=True)
    for _, req in checker.client.requests:
        rep = req["response_format"]["json_schema"]["schema"]["properties"]["repair"]["anyOf"][1]["properties"]
        assert (rep["confidence"]["anyOf"][0]["enum"], rep["state"]["anyOf"][0]["enum"]) == (confidence, state)
        assert rep["category"]["anyOf"][0]["enum"] == rep["tags"]["anyOf"][0]["items"]["enum"] == categories
    assert (review.FIELDS["confidence"]["enum"], review.FIELDS["state"]["enum"],
            review.FIELDS["category"]["enum"]) == (analyze.CONFIDENCES, analyze.STATES, analyze.CATEGORIES)
    if "tagged" not in state:
        with pytest.raises(review.ReviewError, match="limits"):
            reviewer(monkeypatch, completion(verdict("revise", repair={"state": "tagged"}, criterion="status"))).review(candidate(), evidence)
    if "release" not in categories:
        with pytest.raises(review.ReviewError, match="limits"):
            reviewer(monkeypatch, completion(verdict("revise", repair={"tags": ["release"]}, criterion="status"))).review(candidate(), evidence)


@pytest.mark.parametrize("patch,is_upd,match", [
    ({"why_it_matters": "Operators must upgrade immediately."}, False, None),
    ({"sources": "changed"}, False, "immutable"),
    ({"title": STORY["title"]}, False, "does not change"),
    ({"title": ""}, False, None),
    ({"summary": 1}, False, None),
    ({"products": ["unknown"]}, False, None),
    ({"state": "approved"}, False, None),
    ({"title": "Forbidden headline edit"}, True, None),
    ({"update": "Truncated mid-word fragment"}, True, None),
    ({"update": "."}, True, None),
    ({"update": "Forbidden in story scope."}, False, None),
])
def test_apply_repair_rejects_immutable_noop_and_invalid_patches(patch, is_upd, match):
    """Refuse immutable-field, no-op, empty, or unpunctuated repairs."""
    base = candidate(updates=[{"at": "2026-11-08T14:00:00Z", "text": "Maintainers opened a tracking ticket.",
                               "sources": [{"url": STORY["sources"][0]["url"], "title": "Release notes"}]}])
    with pytest.raises(review.ReviewError, match=match):
        review.apply_repair(base, patch, update=is_upd)


@pytest.mark.parametrize("kind,target,val", [
    ("cfg", ("llm", "model"), "another-model"),
    ("cfg", ("llm", "base_url"), "https://other.example/v1"),
    ("cfg", ("llm", "fallback_base_urls"), ["https://fallback.example/v1"]),
    ("cfg", ("review", "model"), "review-only"),
    ("attr", "RELEASE_ISSUE", None),
    ("attr", "UPDATE_SYSTEM_PROMPT", None),
    ("attr", "UPDATE_VERIFY_PROMPT", None),
    ("attr", "ROUTING_PROMPT", None),
])
def test_policy_hash_changes_on_model_endpoint_and_prompt_mutations(monkeypatch, kind, target, val):
    """Change policy_hash when model, endpoint, or prompt constants change, ignoring API keys."""
    initial = review.policy_hash(cfg_llm())
    monkeypatch.setenv("ONIONFLASH_LLM_API_KEY", "a-different-secret")
    assert review.policy_hash(cfg_llm()) == initial
    if kind == "cfg":
        changed = copy.deepcopy(cfg_llm())
        changed[target[0]][target[1]] = val
        assert review.policy_hash(changed) != initial
    else:
        monkeypatch.setattr(review, target, getattr(review, target) + "!")
        assert review.policy_hash(cfg_llm()) != initial


def test_prompts_coverage_isolation_repairs_and_transport_settings(monkeypatch):
    """Check prompt invariants, coverage isolation, UTF-8/JSON errors, and endpoint failover."""
    assert "unnumbered [Proposal]) whose packet source has authority=project-sender" in review.SYSTEM_PROMPT
    assert "When authority=community and case (5) does not apply" in review.SYSTEM_PROMPT
    for prompt in (review.SYSTEM_PROMPT, review.UPDATE_SYSTEM_PROMPT):
        assert "committed into C Tor or Arti" in " ".join(prompt.split())
        assert "including project-sender and official" in prompt
        assert "unquoted_content" in prompt
    for prompt in (review.SYSTEM_PROMPT, review.VERIFY_PROMPT):
        assert "Claims supported by other packet sources need only that source's support." in prompt
    assert reviewer(monkeypatch, completion(verdict("skip", criterion="news_value"))).review(candidate(state="merged"), packet())["verdict"] == "skip"

    public = candidate(why_it_matters="Existing commentary")
    assert review.apply_repair(public, {"why_it_matters": ""})["why_it_matters"] == ""
    chk = reviewer(monkeypatch, completion(verdict()))
    chk.review(public, packet())
    wim = chk.client.requests[0][1]["response_format"]["json_schema"]["schema"]["properties"]["repair"]["anyOf"][1]["properties"]["why_it_matters"]
    assert wim["anyOf"][0]["enum"] == [""] and wim["anyOf"][1] == {"type": "null"}

    bg = {"prior_story": None, "recent": [{"id": "B1", "title": "Earlier coverage"}], "truncated": False}
    bg_chk = reviewer(monkeypatch, completion(verdict()), completion(verdict()))
    bg_chk.review(candidate(), packet(), coverage=bg)
    bg_chk.review(candidate(), packet(), coverage=bg, verification=True)
    for _, req in bg_chk.client.requests:
        payload = json.loads(req["messages"][1]["content"])
        context = payload.pop("evidence_context")
        assert payload == {"candidate": candidate(), "packet": packet(), "coverage_background": bg}
        assert context["source_date_comparisons"] == review.source_date_comparisons(packet())
        assert all(passage in packet()["sources"][0]["passages"] for passage in context["passages"])
        fields = req["response_format"]["json_schema"]["schema"]["properties"]["criteria"]["properties"]
        assert set(fields) == set(review.CRITERIA)
        assert all(c["properties"]["source_refs"]["items"]["enum"] == ["S1", "S1:P1"] for c in fields.values())
    with pytest.raises(review.ReviewError, match="source reference"):
        reviewer(monkeypatch, completion(verdict("skip", criterion="new_information", ref="B1"))).review(candidate(), packet(), coverage=bg)

    skip_ok = verdict("skip", criterion="new_information")
    skip_ok["criteria"]["source_support"]["outcome"] = "fail"
    assert review.validate_review(skip_ok, packet())["verdict"] == "skip"
    with pytest.raises(review.ReviewError, match="Only a revise"):
        review.validate_review(verdict("skip", criterion="news_value", repair={"summary": "Different text"}), packet())

    norm = review.apply_repair(candidate(), {"summary": "  More   precise source wording.  ", "why_it_matters": ""})
    assert norm["summary"] == "More precise source wording." and norm["why_it_matters"] == ""
    assert all(norm[k] == v for k, v in candidate().items() if k not in review.EDITABLE)

    assert reviewer(monkeypatch, completion(verdict("revise", repair={"why_it_matters": ""}))).review(candidate(), packet(), verification=True)["verdict"] == "revise"
    held = reviewer(monkeypatch, completion(verdict("hold"))).review(candidate(), packet(), verification=True)
    assert held["verdict"] == "hold" and held["repair"] is None

    sparse = verdict("revise", repair={"why_it_matters": ""})
    sparse["repair"] = {"why_it_matters": ""}
    assert review.validate_review(sparse, packet())["repair"] == {"why_it_matters": ""}
    sparse["criteria"]["operational_advice"]["source_refs"] = ["S9"]
    with pytest.raises(review.ReviewError, match="source reference"):
        review.validate_review(sparse, packet())

    ev_cr = packet()
    ev_cr["sources"][0]["passages"][0]["text"] += "\r\nA second line."
    assert reviewer(monkeypatch, completion(verdict())).review(candidate(), ev_cr)["verdict"] == "approve"
    ev_cr["sources"][0]["passages"][0]["text"] = "\ud800"
    sur_chk = reviewer(monkeypatch)
    with pytest.raises(AnalysisError, match="UTF-8"):
        sur_chk.review(candidate(), ev_cr)
    assert sur_chk.client.requests == []

    dup_enc = json.dumps(verdict()).replace('"verdict":', '"verdict":"hold","verdict":', 1)
    dup_raw = {"choices": [{"finish_reason": "stop", "message": {"content": dup_enc}}]}
    with pytest.raises(AnalysisError, match="invalid JSON") as cdup:
        reviewer(monkeypatch, Response(200, json.dumps(dup_raw).encode(), {}, "https://llm.example/v1")).review(candidate(), packet())
    assert not cdup.value.retryable
    with pytest.raises(AnalysisError, match="truncated") as ctr:
        reviewer(monkeypatch, completion(verdict(), finish_reason="length")).review(candidate(), packet())
    assert not ctr.value.retryable

    fb_cfg = cfg_llm()
    fb_cfg["llm"].update(fallback_base_urls=["https://fallback.example/v1"], timeout_seconds=180)
    fb_cfg["review"]["model"] = "review-model"
    fb_chk = reviewer(monkeypatch, FetchError("unavailable", status=503), completion(verdict()), settings=fb_cfg)
    assert fb_chk.review(candidate(), packet())["verdict"] == "approve"
    assert [u for u, _ in fb_chk.client.requests] == ["https://llm.example/v1/chat/completions", "https://fallback.example/v1/chat/completions"]
    assert fb_chk.client.requests[-1][1]["model"] == "review-model" and fb_chk.client.requests[-1][1]["max_tokens"] == review.OUTPUT_TOKENS
    assert (fb_chk.http_settings["timeout_seconds"], fb_chk.http_settings["total_timeout_seconds"], fb_chk.http_settings["retry_attempts"]) == (180, 190, 1)

    fake = FakeLLM(completion(verdict()))
    monkeypatch.setattr("onionflash.llm.HttpClient", lambda *a, **kw: fake)
    with review.Reviewer(cfg_llm(), deadline=123.5) as dl_chk:
        dl_chk.clock = lambda: 100.0
        dl_chk.review(candidate(), packet())
        assert dl_chk.deadline == 123.5 and getattr(fake, "deadline", None) is None


@pytest.mark.parametrize("criterion,outcome,expected", [
    ("news_value", "fail", "skip"), ("new_information", "fail", "skip"),
    ("news_value", "insufficient", "hold"), ("new_information", "insufficient", "hold"),
    ("source_support", "fail", "hold"),
])
@pytest.mark.parametrize("verification", [False, True])
def test_a_skip_stands_only_on_a_failed_editorial_criterion(monkeypatch, criterion, outcome, expected, verification):
    """Convert skips without a failed editorial criterion into holds while recording model_verdict."""
    reply = verdict("skip", criterion=criterion)
    reply["criteria"][criterion].update(outcome=outcome, reason=f"Story {COVERED} reports the same event.")
    res = reviewer(monkeypatch, completion(reply)).review(candidate(), packet(), coverage=COVERAGE, verification=verification)
    assert (res["verdict"], res["repair"], res["criteria"]) == (expected, None, reply["criteria"])
    assert res.get("model_verdict") == (None if expected == "skip" else "skip")
    assert review.validate_review(res, packet()) == res
    if expected == "hold":
        with pytest.raises(review.ReviewError, match="editorial criterion"):
            review.validate_review(reply, packet())


@pytest.mark.parametrize("coverage,reason,expected", [
    (COVERAGE, "Earlier coverage reports the same event.", "hold"),
    (COVERAGE, f"Story {COVERED} reports the same event.", "skip"),
    (PRIOR, f"The existing story {COVERED} already reports this.", "skip"),
    (None, f"Story {COVERED} reports the same event.", "hold"),
], ids=["unnamed", "recent", "prior", "no-coverage"])
def test_a_skip_for_new_information_alone_names_a_story_from_coverage(monkeypatch, coverage, reason, expected):
    """Require skips on new_information alone to cite a story ID from coverage."""
    reply = verdict("skip", criterion="new_information")
    reply["criteria"]["new_information"]["reason"] = reason
    assert reviewer(monkeypatch, completion(reply)).review(candidate(), packet(), coverage=coverage)["verdict"] == expected
    reply["criteria"]["news_value"]["outcome"] = "fail"
    assert reviewer(monkeypatch, completion(reply)).review(candidate(), packet(), coverage=coverage)["verdict"] == "skip"


def test_update_scope_confirmed_updates_uncited_notes_and_punctuation_repairs(monkeypatch):
    """Validate latest_update review prompts, repair limits, and per-note completed-action checks."""
    prior = candidate(
        title="Relay compromise confirmed by maintainer", summary="The release fixed the issue before this follow-up.",
        updates=[{"at": "2026-11-08T14:00:00Z", "text": "Maintainers opened a tracking ticket.",
                  "sources": [{"url": STORY["sources"][0]["url"], "title": "Release notes"}]},
                 {"at": "2026-11-08T16:00:00Z", "text": "Operators reported new telemetry.",
                  "sources": [{"url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/41400", "title": "Issue"}]}],
    )
    coverage = {
        "prior_story": {k: prior[k] for k in ("id", "title", "summary", "why_it_matters", "category", "priority",
                                              "confidence", "state", "products", "tags", "published_at", "updated_at", "added_at", "updates")},
        "recent": [], "truncated": False,
    }
    pkt = {
        "sources": [packet()["sources"][0],
                    {"id": "S2", "url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/41400", "title": "Issue",
                     "kind": "gitlab_issue", "authority": "development", "product": "tor", "upstream_state": "opened",
                     "published_at": STORY["published_at"], "updated_at": STORY["updated_at"], "labels": [],
                     "passages": [{"id": "S2:P1", "text": "Operators reported new telemetry."}]}],
        "missing_sources": [], "truncated": False,
    }
    checker = reviewer(
        monkeypatch,
        completion(verdict("revise", repair={"update": "Operators reported verified telemetry.", "state": "developing"}, update=True)),
        completion(verdict(update=True)),
    )
    res = checker.review(prior, pkt, coverage=coverage, update=True)
    assert res["repair"] == {"update": "Operators reported verified telemetry.", "state": "developing"}
    _, body = checker.client.requests[0]
    assert body["messages"][0]["content"] == review.UPDATE_SYSTEM_PROMPT
    assert tuple(body["response_format"]["json_schema"]["schema"]["properties"]["repair"]["anyOf"][1]["properties"]) == review.UPDATE_EDITABLE
    sent = json.loads(body["messages"][1]["content"])
    assert sent["review_scope"] == "latest_update" and set(sent["coverage_background"]["prior_story"]) == {"id", "state", "confidence", "updated_at"}

    repaired = review.apply_repair(prior, res["repair"], update=True)
    assert checker.review(repaired, pkt, coverage=coverage, verification=True, update=True)["verdict"] == "approve"
    assert checker.client.requests[1][1]["messages"][0]["content"] == review.UPDATE_VERIFY_PROMPT
    assert repaired["title"] == prior["title"] and repaired["summary"] == prior["summary"] and repaired["updates"][0] == prior["updates"][0]
    assert repaired["updates"][1] == {**prior["updates"][1], "text": "Operators reported verified telemetry."} and repaired["state"] == "developing"

    with pytest.raises(review.ReviewError):
        review._text("Bad\ufffechar", 100)
    assert review.final_holds(repaired, {"mode": "update", "packet": pkt}) == []
    assert "completed_action" in review.final_holds(review.apply_repair(prior, {"update": "Maintainers fixed the issue in S2."}, update=True),
                                                    {"mode": "update", "packet": pkt})
    hedged_pkt = {**pkt, "sources": [{**pkt["sources"][0], "passages": [{"id": "S1:P1", "text": "A plausibly compromised authority went offline."}]}, pkt["sources"][1]]}
    assert "compromise_headline" in review.final_holds(review.apply_repair(prior, {"update": "The compromised authority remained offline."}, update=True),
                                                       {"mode": "update", "packet": hedged_pkt})

    conf_chk = reviewer(monkeypatch, completion(verdict(update=True)))
    conf_chk.review({**prior, "confidence": "confirmed"}, pkt,
                    coverage={**coverage, "prior_story": {**coverage["prior_story"], "confidence": "confirmed"}}, update=True)
    assert conf_chk.client.requests[0][1]["response_format"]["json_schema"]["schema"]["properties"]["repair"]["anyOf"][1]["properties"]["confidence"]["anyOf"][0]["enum"] == ["confirmed"]

    recent_cov = {"prior_story": None, "recent": [{"id": "a" * 24, "title": "Prior", "retracted": False}], "truncated": False}
    rt_chk = reviewer(monkeypatch, completion(verdict()), completion(verdict()))
    rt_chk.review(candidate(), packet(), coverage=recent_cov)
    rt_chk.review(candidate(), packet(), coverage=recent_cov, verification=True)
    assert rt_chk.client.requests[0][1]["messages"][0]["content"] == review.SYSTEM_PROMPT + review.ROUTING_PROMPT + "\n\n" + review.SOURCE_DATE_CONTEXT_PROMPT
    assert rt_chk.client.requests[1][1]["messages"][0]["content"] == review.VERIFY_PROMPT + review.ROUTING_PROMPT + "\n\n" + review.SOURCE_DATE_CONTEXT_PROMPT

    url99 = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/99"
    cand = {
        "title": "Tor 0.4.9.5 released", "summary": "Tor 0.4.9.5 is out.", "why_it_matters": "",
        "category": "release", "priority": "normal", "confidence": "confirmed", "state": "released",
        "products": ["tor"], "tags": ["release"], "sources": [{"url": url99, "title": "Issue 99"}],
        "updates": [{"at": LATER, "text": "Operators reported packaging progress in comments.", "sources": [{"url": url99, "title": "Issue 99"}]}],
    }
    prep = {
        "mode": "update", "coverage": {"prior_story": {"id": "a" * 24, "confidence": "confirmed"}},
        "limits": {"confidence": {"reported"}, "states": {"reported", "developing", "released"}, "merge_verified": False},
        "packet": {"sources": [{"id": "S1", "url": url99, "authority": "development", "kind": "gitlab_issue",
                                "passages": [{"id": "S1.P1", "text": "Issue body text without completed verbs."},
                                             {"id": "S1.N1", "url": url99 + "#note_1", "text": "We merged and deployed the fix."}]}]},
    }
    assert review.final_holds(review.personal_attribution.normalize(cand, update=prep.get("mode") == "update"), prep) == []
    assert "completed_action" in review.final_holds({**cand, "updates": [{"at": LATER, "text": "Maintainers deployed the fix.",
                                                                          "sources": [{"url": url99, "title": "Issue 99"}]}]}, prep)
    prep_parent_done = {**prep, "packet": {"sources": [{"id": "S1", "url": url99, "authority": "development", "kind": "gitlab_issue",
                                                        "passages": [{"id": "S1.P1", "text": "Earlier release fixed an older unrelated crash."},
                                                                     {"id": "S1.N2", "url": url99 + "#note_2", "text": "Still investigating this regression."}]}]}}
    assert "completed_action" in review.final_holds({**cand, "updates": [{"at": LATER, "text": "Maintainers fixed the regression.",
                                                                          "sources": [{"url": url99 + "#note_2", "title": "Comment"}]}]}, prep_parent_done)
    with pytest.raises(AnalysisError):
        analyze.validate_analysis({"publish": True, "update": ".", "confidence": "reported", "state": "developing",
                                   "evidence": ["exact words here"]}, item(content="Some exact words here in the item."),
                                  schema=analyze.UPDATE_SCHEMA)


def test_final_holds_shouting_malformed_version_and_untrusted_operator_claims():
    """Enforce shouting_caps, malformed_version, and untrusted_operator_claim guards."""
    list_url = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/xyz/"
    src_for = lambda auth, url=list_url: [{"id": "S1", "url": url, "kind": "feed", "authority": auth,
                                           "passages": [{"id": "S1:P1", "text": "Relay telemetry report."}]}]
    prep_for = lambda auth, url=list_url: {"packet": {"sources": src_for(auth, url)}, "payload": {"editorial_kind": "feed"}}

    shout_story = candidate(title="Relays AT RISK FOR DEANONYMIZATION", confidence="reported")
    assert "shouting_caps" in review.final_holds(shout_story, prep_for("trusted-operator"))
    acronym_story = candidate(title="TLS SNI ALPN changes in relay connections", confidence="reported")
    assert review.final_holds(acronym_story, prep_for("trusted-operator")) == []

    bad_ver_story = candidate(summary="Operators reported issues after a post-0.4.17 upgrade.", confidence="reported", products=["tor"])
    assert "malformed_version" in review.final_holds(bad_ver_story, prep_for("trusted-operator"))
    written_bad_story = candidate(summary="Tor 0.4.17 release notes were written today.", confidence="reported", products=["tor"])
    assert "malformed_version" in review.final_holds(written_bad_story, prep_for("trusted-operator"))
    written_prefix_bad = candidate(summary="The post written yesterday cites Tor 0.4.17.", confidence="reported", products=["tor"])
    assert "malformed_version" in review.final_holds(written_prefix_bad, prep_for("trusted-operator"))
    for annotated in (
        "An operator wrote Tor 0.4.17 [sic] in the message.",
        "An operator wrote Tor 0.4.17 (sic) in the message.",
        'The subject was written as "Tor 0.4.17" in the archive.',
        "The subject was written as Tor 0.4.17 in the archive.",
        "Maintainers corrected the Tor 0.4.17 typo.",
    ):
        assert review.final_holds(review.personal_attribution.normalize(candidate(summary=annotated, confidence="reported", products=["tor"])), prep_for("trusted-operator")) == []
    arti_story = candidate(summary="Operators tested 0.4.17 relay builds.", confidence="reported", products=["arti"])
    assert review.final_holds(arti_story, prep_for("trusted-operator")) == []

    inc_story = candidate(title="Operator reports DDoS flood against exit relays",
                          summary="A mailing-list post describes an ongoing DDoS attack.",
                          category="dos", tags=["dos"], confidence="reported")
    assert review.final_holds(review.personal_attribution.normalize(inc_story), prep_for("community")) == ["untrusted_operator_claim"]
    assert review.final_holds(review.personal_attribution.normalize(inc_story), prep_for("trusted-operator")) == []
    assert review.final_holds(review.personal_attribution.normalize(inc_story), prep_for("project-sender")) == []
    assert "confirmed_source" in review.final_holds({**inc_story, "confidence": "confirmed"}, prep_for("trusted-operator"))

    rfc_url = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-dev@lists.torproject.org/message/rfc1/"
    rfc_story = candidate(title="[RFC] Relay congestion signaling extension",
                          summary="A proposal on tor-dev outlines congestion signaling frames.",
                          category="protocol", tags=["protocol"], confidence="reported")
    assert review.final_holds(rfc_story, prep_for("community", rfc_url)) == []

    prop_sources = [{
        "id": "S1", "url": rfc_url, "kind": "feed", "authority": "community",
        "title": "[tor-dev] Proposal 375: Rate-limiting circuit flooding",
        "passages": [{"id": "S1:P1", "text": "Proposal 375 specifies rate limits to defend against circuit flooding and DoS attacks."}],
    }]
    prop_story = candidate(
        title="Proposal 375: Rate-limiting circuit flooding",
        summary="Proposal 375 on tor-dev specifies rate limits to defend against circuit flooding and DoS attacks.",
        category="protocol", tags=["protocol", "dos"], confidence="reported",
    )
    assert review.final_holds(prop_story, {"packet": {"sources": prop_sources}, "payload": {"editorial_kind": "feed"}}) == []
    prop_with_incident = candidate(
        title="Attackers flooded exit relays yesterday",
        summary="Proposal 375 proposes rate limits after the flood disrupted exit relays.",
        category="dos", tags=["dos"], confidence="reported",
    )
    assert review.final_holds(
        prop_with_incident, {"packet": {"sources": prop_sources}, "payload": {"editorial_kind": "feed"}}
    ) == ["untrusted_operator_claim"]

    defense_framing = candidate(
        title="Rate-limit proposal for directory requests",
        summary="A tor-dev post proposes a rate-limit defense against directory flooding.",
        category="protocol", tags=["protocol"], confidence="reported",
    )
    assert review.final_holds(defense_framing, prep_for("community", rfc_url)) == []

    for live_inc in (
        candidate(
            title="Operator reports suspected VPS provider tampering and connection flood on exit relay",
            summary="A mailing-list post describes suspected host tampering and a connection flood.",
            category="relay", tags=["relay"], confidence="reported",
        ),
        candidate(
            title="Operator reports HSDir-targeted circuit overload and attack",
            summary="A mailing-list post reports an HSDir circuit attack on relays.",
            category="relay", tags=["relay"], confidence="reported",
        ),
        candidate(
            title="Post claims rate-limit defense bypass on relays",
            summary="A mailing-list post reports a rate-limit defense bypass.",
            category="relay", tags=["relay"], confidence="reported",
        ),
        candidate(
            title="[RFC] Operator reports active DDoS flood hitting exit relays",
            summary="A post marked RFC reports an active DDoS flood on exit relays.",
            category="dos", tags=["dos"], confidence="reported",
        ),
        candidate(
            title="Attackers flooded exit relays yesterday",
            summary="Proposal 375 proposes rate limits after the flood disrupted exit relays.",
            category="dos", tags=["dos"], confidence="reported",
        ),
        candidate(
            title="Rate-limit discussion on relay list",
            summary="Operators propose rate limits after attackers flooded exit relays.",
            category="relay", tags=["relay"], confidence="reported",
        ),
        candidate(
            title="Relay defense measures",
            summary="An attack targets exit relays.",
            category="relay", tags=["relay"], confidence="reported",
        ),
    ):
        assert review.final_holds(review.personal_attribution.normalize(live_inc), prep_for("community", rfc_url)) == ["untrusted_operator_claim"]

    upd_cand = {
        **rfc_story,
        "sources": [{"url": list_url, "title": "List"}],
        "updates": [{"at": LATER, "text": "OPERATORS REPORT POST-0.4.17 UPGRADE FAILURE.", "sources": [{"url": list_url, "title": "List"}]}],
    }
    upd_holds = review.final_holds(upd_cand, {"mode": "update", "packet": {"sources": src_for("community")}})
    assert set(upd_holds) == {"shouting_caps", "malformed_version"}
    assert review.final_holds({**shout_story, "origin": "network-health"}, prep_for("community")) == []
