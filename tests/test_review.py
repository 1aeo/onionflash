"""Exact-candidate review protocol, immutable repairs, config, and fresh verification."""

import copy
import json

import pytest

from helpers import (
    LATER, NON_RELEASE_CATEGORIES, NON_TAG_STATES, STORY, FakeLLM, completion, verdict, wire_reviewer,
    write_toml,
)
from onionflash import analyze, review
from onionflash.analyze import AnalysisError
from onionflash.config import DEFAULTS, load_config
from onionflash.render import prepare_story
from onionflash.transport import FetchError, Response


def _cfg_llm():
    result = copy.deepcopy(DEFAULTS)
    result["llm"]["base_url"] = "https://llm.example/v1"
    return result


def _reviewer(monkeypatch, *replies, cfg=None):
    return wire_reviewer(cfg or _cfg_llm(), *replies, monkeypatch=monkeypatch)


def _candidate(**changes):
    return prepare_story({**copy.deepcopy(STORY), **changes})


def _packet():
    return {
        "sources": [{"id": "S1", "url": STORY["sources"][0]["url"], "title": "Release notes",
                     "kind": "rss", "authority": "official", "product": "tor",
                     "published_at": STORY["published_at"], "updated_at": STORY["updated_at"], "labels": [],
                     "passages": [{"id": "S1:P1", "text": "The release includes improvements for relay operators."}]}],
        "missing_sources": [], "truncated": False,
    }


def _unit(kind, *texts, authority="development", state=""):
    return {"kind": kind, "authority": authority, "upstream_state": state, "title": texts[0],
            "passages": [{"text": text} for text in texts]}


ISSUE = _unit("gitlab_issue", "dirauth: Remove bastet from list",
              "Last night, bastet's operator notified us that the machine is very plausibly compromised.",
              "In any kind of scenario here, the keys can’t be trusted anymore and bastet will generate a new identity soon.",
              "In the meantime, remove bastet from source as we can't trust it anymore.", state="opened")
MERGED = _unit("gitlab_mr", "Remove bastet's keys from default dirauth list", state="merged")
FEED = _unit("feed", "Tor Browser 16.0.2 is released", "Tor Browser 16.0.2 is now available for Android.", authority="official")
CRASH = _unit("gitlab_issue", "Fix the crash in the parser", state="opened")
COMPROMISED = _unit("gitlab_issue", "Bastet", "The machine was compromised.", state="opened")
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
    ("planned-deployment", "gitlab_issue", [_unit("gitlab_issue", "Crash", "The fix will be deployed next week.")], {"summary": "The fix was deployed."}, DONE),
    ("negated-in-source", "gitlab_issue", [_unit("gitlab_issue", "Crash", "This wasn’t fixed in 2.7.0.")], {"summary": "The crash was fixed in 2.7.0."}, DONE),
    ("compound-in-source", "gitlab_issue", [_unit("gitlab_issue", "Crash", "The parser uses a fixed-size buffer and crashes on long input.")], {"summary": "The crash was fixed."}, DONE),
    ("requested", "gitlab_issue", [ISSUE], {"title": "Tor authority bastet to be removed from source after reported compromise"}, []),
    ("asked", "gitlab_issue", [ISSUE], {"summary": "The issue asks that bastet be removed."}, []),
    ("not-yet", "gitlab_issue", [ISSUE], {"summary": "Bastet has not been removed yet."}, []),
    ("contractions", "gitlab_issue", [ISSUE], {"summary": "Bastet wasn't removed yet, and its keys haven’t been rotated."}, []),
    ("no-fixed-release", "gitlab_issue", [ISSUE], {"summary": "No fixed release has been identified."}, []),
    ("adjective", "gitlab_issue", [ISSUE], {"summary": "The parser uses a fixed-size buffer."}, []),
    ("stated-elsewhere", "gitlab_issue", [_unit("gitlab_issue", "Fix the crash in the parser", "The crash is fixed in main.")], {"summary": "Developers fixed the crash."}, []),
    ("stated-in-comment", "gitlab_issue", [_unit("gitlab_issue", "Protover parser differential", "This was fixed in 2.7.0. Closing.")], {"summary": "This was fixed in Arti 2.7.0."}, []),
    ("noun", "gitlab_issue", [ISSUE], {"title": "Arti 2.8.0 released with low-severity security fixes"}, []),
    ("not-issue-written", "feed", [ISSUE], {"summary": "Tor removes bastet from the authority list."}, []),
    ("merged-title", "gitlab_issue", [ISSUE, MERGED], {"summary": "Bastet's keys were removed from the default authority list."}, []),
    ("merged-title-other-change", "gitlab_issue", [ISSUE, MERGED], {"summary": "Bastet's keys were revoked."}, DONE),
    ("unmerged-title", "gitlab_issue", [ISSUE, {**MERGED, "upstream_state": "opened"}], {"summary": "Bastet's keys were removed from the default authority list."}, DONE),
    ("compromised", "gitlab_issue", [ISSUE], {"title": "Bastet directory authority compromised"}, HEADLINE),
    ("hacked", "gitlab_issue", [ISSUE], {"title": "Tor directory authority bastet hacked"}, HEADLINE),
    ("breach", "gitlab_issue", [ISSUE], {"title": "Bastet authority breach forces key change"}, HEADLINE),
    ("possibly", "gitlab_issue", [_unit("gitlab_issue", "Bastet", "It was possibly compromised.")], {"title": "Bastet compromised"}, HEADLINE),
    ("hedged-by-second-source", "gitlab_issue", [COMPROMISED, _unit("feed", "Bastet", "It may have been compromised.")], {"title": "Bastet compromised"}, HEADLINE),
    ("qualified", "gitlab_issue", [ISSUE], {"title": "Bastet reported plausibly compromised"}, []),
    ("may-have-been", "gitlab_issue", [ISSUE], {"title": "Bastet may have been compromised"}, []),
    ("unhedged-source", "gitlab_issue", [COMPROMISED], {"title": "Bastet compromised"}, []),
    ("issue-confirmed", "gitlab_issue", [ISSUE], {"confidence": "confirmed"}, CONFIRMED),
    ("tag-and-issue-confirmed", "gitlab_issue", [_unit("tag", "arti-v2.7.0", authority="official"), ISSUE], {"confidence": "confirmed"}, CONFIRMED),
    ("unmerged-request-confirmed", "gitlab_mr", [{**MERGED, "upstream_state": ""}], {"confidence": "confirmed", "state": "merged"}, CONFIRMED),
    ("merged-request-confirmed", "gitlab_mr", [MERGED], {"confidence": "confirmed", "state": "merged"}, []),
    ("official-feed-confirmed", "feed", [FEED], {"confidence": "confirmed", "state": "released"}, []),
    ("official-feed-and-issue-confirmed", "feed", [FEED, ISSUE], {"confidence": "confirmed"}, []),
    ("release-shape-confirmed", "feed", [_unit("tag", "tor-0.4.9.16", authority="official"), FEED,
                                         _unit("metrics_timeline", "Relay versions", authority="telemetry")], {"confidence": "confirmed", "state": "released"}, []),
    ("merge-request-released", "gitlab_mr", [MERGED], {"title": "Tor releases a parser fix", "state": "released"}, MERGE),
    ("merge-request-and-issue-fixed", "gitlab_mr", [MERGED, ISSUE], {"state": "fixed"}, []),
    ("operator-only-state", "gitlab_issue", [ISSUE], {"state": "no-longer-listed"}, []),
]
COVERED = "0123456789abcdef01234567"
COVERAGE = {"prior_story": None, "recent": [{"id": COVERED, "title": "Earlier coverage"}], "truncated": False}
PRIOR = {"prior_story": {"id": COVERED, "title": "Earlier coverage"}, "recent": [], "truncated": False}

_BAD_APPROVALS = {
    "source-ref": lambda r: r["criteria"]["source_support"].update(source_refs=["S2:P99"]),
    "issues": lambda r: r.update(issues=[]),
    "model-verdict": lambda r: r.update(model_verdict="hold"),
    "failed-criterion": lambda r: r["criteria"]["source_support"].update(outcome="fail"),
    "changed-text": lambda r: r.update(repair={k: None for k in review.EDITABLE}),
    "missing-criterion": lambda r: r["criteria"].pop("new_information"),
    "missing-refs": lambda r: r["criteria"]["source_support"].update(source_refs=[]),
    "score": lambda r: r.update(score=10),
    "unknown-verdict": lambda r: r.update(verdict="probably"),
    "failed-news-value-approve": lambda r: r["criteria"]["news_value"].update(outcome="fail"),
    "failed-new-information-approve": lambda r: r["criteria"]["new_information"].update(outcome="fail"),
}


def test_review_keeps_only_its_model_and_rejects_unknown_settings(tmp_path):
    """Accept review.model overrides while rejecting unknown review settings."""
    cfg = load_config(write_toml(tmp_path, '[llm]\ntimeout_seconds=45\n[review]\nmodel="critic-model"', name="c1.toml"))
    assert cfg["review"] == {"model": "critic-model"}
    with review.Reviewer(cfg) as rev:
        assert rev.llm["model"] == "critic-model" and rev.llm["max_output_tokens"] == review.OUTPUT_TOKENS
        assert (rev.http_settings["timeout_seconds"], rev.http_settings["total_timeout_seconds"]) == (45, 180)
    with pytest.raises(ValueError, match="review.model"):
        load_config(write_toml(tmp_path, "[review]\nmodel=[]", name="c2.toml"))
    for unknown_key in ("max_passages=1", "max_repairs=0", "timeout_seconds=300"):
        with pytest.raises(ValueError, match="Unknown review settings"):
            load_config(write_toml(tmp_path, f"[review]\n{unknown_key}", name="c3.toml"))
    inh = copy.deepcopy(DEFAULTS)
    inh["llm"]["model"] = "configured-local-model"
    with review.Reviewer(inh) as rev:
        assert rev.llm["model"] == "configured-local-model"


@pytest.mark.parametrize("st", ["released", "tagged"])
@pytest.mark.parametrize("ver", [False, True])
def test_released_and_tagged_candidates_pass_review_and_verification(monkeypatch, st, ver):
    """Approve released and tagged candidates in both review and verification stages."""
    assert _reviewer(monkeypatch, verdict()).review(_candidate(state=st), _packet(), verification=ver)["verdict"] == "approve"


def test_review_protocol_fresh_verification_and_application_issue(monkeypatch):
    """Verify schema constraints, repair application, fresh verification, and application_issue payloads."""
    public = _candidate(why_it_matters="Operators must edit their configuration to exclude the compromised node.")
    checker = _reviewer(monkeypatch, verdict("revise", repair={"why_it_matters": ""}), verdict())
    result = checker.review(public, _packet())
    assert result["repair"] == {"why_it_matters": ""}
    repaired = review.apply_repair(public, result["repair"])
    assert checker.review(repaired, _packet(), verification=True)["verdict"] == "approve"
    first, second = checker.client.bodies
    for check in first["response_format"]["json_schema"]["schema"]["properties"]["criteria"]["properties"].values():
        assert check["properties"]["source_refs"]["items"]["enum"] == sorted(review._packet_refs(_packet()))
    assert "enum" not in review.REFS["items"]
    assert json.loads(first["messages"][1]["content"]) == {"candidate": public, "packet": _packet()}
    assert len(second["messages"]) == 2 and second["messages"][0]["content"] == review.VERIFY_PROMPT
    assert json.loads(second["messages"][1]["content"]) == {"candidate": repaired, "packet": _packet()}

    schema = first["response_format"]["json_schema"]["schema"]
    assert list(schema["properties"]) == schema["required"] == ["criteria", "verdict", "same_story", "repair"]
    for check in schema["properties"]["criteria"]["properties"].values():
        assert list(check["properties"]) == check["required"] == ["reason", "source_refs", "outcome"]
        assert check["properties"]["reason"]["maxLength"] == 240

    untouched = _candidate(confidence="suspected", state="developing", category="security", tags=["security"], why_it_matters="")
    snap = copy.deepcopy(untouched)
    assert _reviewer(monkeypatch, verdict()).review(untouched, _packet())["verdict"] == "approve"
    assert untouched == snap

    rel_pub = _candidate(state="merged", category="release", tags=["release"])
    rel_chk = _reviewer(monkeypatch, verdict())
    rel_res = rel_chk.review(rel_pub, _packet(), issue=review.RELEASE_ISSUE)
    assert rel_res == review.validate_review(verdict(), _packet()) and "model_verdict" not in rel_res
    assert rel_chk.client.bodies[0]["messages"][0]["content"] == review.SYSTEM_PROMPT
    assert json.loads(rel_chk.client.bodies[0]["messages"][1]["content"]) == {
        "candidate": rel_pub, "packet": _packet(), "application_issue": review.RELEASE_ISSUE}


@pytest.mark.parametrize("bad", list(_BAD_APPROVALS))
def test_malformed_or_ambiguous_approval_is_rejected(monkeypatch, bad):
    """Reject malformed, extra-field, or inconsistent approval responses."""
    resp = verdict()
    _BAD_APPROVALS[bad](resp)
    checker = _reviewer(monkeypatch, resp)
    with pytest.raises(review.ReviewError):
        checker.review(_candidate(), _packet())
    assert len(checker.client.requests) == 1


@pytest.mark.parametrize("writer,sources,fields,expected", [c[1:] for c in FINAL_CASES], ids=[c[0] for c in FINAL_CASES])
def test_final_holds_on_real_cases(writer, sources, fields, expected):
    """Verify deterministic final_holds reasons across issue, MR, and feed cases."""
    story = _candidate(**{"title": "Bastet reported plausibly compromised", "why_it_matters": "", "category": "security",
                          "tags": ["security"], "summary": "A public issue reports that bastet's machine is very plausibly compromised.",
                          "confidence": "reported", "state": "developing", **fields})
    assert review.final_holds(story, {"packet": {"sources": sources}, "payload": {"editorial_kind": writer}}) == expected


@pytest.mark.parametrize("sources,confidence,state,categories", [
    ([ISSUE], ["reported", "suspected", "observed-anomaly"], NON_TAG_STATES, analyze.CATEGORIES),
    ([MERGED], analyze.CONFIDENCES, ["merged"], NON_RELEASE_CATEGORIES),
    ([FEED], analyze.CONFIDENCES, NON_TAG_STATES, analyze.CATEGORIES),
    ([_unit("tag", "tor-0.4.9.16", authority="official"), FEED], analyze.CONFIDENCES, analyze.STATES, analyze.CATEGORIES),
], ids=["issue", "merged-request", "official-feed", "tagged-release"])
def test_repair_schema_offers_only_labels_the_packet_allows(monkeypatch, sources, confidence, state, categories):
    """Constrain repair enum choices to packet-supported confidence, state, and category labels."""
    evidence = {"sources": [{**s, "id": f"S{i}", "passages": [{"id": f"S{i}:P1", **s["passages"][0]}]}
                            for i, s in enumerate(sources, 1)], "missing_sources": [], "truncated": False}
    checker = _reviewer(monkeypatch, verdict(), verdict())
    checker.review(_candidate(), evidence)
    checker.review(_candidate(), evidence, verification=True)
    for req in checker.client.bodies:
        rep = req["response_format"]["json_schema"]["schema"]["properties"]["repair"]["anyOf"][1]["properties"]
        assert (rep["confidence"]["anyOf"][0]["enum"], rep["state"]["anyOf"][0]["enum"]) == (confidence, state)
        assert rep["category"]["anyOf"][0]["enum"] == rep["tags"]["anyOf"][0]["items"]["enum"] == categories
    assert (review.FIELDS["confidence"]["enum"], review.FIELDS["state"]["enum"],
            review.FIELDS["category"]["enum"]) == (analyze.CONFIDENCES, analyze.STATES, analyze.CATEGORIES)
    if "tagged" not in state:
        with pytest.raises(review.ReviewError, match="limits"):
            _reviewer(monkeypatch, verdict("revise", repair={"state": "tagged"}, criterion="status")).review(_candidate(), evidence)
    if "release" not in categories:
        with pytest.raises(review.ReviewError, match="limits"):
            _reviewer(monkeypatch, verdict("revise", repair={"tags": ["release"]}, criterion="status")).review(_candidate(), evidence)


@pytest.mark.parametrize("patch,is_upd,match", [
    ({"why_it_matters": "Relays are AT RISK FOR DEANONYMIZATION NOW."}, False, None),
    ({"why_it_matters": "Tor 0.4.17 relays are affected."}, False, None),
    ({"why_it_matters": "x" * (review.FIELD_LIMITS["why_it_matters"] + 1)}, False, None),
    ({"why_it_matters": 123}, False, None),
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
    """Refuse immutable-field, no-op, empty, shouting, malformed-version, or unpunctuated repairs."""
    base = _candidate(updates=[{"at": "2026-11-08T14:00:00Z", "text": "Maintainers opened a tracking ticket.",
                                "sources": [{"url": STORY["sources"][0]["url"], "title": "Release notes"}]}])
    with pytest.raises(review.ReviewError, match=match):
        review.apply_repair(base, patch, update=is_upd)


def test_why_it_matters_repair_grounding_and_clearing(monkeypatch):
    """Allow grounded non-empty why_it_matters repairs while clearing ungrounded numbers, shouting, or community impact."""
    grounded = review.apply_repair(
        _candidate(),
        {"why_it_matters": "  Operators can   read the release notes to assess changes.  "},
    )
    assert grounded["why_it_matters"] == "Operators can read the release notes to assess changes."

    numbered_pkt = {
        "sources": [{
            "id": "S1", "url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41500",
            "title": "Consensus votes exceeding 16 MB are truncated", "kind": "gitlab_issue",
            "authority": "development", "product": "tor", "published_at": STORY["published_at"],
            "updated_at": STORY["updated_at"], "labels": [],
            "passages": [{"id": "S1:P1", "text": "Votes larger than 16 MB fail serialization on 0.4.9.16."}],
        }],
        "missing_sources": [], "truncated": False,
    }
    valid_repair = "Votes over 16 MB fail serialization on 0.4.9.16."
    res_ok = _reviewer(monkeypatch, verdict("revise", criterion="source_support", repair={"why_it_matters": valid_repair})).review(
        _candidate(why_it_matters="All votes fail."), numbered_pkt
    )
    assert res_ok["repair"] == {"why_it_matters": valid_repair}

    for bad_wim in (
        "Votes over 32 MB fail serialization.",
        "Votes over 16 MB fail on 0.4.9.99.",
        "Votes over 16 MB cause TOR VOTES TO FAIL COMPLETELY.",
        "Operators running Tor 0.4.17 lose votes.",
    ):
        cleared = _reviewer(
            monkeypatch,
            verdict("revise", criterion="source_support", repair={"summary": "Tightened summary.", "why_it_matters": bad_wim}),
        ).review(_candidate(why_it_matters="Old text."), numbered_pkt)
        assert cleared["repair"] == {"summary": "Tightened summary.", "why_it_matters": ""}

    arti_pkt = copy.deepcopy(numbered_pkt)
    arti_pkt["sources"][0]["product"] = "arti"
    arti_pkt["sources"][0]["passages"][0]["text"] = "Tested on Tor 0.4.17 build."
    kept_arti = _reviewer(
        monkeypatch,
        verdict("revise", criterion="source_support", repair={"why_it_matters": "Affects Tor 0.4.17 build tests."}),
    ).review(_candidate(products=["arti"]), arti_pkt)
    assert kept_arti["repair"] == {"why_it_matters": "Affects Tor 0.4.17 build tests."}

    list_url = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/R1/"
    comm_pkt = {
        "sources": [{
            "id": "S1", "url": list_url, "title": "[tor-relays] Re: 42 relays failing",
            "kind": "feed", "authority": "community", "product": "tor",
            "published_at": STORY["published_at"], "updated_at": STORY["updated_at"], "labels": [],
            "unquoted_content": "Our 3 relays saw normal load.",
            "passages": [{"id": "S1:P1", "text": "Our 3 relays saw normal load.\n> 42 relays failed."}],
        }],
        "missing_sources": [], "truncated": False,
    }
    comm_cleared = _reviewer(
        monkeypatch,
        verdict("revise", criterion="source_support", repair={"summary": "Sender saw 3 relays.", "why_it_matters": "Our 3 relays saw normal load."}),
    ).review(_candidate(why_it_matters="42 relays failed."), comm_pkt)
    assert comm_cleared["repair"] == {"summary": "Sender saw 3 relays.", "why_it_matters": ""}

    trusted_pkt = copy.deepcopy(comm_pkt)
    trusted_pkt["sources"][0]["authority"] = "trusted-operator"
    quoted_num_cleared = _reviewer(
        monkeypatch,
        verdict("revise", criterion="source_support", repair={"why_it_matters": "42 relays failed."}),
    ).review(_candidate(why_it_matters="Old text."), trusted_pkt)
    assert quoted_num_cleared["repair"] == {"why_it_matters": ""}
    unquoted_num_kept = _reviewer(
        monkeypatch,
        verdict("revise", criterion="source_support", repair={"why_it_matters": "3 relays saw normal load."}),
    ).review(_candidate(why_it_matters="Old text."), trusted_pkt)
    assert unquoted_num_kept["repair"] == {"why_it_matters": "3 relays saw normal load."}


@pytest.mark.parametrize("kind,target,val", [
    ("cfg", ("llm", "model"), "another-model"),
    ("cfg", ("llm", "base_url"), "https://other.example/v1"),
    ("cfg", ("llm", "fallback_base_urls"), ["https://fallback.example/v1"]),
    ("cfg", ("review", "model"), "review-only"),
    ("attr", "RELEASE_ISSUE", None),
    ("attr", "UPDATE_SYSTEM_PROMPT", None),
    ("attr", "UPDATE_VERIFY_PROMPT", None),
    ("attr", "ROUTING_PROMPT", None),
    ("attr", "VALIDATION_REASK_PROMPT", None),
])
def test_policy_hash_changes_on_model_endpoint_and_prompt_mutations(monkeypatch, kind, target, val):
    """Change policy_hash when model, endpoint, or prompt constants change, ignoring API keys."""
    initial = review.policy_hash(_cfg_llm())
    monkeypatch.setenv("ONIONFLASH_LLM_API_KEY", "a-different-secret")
    assert review.policy_hash(_cfg_llm()) == initial
    if kind == "cfg":
        changed = copy.deepcopy(_cfg_llm())
        changed[target[0]][target[1]] = val
        assert review.policy_hash(changed) != initial
    else:
        monkeypatch.setattr(review, target, getattr(review, target) + "!")
        assert review.policy_hash(_cfg_llm()) != initial


def test_prompts_coverage_isolation_repairs_and_transport_settings(monkeypatch):
    """Check prompt invariants, coverage isolation, UTF-8/JSON errors, and endpoint failover."""
    assert "unnumbered [Proposal]) whose packet source has authority=project-sender" in review.SYSTEM_PROMPT
    assert "When\nauthority=community, posts without an explicit [RFC] tag" in review.SYSTEM_PROMPT
    for prompt in (review.SYSTEM_PROMPT, review.UPDATE_SYSTEM_PROMPT):
        assert "committed into C Tor's codebase" in prompt
        assert "including project-sender and official" in prompt
        assert "unquoted_content" in prompt
    for prompt in (review.SYSTEM_PROMPT, review.VERIFY_PROMPT):
        assert "Claims supported by other packet sources need only that source's support." in prompt
    assert _reviewer(monkeypatch, verdict("skip", criterion="news_value")).review(_candidate(state="merged"), _packet())["verdict"] == "skip"

    assert "thread_context or thread_root" in review.SYSTEM_PROMPT
    assert "cross-channel coverage" in review.ROUTING_PROMPT
    assert "shared CVEs" in review.ROUTING_PROMPT
    public = _candidate(why_it_matters="Existing commentary")
    assert review.apply_repair(public, {"why_it_matters": ""})["why_it_matters"] == ""
    chk = _reviewer(monkeypatch, verdict())
    chk.review(public, _packet())
    wim = chk.client.bodies[0]["response_format"]["json_schema"]["schema"]["properties"]["repair"]["anyOf"][1]["properties"]["why_it_matters"]
    assert wim["anyOf"][0] == {"type": "string", "maxLength": review.FIELD_LIMITS["why_it_matters"]}
    assert "enum" not in wim["anyOf"][0] and wim["anyOf"][1] == {"type": "null"}

    bg = {"prior_story": None, "recent": [{"id": "B1", "title": "Earlier coverage"}], "truncated": False}
    bg_chk = _reviewer(monkeypatch, verdict(), verdict())
    bg_chk.review(_candidate(), _packet(), coverage=bg)
    bg_chk.review(_candidate(), _packet(), coverage=bg, verification=True)
    for req in bg_chk.client.bodies:
        assert json.loads(req["messages"][1]["content"]) == {"candidate": _candidate(), "packet": _packet(), "coverage_background": bg}
        fields = req["response_format"]["json_schema"]["schema"]["properties"]["criteria"]["properties"]
        assert set(fields) == set(review.CRITERIA)
        assert all(c["properties"]["source_refs"]["items"]["enum"] == ["S1", "S1:P1"] for c in fields.values())
    with pytest.raises(review.ReviewError, match="source reference"):
        _reviewer(monkeypatch, verdict("skip", criterion="new_information", ref="B1")).review(_candidate(), _packet(), coverage=bg)

    skip_ok = verdict("skip", criterion="new_information", criteria={"source_support": {"outcome": "fail"}})
    assert review.validate_review(skip_ok, _packet())["verdict"] == "skip"
    with pytest.raises(review.ReviewError, match="Only a revise"):
        review.validate_review(verdict("skip", criterion="news_value", repair={"summary": "Different text"}), _packet())

    norm = review.apply_repair(_candidate(), {"summary": "  More   precise source wording.  ", "why_it_matters": ""})
    assert norm["summary"] == "More precise source wording." and norm["why_it_matters"] == ""
    assert all(norm[k] == v for k, v in _candidate().items() if k not in review.EDITABLE)

    assert _reviewer(monkeypatch, verdict("revise", repair={"why_it_matters": ""})).review(_candidate(), _packet(), verification=True)["verdict"] == "revise"
    held = _reviewer(monkeypatch, verdict("hold")).review(_candidate(), _packet(), verification=True)
    assert held["verdict"] == "hold" and held["repair"] is None

    sparse = {**verdict("revise", repair={"why_it_matters": ""}), "repair": {"why_it_matters": ""}}
    assert review.validate_review(sparse, _packet())["repair"] == {"why_it_matters": ""}
    sparse["criteria"]["operational_advice"]["source_refs"] = ["S9"]
    with pytest.raises(review.ReviewError, match="source reference"):
        review.validate_review(sparse, _packet())

    ev_cr = _packet()
    ev_cr["sources"][0]["passages"][0]["text"] += "\r\nA second line."
    assert _reviewer(monkeypatch, verdict()).review(_candidate(), ev_cr)["verdict"] == "approve"
    ev_cr["sources"][0]["passages"][0]["text"] = "\ud800"
    sur_chk = _reviewer(monkeypatch)
    with pytest.raises(AnalysisError, match="UTF-8"):
        sur_chk.review(_candidate(), ev_cr)
    assert sur_chk.client.requests == []

    dup_enc = json.dumps(verdict()).replace('"verdict":', '"verdict":"hold","verdict":', 1)
    dup_raw = {"choices": [{"finish_reason": "stop", "message": {"content": dup_enc}}]}
    with pytest.raises(AnalysisError, match="invalid JSON") as cdup:
        _reviewer(monkeypatch, Response(200, json.dumps(dup_raw).encode(), {}, "https://llm.example/v1")).review(_candidate(), _packet())
    assert not cdup.value.retryable
    with pytest.raises(AnalysisError, match="truncated") as ctr:
        _reviewer(monkeypatch, completion(verdict(), finish_reason="length")).review(_candidate(), _packet())
    assert not ctr.value.retryable

    fb_cfg = _cfg_llm()
    fb_cfg["llm"].update(fallback_base_urls=["https://fallback.example/v1"], timeout_seconds=180)
    fb_cfg["review"]["model"] = "review-model"
    fb_chk = _reviewer(monkeypatch, FetchError("unavailable", status=503), verdict(), cfg=fb_cfg)
    assert fb_chk.review(_candidate(), _packet())["verdict"] == "approve"
    assert [u for u, _ in fb_chk.client.requests] == ["https://llm.example/v1/chat/completions", "https://fallback.example/v1/chat/completions"]
    assert fb_chk.client.bodies[-1]["model"] == "review-model" and fb_chk.client.bodies[-1]["max_tokens"] == review.OUTPUT_TOKENS
    assert (fb_chk.http_settings["timeout_seconds"], fb_chk.http_settings["total_timeout_seconds"], fb_chk.http_settings["retry_attempts"]) == (180, 190, 1)

    fake = FakeLLM(verdict())
    monkeypatch.setattr("onionflash.llm.HttpClient", lambda *a, **kw: fake)
    with review.Reviewer(_cfg_llm(), deadline=123.5) as dl_chk:
        dl_chk.clock = lambda: 100.0
        dl_chk.review(_candidate(), _packet())
        assert dl_chk.deadline == 123.5 and getattr(fake, "deadline", None) is None


@pytest.mark.parametrize("criterion,outcome,expected", [
    ("news_value", "fail", "skip"), ("new_information", "fail", "skip"),
    ("news_value", "insufficient", "hold"), ("new_information", "insufficient", "hold"),
    ("source_support", "fail", "hold"),
])
@pytest.mark.parametrize("verification", [False, True])
@pytest.mark.parametrize("update", [False, True])
def test_a_skip_stands_only_on_a_failed_editorial_criterion(monkeypatch, criterion, outcome, expected, verification, update):
    """Convert skips without a failed editorial criterion into holds while recording model_verdict."""
    reply = verdict("skip", criterion=criterion, update=update,
                    criteria={criterion: {"outcome": outcome, "reason": f"Story {COVERED} reports the same event."}})
    cov = PRIOR if update else COVERAGE
    cand = _candidate(updates=[{"at": "2026-11-08T14:00:00Z", "text": "Earlier update.",
                                "sources": [{"url": STORY["sources"][0]["url"], "title": "Release notes"}]}]) if update else _candidate()
    res = _reviewer(monkeypatch, reply).review(cand, _packet(), coverage=cov, verification=verification, update=update)
    assert (res["verdict"], res["repair"], res["criteria"]) == (expected, None, reply["criteria"])
    assert res.get("model_verdict") == (None if expected == "skip" else "skip")
    assert review.validate_review(res, _packet(), update=update) == res
    if expected == "hold":
        with pytest.raises(review.ReviewError, match="editorial criterion"):
            review.validate_review(reply, _packet(), update=update)


@pytest.mark.parametrize("update,coverage,reason,expected", [
    (False, COVERAGE, "Earlier coverage reports the same event.", "hold"),
    (False, COVERAGE, f"Story {COVERED} reports the same event.", "skip"),
    (False, PRIOR, f"The existing story {COVERED} already reports this.", "skip"),
    (False, None, f"Story {COVERED} reports the same event.", "hold"),
    (True, PRIOR, "Already covered by prior_story; no new facts.", "skip"),
    (True, PRIOR, f"Repeats {COVERED}.", "skip"),
    (True, PRIOR, "Unrelated ticket wrongly attached to this story.", "hold"),
    (True, PRIOR, f"Different event from {COVERED}.", "hold"),
    (True, PRIOR, "Different story or product altogether.", "hold"),
    (True, PRIOR, "Different incident on another branch.", "hold"),
    (True, {"prior_story": {"id": COVERED, "title": "Prior"}, "recent": [{"id": "f" * 24, "title": "Retracted", "retracted": True}]},
     f"Repeats retracted story {'f' * 24}.", "hold"),
    (True, {"prior_story": {"id": COVERED, "title": "Prior", "retracted": True}, "recent": []},
     "Repeats retracted prior story.", "hold"),
    (True, None, "Already covered by prior_story.", "hold"),
], ids=["story-unnamed", "story-recent", "story-prior", "story-no-cov",
        "upd-no-hex-id", "upd-with-id", "upd-unrelated", "upd-different-event",
        "upd-different-story-product", "upd-different-incident", "upd-retracted-recent",
        "upd-retracted-prior", "upd-no-cov"])
def test_a_skip_for_new_information_alone_names_a_story_from_coverage(monkeypatch, update, coverage, reason, expected):
    """Require story-mode new_information skips to name a live ID, and allow update-mode redundant skips while holding unrelated/retracted ones."""
    reply = verdict("skip", criterion="new_information", reason=reason, update=update)
    cand = _candidate(updates=[{"at": "2026-11-08T14:00:00Z", "text": "Earlier update.",
                                "sources": [{"url": STORY["sources"][0]["url"], "title": "Release notes"}]}]) if update else _candidate()
    assert _reviewer(monkeypatch, reply).review(cand, _packet(), coverage=coverage, update=update)["verdict"] == expected
    if not update:
        reply["criteria"]["news_value"]["outcome"] = "fail"
        assert _reviewer(monkeypatch, reply).review(cand, _packet(), coverage=coverage, update=update)["verdict"] == "skip"


def test_update_scope_confirmed_updates_uncited_notes_and_punctuation_repairs(monkeypatch):
    """Validate latest_update review prompts, repair limits, and per-note completed-action checks."""
    prior = _candidate(
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
        "sources": [_packet()["sources"][0],
                    {"id": "S2", "url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/41400", "title": "Issue",
                     "kind": "gitlab_issue", "authority": "development", "product": "tor", "upstream_state": "opened",
                     "published_at": STORY["published_at"], "updated_at": STORY["updated_at"], "labels": [],
                     "passages": [{"id": "S2:P1", "text": "Operators reported new telemetry."}]}],
        "missing_sources": [], "truncated": False,
    }
    checker = _reviewer(
        monkeypatch,
        verdict("revise", repair={"update": "Operators reported verified telemetry.", "state": "developing"}, update=True),
        verdict(update=True),
    )
    res = checker.review(prior, pkt, coverage=coverage, update=True)
    assert res["repair"] == {"update": "Operators reported verified telemetry.", "state": "developing"}
    body = checker.client.bodies[0]
    assert body["messages"][0]["content"] == review.UPDATE_SYSTEM_PROMPT
    assert tuple(body["response_format"]["json_schema"]["schema"]["properties"]["repair"]["anyOf"][1]["properties"]) == review.UPDATE_EDITABLE
    sent = json.loads(body["messages"][1]["content"])
    assert sent["review_scope"] == "latest_update" and set(sent["coverage_background"]["prior_story"]) == {"id", "state", "confidence", "updated_at"}

    repaired = review.apply_repair(prior, res["repair"], update=True)
    assert checker.review(repaired, pkt, coverage=coverage, verification=True, update=True)["verdict"] == "approve"
    assert checker.client.bodies[1]["messages"][0]["content"] == review.UPDATE_VERIFY_PROMPT
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

    conf_chk = _reviewer(monkeypatch, verdict(update=True))
    conf_chk.review({**prior, "confidence": "confirmed"}, pkt,
                    coverage={**coverage, "prior_story": {**coverage["prior_story"], "confidence": "confirmed"}}, update=True)
    assert conf_chk.client.bodies[0]["response_format"]["json_schema"]["schema"]["properties"]["repair"]["anyOf"][1]["properties"]["confidence"]["anyOf"][0]["enum"] == ["confirmed"]

    recent_cov = {"prior_story": None, "recent": [{"id": "a" * 24, "title": "Prior", "retracted": False}], "truncated": False}
    rt_chk = _reviewer(monkeypatch, verdict(), verdict())
    rt_chk.review(_candidate(), _packet(), coverage=recent_cov)
    rt_chk.review(_candidate(), _packet(), coverage=recent_cov, verification=True)
    assert rt_chk.client.bodies[0]["messages"][0]["content"] == review.SYSTEM_PROMPT + review.ROUTING_PROMPT
    assert rt_chk.client.bodies[1]["messages"][0]["content"] == review.VERIFY_PROMPT + review.ROUTING_PROMPT

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
    assert review.final_holds(cand, prep) == []
    assert "completed_action" in review.final_holds({**cand, "updates": [{"at": LATER, "text": "Maintainers deployed the fix.",
                                                                          "sources": [{"url": url99, "title": "Issue 99"}]}]}, prep)
    prep_parent_done = {**prep, "packet": {"sources": [{"id": "S1", "url": url99, "authority": "development", "kind": "gitlab_issue",
                                                        "passages": [{"id": "S1.P1", "text": "Earlier release fixed an older unrelated crash."},
                                                                     {"id": "S1.N2", "url": url99 + "#note_2", "text": "Still investigating this regression."}]}]}}
    assert "completed_action" in review.final_holds({**cand, "updates": [{"at": LATER, "text": "Maintainers fixed the regression.",
                                                                          "sources": [{"url": url99 + "#note_2", "title": "Comment"}]}]}, prep_parent_done)


def test_final_holds_shouting_malformed_version_and_untrusted_operator_claims():
    """Enforce shouting_caps, malformed_version, and untrusted_operator_claim guards."""
    list_url = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/xyz/"
    src_for = lambda auth, url=list_url: [{"id": "S1", "url": url, "kind": "feed", "authority": auth,
                                           "passages": [{"id": "S1:P1", "text": "Relay telemetry report."}]}]
    prep_for = lambda auth, url=list_url: {"packet": {"sources": src_for(auth, url)}, "payload": {"editorial_kind": "feed"}}

    shout_story = _candidate(title="Relays AT RISK FOR DEANONYMIZATION", confidence="reported")
    assert "shouting_caps" in review.final_holds(shout_story, prep_for("trusted-operator"))
    assert review.final_holds(_candidate(title="TLS SNI ALPN changes in relay connections", confidence="reported"),
                              prep_for("trusted-operator")) == []

    for bad_summary in (
        "Operators reported issues after a post-0.4.17 upgrade.",
        "Tor 0.4.17 release notes were written today.",
        "The post written yesterday cites Tor 0.4.17.",
    ):
        assert "malformed_version" in review.final_holds(
            _candidate(summary=bad_summary, confidence="reported", products=["tor"]), prep_for("trusted-operator")
        )
    for annotated in (
        "An operator wrote Tor 0.4.17 [sic] in the message.",
        "An operator wrote Tor 0.4.17 (sic) in the message.",
        'The subject was written as "Tor 0.4.17" in the archive.',
        "The subject was written as Tor 0.4.17 in the archive.",
        "Maintainers corrected the Tor 0.4.17 typo.",
    ):
        assert review.final_holds(_candidate(summary=annotated, confidence="reported", products=["tor"]), prep_for("trusted-operator")) == []
    assert review.final_holds(_candidate(summary="Operators tested 0.4.17 relay builds.", confidence="reported", products=["arti"]),
                              prep_for("trusted-operator")) == []

    inc_story = _candidate(title="Operator reports DDoS flood against exit relays",
                           summary="A mailing-list post describes an ongoing DDoS attack.",
                           category="dos", tags=["dos"], confidence="reported")
    assert review.final_holds(inc_story, prep_for("community")) == ["untrusted_operator_claim"]
    assert review.final_holds(inc_story, prep_for("trusted-operator")) == []
    assert review.final_holds(inc_story, prep_for("project-sender")) == []
    assert "confirmed_source" in review.final_holds({**inc_story, "confidence": "confirmed"}, prep_for("trusted-operator"))

    rfc_url = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-dev@lists.torproject.org/message/rfc1/"
    rfc_story = _candidate(title="[RFC] Relay congestion signaling extension",
                           summary="A proposal on tor-dev outlines congestion signaling frames.",
                           category="protocol", tags=["protocol"], confidence="reported")
    assert review.final_holds(rfc_story, prep_for("community", rfc_url)) == []

    prop_sources = [{
        "id": "S1", "url": rfc_url, "kind": "feed", "authority": "community",
        "title": "[tor-dev] Proposal 375: Rate-limiting circuit flooding",
        "passages": [{"id": "S1:P1", "text": "Proposal 375 specifies rate limits to defend against circuit flooding and DoS attacks."}],
    }]
    prop_story = _candidate(
        title="Proposal 375: Rate-limiting circuit flooding",
        summary="Proposal 375 on tor-dev specifies rate limits to defend against circuit flooding and DoS attacks.",
        category="protocol", tags=["protocol", "dos"], confidence="reported",
    )
    assert review.final_holds(prop_story, {"packet": {"sources": prop_sources}, "payload": {"editorial_kind": "feed"}}) == []
    prop_with_incident = _candidate(
        title="Attackers flooded exit relays yesterday",
        summary="Proposal 375 proposes rate limits after the flood disrupted exit relays.",
        category="dos", tags=["dos"], confidence="reported",
    )
    assert review.final_holds(
        prop_with_incident, {"packet": {"sources": prop_sources}, "payload": {"editorial_kind": "feed"}}
    ) == ["untrusted_operator_claim"]

    defense_framing = _candidate(
        title="Rate-limit proposal for directory requests",
        summary="A tor-dev post proposes a rate-limit defense against directory flooding.",
        category="protocol", tags=["protocol"], confidence="reported",
    )
    assert review.final_holds(defense_framing, prep_for("community", rfc_url)) == []

    live_incidents = [
        prop_with_incident,
        *(
            _candidate(title=title, summary=summary, category=cat, tags=[cat], confidence="reported")
            for title, summary, cat in (
                ("Operator reports suspected VPS provider tampering and connection flood on exit relay",
                 "A mailing-list post describes suspected host tampering and a connection flood.", "relay"),
                ("Operator reports HSDir-targeted circuit overload and attack",
                 "A mailing-list post reports an HSDir circuit attack on relays.", "relay"),
                ("Post claims rate-limit defense bypass on relays",
                 "A mailing-list post reports a rate-limit defense bypass.", "relay"),
                ("[RFC] Operator reports active DDoS flood hitting exit relays",
                 "A post marked RFC reports an active DDoS flood on exit relays.", "dos"),
                ("Rate-limit discussion on relay list",
                 "Operators propose rate limits after attackers flooded exit relays.", "relay"),
                ("Relay defense measures", "An attack targets exit relays.", "relay"),
            )
        ),
    ]
    for live_inc in live_incidents:
        assert review.final_holds(live_inc, prep_for("community", rfc_url)) == ["untrusted_operator_claim"]

    upd_cand = {
        **rfc_story,
        "sources": [{"url": list_url, "title": "List"}],
        "updates": [{"at": LATER, "text": "OPERATORS REPORT POST-0.4.17 UPGRADE FAILURE.", "sources": [{"url": list_url, "title": "List"}]}],
    }
    upd_holds = review.final_holds(upd_cand, {"mode": "update", "packet": {"sources": src_for("community")}})
    assert set(upd_holds) == {"shouting_caps", "malformed_version"}
    assert review.final_holds({**shout_story, "origin": "network-health"}, prep_for("community")) == []


def test_apply_repair_deduplicates_enum_arrays_and_rejects_duplicate_only_product_repairs():
    """Deduplicate repaired `products` and reject duplicate-only `['tor', 'tor']` no-op repairs."""
    cand = _candidate(products=["tor"])
    with pytest.raises(review.ReviewError, match="does not change"):
        review.apply_repair(cand, {"products": ["tor", "tor"]})
    repaired = review.apply_repair(cand, {"products": ["tor", "arti", "tor"]})
    assert repaired["products"] == ["tor", "arti"]


@pytest.mark.parametrize("bad_repair", [
    {"tags": 123},
    {"tags": True},
    {"tags": [123]},
    {"confidence": ["confirmed"]},
])
def test_within_label_limits_and_wire_reviewer_reject_non_iterable_or_non_string_repairs(monkeypatch, bad_repair):
    """Return `False` in `within_label_limits` and raise `ReviewError` on malformed wire `repair` values."""
    limits = analyze.label_limits([ISSUE])
    assert review.within_label_limits(bad_repair, limits) is False
    checker = _reviewer(monkeypatch, verdict("revise", criterion="status", repair=bad_repair))
    with pytest.raises(review.ReviewError):
        checker.review(_candidate(), _packet())


def test_apply_repair_cleans_stale_category_and_release_tags_unless_explicit():
    """Drop stale category and `release` tags on category/state repairs while honoring explicit `tags` edits."""
    sec_cand = _candidate(category="security", tags=["security"])
    repaired_relay = review.apply_repair(sec_cand, {"category": "relay"})
    assert repaired_relay["category"] == "relay" and repaired_relay["tags"] == ["relay"]

    rel_cand = _candidate(category="release", state="developing", tags=["release"])
    assert review.release_labels_match_state(rel_cand) is False
    repaired_feat = review.apply_repair(rel_cand, {"category": "feature"})
    assert repaired_feat["category"] == "feature" and repaired_feat["tags"] == ["feature"]
    assert review.release_labels_match_state(repaired_feat) is True

    explicit_rel = review.apply_repair(rel_cand, {"category": "feature", "tags": ["feature", "release"]})
    assert explicit_rel["tags"] == ["feature", "release"]
    assert review.release_labels_match_state(explicit_rel) is False


def test_update_repair_limits_and_final_holds_honor_established_prior_story_state():
    """Allow non-`merged` states in update mode when `prior_story` or public sources establish them."""
    mr_units = [
        {
            "id": f"S{i}",
            "url": f"https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/{100 + i}",
            "title": f"Merge request {i}",
            "kind": "gitlab_mr",
            "authority": "development",
            "upstream_state": "merged",
            "passages": [{"id": f"S{i}:P1", "text": f"Follow-up merge {i} completed."}],
        }
        for i in range(1, 9)
    ]
    packet = {"sources": mr_units, "missing_sources": [], "truncated": True}
    tag_url = "https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-0.4.9.6"
    coverage_tagged = {"prior_story": {"id": "a" * 24, "confidence": "confirmed", "state": "tagged"}, "recent": []}
    limits_tagged = review.repair_limits(packet, coverage_tagged, update=True)
    assert "tagged" in limits_tagged["state"]

    cand_tagged = _candidate(
        confidence="confirmed",
        state="tagged",
        category="release",
        tags=["release"],
        sources=[
            *[{"url": u["url"], "title": u["title"]} for u in mr_units],
            {"url": tag_url, "title": "tor-0.4.9.6"},
        ],
        updates=[{
            "at": LATER,
            "text": "Follow-up merge 8 completed.",
            "sources": [{"url": mr_units[-1]["url"], "title": mr_units[-1]["title"]}],
        }],
    )
    assert review.final_holds(cand_tagged, {"mode": "update", "packet": packet, "coverage": coverage_tagged}) == []

    coverage_fixed = {"prior_story": {"id": "b" * 24, "confidence": "confirmed", "state": "fixed"}, "recent": []}
    limits_fixed = review.repair_limits({"sources": mr_units[:2]}, coverage_fixed, update=True)
    assert "fixed" in limits_fixed["state"] and "tagged" not in limits_fixed["state"]
    cand_fixed = _candidate(
        confidence="confirmed",
        state="fixed",
        category="security",
        tags=["security"],
        sources=[{"url": u["url"], "title": u["title"]} for u in mr_units[:2]],
        updates=[{
            "at": LATER,
            "text": "Follow-up merge 2 completed.",
            "sources": [{"url": mr_units[1]["url"], "title": mr_units[1]["title"]}],
        }],
    )
    assert review.final_holds(
        cand_fixed, {"mode": "update", "packet": {"sources": mr_units[:2]}, "coverage": coverage_fixed}
    ) == []


def test_skip_stands_distinguishes_negated_unrelated_event_phrases():
    """Keep update skips when reason negates unrelated-event language while holding positive unrelated flags."""
    live_id = "a" * 24
    coverage = {"prior_story": {"id": live_id, "state": "developing"}, "recent": []}

    neg_reply = verdict(
        "skip",
        criterion="new_information",
        update=True,
        reason=f"Repeats {live_id}; this is not a different incident.",
    )
    assert review._skip_stands(neg_reply["criteria"], coverage, update=True) is True

    neg_no_story_reply = verdict(
        "skip",
        criterion="new_information",
        update=True,
        reason="No new facts; not an unrelated event.",
    )
    assert review._skip_stands(neg_no_story_reply["criteria"], coverage, update=True) is True

    pos_reply = verdict(
        "skip",
        criterion="new_information",
        update=True,
        reason=f"Different incident from {live_id}.",
    )
    assert review._skip_stands(pos_reply["criteria"], coverage, update=True) is False


def _specialist_verdict(action="approve", **kwargs):
    """Build a valid review verdict dict for specialist merge tests."""
    return verdict(action, **kwargs)


def test_reviewer_specialist_prompts_validation_and_policy_hash(monkeypatch):
    """Specialist lenses inject domain guidance, preserve default None, and affect policy_hash."""
    assert review.REVIEW_VERSION == "onionflash-review-20"
    assert review.SPECIALISTS == (
        "grounding_status",
        "attribution_scope_advice",
        "novelty_news",
    )

    cand = _candidate()
    pkt = _packet()
    cfg = _cfg_llm()
    baseline_hash = review.policy_hash(cfg)

    monkeypatch.setitem(
        review.SPECIALIST_PROMPTS,
        "grounding_status",
        review.SPECIALIST_PROMPTS["grounding_status"] + " EXTRA",
    )
    assert review.policy_hash(cfg) != baseline_hash
    monkeypatch.undo()

    reviewer = wire_reviewer(
        cfg,
        *[_specialist_verdict("approve") for _ in range(4)],
        monkeypatch=monkeypatch,
    )

    res_none = reviewer.review(cand, pkt, specialist=None)
    assert res_none["verdict"] == "approve"
    default_body = json.dumps(reviewer.client.bodies[0])
    for spec_prompt in review.SPECIALIST_PROMPTS.values():
        assert spec_prompt.strip().splitlines()[0] not in default_body

    for idx, spec in enumerate(review.SPECIALISTS, start=1):
        res_spec = reviewer.review(cand, pkt, specialist=spec)
        assert res_spec["verdict"] == "approve"
        spec_body = json.dumps(reviewer.client.bodies[idx])
        assert f"SPECIALIST VERIFICATION FOCUS ({spec}" in spec_body

    calls_before_invalid = len(reviewer.client.bodies)
    with pytest.raises(review.ReviewError, match="Unknown review specialist"):
        reviewer.review(cand, pkt, specialist="nonexistent")
    assert len(reviewer.client.bodies) == calls_before_invalid


def test_merge_specialist_verdicts_approves_unanimous_and_unions_refs():
    """Three clean specialist approvals produce approve and union packet source_refs."""
    v1 = _specialist_verdict("approve", ref="S1")
    v2 = _specialist_verdict("approve", ref="S1:P1")
    v3 = _specialist_verdict("approve", ref="S1")

    merged = review.merge_specialist_verdicts([v1, v2, v3], _candidate(), _packet())
    assert merged["verdict"] == "approve"
    refs = merged["criteria"]["source_support"]["source_refs"]
    assert refs == ["S1", "S1:P1"]


def test_merge_specialist_verdicts_factual_fail_closed_and_outlier_rules():
    """Primary factual or majority factual failures fail closed; lone out-of-domain factual failure does not."""
    cand = _candidate()
    pkt = _packet()
    clean = _specialist_verdict("approve")

    # Primary factual defect in grounding_status (`status`) blocks approval.
    v_ground_hold = _specialist_verdict(
        "hold",
        criterion="status",
        reason="Candidate claims patch shipped when discussion is still open.",
    )
    merged_hold = review.merge_specialist_verdicts(
        [v_ground_hold, copy.deepcopy(clean), copy.deepcopy(clean)],
        cand,
        pkt,
    )
    assert merged_hold["verdict"] == "hold"
    assert merged_hold["criteria"]["status"]["outcome"] == "fail"

    # Primary factual defect in attribution_scope_advice (`operational_advice`) blocks approval.
    v_attr_hold = _specialist_verdict(
        "hold",
        criterion="operational_advice",
        reason="Candidate invents unattributed operator remediation advice.",
    )
    merged_attr = review.merge_specialist_verdicts(
        [copy.deepcopy(clean), v_attr_hold, copy.deepcopy(clean)],
        cand,
        pkt,
    )
    assert merged_attr["verdict"] == "hold"
    assert merged_attr["criteria"]["operational_advice"]["outcome"] == "fail"

    # Lone out-of-domain factual objection from `novelty_news` does not cause false alarm.
    v_ood_factual = _specialist_verdict(
        "hold",
        criterion="source_support",
        reason="Out-of-domain concern while factual lenses approved.",
    )
    merged_ood = review.merge_specialist_verdicts(
        [copy.deepcopy(clean), copy.deepcopy(clean), v_ood_factual],
        cand,
        pkt,
    )
    assert merged_ood["verdict"] == "approve"

    # Two specialists failing the same factual criterion fail closed even if outside primary.
    v_scope_ood = _specialist_verdict(
        "hold",
        criterion="status",
        reason="Status overstated.",
    )
    v_news_ood = _specialist_verdict(
        "hold",
        criterion="status",
        reason="Status overstated.",
    )
    merged_majority_factual = review.merge_specialist_verdicts(
        [copy.deepcopy(clean), v_scope_ood, v_news_ood],
        cand,
        pkt,
    )
    assert merged_majority_factual["verdict"] == "hold"
    assert merged_majority_factual["criteria"]["status"]["outcome"] == "fail"


def test_merge_specialist_verdicts_non_conflicting_revise_vs_conflict_hold():
    """Single-domain factual revise merges safely; conflicting edits fail closed to hold."""
    cand = _candidate()
    pkt = _packet()
    clean = _specialist_verdict("approve")

    # Single primary specialist proposing a clean repair returns revise with repair intact.
    v_revise = _specialist_verdict(
        "revise",
        criterion="scope_timing",
        reason="Clear unsupported impact line.",
        repair={"why_it_matters": ""},
    )
    merged_rev = review.merge_specialist_verdicts(
        [copy.deepcopy(clean), v_revise, copy.deepcopy(clean)],
        cand,
        pkt,
    )
    assert merged_rev["verdict"] == "revise"
    assert merged_rev["repair"] == {"why_it_matters": ""}

    # Conflicting fixes on the same non-impact field fail closed to hold instead of overwriting.
    v_fix_a = _specialist_verdict(
        "revise",
        criterion="source_support",
        reason="Trim summary wording.",
        repair={"summary": "Version A summary."},
    )
    v_fix_b = _specialist_verdict(
        "revise",
        criterion="actor_and_action",
        reason="Different summary wording.",
        repair={"summary": "Version B summary."},
    )
    merged_conflict = review.merge_specialist_verdicts(
        [v_fix_a, v_fix_b, copy.deepcopy(clean)],
        cand,
        pkt,
    )
    assert merged_conflict["verdict"] == "hold"


def test_merge_specialist_verdicts_editorial_skip_requires_majority_and_story_routing():
    """Lone editorial skip is ignored; majority skip stands and respects update/same_story rules."""
    cand = _candidate()
    pkt = _packet()
    clean = _specialist_verdict("approve")

    # Lone editorial skip outlier must not veto newsroom approval.
    v_lone_skip = _specialist_verdict(
        "skip",
        criterion="news_value",
        reason="Routine bugfix.",
    )
    merged_pass = review.merge_specialist_verdicts(
        [v_lone_skip, copy.deepcopy(clean), copy.deepcopy(clean)],
        cand,
        pkt,
    )
    assert merged_pass["verdict"] == "approve"

    # Majority (2 of 3) editorial skip stands.
    v_skip_a = _specialist_verdict("skip", criterion="news_value", reason="Routine minor build tweak.")
    v_skip_b = _specialist_verdict("skip", criterion="news_value", reason="Low impact maintenance.")
    merged_skip = review.merge_specialist_verdicts(
        [copy.deepcopy(clean), v_skip_a, v_skip_b],
        cand,
        pkt,
    )
    assert merged_skip["verdict"] == "skip"
    assert merged_skip["criteria"]["news_value"]["outcome"] == "fail"

    # Update mode: majority new_information skip naming live story stands as skip.
    live_id = COVERED
    upd_cand = _candidate(
        updates=[{
            "at": LATER,
            "text": "Tor maintains ongoing build checks.",
            "sources": [{"url": STORY["sources"][0]["url"], "title": STORY["sources"][0]["title"]}],
        }]
    )
    upd_clean = _specialist_verdict("approve", update=True)
    upd_skip_1 = _specialist_verdict(
        "skip",
        criterion="new_information",
        update=True,
        reason=f"Same ongoing work as {live_id}; no user-visible change.",
    )
    upd_skip_2 = _specialist_verdict(
        "skip",
        criterion="new_information",
        update=True,
        reason=f"Same story as {live_id} without fresh facts.",
    )
    merged_upd_skip = review.merge_specialist_verdicts(
        [upd_clean, upd_skip_1, upd_skip_2],
        upd_cand,
        pkt,
        update=True,
        coverage=PRIOR,
    )
    assert merged_upd_skip["verdict"] == "skip"

    # Story-mode routing requires majority same_story agreement.
    r_skip_1 = _specialist_verdict(
        "skip",
        criterion="new_information",
        same_story=live_id,
        reason=f"Duplicates {live_id}.",
    )
    r_skip_2 = _specialist_verdict(
        "skip",
        criterion="new_information",
        same_story=live_id,
        reason=f"Covered by {live_id}.",
    )
    merged_route = review.merge_specialist_verdicts(
        [copy.deepcopy(clean), r_skip_1, r_skip_2],
        cand,
        pkt,
        coverage=COVERAGE,
    )
    assert merged_route["verdict"] == "skip"
    assert merged_route["same_story"] == live_id


def test_review_validation_catches_incomplete_fragment_and_unattributed_advice(monkeypatch):
    """Validator/apply_repair reject or clear incomplete why_it_matters fragments and unattributed advice."""
    pkt = _packet()
    fragment = "Because of recent fixes, the network currently has a lot of <= 0.4.8.x"

    # Fragment lacking terminal punctuation fails apply_repair and is cleared on _validate.
    with pytest.raises(review.ReviewError, match="Invalid repair field"):
        review.apply_repair(_candidate(), {"why_it_matters": fragment})

    reviewer = wire_reviewer(
        _cfg_llm(),
        _specialist_verdict("revise", criterion="scope_timing", repair={"why_it_matters": fragment}),
        _specialist_verdict(
            "revise",
            criterion="operational_advice",
            repair={"why_it_matters": "Operators should switch to 64-bit builds immediately."},
        ),
        _specialist_verdict(
            "revise",
            criterion="scope_timing",
            repair={"why_it_matters": "Operators should check the advisory."},
        ),
        monkeypatch=monkeypatch,
    )
    res_frag = reviewer.review(_candidate(), pkt)
    assert res_frag["repair"]["why_it_matters"] == ""

    res_adv = reviewer.review(_candidate(), pkt)
    assert res_adv["repair"]["why_it_matters"] == ""

    # When the directive verb IS present in packet context, grounded advice is preserved.
    grounded_pkt = copy.deepcopy(pkt)
    grounded_pkt["sources"][0]["passages"].append({"id": "S1:P2", "text": "Operators should check the advisory."})
    res_grounded = reviewer.review(_candidate(), grounded_pkt)
    assert res_grounded["repair"]["why_it_matters"] == "Operators should check the advisory."


def test_widen_update_state_preserves_prior_released_and_blocks_issue_released():
    """Prior released stories allow released updates, while bare issue stories fail confirmed_source."""
    issue_pkt = copy.deepcopy(_packet())
    issue_pkt["sources"][0]["kind"] = "gitlab_issue"
    issue_pkt["sources"][0]["authority"] = "development"
    issue_cand = _candidate(
        category="release",
        confidence="confirmed",
        state="released",
    )
    holds = review.final_holds(
        issue_cand,
        {"packet": issue_pkt, "mode": "story", "payload": {"editorial_kind": "gitlab_issue"}},
    )
    assert "confirmed_source" in holds

    limits = {"state": ["open", "fixed", "closed"]}
    review._widen_update_state(
        limits,
        issue_pkt["sources"],
        PRIOR["prior_story"] | {"state": "released", "category": "release"},
    )
    assert "released" in limits["state"]

