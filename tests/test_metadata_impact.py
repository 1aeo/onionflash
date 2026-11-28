"""Tests for Wave 7 metadata, impact, and editorial craft guards and passes."""

import copy
import json

import pytest

from helpers import DATE, FakeLLM, analysis, completion, item, load_evaluator, make_config, update_analysis
from onionflash import analyze, cli, llm, review_gate, util
from onionflash.analyze import Analyzer, cache_key
from onionflash.config import DEFAULTS
from onionflash.llm import (
    AnalysisError,
    CompletionDeferred,
    has_tracker_opener,
    is_incomplete_or_filler_impact,
    label_limits,
    shorten_commit_hashes,
)
from onionflash.transport import FetchError
from onionflash.util import is_dirauth_category_story, should_confirm_official_feed


@pytest.mark.parametrize(
    "text,expected",
    [
        ("Users can click here to learn more.", "filler_impact"),
        ("See the link below for full details.", "filler_impact"),
        ("Follow the link to read the full announcement.", "filler_impact"),
        ("See the linked issue for more information.", "filler_impact"),
        ("Visit the link to participate.", "filler_impact"),
        ("The Tor Project asks users to complete the survey via the link.", "filler_impact"),
        ("Relay operators can respond using the link.", "filler_impact"),
        ("More details are available via the link.", "filler_impact"),
        ("The post directs readers to read the full survey report for details.", "filler_impact"),
        # Concrete source-stated consequences must continue to pass.
        ("Clients may crash on malformed cells; see the linked advisory for details.", None),
        ("Operators can read the release notes to assess the changes.", None),
        ("The announcement asks relay operators to upgrade to 0.4.9.16.", None),
        ("A client with no PoW can evict a queued client that did.", None),
    ],
)
def test_meta_link_cta_filler_detection(text, expected):
    """Reject meta link-CTA filler lacking a concrete consequence while passing concrete impacts."""
    assert is_incomplete_or_filler_impact(text) == expected


def test_shorten_commit_hashes_preserves_urls_fingerprints_and_evidence():
    """Shorten standalone 40-char commit SHAs in prose without mutating URLs, fingerprints, or SHA-256 digests."""
    sha = "cadcd0d310831ba237fff4c1a39ef51c53b506db"
    sha2 = "44674369c1234567890abcdef1234567890abcde"
    sha256 = "e53e0384a853d286697f055dc6c644b9a955c07b71787e3868c800902453e846"
    fp_upper = "1A25C6358DB91342AA51720A5038B72742732498"
    fp_lower = "f533c81cef0bc0267857c99b2f471adf249fa232"

    assert shorten_commit_hashes(f"Tested against commit {sha} on main.") == "Tested against commit cadcd0d3 on main."
    assert shorten_commit_hashes(f"Fixed in revision {sha2} (at {sha}).") == "Fixed in revision 44674369 (at cadcd0d3)."
    assert shorten_commit_hashes(f"Reproduces at `{sha}`.") == "Reproduces at `cadcd0d3`."
    assert shorten_commit_hashes(f"tor@{sha} triggers the bug.") == "tor@cadcd0d3 triggers the bug."

    url = f"https://gitlab.torproject.org/tpo/core/tor/-/commit/{sha}"
    assert shorten_commit_hashes(f"See {url} for details.") == f"See {url} for details."
    http_url = f"http://git.example/tor.git/commit/?id={sha}"
    assert shorten_commit_hashes(f"Link: {http_url}") == f"Link: {http_url}"
    assert shorten_commit_hashes(f"Relay fingerprint {fp_lower} and v3ident={fp_lower}") == (
        f"Relay fingerprint {fp_lower} and v3ident={fp_lower}"
    )
    assert shorten_commit_hashes(f"Authority ${fp_lower} and {fp_upper}") == f"Authority ${fp_lower} and {fp_upper}"
    assert shorten_commit_hashes(f"Digest {sha256} unchanged.") == f"Digest {sha256} unchanged."


@pytest.mark.parametrize(
    "title,expected",
    [
        ("Tor issue reports consensus vote truncation", True),
        ("Arti issue says PoW queue overflows under load", True),
        ("An opened Tor Browser issue investigates WebRTC leak", True),
        ("GitLab issue reports relay startup crash", True),
        ("A Tor merge request proposes removing legacy code", True),
        ("Tor issue #41500: consensus vote serialization fails", True),
        ("Tor consensus votes over 16 MB truncated before signing", False),
        ("OpenSSL 4.x fallback reported on custom Tor builds", False),
        ("Tor Browser 16.0 fixes security vulnerabilities", False),
        ("Directory authority maatuska plans dual-stack migration", False),
    ],
)
def test_has_tracker_opener(title, expected):
    """Detect boilerplate tracker openers while passing direct event-first headlines."""
    assert has_tracker_opener(title) is expected


def test_dirauth_category_story_extended_rules_and_negative_checks():
    """Classify auth_dirs.inc, fallback_dirs.inc, and authority OrPort/DirPort ops without catching generic relays."""
    auth_dirs_mr = item(
        kind="gitlab_mr",
        upstream_state="merged",
        url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1999",
        title="Update auth_dirs.inc for authority key update",
        content="Updates src/app/config/auth_dirs.inc with new IPv6 address.",
        labels=[],
    )
    fallback_dirs_mr = item(
        kind="gitlab_mr",
        upstream_state="merged",
        url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/2001",
        title="Update fallback_dirs.inc for 0.4.9",
        content="Regenerates fallback_dirs.inc directory mirror list.",
        labels=[],
    )
    port_change = item(
        kind="gitlab_issue",
        url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/42150",
        title="Change OrPort and DirPort for maatuska",
        content="Directory authority maatuska is changing its OrPort from 80 to 443 and DirPort.",
        labels=[],
    )
    body_port_change = item(
        kind="gitlab_issue",
        url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/42151",
        title="Update authority ports in Tor",
        content="Directory authority longclaw will move its OrPort to 9001 next month.",
        labels=[],
    )
    assert is_dirauth_category_story([auth_dirs_mr]) is True
    assert is_dirauth_category_story([fallback_dirs_mr]) is True
    assert is_dirauth_category_story([port_change]) is True
    assert is_dirauth_category_story([body_port_change]) is True

    # Generic relay operator posts mentioning OrPort/DirPort or community fallback_dirs.inc questions stay False.
    generic_relay_orport = item(
        kind="feed",
        authority="community",
        url="https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/OR1/",
        title="[tor-relays] My relay OrPort 9001 unreachable after restart",
        content="My exit relay changed OrPort and DirPort and seems unreachable.",
        labels=[],
    )
    trusted_relay_orport = item(
        kind="feed",
        authority="trusted-operator",
        url="https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/OR2/",
        title="[tor-relays] Relay operator asks about DirPort 80 vs 443",
        content="Relay operators are seeing warnings on DirPort 80.",
        labels=[],
    )
    community_fallback_q = item(
        kind="feed",
        authority="community",
        url="https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/FB1/",
        title="[tor-relays] Question about fallback_dirs.inc criteria",
        content="How do relays get updated into fallback_dirs.inc?",
        labels=[],
    )
    assert is_dirauth_category_story([generic_relay_orport]) is False
    assert is_dirauth_category_story([trusted_relay_orport]) is False
    assert is_dirauth_category_story([community_fallback_q]) is False


def test_should_confirm_official_feed_and_project_sender_invariant():
    """Confirm non-tag non-hedged official feeds while keeping project-sender on tor-relays strictly reported."""
    tor_blog_survey = item(
        kind="feed",
        authority="official",
        url="https://blog.torproject.org/tor-browser-user-survey-2026/",
        title="Tor Browser User Survey 2026",
        content="The Tor Project is running a user survey to understand browser usage.",
        labels=[],
    )
    tails_news = item(
        kind="feed",
        authority="official",
        url="https://tails.net/news/version_7.0/index.en.html",
        title="Tails 7.0 is out",
        content="Tails 7.0 is now available.",
        labels=[],
    )
    tor_announce = item(
        kind="feed",
        authority="official",
        url="https://lists.torproject.org/pipermail/tor-announce/2026-November/001000.html",
        title="[tor-announce] Tor 0.4.9.17 released",
        content="Tor 0.4.9.17 is now available.",
        labels=[],
    )
    hedged_official = item(
        kind="feed",
        authority="official",
        url="https://lists.torproject.org/pipermail/tor-announce/2026-November/001001.html",
        title="[tor-announce] Suspected compromise of mirror host",
        content="A mirror host was plausibly compromised; investigation continues.",
        labels=[],
    )
    reply_official = item(
        kind="feed",
        authority="official",
        url="https://lists.torproject.org/pipermail/tor-announce/2026-November/001002.html",
        title="Re: [tor-announce] Tor 0.4.9.17 released",
        content="Follow-up note.",
        labels=[],
    )
    tag_official = item(kind="tag", authority="official", title="tor-0.4.9.17", content="", labels=[])
    project_sender_relays = item(
        kind="feed",
        authority="project-sender",
        url="https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/PS1/",
        title="[tor-relays] Relay bandwidth observations",
        content="Measured directory-stream overhead across relays.",
        labels=[],
    )

    assert should_confirm_official_feed(tor_blog_survey) is True
    assert should_confirm_official_feed(tails_news) is True
    assert should_confirm_official_feed(tor_announce) is True
    assert should_confirm_official_feed(hedged_official) is False
    assert should_confirm_official_feed(reply_official) is False
    assert should_confirm_official_feed(tag_official) is False
    assert should_confirm_official_feed(project_sender_relays) is False

    # Critical invariant: project-sender on tor-relays MUST NOT allow confidence="confirmed".
    assert "confirmed" not in label_limits([project_sender_relays])["confidence"]
    assert "confirmed" in label_limits([tor_blog_survey])["confidence"]


def test_metadata_impact_pass_refines_labels_shortens_hashes_tracks_clears_and_fails_soft(monkeypatch):
    """Run focused metadata/impact pass before polish, refine labels/impact, preserve cache_key parity, and fail soft."""
    cfg = copy.deepcopy(DEFAULTS)
    cfg["llm"].update(base_url="https://llm.example/v1", api_key_env="MI_TEST_KEY", writer_reasoning=True, send_chat_template_kwargs=True)
    monkeypatch.setenv("MI_TEST_KEY", "synthetic-fixture-value")

    sha = "cadcd0d310831ba237fff4c1a39ef51c53b506db"
    url = f"https://gitlab.torproject.org/tpo/core/tor/-/commit/{sha}"

    # 1. cache_key parity: metadata_impact_pass=False matches baseline, True diverges only for prior is None.
    row = {"content_hash": "f" * 64}
    base_k = cache_key(row, DEFAULTS["llm"])
    assert cache_key(row, DEFAULTS["llm"], metadata_impact_pass=False) == base_k
    mi_k = cache_key(row, DEFAULTS["llm"], metadata_impact_pass=True)
    assert mi_k != base_k
    prior = {
        "title": "Prior", "summary": "S", "why_it_matters": "",
        "confidence": "reported", "state": "developing", "updated_at": DATE,
        "category": "network", "sources": [], "updates": [],
    }
    assert cache_key(row, DEFAULTS["llm"], prior=prior, metadata_impact_pass=True) == cache_key(
        row, DEFAULTS["llm"], prior=prior, metadata_impact_pass=False
    )
    with monkeypatch.context() as mp:
        mp.setattr(analyze, "METADATA_IMPACT_PROMPT", analyze.METADATA_IMPACT_PROMPT + "\nExtra rule.")
        assert cache_key(row, DEFAULTS["llm"]) == base_k
        assert cache_key(row, DEFAULTS["llm"], metadata_impact_pass=True) != mi_k

    # 2. Survey story: metadata_impact_pass refines security->network, reported->confirmed, strips meta-CTA filler,
    #    and runs BEFORE polish, using non-thinking profile.
    survey_src = item(
        kind="feed",
        authority="official",
        url="https://blog.torproject.org/tor-browser-user-survey-2026/",
        title="Tor Browser User Survey 2026",
        content=f"Tor Browser launched a user survey at commit {sha}. See {url} for details.",
        labels=[],
    )
    ev = f"Tor Browser launched a user survey at commit {sha}."
    draft_reply = analysis(
        title=f"Tor Browser launches survey at commit {sha}",
        summary=f"Tor Browser launched a survey at commit {sha}. Details at {url}.",
        why_it_matters="The Tor Project asks users to complete the survey via the link.",
        category="security",
        priority="high",
        confidence="reported",
        state="developing",
        products=["tor-browser"],
        tags=["security"],
        evidence=[ev],
    )
    mi_reply = {
        "category": "network",
        "priority": "normal",
        "confidence": "confirmed",
        "state": "developing",
        "products": ["tor-browser"],
        "tags": ["network"],
        "why_it_matters": f"User feedback shapes upcoming Tor Browser priorities based on commit {sha}.",
    }
    polish_reply = {
        "title": f"Tor Browser launches 2026 user survey at commit {sha}",
        "summary": f"The Tor Project launched a 2026 Tor Browser user survey at commit {sha}. Details at {url}.",
        "why_it_matters": "User feedback shapes upcoming Tor Browser priorities based on commit cadcd0d3.",
    }
    writer = Analyzer(cfg, editorial_polish=True, metadata_impact_pass=True)
    writer.client = FakeLLM(draft_reply, mi_reply, polish_reply)
    out = writer.analyze(survey_src)
    assert writer.calls == 3
    # Initial draft's meta link-CTA why_it_matters was cleared (clears=1), while MI+polish produced grounded shortened impact.
    assert writer.clears == 1
    assert out["category"] == "network"
    assert out["confidence"] == "confirmed"
    assert out["priority"] == "normal"
    assert out["tags"] == ["network"]
    assert sha not in out["title"] and "cadcd0d3" in out["title"]
    assert f"commit cadcd0d3" in out["summary"] and url in out["summary"]
    assert out["why_it_matters"] == "User feedback shapes upcoming Tor Browser priorities based on commit cadcd0d3."
    assert out["evidence"] == [ev]
    # Verify metadata_impact call used non-thinking profile and onionflash_metadata_impact schema.
    mi_req = writer.client.requests[1][1]
    assert mi_req["response_format"]["json_schema"]["name"] == "onionflash_metadata_impact"
    assert mi_req["chat_template_kwargs"] == {"enable_thinking": False}
    assert mi_req["max_tokens"] == 1200

    # 3. project-sender on tor-relays MUST stay confidence="reported" even if model attempts "confirmed" or normalizer runs.
    relays_src = item(
        kind="feed",
        authority="project-sender",
        url="https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/R99/",
        title="[tor-relays] Relay metrics check",
        content="Observed descriptor upload timeout across 4 relays.",
        labels=[],
    )
    relays_draft = analysis(
        title="Descriptor upload timeouts observed across 4 relays",
        summary="A report notes descriptor upload timeouts across 4 relays.",
        why_it_matters="",
        category="relay",
        tags=["relay"],
        confidence="reported",
        evidence=["Observed descriptor upload timeout across 4 relays."],
    )
    relays_mi = {
        "category": "relay",
        "priority": "normal",
        "confidence": "reported",
        "state": "developing",
        "products": ["tor"],
        "tags": ["relay"],
        "why_it_matters": "Four relays observed descriptor upload timeouts.",
    }
    relays_writer = Analyzer(cfg, metadata_impact_pass=True)
    relays_writer.client = FakeLLM(relays_draft, relays_mi)
    relays_out = relays_writer.analyze(relays_src)
    assert relays_out["confidence"] == "reported"
    assert "confirmed" not in relays_writer.client.requests[1][1]["response_format"]["json_schema"]["schema"]["properties"]["confidence"]["enum"]

    # 4. Fail-soft on non-retryable AnalysisError and CompletionDeferred; re-raise retryable error; track clears across passes.
    clean_draft = analysis(
        title="OpenBSD build test crash reported",
        summary="An issue reports a SIGSEGV in an OpenBSD unit test.",
        why_it_matters="",
        category="protocol",
        tags=["protocol"],
        evidence=["Observed descriptor upload timeout across 4 relays."],
    )
    for err_reply in (
        {"unexpected": "keys"},
        completion(relays_mi, finish_reason="length"),
        CompletionDeferred("deadline"),
    ):
        fs_writer = Analyzer(cfg, metadata_impact_pass=True)
        fs_writer.client = FakeLLM(clean_draft, err_reply)
        assert fs_writer.analyze(relays_src)["title"] == clean_draft["title"]
        assert fs_writer.calls == 2 and fs_writer.clears == 0

    bad_num_mi = {**relays_mi, "why_it_matters": "999 relays crashed."}
    clears_writer = Analyzer(cfg, metadata_impact_pass=True)
    clears_writer.client = FakeLLM(clean_draft, bad_num_mi)
    clears_out = clears_writer.analyze(relays_src)
    assert clears_out["why_it_matters"] == "" and clears_writer.clears == 1

    retry_writer = Analyzer(cfg, metadata_impact_pass=True)
    retry_writer.client = FakeLLM(clean_draft, FetchError("HTTP 503", status=503))
    with pytest.raises(AnalysisError) as exc_info:
        retry_writer.analyze(relays_src)
    assert exc_info.value.retryable is True

    # 5. Tag items and update mode skip metadata_impact_pass.
    tag_writer = Analyzer(cfg, metadata_impact_pass=True)
    tag_writer.client = FakeLLM()
    assert tag_writer.analyze(item(kind="tag", title="tor-0.4.9.17", content=""))["state"] == "tagged"
    assert tag_writer.calls == 0

    upd_writer = Analyzer(cfg, metadata_impact_pass=True)
    upd_writer.client = FakeLLM(update_analysis(update="Update posted.", evidence=["Observed descriptor upload timeout across 4 relays."]))
    assert upd_writer.analyze(relays_src, prior=prior)["update"] == "Update posted."
    assert upd_writer.calls == 1


def test_cli_review_gate_and_evaluate_review_metadata_impact_wiring(tmp_path, monkeypatch):
    """Verify cli._new_analyzer, review_gate._writer_metadata_impact, and evaluate_review --metadata-impact wiring."""
    assert cli._draft_metadata_impact() is True
    built = cli._new_analyzer(make_config(tmp_path))
    try:
        assert built.metadata_impact_pass is True
        assert review_gate._writer_metadata_impact(built) is True
    finally:
        built.close()

    class _PlainStub:
        best_of = 1
        quote_digest = False

    assert review_gate._writer_metadata_impact(_PlainStub()) is False
    assert cli._draft_metadata_impact(_PlainStub()) is False

    eval_mod = load_evaluator()
    seen_opts = []
    monkeypatch.setattr(eval_mod, "load_config", lambda _: make_config(tmp_path))
    monkeypatch.setattr(
        eval_mod,
        "evaluate",
        lambda _cfg, _cs, _out, **kw: seen_opts.append(kw) or {
            "controlled_mismatches": 0, "false_routes": 0, "target_missed": [], "errors": 0, "incomplete": False,
        },
    )
    cfg_path = tmp_path / "cfg.toml"
    cfg_path.write_text('[storage]\ndatabase = "s.sqlite3"\noutput_dir = "pub"\n', encoding="utf-8")
    out_path = tmp_path / "out.jsonl"
    cases_path = tmp_path / "cases.json"
    cases_path.write_text(
        json.dumps({
            "defaults": {"why_it_matters": "", "category": "network", "tags": ["network"], "priority": "normal",
                         "confidence": "reported", "state": "developing", "products": ["tor"],
                         "published_at": DATE, "updated_at": DATE, "added_at": DATE},
            "packets": {"p1": {"sources": [{"url": "https://example.org/1", "title": "T", "kind": "feed",
                                            "authority": "official", "product": "tor", "published_at": DATE,
                                            "updated_at": DATE, "passages": ["Body."]}]}},
            "cases": [{"id": "c1", "packet": "p1", "expected": "approve",
                       "candidate": {"id": "a" * 24, "title": "T", "summary": "S."}}],
        }),
        encoding="utf-8",
    )
    rc = eval_mod.main([
        "--config", str(cfg_path),
        "--cases", str(cases_path),
        "--output", str(out_path),
        "--draft",
        "--metadata-impact",
    ])
    assert rc == 0
    assert seen_opts[0]["metadata_impact"] is True
