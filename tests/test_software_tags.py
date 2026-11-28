"""Tests for software taxonomy, URL tagging, software filter views, feeds, and cleanup."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from helpers import analysis, item, make_config, seed_story, tag

from onionflash import analyze, editorial, publication, render, schema, store, util


def _seed_published_story(
    st: store.Store,
    *,
    sid: str,
    url: str,
    title: str,
    product: str,
    category: str = "release",
    products: list[str] | None = None,
    observed: str = "2026-11-10T12:00:00Z",
    kind: str = "gitlab_issue",
) -> str:
    raw = item(
        id=sid,
        source_id=f"src-{sid}",
        url=url,
        title=title,
        content="Upstream maintenance notes document the change across affected builds.",
        published_at=observed,
        updated_at=observed,
        kind=kind,
        product=product,
    )
    draft = analysis(
        title=title,
        summary="Upstream maintenance notes document the change across affected builds.",
        why_it_matters="Operators running the affected software should review the upstream notes.",
        category=category,
        priority="normal",
        confidence="reported",
        state="developing",
        products=products if products is not None else [product],
        tags=[category],
        evidence=["Upstream maintenance notes document the change"],
    )
    return seed_story(st, raw, draft, at=observed)["id"]


def test_schema_software_and_products_order():
    """Define the ten upstream software slugs ahead of the network fallback."""
    assert schema.SOFTWARE == [
        "tor",
        "arti",
        "tor-browser",
        "snowflake",
        "webtunnel",
        "lyrebird",
        "torspec",
        "tails",
        "oniux",
        "orbot",
    ]
    assert schema.PRODUCTS == [*schema.SOFTWARE, "network"]


def test_gitlab_url_and_source_software_extraction():
    """Extract lowercase software slugs from GitLab URLs, blog announcements, and source lists."""
    cases = [
        ("https://gitlab.torproject.org/tpo/core/tor/-/issues/41000", "tpo/core/tor", "tor", "tor"),
        ("https://gitlab.torproject.org/tpo/core/arti/-/work_items/1200", "tpo/core/arti", "arti", "arti"),
        ("https://gitlab.torproject.org/tpo/applications/tor-browser/-/merge_requests/900", "tpo/applications/tor-browser", "tor-browser", "tor-browser"),
        ("https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/tags/v2.10.1?format=atom", "tpo/anti-censorship/pluggable-transports/snowflake", "snowflake", "snowflake"),
        ("https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel/-/blob/main/README.md#L1", "tpo/anti-censorship/pluggable-transports/webtunnel", "webtunnel", "webtunnel"),
        ("https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/-/releases/v0.5.0", "tpo/anti-censorship/pluggable-transports/lyrebird", "lyrebird", "lyrebird"),
        ("https://gitlab.torproject.org/tpo/core/torspec/-/commit/deadbeef", "tpo/core/torspec", "torspec", "torspec"),
        ("HTTPS://GitLab.TorProject.ORG/TPO/Tails/Tails/-/issues/20500", "tpo/tails/tails", "tails", "tails"),
        ("https://gitlab.torproject.org/tpo/core/oniux/-/tags/v0.15.0", "tpo/core/oniux", "oniux", "oniux"),
        ("https://gitlab.torproject.org/tpo/core/tor/-/blob/main/dir/-/issues/1", "tpo/core/tor", "tor", "tor"),
        ("https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/future-pt/-/tags/v0.1.0", "tpo/anti-censorship/pluggable-transports/future-pt", "future-pt", None),
    ]
    for url, expected_path, expected_repo, expected_sw in cases:
        assert util.gitlab_project_path(url) == expected_path
        assert util.gitlab_repo_name(url) == expected_repo
        assert util.software_from_url(url) == expected_sw

    for non_match in (
        None,
        123,
        "",
        "http://gitlab.torproject.org/tpo/core/tor/-/issues/1",
        "https://gitlab.torproject.org:8443/tpo/core/tor/-/issues/1",
        "https://example.org/tpo/core/tor/-/issues/1",
        "https://gitlab.torproject.org/tor/-/issues/1",
        "https://gitlab.torproject.org/tpo/../tor/-/issues/1",
        "https://gitlab.torproject.org/tpo/core/tor/-/pipelines/42",
        "https://gitlab.torproject.org/tpo/core/tor",
    ):
        assert util.gitlab_project_path(non_match) is None
        assert util.gitlab_repo_name(non_match) is None

    assert util.software_from_url("https://blog.torproject.org/new-release-tor-browser-14-5/") == "tor-browser"
    assert util.software_from_url("https://BLOG.torproject.org/New-Release-Tails-7-0/") == "tails"
    assert util.software_from_url("https://tails.net/news/version_7.18/") == "tails"
    assert util.software_from_url("https://www.tails.net/news/index.en.rss") == "tails"
    assert util.software_from_url("http://tails.net/news/version_7.18/") is None
    assert util.software_from_url("https://tails.net:8443/news/version_7.18/") is None
    assert util.software_from_url("https://blog.torproject.org/new-release-tor-0-4-9-16/") == "tor"
    assert util.software_from_url("https://blog.torproject.org/new-release-arti-1-4-0/") == "arti"
    assert util.software_from_url("https://blog.torproject.org/2025/01/new-release-tor-1/") is None
    assert util.software_from_url("https://example.org/new-release-tor-1/") is None
    assert util.software_from_url("https://github.com/guardianproject/orbot-android/releases/tag/17.7.0-RC-1") == "orbot"
    assert util.software_from_url("https://github.com/guardianproject/orbot-apple/releases/tag/1.8.0") == "orbot"
    assert util.software_from_url("https://github.com/guardianproject/orbot/releases/tag/v1.0.0") == "orbot"
    assert util.software_from_url("http://github.com/guardianproject/orbot-android/releases") is None
    assert util.software_from_url("https://github.com:8443/guardianproject/orbot-android/releases") is None
    assert util.software_from_url("https://example.org:invalid/post") is None
    assert util.software_from_url("https://github.com/other/orbot-android/releases") is None

    found = util.software_from_sources([
        {"url": "https://example.org/post"},
        {"url": "https://example.org:invalid/post"},
        {"url": "https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/issues/10"},
        "https://blog.torproject.org/new-release-tor-browser-14-5/",
        {"url": "https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/merge_requests/11"},
        "https://blog.torproject.org/new-release-tails-7-0/",
        "https://tails.net/news/version_7.18/",
        "https://gitlab.torproject.org/tpo/core/oniux/-/tags/v0.15.0",
        "https://github.com/guardianproject/orbot-android/releases/tag/17.7.0",
    ])
    assert found == ["snowflake", "tor-browser", "tails", "oniux", "orbot"]


def test_release_mentions_and_clusters_for_pluggable_transports():
    """Detect pluggable transport release mentions and Tails news releases cleanly."""
    assert util.release_mentions({"title": "Snowflake 2.10.1 released", "content": "Details"}) == ["release:snowflake:2.10.1"]
    assert util.release_mentions({"title": "WebTunnel 0.1.0 is now available", "content": "Details"}) == ["release:webtunnel:0.1.0"]
    assert util.release_mentions({"title": "Lyrebird 0.5.0 available", "content": "Details"}) == ["release:lyrebird:0.5.0"]
    assert util.release_mentions({"title": "Tor Browser 14.5.1 available", "content": "Details"}) == ["release:tor-browser:14.5.1"]
    assert util.release_mentions({"title": "Tails 7.16 available", "content": "Tails 7.16 details"}) == []
    assert util.item_cluster({"title": "Snowflake 2.10.1 available", "content": "", "product": "network", "url": "https://example.org/s"}) == "release:snowflake:2.10.1"

    tails_news_item = {
        "kind": "feed",
        "authority": "official",
        "product": "tails",
        "url": "https://tails.net/news/version_7.18/",
        "title": "Tails 7.18",
        "content": "Tails 7.18 updates Tor Browser and the Tor client.",
    }
    assert util.item_cluster(tails_news_item) == "release:tails:7.18"
    assert util.is_official_release_announcement(tails_news_item) is True
    assert util.mandatory_news_rule(tails_news_item) == "release_announcement"
    tails_out_item = {**tails_news_item, "title": "Tails 7.18 is out!"}
    assert util.item_cluster(tails_out_item) == "release:tails:7.18"
    assert util.is_official_release_announcement(tails_out_item) is True
    tails_delayed = {**tails_news_item, "title": "Tails 7.18 delayed"}
    assert util.item_cluster(tails_delayed).startswith("url:")
    assert util.is_official_release_announcement(tails_delayed) is False
    tails_issue = {
        "kind": "gitlab_issue",
        "authority": "development",
        "product": "tails",
        "url": "https://gitlab.torproject.org/tpo/tails/tails/-/work_items/20501",
        "title": "Tails 7.18 fails to boot on Mac",
        "content": "Boot hangs after greeter.",
    }
    assert not util.item_cluster(tails_issue).startswith("release:")


def test_tag_notice_labels_fallback_and_length_bounds():
    """Render display names, URL software resolution, future repo fallback, and title length limits."""
    expected_labels = {
        "tor": "Tor",
        "arti": "Arti",
        "tor-browser": "Tor Browser",
        "snowflake": "Snowflake",
        "webtunnel": "WebTunnel",
        "lyrebird": "Lyrebird",
        "torspec": "Tor specification",
        "tails": "Tails",
        "oniux": "oniux",
        "orbot": "Orbot",
    }
    for slug, label in expected_labels.items():
        notice = analyze.tag_notice(tag(product=slug, title=f"{slug}-1.0.0", url=f"https://example.org/tags/{slug}-1.0.0"))
        assert notice["title"] == f"{label} tag observed: {slug}-1.0.0"
        assert notice["products"] == [slug]
        assert f"The upstream {label} feed lists the tag “{slug}-1.0.0”." in notice["summary"]
        assert "upstream" in notice["summary"]
        assert "released" not in notice["summary"].lower()
        assert "verified" not in notice["summary"].lower()

    inferred = analyze.tag_notice(
        tag(
            product="network",
            title="v2.10.1",
            url="https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/tags/v2.10.1",
        )
    )
    assert inferred["title"] == "Snowflake tag observed: v2.10.1"
    assert inferred["products"] == ["snowflake"]

    future = analyze.tag_notice(
        tag(
            product="network",
            title="v0.1.0",
            url="https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/future-pt/-/tags/v0.1.0",
        )
    )
    assert future["title"] == "future-pt tag observed: v0.1.0"
    assert future["products"] == ["network"]
    assert future["summary"].startswith("The upstream future-pt feed lists the tag “v0.1.0”.")

    generic = analyze.tag_notice(tag(product="network", title="v9.9.9", url="https://example.org/tags/v9.9.9"))
    assert generic["title"] == "Upstream tag observed: v9.9.9"
    assert generic["products"] == ["network"]
    assert generic["summary"].startswith("The upstream feed lists the tag “v9.9.9”.")

    long_tag = "release-" + ("x" * 130)
    bounded = analyze.tag_notice(tag(product="tor-browser", title=long_tag))
    assert len(bounded["title"]) <= analyze.SCHEMA["properties"]["title"]["maxLength"]
    assert bounded["title"].endswith("…")

    long_repo = "r" * 130
    long_repo_notice = analyze.tag_notice(
        tag(
            product="network",
            title="v1.2.3",
            url=f"https://gitlab.torproject.org/tpo/anti-censorship/{long_repo}/-/tags/v1.2.3",
        )
    )
    assert len(long_repo_notice["title"]) <= analyze.SCHEMA["properties"]["title"]["maxLength"]
    assert long_repo_notice["title"].endswith(": v1.2.3")
    assert long_repo_notice["products"] == ["network"]

    long_both = analyze.tag_notice(
        tag(
            product="network",
            title="tag-" + ("z" * 100),
            url=f"https://gitlab.torproject.org/tpo/anti-censorship/{long_repo}/-/tags/{'z' * 20}",
        )
    )
    assert len(long_both["title"]) <= analyze.SCHEMA["properties"]["title"]["maxLength"]
    assert "… tag observed: tag-" in long_both["title"]


def test_validate_analysis_merges_deterministic_software_within_limit():
    """Merge deterministic software slugs into products without breaking tag parity or schema bounds."""
    raw = item(
        kind="gitlab_mr",
        product="tor",
        url="https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel/-/merge_requests/12",
    )
    draft = analysis(products=["network", "arti", "tor-browser", "snowflake"])
    validated = analyze.validate_analysis(draft, raw)
    assert validated["products"] == ["network", "arti", "tor-browser", "snowflake", "webtunnel"]

    raw_full = item(
        kind="gitlab_mr",
        product="tor",
        url="https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel/-/merge_requests/12",
    )
    capped = analyze.validate_analysis(analysis(products=["arti", "tor-browser", "snowflake", "lyrebird", "torspec"]), raw_full)
    assert len(capped["products"]) == 5
    assert capped["products"] == ["arti", "tor-browser", "snowflake", "lyrebird", "torspec"]

    tag_item = tag(product="arti", title="arti-1.2.0", url="https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-0.4.9.16")
    tag_draft = analyze.tag_notice(tag_item)
    assert analyze.validate_analysis(copy.deepcopy(tag_draft), tag_item) == tag_draft
    for slug in schema.PRODUCTS:
        assert slug in analyze.SYSTEM_PROMPT


def test_render_software_pills_filter_bars_feeds_and_css(tmp_path):
    """Render software pills, cross-filter navigation, combined headings, RSS links, and print CSS."""
    cfg = make_config(tmp_path)
    site, base = cfg["site"], cfg["site"]["base_url"]

    raw_story = {
        "id": "story_sw_01",
        "title": "Snowflake server updates transport negotiation",
        "summary": "Upstream maintainers documented transport negotiation updates.",
        "why_it_matters": "Bridge operators running Snowflake should track the upcoming release.",
        "category": "release",
        "priority": "normal",
        "confidence": "reported",
        "state": "developing",
        "products": ["network"],
        "tags": ["release"],
        "sources": [
            {
                "title": "Snowflake MR",
                "url": "https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/merge_requests/99",
            },
            {
                "title": "Tails release note",
                "url": "https://blog.torproject.org/new-release-tails-7-0/",
            },
        ],
        "published_at": "2026-11-10T10:00:00Z",
        "updated_at": "2026-11-10T12:00:00Z",
        "added_at": "2026-11-10T10:00:00Z",
    }
    prepared = render.prepare_story(raw_story)
    assert prepared["products"] == ["network", "snowflake", "tails"]
    assert prepared["tags"] == ["release"]
    assert render.story_software(prepared) == ["snowflake", "tails"]

    retracted = render.prepare_story(
        {
            **raw_story,
            "title": editorial.retracted_fields("Duplicate report.")["title"],
            "summary": editorial.retracted_fields("Duplicate report.")["summary"],
            "why_it_matters": "",
        },
        editorial={
            "status": "retracted",
            "action": "retract",
            "at": "2026-11-10T13:00:00Z",
            "reason": "Duplicate report.",
            "revision": 1,
            "history": [],
        },
    )
    retracted_article = render.article_html(site, base, retracted)
    assert 'class="software-label"' not in retracted_article

    fixed_alert = render.prepare_story(
        {
            **raw_story,
            "origin": "network-health",
            "products": ["network"],
        }
    )
    assert fixed_alert["products"] == ["network"]

    assert render.feed_path() == "feed.xml"
    assert render.feed_path("security") == "tags/security.xml"
    assert render.feed_path(software="snowflake") == "software/snowflake.xml"
    assert render.feed_path("security", "snowflake") == "software/snowflake.xml"
    with pytest.raises(ValueError, match="Unknown software"):
        render.feed_path(software="network")

    sw_rss = render.rss_header(site, base, "software/tor-browser.xml", "2026-11-10T12:00:00Z", software="tor-browser").decode("utf-8")
    assert "Onion Flash · tor-browser" in sw_rss
    assert f"{base}software/tor-browser.xml" in sw_rss

    page_html = render.index_html(site, base, [prepared], [], total=25, page=2, pages=3, topic="release", software="snowflake")
    assert '<div class="filter-bars">' in page_html
    assert '<nav class="topics" aria-label="News topics">' in page_html
    assert '<nav class="software-filters" aria-label="Software">' in page_html
    assert f'<a href="{base}software/snowflake/">All news</a>' in page_html
    assert f'<a href="{base}topics/release/software/snowflake/" aria-current="page">Releases</a>' in page_html
    assert f'<a href="{base}topics/release/">All software</a>' in page_html
    assert f'<a href="{base}topics/release/software/snowflake/" aria-current="page">snowflake</a>' in page_html
    assert "<h1>Releases · snowflake news</h1>" in page_html
    assert "<title>Onion Flash — Releases · snowflake news, page 2</title>" in page_html
    assert f'href="{base}topics/release/software/snowflake/" rel="prev"' in page_html
    assert f'href="{base}topics/release/software/snowflake/page/3/" rel="next"' in page_html
    assert "25 stories in the complete releases snowflake history." in page_html
    assert f'<a class="subscribe-link" href="{base}software/snowflake.xml">snowflake RSS feed</a>' in page_html
    assert f'<a class="software-label" href="{base}software/snowflake/">snowflake</a>' in page_html

    sw_only_empty = render.index_html(site, base, [], [], total=0, software="lyrebird")
    assert "<h1>lyrebird news</h1>" in sw_only_empty
    assert "No stories for this software yet." in sw_only_empty
    assert f'<a class="subscribe-link" href="{base}software/lyrebird.xml">lyrebird RSS feed</a>' in sw_only_empty

    css = (Path(render.__file__).parent / "assets" / "style.css").read_text()
    for selector in (".filter-bars", ".software-filters", ".software-label"):
        assert selector in css
    assert "@media print" in css and ".filter-bars" in css.split("@media print", 1)[1]


def test_publication_software_views_feeds_pagination_and_merge_cleanup(tmp_path):
    """Build software and topic-software listings, RSS feeds, query plans, and merge cleanup."""
    cfg = make_config(tmp_path)
    cfg["site"]["page_size"] = 1
    st = store.Store(Path(cfg["storage"]["database"]))
    try:
        sid_snow_1 = _seed_published_story(
            st,
            sid="snow_rel_1",
            url="https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/issues/1",
            title="Snowflake ICE fallback issue",
            product="network",
            category="release",
            observed="2026-11-10T10:00:00Z",
        )
        sid_snow_2 = _seed_published_story(
            st,
            sid="snow_rel_2",
            url="https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/issues/2",
            title="Snowflake proxy negotiation patch",
            product="snowflake",
            category="release",
            observed="2026-11-10T11:00:00Z",
        )
        sid_tails = _seed_published_story(
            st,
            sid="tails_sec_1",
            url="https://blog.torproject.org/new-release-tails-7-0/",
            title="Tails security release notice",
            product="network",
            category="security",
            observed="2026-11-10T12:00:00Z",
        )

        result = publication.build(cfg, st)
        assert result["published_stories"] == 3
        out = Path(cfg["storage"]["output_dir"])

        assert publication.public_path_allowed("software/snowflake.xml")
        assert publication.public_path_allowed("software/snowflake/page/2/index.html")
        assert publication.public_path_allowed("topics/release/software/snowflake/page/2/index.html")
        assert not publication.public_path_allowed("software/network/index.html")
        assert not publication.public_path_allowed("software/network.xml")
        assert not publication.public_path_allowed("software/tor/topics/release/index.html")

        assert (out / "software/snowflake/index.html").is_file()
        assert (out / "software/snowflake/page/2/index.html").is_file()
        assert (out / "topics/release/software/snowflake/index.html").is_file()
        assert (out / "topics/release/software/snowflake/page/2/index.html").is_file()
        assert (out / "software/tails/index.html").is_file()
        assert (out / "topics/security/software/tails/index.html").is_file()

        snow_rss = (out / "software/snowflake.xml").read_text()
        assert "Snowflake ICE fallback issue" in snow_rss
        assert "Snowflake proxy negotiation patch" in snow_rss
        assert "Tails security release notice" not in snow_rss

        empty_rss = (out / "software/webtunnel.xml").read_text()
        assert "Onion Flash · webtunnel" in empty_rss
        assert "<item>" not in empty_rss

        for sw, sql, params in (
            ("tor", "SELECT c.story_id FROM public_catalog c WHERE c.story_id NOT IN (SELECT story_id FROM story_aliases) ORDER BY c.added_at DESC,c.updated_at DESC,c.story_id DESC LIMIT ?", (10,)),
            ("topic", "SELECT c.story_id FROM public_story_topics t JOIN public_catalog c ON c.story_id=t.story_id WHERE t.topic=? AND t.story_id NOT IN (SELECT story_id FROM story_aliases) ORDER BY t.added_at DESC,t.updated_at DESC,t.story_id DESC LIMIT ?", ("release", 10)),
            ("software", "SELECT c.story_id FROM public_story_software s JOIN public_catalog c ON c.story_id=s.story_id WHERE s.software=? AND s.story_id NOT IN (SELECT story_id FROM story_aliases) ORDER BY s.added_at DESC,s.updated_at DESC,s.story_id DESC LIMIT ?", ("snowflake", 10)),
            ("both", "SELECT c.story_id FROM public_story_topics t CROSS JOIN public_story_software s ON s.story_id=t.story_id AND s.software=? JOIN public_catalog c ON c.story_id=t.story_id WHERE t.topic=? AND t.story_id NOT IN (SELECT story_id FROM story_aliases) ORDER BY t.added_at DESC,t.updated_at DESC,t.story_id DESC LIMIT ?", ("snowflake", "release", 10)),
        ):
            details = [r["detail"] for r in st.db.execute("EXPLAIN QUERY PLAN " + sql, params).fetchall()]
            assert not any("TEMP B-TREE" in detail for detail in details), (sw, details)

        snap = json.loads((out / "news" / sid_snow_1 / "story.json").read_text())
        assert "snowflake" in snap["products"]

        # Merging one Snowflake story into the other cleans public_story_software and drops page/2.
        snow_1_sha = editorial.show(st.db, sid_snow_1)["hash"]
        editorial.merge(
            st.db,
            sid_snow_1,
            sid_snow_2,
            reason="Combine duplicate Snowflake report.",
            expect_hash=snow_1_sha,
            base_url=cfg["site"]["base_url"],
            observed="2026-11-10T13:00:00Z",
        )
        publication.build(cfg, st)
        assert st.db.execute("SELECT COUNT(*) FROM public_story_software WHERE story_id=?", (sid_snow_1,)).fetchone()[0] == 0
        assert not (out / "software/snowflake/page/2/index.html").exists()
        assert not (out / "topics/release/software/snowflake/page/2/index.html").exists()
        assert "Snowflake proxy negotiation patch" in (out / "software/snowflake.xml").read_text()
        assert "Snowflake ICE fallback issue" not in (out / "software/snowflake.xml").read_text()

        # Verify retracted stories keep no visible software pills.
        tails_sha = editorial.show(st.db, sid_tails)["hash"]
        editorial.retract(st.db, sid_tails, reason="Withdrawn test story.", expect_hash=tails_sha, observed="2026-11-10T14:00:00Z")
        publication.build(cfg, st)
        assert 'class="software-label"' not in (out / "news" / sid_tails / "index.html").read_text()
    finally:
        st.db.close()


def test_editorial_merge_tolerates_missing_software_table(tmp_path):
    """Allow editorial.merge to run safely when legacy DBs lack `public_story_software`."""
    cfg = make_config(tmp_path)
    st = store.Store(Path(cfg["storage"]["database"]))
    try:
        sid_zero = _seed_published_story(
            st,
            sid="zero_legacy",
            url="https://gitlab.torproject.org/tpo/core/tor/-/issues/99",
            title="Legacy earliest story",
            product="tor",
            observed="2026-11-10T09:00:00Z",
        )
        sid_dup = _seed_published_story(
            st,
            sid="dup_legacy",
            url="https://gitlab.torproject.org/tpo/core/tor/-/issues/100",
            title="Legacy duplicate story",
            product="tor",
            observed="2026-11-10T10:00:00Z",
        )
        sid_surv = _seed_published_story(
            st,
            sid="surv_legacy",
            url="https://gitlab.torproject.org/tpo/core/tor/-/issues/101",
            title="Legacy survivor story",
            product="tor",
            observed="2026-11-10T11:00:00Z",
        )
        publication.build(cfg, st)
        zero_sha = editorial.show(st.db, sid_zero)["hash"]
        editorial.merge(
            st.db,
            sid_zero,
            sid_dup,
            reason="Initial merge before table drop.",
            expect_hash=zero_sha,
            base_url=cfg["site"]["base_url"],
            observed="2026-11-10T11:30:00Z",
        )
        dup_sha = editorial.show(st.db, sid_dup)["hash"]
        with st.db:
            st.db.execute("DROP TABLE public_story_software")
        result = editorial.merge(
            st.db,
            sid_dup,
            sid_surv,
            reason="Legacy schema merge test.",
            expect_hash=dup_sha,
            base_url=cfg["site"]["base_url"],
            observed="2026-11-10T12:00:00Z",
        )
        assert result["merged_into"] == sid_surv
    finally:
        st.db.close()
