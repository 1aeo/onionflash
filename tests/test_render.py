"""Publication boundary tests: trusted layout, untrusted source content."""

from __future__ import annotations

import copy
from html.parser import HTMLParser
import json
import logging
import re
import xml.etree.ElementTree as ET

import pytest

from helpers import SITE_CONFIG, STORY, publish_stories
from onionflash.analyze import SCHEMA
from onionflash.render import CATEGORIES, _page_url
from onionflash.schema import UPDATE_CHARS


class Page(HTMLParser):
    """Inspect actual HTML elements and link labels, ignoring escaped source text."""
    def __init__(self, text):
        super().__init__()
        self.tags, self.links, self.summaries = [], [], []
        self.nav = self.link = self.summary = None
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append((tag, attrs))
        if tag == "nav": self.nav = attrs.get("aria-label")
        elif tag == "a":
            self.link = {**attrs, "text": "", "nav": self.nav}
            self.links.append(self.link)
        elif tag == "summary":
            self.summary = {"text": ""}
            self.summaries.append(self.summary)

    def handle_endtag(self, tag):
        if tag == "nav": self.nav = None
        elif tag == "a": self.link = None
        elif tag == "summary": self.summary = None

    def handle_data(self, text):
        if self.link is not None: self.link["text"] += text
        if self.summary is not None: self.summary["text"] += text

    def story_ids(self):
        return [attrs["id"].removeprefix("story-") for tag, attrs in self.tags if tag == "article" and attrs.get("class") == "story"]


def render_site(tmp_path, stories=None, *, health=(), name="site", **site):
    output = tmp_path / name
    publish_stories([copy.deepcopy(STORY)] if stories is None else stories, output, health=health, **site)
    return output


def assert_skipped(tmp_path, bad, name="bad"):
    output = tmp_path / name
    bad = {**bad, "id": "rejected"} if bad["id"] == STORY["id"] else bad
    assert publish_stories([bad, copy.deepcopy(STORY)], output) == 1
    assert [p.name for p in (output / "news").iterdir()] == [STORY["id"]]
    assert len(json.loads((output / "feed.json").read_text())["items"]) == 1


@pytest.fixture(scope="module")
def shared_sites(tmp_path_factory):
    root = tmp_path_factory.mktemp("rendered")
    single = render_site(root, name="single")
    paged_stories = [dict(STORY, id=f"release{n}", added_at=f"2026-11-{n + 1:02}T12:00:00Z") for n in range(3)]
    paged = render_site(root, paged_stories, page_size=1, name="paged")
    return single, paged


def test_valid_feeds_permalink_dates_and_source_domain(shared_sites):
    output, _ = shared_sites
    root = ET.parse(output / "feed.xml")
    entry = root.find("./channel/item")
    assert entry.findtext("guid") == "https://example.com/onionflash/news/0123456789abcdef01234567/"
    assert entry.findtext("pubDate") == "Sun, 08 Nov 2026 12:00:00 GMT"
    assert root.findtext("./channel/lastBuildDate") == "Sun, 08 Nov 2026 14:00:00 GMT"
    assert 'Release announcement</a> <span class="source-domain">blog.torproject.org' in entry.findtext("description")
    feed = json.loads((output / "feed.json").read_text())
    assert feed["items"][0]["date_published"] == STORY["published_at"]
    assert feed["items"][0]["date_modified"] == STORY["updated_at"]
    assert (output / "news" / STORY["id"] / "index.html").is_file()


def test_source_html_and_attributes_are_escaped_in_every_format(tmp_path):
    story = {**copy.deepcopy(STORY), "title": '<img src=x onerror="alert(1)"> & news',
             "summary": '<script>alert("bad")</script> and </script>',
             "sources": [{"url": STORY["sources"][0]["url"], "title": '"><svg onload=alert(1)>'}]}
    output = render_site(tmp_path, [story])
    for file in (output / "index.html", output / "news" / story["id"] / "index.html"):
        text = file.read_text()
        assert "<img src=x" not in text and "<svg onload=" not in text and "<script>alert" not in text and "&lt;script&gt;" in text
    description = ET.parse(output / "feed.xml").findtext("./channel/item/description")
    assert "<script>alert" not in description and "&lt;script&gt;" in description
    feed_item = json.loads((output / "feed.json").read_text())["items"][0]
    assert "<script>" in feed_item["content_text"] and "content_html" not in feed_item


def test_homepage_orders_by_addition_before_edits_and_keeps_feed_dates(tmp_path):
    older = {**STORY, "id": "older", "published_at": "2026-11-01T12:00:00Z", "updated_at": "2026-11-09T12:00:00Z"}
    newer = {**STORY, "id": "newer"}
    output = render_site(tmp_path, [older, newer])
    page = (output / "index.html").read_text()
    assert page.index('id="story-newer"') < page.index('id="story-older"')
    lim_page = (render_site(tmp_path, [older, newer], page_size=1, name="limited") / "index.html").read_text()
    assert 'id="story-newer"' in lim_page and 'id="story-older"' not in lim_page
    assert 'Latest story update <time datetime="2026-11-09T12:00:00Z"' in lim_page
    assert json.loads((output / "feed.json").read_text())["items"][0]["id"] == "https://example.com/onionflash/news/older/"

    resurfaced = {**STORY, "id": "resurfaced", "published_at": "2026-09-22T12:00:00Z",
                  "updated_at": "2026-09-22T12:00:00Z", "added_at": "2026-11-09T12:00:00Z"}
    earlier = {**STORY, "id": "earlier", "published_at": "2026-11-05T12:00:00Z",
               "updated_at": "2026-11-10T12:00:00Z", "added_at": "2026-11-05T12:00:00Z"}
    added_out = render_site(tmp_path, [earlier, resurfaced], name="added")
    added_page = (added_out / "index.html").read_text()
    assert added_page.index('id="story-resurfaced"') < added_page.index('id="story-earlier"')
    card = added_page[added_page.index('id="story-resurfaced"'):added_page.index('id="story-earlier"')]
    assert '<span class="story-date"><time datetime="2026-11-09T12:00:00Z"' in card and "updated-note" not in card
    res_art = (added_out / "news/resurfaced/index.html").read_text()
    assert 'First published <time datetime="2026-11-09T12:00:00Z"' in res_art and "Last updated" not in res_art
    same = render_site(tmp_path, [{**resurfaced, "updated_at": resurfaced["added_at"]}], name="same")
    assert "Last updated" not in (same / "news/resurfaced/index.html").read_text()
    ear_art = (added_out / "news/earlier/index.html").read_text()
    assert 'First published <time datetime="2026-11-05T12:00:00Z"' in ear_art and 'Last updated <time datetime="2026-11-10T12:00:00Z"' in ear_art
    dates = {i.findtext("link"): i.findtext("pubDate") for i in ET.parse(added_out / "feed.xml").findall("./channel/item")}
    assert dates["https://example.com/onionflash/news/resurfaced/"] == "Tue, 22 Sep 2026 12:00:00 GMT"


def test_dated_updates_list_newest_first_and_cards_and_feeds_show_the_latest(tmp_path):
    src = {"url": "https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1", "title": "<b>Merge request</b>"}
    quoted, third = {"url": 'https://example.org/a"onmouseover=x', "title": "Quoted"}, {"url": "https://example.org/third", "title": "Third"}
    story = copy.deepcopy(STORY)
    story["updates"] = [
        {"at": "2026-11-09T09:00:00Z", "text": "The fix was proposed.", "sources": [src]},
        {"at": "2026-11-10T09:00:00+00:00", "text": "The fix was merged. <script>alert(1)</script>",
         "sources": [src, {"url": "javascript:alert(1)", "title": "bad"}]},
        {"at": "2026-11-09T09:00:00Z", "text": "x" * (UPDATE_CHARS + 50),
         "sources": [quoted, src, third, {"url": "https://example.org/fourth", "title": "Fourth"}]},
        "not an update", {"at": "2026-11-11T09:00:00", "text": "No time zone.", "sources": [src]},
        {"at": "2026-11-11T09:00:00Z", "text": "No source.", "sources": []},
        {"at": "2026-11-11T09:00:00Z", "text": "Unsafe source.", "sources": [{"url": "http://example.org/", "title": "x"}]},
        {"at": "2026-11-11T09:00:00Z", "text": " ", "sources": [src]},
    ]
    output = render_site(tmp_path, [story])
    public = json.loads((output / "news" / story["id"] / "story.json").read_text())
    assert public["updates"] == [
        {"at": "2026-11-09T09:00:00Z", "text": "The fix was proposed.", "sources": [src]},
        {"at": "2026-11-10T09:00:00Z", "text": "The fix was merged. <script>alert(1)</script>", "sources": [src]},
        {"at": "2026-11-09T09:00:00Z", "text": "x" * UPDATE_CHARS, "sources": [quoted, src, third]},
    ]
    article = (output / "news" / story["id"] / "index.html").read_text()
    positions = [article.index(t) for t in ("The fix was merged.", "x" * UPDATE_CHARS, "The fix was proposed.")]
    assert positions == sorted(positions)
    assert '<time datetime="2026-11-10T09:00:00Z" title="2026-11-10 09:00 UTC">Nov 10, 2026 · 09:00 UTC</time>' in article
    assert 'rel="noopener noreferrer">&lt;b&gt;Merge request&lt;/b&gt;</a>' in article
    assert 'href="https://example.org/a&quot;onmouseover=x"' in article
    home = (output / "index.html").read_text()
    rss = ET.parse(output / "feed.xml").findtext("./channel/item/description")
    content = json.loads((output / "feed.json").read_text())["items"][0]["content_text"]
    assert "Update · 2026-11-10T09:00:00Z: The fix was merged. <script>alert(1)</script>" in content
    for text in (home, rss, article):
        assert "<script>alert" not in text and "&lt;script&gt;" in text
    for text in (home, rss, content):
        assert "The fix was merged." in text and "The fix was proposed." not in text
    for text in (home, rss, content, article, json.dumps(public)):
        for dropped in ("No time zone.", "No source.", "Unsafe source.", "javascript:"):
            assert dropped not in text
    assert '<strong>Update · <time datetime="2026-11-10T09:00:00Z"' in home and "updated-note" not in home


@pytest.mark.parametrize("updates", [None, [], "text", [{"at": "2026-11-10T09:00:00Z", "text": "No source."}]])
def test_a_story_without_updates_has_no_updates_key_or_markup(tmp_path, updates):
    story = copy.deepcopy(STORY)
    if updates is not None:
        story["updates"] = updates
    output = render_site(tmp_path, [story])
    assert "updates" not in json.loads((output / "news" / story["id"] / "story.json").read_text())
    home = (output / "index.html").read_text()
    assert '<span class="updated-note">Updated <time datetime="2026-11-08T14:00:00Z"' in home
    for text in (home, (output / "news" / story["id"] / "index.html").read_text(),
                 (output / "feed.xml").read_text(), (output / "feed.json").read_text()):
        assert "Update ·" not in text and "update-list" not in text


@pytest.mark.parametrize("url", [
    "javascript:alert(1)", "data:text/html,test", "//example.com/", "https://user:secret@example.com/",
    "http://127.0.0.1/", "http://169.254.169.254/", "http://127.1/", "http://0177.0.0.1/",
    "http://0x7f.0.0.1/", "http://localhost/", "http://test.internal/",
    "https://example.com/\nmalicious", "https://example.com:99999/",
])
def test_unsafe_sources_cannot_be_published(tmp_path, url):
    assert_skipped(tmp_path, {**copy.deepcopy(STORY), "sources": [{"url": url, "title": "bad"}]})


@pytest.mark.parametrize("bad_id", ["../outside", "/tmp/escape", "a/b", "a\\b", 'a" onload=x', "", "a" * 65])
def test_unsafe_ids_cannot_escape_output_directory(tmp_path, bad_id):
    assert_skipped(tmp_path, {**copy.deepcopy(STORY), "id": bad_id})
    assert not (tmp_path / "outside").exists()


@pytest.mark.parametrize("change", [
    {"published_at": "2026-11-08T12:00:00"}, {"updated_at": "not a date"}, {"category": '"><script>'},
    {"priority": "urgent"}, {"confidence": "definitely"}, {"state": "hacked"},
    {"category": ["security"]}, {"sources": None}, {"tags": None}, {"title": None},
])
def test_invalid_or_malformed_stored_fields_are_skipped(tmp_path, change):
    assert_skipped(tmp_path, {**copy.deepcopy(STORY), "id": "malformed0123456789abcdef", **change})


def test_mixed_valid_invalid_stories_malformed_lists_unicode_and_controls(tmp_path, caplog):
    with_bad_src = copy.deepcopy(STORY)
    with_bad_src["sources"].append({"url": "javascript:alert(1)", "title": "bad"})
    out1 = render_site(tmp_path, [with_bad_src], name="s1")
    assert "javascript:" not in (out1 / "index.html").read_text() and "javascript:" not in (out1 / "feed.json").read_text()

    noisy = {**copy.deepcopy(STORY), "title": "Straße\x00\x01\x08\ud800 relay notes",
             "tags": ["release", 7, ["unhashable"], "not-a-topic"], "products": ["tor", None, ["x"], "elsewhere"],
             "sources": ["not a source", *STORY["sources"]], "state": "no-longer-listed"}
    out2 = render_site(tmp_path, [noisy], name="s2")
    feed_item = json.loads((out2 / "feed.json").read_text())["items"][0]
    assert feed_item["tags"] == ["release"] and STORY["sources"][0]["url"] in feed_item["content_text"]
    assert "Straße relay notes</a>" in (out2 / "index.html").read_text() and "data-search" not in (out2 / "index.html").read_text()
    assert ET.parse(out2 / "feed.xml").findtext("./channel/item/title") == "Straße relay notes"
    assert "<span>Event status</span> No longer listed" in (out2 / "news" / noisy["id"] / "index.html").read_text()
    assert "no-longer-listed" not in SCHEMA["properties"]["state"]["enum"]

    with pytest.raises(ValueError, match="No stored story can be rendered"):
        render_site(tmp_path, [{**copy.deepcopy(STORY), "sources": [{"url": "javascript:alert(1)", "title": "bad"}]}], name="allbad")

    bad_peer = {**copy.deepcopy(STORY), "id": "badbadbadbadbadbadbadbad", "sources": [{"url": "javascript:alert(1)", "title": "x"}]}
    mixed = tmp_path / "mixed"
    with caplog.at_level(logging.WARNING, logger="onionflash.publication"):
        assert publish_stories([bad_peer, copy.deepcopy(STORY)], mixed) == 1
    assert "Quarantined unrenderable story badbadbadbadbadbadbadbad (ValueError)" in caplog.text
    assert (mixed / "news" / STORY["id"] / "index.html").is_file() and not (mixed / "news" / bad_peer["id"]).exists()


@pytest.mark.parametrize("unsafe_url", ["javascript:alert(1)", "https://user:secret@example.org/", "http://127.0.0.1/"])
def test_unsafe_health_website_url_unlinked(tmp_path, unsafe_url):
    upage = (render_site(tmp_path, health=[{"name": "Source", "website_url": unsafe_url}]) / "index.html").read_text()
    assert "<span>Source</span>" in upage and unsafe_url not in upage


def test_empty_state_health_panel_headers_and_determinism(tmp_path, shared_sites):
    empty = render_site(tmp_path, [], name="empty")
    empty_page = (empty / "index.html").read_text()
    assert "The feed is getting started." in empty_page and 'class="story"' not in empty_page
    assert ET.parse(empty / "feed.xml").findall("./channel/item") == [] and json.loads((empty / "feed.json").read_text())["items"] == []

    health = [
        {"name": "Fresh", "website_url": "https://example.org/a", "stale": False,
         "last_success": "2026-11-08T12:00:00Z", "error": "Bearer top-secret at 192.168.50.10"},
        {"name": "Old", "website_url": "https://example.org/b", "stale": True},
        {"name": '<img src=x onerror="alert(1)">', "website_url": "https://example.org/list/?a=1&b=2"},
    ]
    hpage = (render_site(tmp_path, health=health, name="health") / "index.html").read_text()
    assert 'Fresh</a><span class="health-state">Collected</span>' in hpage and 'Old</a><span class="health-state delayed">Delayed</span>' in hpage
    assert 'href="https://example.org/list/?a=1&amp;b=2">&lt;img' in hpage and "<img src=x" not in hpage
    assert all(s not in hpage for s in ("Last success", "top-secret", "192.168.50.10"))

    sub, _ = shared_sites
    spage = (sub / "index.html").read_text()
    assert 'href="https://example.com/onionflash/style.css"' in spage and "app.js" not in spage
    assert 'href="https://example.com/onionflash/feed.xml"' in spage and (sub / "style.css").is_file() and (sub / "mark.svg").is_file()
    headers = (sub / "_headers").read_text()
    assert headers.startswith("/onionflash/*\n") and "script-src 'none'" in headers and "connect-src 'none'" in headers
    site_hdr, feeds_hdr = headers.strip().split("\n\n")
    assert "style-src 'self'" in site_hdr and "unsafe-inline" not in site_hdr
    assert feeds_hdr.startswith("/onionflash/*.xml\n") and "\n  ! Content-Security-Policy\n" in feeds_hdr
    assert "style-src 'unsafe-inline'" in feeds_hdr and "img-src data:" in feeds_hdr and "'self'" not in feeds_hdr and "Content-Type:" not in headers

    local = render_site(tmp_path, base_url="http://127.0.0.1:8788/", name="local")
    assert 'href="http://127.0.0.1:8788/feed.xml"' in (local / "index.html").read_text()
    lheaders = (local / "_headers").read_text()
    assert lheaders.startswith("/*\n") and "\n/*.xml\n  ! Content-Security-Policy\n" in lheaders

    second = render_site(tmp_path, name="sub2")
    for file in sub.rglob("*"):
        if file.is_file():
            assert file.read_bytes() == (second / file.relative_to(sub)).read_bytes()
    assert not re.search(r"© \d{4}", spage)
    assert len(ET.parse(sub / "tags/release.xml").findall("./channel/item")) == 1 and ET.parse(sub / "tags/security.xml").findall("./channel/item") == []


@pytest.mark.parametrize("rel_html", ["index.html", f"news/{STORY['id']}/index.html", *[f"topics/{t}/index.html" for t in CATEGORIES]])
def test_zero_js_and_clean_attributes_on_every_html_page(shared_sites, rel_html):
    single, _ = shared_sites
    assert not list(single.rglob("*.js"))
    text = (single / rel_html).read_text()
    parsed = Page(text)
    assert not ({tag for tag, _ in parsed.tags} & {"script", "button", "input", "iframe"})
    for _, attrs in parsed.tags:
        assert not any(name.startswith("on") for name in attrs)
        assert not ({"data-tags", "data-search", "data-news-tools", "data-filter"} & attrs.keys())
        assert not any(str(v).startswith("javascript:") for v in attrs.values())
    assert "no-results" not in text and "app.js" not in text


@pytest.mark.parametrize("topic", [None, *CATEGORIES])
def test_topic_navigation_marks_current_page(shared_sites, topic):
    single, _ = shared_sites
    parsed = Page((single / (_page_url("", 1, topic) + "index.html")).read_text())
    links = [l for l in parsed.links if l["nav"] == "News topics"]
    assert len(links) == 1 + len(CATEGORIES)
    current = [l for l in links if l.get("aria-current") == "page"]
    assert len(current) == 1 and current[0]["href"] == _page_url(SITE_CONFIG["site"]["base_url"], 1, topic)
    assert current[0]["text"] == CATEGORIES.get(topic, "All news")
    if topic:
        assert any(l["href"].endswith(f"tags/{topic}.xml") for l in parsed.links)


@pytest.mark.parametrize("num,exp", [(1, "release2"), (2, "release1"), (3, "release0")])
def test_topic_pagination_canonical_and_prev_next(shared_sites, num, exp):
    _, paged = shared_sites
    purl = _page_url(SITE_CONFIG["site"]["base_url"], num, "release")
    parsed = Page((paged / _page_url("", num, "release") / "index.html").read_text())
    assert parsed.story_ids() == [exp]
    assert [a["href"] for t, a in parsed.tags if t == "link" and a.get("rel") == "canonical"] == [purl]
    nav = [l for l in parsed.links if l["nav"] == "News pages"]
    assert {l["rel"] for l in nav} == ({"next"} if num == 1 else {"prev"} if num == 3 else {"next", "prev"})
    for l in nav:
        assert l["href"] == _page_url(SITE_CONFIG["site"]["base_url"], num + (1 if l["rel"] == "next" else -1), "release")
    assert len(ET.parse(paged / "tags/release.xml").findall("./channel/item")) == 3


@pytest.mark.parametrize("bad_topic", ["../outside", "<script>", "tor", ""])
def test_invalid_topic_slug_rejected(bad_topic):
    with pytest.raises(ValueError):
        _page_url("https://example.com/", 1, bad_topic)


def test_topics_routing_and_global_nav(tmp_path, shared_sites):
    authority = {**copy.deepcopy(STORY), "id": "authority123", "category": "directory-authority",
                 "tags": ["security"], "title": "An authority security report"}
    release = {**copy.deepcopy(STORY), "id": "release456", "category": "release",
               "tags": ["security"], "title": "A security release"}
    output = render_site(tmp_path, [authority, release])
    assert 'href="https://example.com/onionflash/topics/security/"' in (output / "index.html").read_text()
    story_ids = lambda t: set(Page((output / f"topics/{t}/index.html").read_text()).story_ids())
    titles = lambda t: {i.findtext("title") for i in ET.parse(output / f"tags/{t}.xml").findall("./channel/item")}
    assert story_ids("security") == {authority["id"], release["id"]}
    assert story_ids("directory-authority") == {authority["id"]} and story_ids("release") == {release["id"]}
    assert story_ids("network") == set() and not (output / "topics/tor").exists()
    assert titles("security") == {authority["title"], release["title"]}
    assert titles("directory-authority") == {authority["title"]} and titles("network") == set()

    single, _ = shared_sites
    expected_nav = {"Home", "Onion Vanity", "Blog", "Onion Flash", "Metrics",
                    "Exit DNS Health", "AROI Validator", "RouteFluxMap", "Contact"}
    for file in (single / "index.html", single / "news" / STORY["id"] / "index.html"):
        parsed = Page(file.read_text())
        menu = [a for t, a in parsed.tags if t == "details" and a.get("class") == "site-nav-mobile"]
        assert len(menu) == 1 and "open" not in menu[0] and {"text": "Menu"} in parsed.summaries
        links = [l for l in parsed.links if l["nav"] == "1AEO websites"]
        assert len(links) == 2 * len(expected_nav) and {l["text"] for l in links} == expected_nav
        assert all(l["href"].startswith("https://") for l in links)
        assert all(l.get("aria-current") == "true" for l in links if l["text"] == "Onion Flash")

    empty_topic = (single / "topics/network/index.html").read_text()
    assert "No stories in this topic yet." in empty_topic and Page(empty_topic).story_ids() == []
