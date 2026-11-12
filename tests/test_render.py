"""Publication boundary tests: trusted layout, untrusted source content."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from html.parser import HTMLParser
from unittest.mock import patch

from onionflash.analyze import SCHEMA
from onionflash.cli import build
from onionflash.config import DEFAULTS
from onionflash.render import CATEGORIES, _page_url
from onionflash.schema import UPDATE_CHARS
from onionflash.store import Store


CONFIG = {
    "site": {
        "title": "Onion Flash",
        "base_url": "https://example.com/onionflash/",
        "repository_url": "https://github.com/1aeo/onionflash",
    }
}
STORY = {
    "id": "0123456789abcdef01234567",
    "title": "Tor publishes a release",
    "summary": "A new release includes improvements for relay operators.",
    "why_it_matters": "Operators can read the release notes to assess the changes.",
    "category": "release",
    "products": ["tor"],
    "priority": "normal",
    "confidence": "confirmed",
    "state": "released",
    "tags": ["release"],
    "sources": [{"url": "https://blog.torproject.org/example/", "title": "Release announcement"}],
    "published_at": "2026-11-08T12:00:00Z",
    "updated_at": "2026-11-08T14:00:00Z",
}


def publish(stories, output, *, health=(), **site):
    """Store the stories and publish them through the production build; returns the skipped count."""
    cfg = copy.deepcopy(DEFAULTS)
    cfg["site"].update(CONFIG["site"], **site)
    cfg["storage"].update(database=f"{output}.sqlite3", output_dir=str(output))
    with Store(cfg["storage"]["database"]) as store, patch.object(Store, "health", return_value=list(health)):
        for number, story in enumerate(stories):
            store.db.execute("INSERT INTO stories(id,cluster_key,payload,published_at,updated_at) VALUES(?,?,?,'','')",
                             (story["id"], f"test:{number}", json.dumps(story)))
        store.db.commit()
        return build(cfg, store)["stories_skipped"]


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
        if tag == "nav":
            self.nav = attrs.get("aria-label")
        elif tag == "a":
            self.link = {**attrs, "text": "", "nav": self.nav}
            self.links.append(self.link)
        elif tag == "summary":
            self.summary = {"text": ""}
            self.summaries.append(self.summary)

    def handle_endtag(self, tag):
        if tag == "nav":
            self.nav = None
        elif tag == "a":
            self.link = None
        elif tag == "summary":
            self.summary = None

    def handle_data(self, text):
        if self.link is not None:
            self.link["text"] += text
        if self.summary is not None:
            self.summary["text"] += text

    def story_ids(self):
        return [attrs["id"].removeprefix("story-") for tag, attrs in self.tags
                if tag == "article" and attrs.get("class") == "story"]


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def render(self, stories=None, *, health=(), name="site", **site):
        output = self.root / name
        publish([copy.deepcopy(STORY)] if stories is None else stories, output, health=health, **site)
        return output

    def test_valid_feeds_stable_permalink_original_publication_date(self):
        output = self.render()
        root = ET.parse(output / "feed.xml")
        item = root.find("./channel/item")
        self.assertEqual(item.findtext("guid"), "https://example.com/onionflash/news/0123456789abcdef01234567/")
        self.assertEqual(item.findtext("pubDate"), "Sun, 08 Nov 2026 12:00:00 GMT")
        self.assertEqual(root.findtext("./channel/lastBuildDate"), "Sun, 08 Nov 2026 14:00:00 GMT")
        feed = json.loads((output / "feed.json").read_text())
        self.assertEqual(feed["items"][0]["date_published"], STORY["published_at"])
        self.assertEqual(feed["items"][0]["date_modified"], STORY["updated_at"])
        self.assertTrue((output / "news" / STORY["id"] / "index.html").is_file())

    def test_feed_source_lines_separate_title_and_domain(self):
        description = ET.parse(self.render() / "feed.xml").find("./channel/item").findtext("description")
        self.assertIn('Release announcement</a> <span class="source-domain">blog.torproject.org', description)

    def test_source_html_and_attributes_are_escaped_in_every_format(self):
        story = copy.deepcopy(STORY)
        story["title"] = '<img src=x onerror="alert(1)"> & news'
        story["summary"] = '<script>alert("bad")</script> and </script>'
        story["sources"][0]["title"] = '\"><svg onload=alert(1)>'
        output = self.render([story])
        for file in [output / "index.html", output / "news" / story["id"] / "index.html"]:
            text = file.read_text()
            self.assertNotIn('<img src=x', text)
            self.assertNotIn('<svg onload=', text)
            self.assertNotIn('<script>alert', text)
            self.assertIn('&lt;script&gt;', text)
        description = ET.parse(output / "feed.xml").findtext("./channel/item/description")
        self.assertNotIn('<script>alert', description)
        self.assertIn('&lt;script&gt;', description)
        feed = json.loads((output / "feed.json").read_text())
        self.assertIn('<script>', feed["items"][0]["content_text"])
        self.assertNotIn('content_html', feed["items"][0])

    def test_homepage_puts_new_publications_before_recent_edits_to_old_stories(self):
        older = {**STORY, "id": "older", "published_at": "2026-11-01T12:00:00Z", "updated_at": "2026-11-09T12:00:00Z"}
        newer = {**STORY, "id": "newer"}
        output = self.render([older, newer])
        page = (output / "index.html").read_text()
        self.assertLess(page.index('id="story-newer"'), page.index('id="story-older"'))
        # A small homepage must select the newest publication before truncation.
        limited = self.render([older, newer], page_size=1, name="limited")
        page = (limited / "index.html").read_text()
        self.assertIn('id="story-newer"', page)
        self.assertNotIn('id="story-older"', page)
        self.assertIn('Latest story update <time datetime="2026-11-09T12:00:00Z"', page)
        self.assertEqual(json.loads((output / "feed.json").read_text())["items"][0]["id"], "https://example.com/onionflash/news/older/")

    def assert_skipped(self, bad, name):
        """Render a bad story next to a valid one: only the valid story is published."""
        output = self.root / name
        bad = {**bad, "id": "rejected"} if bad["id"] == STORY["id"] else bad
        self.assertEqual(publish([bad, copy.deepcopy(STORY)], output), 1)
        self.assertEqual([p.name for p in (output / "news").iterdir()], [STORY["id"]])
        self.assertEqual(len(json.loads((output / "feed.json").read_text())["items"]), 1)

    def test_homepage_orders_by_when_onion_flash_added_the_story(self):
        # An old issue first published today is new on Onion Flash; an edit to an
        # earlier story does not move it above newer additions.
        resurfaced = {**STORY, "id": "resurfaced", "published_at": "2026-09-22T12:00:00Z",
                      "updated_at": "2026-09-22T12:00:00Z", "added_at": "2026-11-09T12:00:00Z"}
        earlier = {**STORY, "id": "earlier", "published_at": "2026-11-05T12:00:00Z",
                   "updated_at": "2026-11-10T12:00:00Z", "added_at": "2026-11-05T12:00:00Z"}
        page = (self.render([earlier, resurfaced]) / "index.html").read_text()
        self.assertLess(page.index('id="story-resurfaced"'), page.index('id="story-earlier"'))
        # Cards and story pages show when Onion Flash first published the story; feeds keep the source date.
        card = page[page.index('id="story-resurfaced"'):page.index('id="story-earlier"')]
        self.assertIn('<span class="story-date"><time datetime="2026-11-09T12:00:00Z"', card)
        self.assertNotIn("updated-note", card)
        article = (self.root / "site" / "news" / "resurfaced" / "index.html").read_text()
        self.assertIn('First published <time datetime="2026-11-09T12:00:00Z"', article)
        # A source update before or at the first-published date is not a later update.
        self.assertNotIn("Last updated", article)
        same = self.render([{**resurfaced, "updated_at": resurfaced["added_at"]}], name="same") / "news" / "resurfaced" / "index.html"
        self.assertNotIn("Last updated", same.read_text())
        article = (self.root / "site" / "news" / "earlier" / "index.html").read_text()
        self.assertIn('First published <time datetime="2026-11-05T12:00:00Z"', article)
        self.assertIn('Last updated <time datetime="2026-11-10T12:00:00Z"', article)
        dates = {item.findtext("link"): item.findtext("pubDate") for item in ET.parse(self.root / "site" / "feed.xml").findall("./channel/item")}
        self.assertEqual(dates["https://example.com/onionflash/news/resurfaced/"], "Tue, 22 Sep 2026 12:00:00 GMT")

    def test_dated_updates_list_newest_first_and_cards_and_feeds_show_the_latest(self):
        source = {"url": "https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1", "title": "<b>Merge request</b>"}
        quoted = {"url": 'https://example.org/a"onmouseover=x', "title": "Quoted"}
        third = {"url": "https://example.org/third", "title": "Third"}
        story = copy.deepcopy(STORY)
        story["updates"] = [
            {"at": "2026-11-09T09:00:00Z", "text": "The fix was proposed.", "sources": [source]},
            {"at": "2026-11-10T09:00:00+00:00", "text": "The fix was merged. <script>alert(1)</script>",
             "sources": [source, {"url": "javascript:alert(1)", "title": "bad"}]},
            # Text is cut, only the first three sources count, and on a tie the later entry is listed first.
            {"at": "2026-11-09T09:00:00Z", "text": "x" * (UPDATE_CHARS + 50),
             "sources": [quoted, source, third, {"url": "https://example.org/fourth", "title": "Fourth"}]},
            # Malformed entries are dropped, never published and never fatal.
            "not an update", {"at": "2026-11-11T09:00:00", "text": "No time zone.", "sources": [source]},
            {"at": "2026-11-11T09:00:00Z", "text": "No source.", "sources": []},
            {"at": "2026-11-11T09:00:00Z", "text": "Unsafe source.", "sources": [{"url": "http://example.org/", "title": "x"}]},
            {"at": "2026-11-11T09:00:00Z", "text": " ", "sources": [source]},
        ]
        output = self.render([story])
        public = json.loads((output / "news" / story["id"] / "story.json").read_text())
        self.assertEqual(public["updates"], [
            {"at": "2026-11-09T09:00:00Z", "text": "The fix was proposed.", "sources": [source]},
            {"at": "2026-11-10T09:00:00Z", "text": "The fix was merged. <script>alert(1)</script>", "sources": [source]},
            {"at": "2026-11-09T09:00:00Z", "text": "x" * UPDATE_CHARS, "sources": [quoted, source, third]}])
        article = (output / "news" / story["id"] / "index.html").read_text()
        positions = [article.index(text) for text in ("The fix was merged.", "x" * UPDATE_CHARS, "The fix was proposed.")]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('<time datetime="2026-11-10T09:00:00Z" title="2026-11-10 09:00 UTC">Nov 10, 2026 · 09:00 UTC</time>', article)
        self.assertIn('rel="noopener noreferrer">&lt;b&gt;Merge request&lt;/b&gt;</a>', article)
        self.assertIn('href="https://example.org/a&quot;onmouseover=x"', article)
        home = (output / "index.html").read_text()
        rss = ET.parse(output / "feed.xml").findtext("./channel/item/description")
        content = json.loads((output / "feed.json").read_text())["items"][0]["content_text"]
        self.assertIn("Update · 2026-11-10T09:00:00Z: The fix was merged. <script>alert(1)</script>", content)
        for text in (home, rss, article):
            self.assertNotIn("<script>alert", text)
            self.assertIn("&lt;script&gt;", text)
        for text in (home, rss, content):
            self.assertIn("The fix was merged.", text)
            self.assertNotIn("The fix was proposed.", text)
        for text in (home, rss, content, article, json.dumps(public)):
            for dropped in ("No time zone.", "No source.", "Unsafe source.", "javascript:"):
                self.assertNotIn(dropped, text)
        # The card's latest update replaces its update date.
        self.assertIn('<strong>Update · <time datetime="2026-11-10T09:00:00Z"', home)
        self.assertNotIn("updated-note", home)

    def test_a_story_without_updates_has_no_updates_key_or_markup(self):
        for index, updates in enumerate([None, [], "text", [{"at": "2026-11-10T09:00:00Z", "text": "No source."}]]):
            with self.subTest(updates=updates):
                story = copy.deepcopy(STORY)
                if updates is not None:
                    story["updates"] = updates
                output = self.render([story], name=f"plain-{index}")
                self.assertNotIn("updates", json.loads((output / "news" / story["id"] / "story.json").read_text()))
                home = (output / "index.html").read_text()
                self.assertIn('<span class="updated-note">Updated <time datetime="2026-11-08T14:00:00Z"', home)
                for text in (home, (output / "news" / story["id"] / "index.html").read_text(), (output / "feed.xml").read_text(),
                             (output / "feed.json").read_text()):
                    self.assertNotIn("Update ·", text)
                    self.assertNotIn("update-list", text)

    def test_no_longer_listed_is_a_public_state_the_writer_cannot_choose(self):
        story = {**copy.deepcopy(STORY), "state": "no-longer-listed"}
        article = (self.render([story]) / "news" / story["id"] / "index.html").read_text()
        self.assertIn('<span>Event status</span> No longer listed', article)
        self.assertNotIn("no-longer-listed", SCHEMA["properties"]["state"]["enum"])

    def test_source_panel_shows_only_freshness_not_times_or_errors(self):
        health = [{"name": "Fresh", "website_url": "https://example.org/a", "stale": False, "last_success": "2026-11-08T12:00:00Z", "error": "boom"},
                  {"name": "Old", "website_url": "https://example.org/b", "stale": True}]
        page = (self.render(health=health) / "index.html").read_text()
        self.assertIn('Fresh</a><span class="health-state">Collected</span>', page)
        self.assertIn('Old</a><span class="health-state delayed">Delayed</span>', page)
        self.assertNotIn("Last success", page)
        self.assertNotIn("boom", page)

    def test_unsafe_sources_cannot_be_published(self):
        for index, url in enumerate([
            "javascript:alert(1)", "data:text/html,test", "//example.com/",
            "https://user:secret@example.com/", "http://127.0.0.1/",
            "http://169.254.169.254/", "http://127.1/", "http://0177.0.0.1/",
            "http://0x7f.0.0.1/", "http://localhost/", "http://test.internal/",
            "https://example.com/\nmalicious", "https://example.com:99999/",
        ]):
            with self.subTest(url=url):
                story = copy.deepcopy(STORY)
                story["sources"] = [{"url": url, "title": "bad"}]
                self.assert_skipped(story, f"unsafe-{index}")

    def test_unsafe_source_is_omitted_when_valid_source_exists(self):
        story = copy.deepcopy(STORY)
        story["sources"].append({"url": "javascript:alert(1)", "title": "bad"})
        output = self.render([story])
        self.assertNotIn("javascript:", (output / "index.html").read_text())
        self.assertNotIn("javascript:", (output / "feed.json").read_text())

    def test_unsafe_ids_cannot_escape_output_directory(self):
        for index, value in enumerate(["../outside", "/tmp/escape", "a/b", "a\\b", "a\" onload=x", "", "a" * 65]):
            with self.subTest(value=value):
                story = copy.deepcopy(STORY)
                story["id"] = value
                self.assert_skipped(story, f"id-{index}")
        self.assertFalse((self.root / "outside").exists())

    def test_invalid_dates_and_classifications_fail(self):
        for index, change in enumerate([
            {"published_at": "2026-11-08T12:00:00"}, {"updated_at": "not a date"},
            {"category": '\"><script>'}, {"priority": "urgent"},
            {"confidence": "definitely"}, {"state": "hacked"},
        ]):
            with self.subTest(change=change):
                story = copy.deepcopy(STORY)
                story.update(change)
                self.assert_skipped(story, f"class-{index}")

    def test_malformed_list_entries_are_dropped_without_hiding_the_story(self):
        story = copy.deepcopy(STORY)
        story.update(tags=["release", 7, ["unhashable"], "not-a-topic"], products=["tor", None, ["x"], "elsewhere"],
                     sources=["not a source", *STORY["sources"]])
        output = self.render([story])
        item = json.loads((output / "feed.json").read_text())["items"][0]
        self.assertEqual(item["tags"], ["release"])
        self.assertIn(STORY["sources"][0]["url"], item["content_text"])

    def test_unicode_title_is_readable_without_hidden_search_data(self):
        story = copy.deepcopy(STORY)
        story["title"] = "Straße relay notes"
        page = (self.render([story]) / "index.html").read_text()
        self.assertIn('Straße relay notes</a>', page)
        self.assertNotIn('data-search', page)

    def test_malformed_stored_fields_are_skipped(self):
        for index, change in enumerate([{"category": ["security"]}, {"sources": None}, {"tags": None}, {"title": None}]):
            with self.subTest(change=change):
                story = copy.deepcopy(STORY)
                story.update(change, id=f"malformed{index}")
                self.assert_skipped(story, f"malformed-{index}")

    def test_build_fails_instead_of_publishing_an_empty_site_when_every_story_fails(self):
        bad = copy.deepcopy(STORY)
        bad["sources"] = [{"url": "javascript:alert(1)", "title": "bad"}]
        with self.assertRaisesRegex(ValueError, "No stored story can be rendered"):
            self.render([bad])

    def test_one_unrenderable_story_does_not_block_the_others(self):
        bad = copy.deepcopy(STORY)
        bad.update(id="badbadbadbadbadbadbadbad", sources=[{"url": "javascript:alert(1)", "title": "x"}])
        output = self.root / "mixed"
        with self.assertLogs("onionflash.publication", "WARNING") as logs:
            self.assertEqual(publish([bad, copy.deepcopy(STORY)], output), 1)
        self.assertEqual(logs.output, ["WARNING:onionflash.publication:Quarantined unrenderable story badbadbadbadbadbadbadbad (ValueError)"])
        self.assertTrue((output / "news" / STORY["id"] / "index.html").is_file())
        self.assertFalse((output / "news" / bad["id"]).exists())
        self.assertEqual(len(json.loads((output / "feed.json").read_text())["items"]), 1)

    def test_feed_control_characters_are_removed_and_xml_parses(self):
        story = copy.deepcopy(STORY)
        story["title"] = "Release\x00\x01\x08\ud800 test"
        output = self.render([story])
        self.assertEqual(ET.parse(output / "feed.xml").findtext("./channel/item/title"), "Release test")

    def test_empty_state_contains_no_fabricated_items(self):
        output = self.render([])
        page = (output / "index.html").read_text()
        self.assertIn("The feed is getting started.", page)
        self.assertNotIn('class="story"', page)
        self.assertEqual(ET.parse(output / "feed.xml").findall("./channel/item"), [])
        self.assertEqual(json.loads((output / "feed.json").read_text())["items"], [])

    def test_subdirectory_urls_assets_and_headers_are_consistent(self):
        output = self.render()
        page = (output / "index.html").read_text()
        self.assertIn('href="https://example.com/onionflash/style.css"', page)
        self.assertNotIn('app.js', page)
        self.assertIn('href="https://example.com/onionflash/feed.xml"', page)
        for name in ["style.css", "mark.svg"]:
            self.assertTrue((output / name).is_file())
        headers = (output / "_headers").read_text()
        self.assertTrue(headers.startswith("/onionflash/*\n"))
        self.assertIn("script-src 'none'", headers)
        self.assertIn("connect-src 'none'", headers)
        site, feeds = headers.strip().split("\n\n")
        self.assertIn("style-src 'self'", site)
        self.assertNotIn("unsafe-inline", site)
        self.assertTrue(feeds.startswith("/onionflash/*.xml\n"))
        self.assertIn("\n  ! Content-Security-Policy\n", feeds)
        # Replaced, not appended: a policy's first style-src and img-src apply.
        self.assertIn("style-src 'unsafe-inline'", feeds)
        self.assertIn("img-src data:", feeds)
        self.assertNotIn("'self'", feeds)
        # Browsers download, or show as text, feeds served as application/rss+xml.
        self.assertNotIn("Content-Type:", headers)

    def test_root_and_local_preview_base_urls_are_supported(self):
        output = self.render(base_url="http://127.0.0.1:8788/")
        self.assertIn('href="http://127.0.0.1:8788/feed.xml"', (output / "index.html").read_text())
        headers = (output / "_headers").read_text()
        self.assertTrue(headers.startswith("/*\n"))
        self.assertIn("\n/*.xml\n  ! Content-Security-Policy\n", headers)  # the empty prefix

    def test_private_health_errors_are_never_exposed(self):
        output = self.render(health=[{"name": "Tor releases", "last_success": "2026-11-08T12:00:00Z", "stale": True, "error": "Bearer top-secret at 192.168.50.10"}])
        text = (output / "index.html").read_text()
        self.assertIn("Delayed", text)
        self.assertNotIn("top-secret", text)
        self.assertNotIn("192.168.50.10", text)

    def test_health_links_escape_labels_and_reject_unsafe_destinations(self):
        name = '<img src=x onerror="alert(1)">'
        health = [{"name": name, "website_url": "https://example.org/list/?a=1&b=2"}]
        page = (self.render(health=health) / "index.html").read_text()
        self.assertIn('href="https://example.org/list/?a=1&amp;b=2">&lt;img', page)
        self.assertNotIn('<img src=x', page)
        for i, url in enumerate(["javascript:alert(1)", "https://user:secret@example.org/", "http://127.0.0.1/"]):
            with self.subTest(url=url):
                page = (self.render(health=[{"name": "Source", "website_url": url}], name=f"health-{i}") / "index.html").read_text()
                self.assertIn('<span>Source</span>', page)
                self.assertNotIn(url, page)

    def test_output_deterministic_and_category_feed_is_filtered(self):
        first = self.render(name="a")
        second = self.render(name="b")
        for file in first.rglob("*"):
            if file.is_file():
                self.assertEqual(file.read_bytes(), (second / file.relative_to(first)).read_bytes())
        # No page carries the current year, so a new year rewrites nothing.
        self.assertNotRegex((first / "index.html").read_text(), r"© \d{4}")
        self.assertEqual(len(ET.parse(first / "tags/release.xml").findall("./channel/item")), 1)
        self.assertEqual(ET.parse(first / "tags/security.xml").findall("./channel/item"), [])

    def test_topic_pages_include_primary_categories_or_secondary_tags(self):
        authority = copy.deepcopy(STORY)
        authority.update(id="authority123", category="directory-authority", tags=["security"], title="An authority security report")
        release = copy.deepcopy(STORY)
        release.update(id="release456", category="release", tags=["security"], title="A security release")
        output = self.render([authority, release])
        page = (output / "index.html").read_text()
        self.assertIn('href="https://example.com/onionflash/topics/security/"', page)
        def story_ids(topic):
            return set(Page((output / f"topics/{topic}/index.html").read_text()).story_ids())
        # Neither story's primary category is security, but both are relevant.
        self.assertEqual(story_ids("security"), {authority["id"], release["id"]})
        self.assertEqual(story_ids("directory-authority"), {authority["id"]})
        self.assertEqual(story_ids("release"), {release["id"]})
        self.assertEqual(story_ids("network"), set())
        self.assertFalse((output / "topics/tor").exists())  # Products are not topics.
        def titles(topic):
            return {item.findtext("title") for item in ET.parse(output / f"tags/{topic}.xml").findall("./channel/item")}
        self.assertEqual(titles("security"), {authority["title"], release["title"]})
        self.assertEqual(titles("directory-authority"), {authority["title"]})
        self.assertEqual(titles("release"), {release["title"]})
        self.assertEqual(titles("network"), set())

    def test_every_page_has_no_browser_script_or_dead_search_controls(self):
        output = self.render()
        self.assertFalse(list(output.rglob("*.js")))
        for file in output.rglob("*.html"):
            text = file.read_text()
            parsed = Page(text)
            self.assertFalse({tag for tag, attrs in parsed.tags} & {"script", "button", "input", "iframe"})
            for tag, attrs in parsed.tags:
                self.assertFalse(any(name.startswith("on") for name in attrs))
                self.assertFalse({"data-tags", "data-search", "data-news-tools", "data-filter"} & attrs.keys())
                self.assertFalse(any(str(value).startswith("javascript:") for value in attrs.values()))
            self.assertNotIn("no-results", text)
            self.assertNotIn("app.js", text)

    def test_native_mobile_menu_and_desktop_header_keep_plain_text_links(self):
        output = self.render()
        expected = {"Home", "Onion Vanity", "Blog", "Onion Flash", "Metrics",
                    "Exit DNS Health", "AROI Validator", "RouteFluxMap", "Contact"}
        for file in (output / "index.html", output / "news" / STORY["id"] / "index.html"):
            parsed = Page(file.read_text())
            menu = [attrs for tag, attrs in parsed.tags if tag == "details" and attrs.get("class") == "site-nav-mobile"]
            self.assertEqual(len(menu), 1)
            self.assertNotIn("open", menu[0])
            self.assertIn({"text": "Menu"}, parsed.summaries)
            links = [link for link in parsed.links if link["nav"] == "1AEO websites"]
            self.assertEqual(len(links), 2 * len(expected))
            self.assertEqual({link["text"] for link in links}, expected)
            self.assertTrue(all(link["href"].startswith("https://") for link in links))
            self.assertTrue(all(link.get("aria-current") == "true" for link in links if link["text"] == "Onion Flash"))

    def test_all_topic_links_exist_with_selected_topic_and_empty_pages(self):
        output = self.render()
        for topic in [None, *CATEGORIES]:
            file = output / (_page_url("", 1, topic) + "index.html")
            parsed = Page(file.read_text())
            links = [link for link in parsed.links if link["nav"] == "News topics"]
            self.assertEqual(len(links), 1 + len(CATEGORIES))
            current = [link for link in links if link.get("aria-current") == "page"]
            self.assertEqual(len(current), 1)
            self.assertEqual(current[0]["href"], _page_url(CONFIG["site"]["base_url"], 1, topic))
            self.assertEqual(current[0]["text"], CATEGORIES.get(topic, "All news"))
            if topic:
                self.assertTrue(any(link["href"].endswith(f"tags/{topic}.xml") for link in parsed.links))
        empty = (output / "topics/network/index.html").read_text()
        self.assertIn("No stories in this topic yet.", empty)
        self.assertEqual(Page(empty).story_ids(), [])

    def test_topic_pagination_canonical_urls_and_newest_first_order(self):
        stories = [dict(STORY, id=f"release{number}", added_at=f"2026-11-{number + 1:02}T12:00:00Z") for number in range(3)]
        output = self.render(stories, page_size=1)
        for number, expected in [(1, "release2"), (2, "release1"), (3, "release0")]:
            page_url = _page_url(CONFIG["site"]["base_url"], number, "release")
            file = output / _page_url("", number, "release") / "index.html"
            parsed = Page(file.read_text())
            self.assertEqual(parsed.story_ids(), [expected])
            canonical = [attrs["href"] for tag, attrs in parsed.tags if tag == "link" and attrs.get("rel") == "canonical"]
            self.assertEqual(canonical, [page_url])
            pagination = [link for link in parsed.links if link["nav"] == "News pages"]
            self.assertEqual({link["rel"] for link in pagination}, ({"next"} if number == 1 else {"prev"} if number == 3 else {"next", "prev"}))
            for link in pagination:
                next_page = number + (1 if link["rel"] == "next" else -1)
                self.assertEqual(link["href"], _page_url(CONFIG["site"]["base_url"], next_page, "release"))
        self.assertEqual(len(ET.parse(output / "tags/release.xml").findall("./channel/item")), 3)

    def test_unknown_topic_cannot_become_a_path_or_html(self):
        for topic in ["../outside", '<script>', "tor", ""]:
            with self.assertRaises(ValueError):
                _page_url("https://example.com/", 1, topic)


if __name__ == "__main__":
    unittest.main()
