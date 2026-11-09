"""Publication boundary tests: trusted layout, untrusted source content."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from onionflash.render import render_site


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


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def render(self, stories=None, *, health=None, config=None, name="site"):
        output = self.root / name
        render_site(config or CONFIG, [copy.deepcopy(STORY)] if stories is None else stories, health or [], output)
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
                with self.assertRaises(ValueError):
                    self.render([story], name=f"unsafe-{index}")

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
                with self.assertRaises(ValueError):
                    self.render([story], name=f"id-{index}")
        self.assertFalse((self.root / "outside").exists())

    def test_duplicate_ids_fail_before_writing_output(self):
        with self.assertRaises(ValueError):
            self.render([STORY, STORY])
        self.assertFalse((self.root / "site").exists())

    def test_invalid_dates_and_classifications_fail(self):
        for index, change in enumerate([
            {"published_at": "2026-11-08T12:00:00"}, {"updated_at": "not a date"},
            {"category": '\"><script>'}, {"priority": "urgent"},
            {"confidence": "definitely"}, {"state": "hacked"},
        ]):
            with self.subTest(change=change):
                story = copy.deepcopy(STORY)
                story.update(change)
                with self.assertRaises(ValueError):
                    self.render([story], name=f"class-{index}")

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
        self.assertIn('src="https://example.com/onionflash/app.js"', page)
        self.assertIn('href="https://example.com/onionflash/feed.xml"', page)
        for name in ["style.css", "app.js", "mark.svg"]:
            self.assertTrue((output / name).is_file())
        headers = (output / "_headers").read_text()
        self.assertTrue(headers.startswith("/onionflash/*\n"))
        self.assertIn("script-src 'self'", headers)
        self.assertNotIn("unsafe-inline", headers)

    def test_root_and_local_preview_base_urls_are_supported(self):
        config = {"site": {"base_url": "http://127.0.0.1:8788/"}}
        output = self.render(config=config)
        self.assertIn('href="http://127.0.0.1:8788/feed.xml"', (output / "index.html").read_text())
        self.assertTrue((output / "_headers").read_text().startswith("/*\n"))

    def test_bad_base_url_and_traversal_are_rejected(self):
        for index, base in enumerate(["javascript:bad", "https://example.com/x/../", "https://example.com/%2e%2e/", "https://example.com/?token=secret", "https://secret@example.com/"]):
            with self.subTest(base=base):
                with self.assertRaises(ValueError):
                    self.render(config={"site": {"base_url": base}}, name=f"base-{index}")

    def test_private_health_errors_are_never_exposed(self):
        output = self.render(health=[{"name": "Tor releases", "last_success": "2026-11-08T12:00:00Z", "stale": True, "error": "Bearer top-secret at 192.168.50.10"}])
        text = (output / "index.html").read_text()
        self.assertIn("Delayed", text)
        self.assertNotIn("top-secret", text)
        self.assertNotIn("192.168.50.10", text)

    def test_existing_output_or_symlink_is_rejected(self):
        output = self.render()
        with self.assertRaises(ValueError):
            render_site(CONFIG, [], [], output)
        link = self.root / "link"
        link.symlink_to(output, target_is_directory=True)
        with self.assertRaises(ValueError):
            render_site(CONFIG, [], [], link)

    def test_output_deterministic_and_category_feed_is_filtered(self):
        first = self.render(name="a")
        second = self.render(name="b")
        for file in first.rglob("*"):
            if file.is_file():
                self.assertEqual(file.read_bytes(), (second / file.relative_to(first)).read_bytes())
        self.assertEqual(len(ET.parse(first / "tags/release.xml").findall("./channel/item")), 1)
        self.assertEqual(ET.parse(first / "tags/security.xml").findall("./channel/item"), [])

    def test_secondary_security_tags_appear_in_filters_and_each_relevant_feed(self):
        authority = copy.deepcopy(STORY)
        authority.update(id="authority123", category="directory-authority", tags=["security"], title="An authority security report")
        release = copy.deepcopy(STORY)
        release.update(id="release456", category="release", tags=["security"], title="A security release")
        output = self.render([authority, release])
        page = (output / "index.html").read_text()
        # Neither story's primary category is security, but both are relevant.
        self.assertIn('data-filter="security"', page)
        self.assertIn('data-tags="directory-authority security tor"', page)
        self.assertIn('data-tags="release security tor"', page)
        def titles(topic):
            return {item.findtext("title") for item in ET.parse(output / f"tags/{topic}.xml").findall("./channel/item")}
        self.assertEqual(titles("security"), {authority["title"], release["title"]})
        self.assertEqual(titles("directory-authority"), {authority["title"]})
        self.assertEqual(titles("release"), {release["title"]})
        self.assertEqual(titles("network"), set())


if __name__ == "__main__":
    unittest.main()
