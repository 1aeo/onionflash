"""Discourse transport metadata cannot create revisions or hide announcement edits."""

from html import escape

import pytest

from helpers import DATE, LATER, FakeClient, analysis, finish_reviewed, response, source
from onionflash.collect import collect_source
from onionflash.config import DEFAULTS
from onionflash.store import item_hash
from onionflash.util import plain_text


TOPIC = "https://forum.example.org/t/relay-announcement/42"
STREAM = source(id="forum-releases", url="https://forum.example.org/c/releases/1.rss",
                authority="official", product="tor")
BODY = ("<p>The project is evaluating additional defenses.</p>"
        "<p>Further releases are expected.</p>")


def footer(posts=1, participants=1, url=TOPIC):
    """Build a synthetic Discourse RSS topic footer trailer."""
    return (f'<p><small>{posts} post{"s" if posts != 1 else ""} - '
            f'{participants} participant{"s" if participants != 1 else ""}</small></p>\n'
            f'<p><a href="{escape(url, quote=True)}">Read full topic</a></p>')


def collected(body=BODY, trailer=None, *, discourse=True, prefix="discourse", encoded=False,
              topic=TOPIC, observed=DATE, limit=None):
    """Collect one synthetic Discourse RSS feed entry with an optional trailer."""
    namespace = f'xmlns:{prefix}="http://www.discourse.org/"' if discourse else ""
    element = "content:encoded" if encoded else "description"
    content = body + "\n  " + (footer(url=topic) if trailer is None else trailer)
    xml = (f'<rss version="2.0" {namespace} xmlns:content="http://purl.org/rss/1.0/modules/content/">'
           '<channel><title>Releases</title><link>https://forum.example.org/</link>'
           '<description>Announcements</description><item><title>Security Release 0.4.9.17</title>'
           f'<link>{escape(topic)}</link><pubDate>Sun, 08 Nov 2026 12:00:00 GMT</pubDate>'
           f'<{element}><![CDATA[{content}]]></{element}>'
           '</item></channel></rss>').encode()
    settings = {**DEFAULTS["collection"], **({"content_chars": limit} if limit is not None else {})}
    result = collect_source(FakeClient([response(xml, url=STREAM["url"])]), STREAM, {}, settings, observed)
    return result["items"][0]


def publish_initial(store, item):
    """Ingest and publish `item` as the initial developing story in `store`."""
    assert store.ingest(item, DATE)
    finish_reviewed(store, store.pending(1, DATE)[0], analysis(
        title="Tor evaluates further defenses", summary=plain_text(BODY, 1000), why_it_matters="",
        category="dos", tags=["dos"], confidence="confirmed", state="developing",
        evidence=["The project is evaluating additional defenses."]), "initial", DATE)
    return store.stories()[0]


@pytest.mark.parametrize("encoded,prefix", [(False, "discourse"), (True, "forum")])
def test_generated_counts_do_not_requeue_a_published_announcement(store, encoded, prefix):
    """Ignore Discourse post/participant count changes in the generated footer."""
    initial = collected(encoded=encoded, prefix=prefix)
    assert initial["content"] == plain_text(BODY, 1000)
    published = publish_initial(store, initial)
    repeated = collected(trailer=footer(12, 7), encoded=encoded, prefix=prefix, observed=LATER)
    assert repeated["published_at"] == initial["published_at"]
    assert item_hash(repeated) == item_hash(initial)
    assert not store.ingest(repeated, LATER)
    assert not store.pending(10, LATER)
    assert store.stories()[0] == published


@pytest.mark.parametrize("edited", [
    BODY + "<p>Another mitigation is now being tested.</p>",
    BODY.replace("evaluating", "testing"),
    BODY.replace("<p>Further releases are expected.</p>", ""),
])
def test_real_same_timestamp_body_changes_still_queue(store, edited):
    """Re-queue an official announcement when body prose changes under the same timestamp."""
    initial = collected()
    published = publish_initial(store, initial)
    changed = collected(edited, footer(3, 2), observed=LATER)
    assert changed["published_at"] == changed["updated_at"] == initial["published_at"]
    assert changed["content"] == plain_text(edited, 1000)
    assert store.ingest(changed, LATER)
    assert store.pending(1, LATER)[0]["story_id"] == published["id"]
    assert store.stories()[0] == published


@pytest.mark.parametrize("before,after", [("12 relays", "13 relays"), ("8 posts", "9 posts")])
def test_authored_counts_and_footer_like_text_are_preserved(store, before, after):
    """Keep authored count text and non-terminal trailers intact when stripping only the footer."""
    authored = BODY + "<p>12 relays reported circuit pressure.</p>" + footer(8, 4)
    initial = collected(authored, footer())
    assert initial["content"] == plain_text(authored, 2000)
    publish_initial(store, initial)
    changed_body = authored.replace(before, after)
    changed = collected(changed_body, footer(2, 2), observed=LATER)
    assert changed["content"] == plain_text(changed_body, 2000)
    assert store.ingest(changed, LATER)


@pytest.mark.parametrize("trailer,discourse", [
    (footer(), False),
    (footer(url="https://forum.example.org/t/another-topic/43"), True),
    (footer(url="http://forum.example.org/t/relay-announcement/42"), True),
    ("<p><small>1 post - 1 participant</small></p>", True),
    (f'<p><a href="{TOPIC}">Read full topic</a></p>', True),
    (footer() + "<p>Additional defenses are now deployed.</p>", True),
    ("<blockquote>" + footer() + "</blockquote>", True),
    ("1 post - 1 participant\nRead full topic", True),
])
def test_unproven_or_nonterminal_trailers_are_not_removed(trailer, discourse):
    """Preserve non-Discourse, mismatched-URL, quoted, or nonterminal trailers."""
    assert collected(trailer=trailer, discourse=discourse)["content"] == plain_text(BODY + "\n  " + trailer, 20000)


def test_matching_footer_links_decode_html_entities_and_normalization_stays_bounded():
    """Decode HTML-escaped footer URLs and bound content after stripping Discourse trailers."""
    topic = TOPIC + "?filter=one&scope=two"
    assert collected(topic=topic)["content"] == plain_text(BODY, 1000)
    body = "<p>" + "Long announcement text. " * 50 + "</p>"
    assert collected(body, footer(1000, 500), limit=80)["content"] == plain_text(body, 80)


def test_legacy_footer_body_is_revised_once_without_rewriting_history(store):
    """Re-ingest stripped body once over a legacy footer-containing stored item without altering history."""
    initial = collected()
    legacy = {**initial, "content": plain_text(BODY + footer(), 20000)}
    published = publish_initial(store, legacy)
    old_analysis = store.db.execute("SELECT result,source_payload FROM analyses WHERE cache_key='initial'").fetchone()[:]
    assert store.ingest(initial, LATER)
    assert store.pending(1, LATER)[0]["story_id"] == published["id"]
    assert not store.ingest(collected(trailer=footer(3, 2)), LATER)
    assert store.stories()[0] == published
    assert store.db.execute("SELECT result,source_payload FROM analyses WHERE cache_key='initial'").fetchone()[:] == old_analysis
    assert store.ingest(collected(BODY + "<p>The project has announced a new mitigation.</p>", footer(4, 3)), LATER)
