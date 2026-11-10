"""Curated timeline Atom behavior: identity, XHTML context and historic dates."""
from xml.sax.saxutils import escape

import pytest

from onionflash.collect import collect_source
from onionflash.config import DEFAULTS
from test_core import DATE, FakeClient, response, source


def entry(identity, title, updated=DATE, alternate=None):
    link = f'<link href="{escape(alternate)}"/>' if alternate else ""
    return f'''<entry><id>{escape(identity)}</id><title>{escape(title)}</title>
      <updated>{updated}</updated>{link}<content type="xhtml">
        <div xmlns="http://www.w3.org/1999/xhtml"><p>Dates: 2026-11-08</p>
        <p>Protocols: snowflake</p><p>Unknown: Yes</p></div>
      </content></entry>'''


def collect(entries, started=DATE):
    body = ('<feed xmlns="http://www.w3.org/2005/Atom"><title>Timeline</title>'
            '<id>https://metrics.example.org/news.atom</id><updated>' + DATE + '</updated>'
            + ''.join(entries) + '</feed>').encode()
    stream = source(kind="feed", authority="telemetry", max_items=1000)
    return collect_source(FakeClient([response(body)]), stream, {}, DEFAULTS['collection'], started)


def test_atom_id_fallback_and_xhtml_context_preserve_event_dates():
    url = 'https://metrics.example.org/news.atom#event'
    result = collect([entry(url, 'An unexplained network change')])
    item = result['items'][0]
    assert item['url'] == url
    assert 'Protocols: snowflake' in item['content']
    assert 'Unknown: Yes' in item['content']
    assert item['published_at'] == DATE == item['updated_at']


def test_historic_duplicate_ids_do_not_create_fresh_news_or_warnings():
    url = 'https://metrics.example.org/news.atom#old'
    assert collect([entry(url, 'First old event', '2026-03-09T12:00:00Z'),
                    entry(url, 'Different old event', '2026-03-09T12:00:00Z')])['items'] == []


def test_conflicting_recent_id_fallbacks_are_skipped_without_losing_other_entries():
    url = 'https://metrics.example.org/news.atom#collision'
    result = collect([entry(url, 'First event'), entry(url, 'Different event'),
                      entry('https://metrics.example.org/news.atom#unique', 'Unambiguous event')])
    # Ambiguous entries are skipped and counted; the feed itself stays healthy.
    assert [item['title'] for item in result['items']] == ['Unambiguous event']
    assert result['skipped'] == 2


def test_identical_duplicates_and_distinct_update_times_remain_supported():
    url = 'https://metrics.example.org/news.atom#event'
    assert len(collect([entry(url, 'Same event'), entry(url, 'Same event')])['items']) == 2
    # Collected after the later entry: dates are never later than the poll time.
    assert len(collect([entry(url, 'First version'),
                        entry(url, 'Updated version', '2026-11-08T12:01:00Z')], started='2026-11-08T12:05:00Z')['items']) == 2


def test_normal_alternate_links_keep_existing_revision_behavior():
    link = 'https://example.org/incident'
    items = collect([entry('urn:one', 'First update', alternate=link),
                     entry('urn:two', 'Second update', alternate=link)])['items']
    assert len(items) == 2


def test_rss_guid_revision_behavior_is_unchanged():
    entries = ''.join(
        f'<item><guid isPermaLink="true">https://example.org/incident</guid>'
        f'<title>Update {number}</title><description>Revision {number}</description>'
        '<pubDate>Sun, 08 Nov 2026 12:00:00 GMT</pubDate></item>'
        for number in [1, 2]
    )
    body = ('<rss version="2.0"><channel><title>Updates</title>'
            '<link>https://example.org/</link><description>News</description>'
            + entries + '</channel></rss>').encode()
    result = collect_source(FakeClient([response(body)]), source(), {}, DEFAULTS['collection'], DATE)
    assert len(result['items']) == 2


def test_unsafe_id_is_not_used_as_a_citation_and_long_titles_keep_context():
    assert collect([entry('urn:uuid:unlinked', 'No public citation')])['items'] == []
    assert collect([entry('https://127.0.0.1/private', 'Unsafe citation')])['items'] == []
    title = 'A long event description ' * 30 + 'The cause remains unknown.'
    item = collect([entry('https://metrics.example.org/news.atom#long', title)])['items'][0]
    assert len(item['title']) == 500
    assert 'The cause remains unknown.' in item['content']
