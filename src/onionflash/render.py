"""Deterministic, dependency-free static news publishing.

Only the public story fields are rendered. Raw source bodies, evidence excerpts,
errors, credentials, and database records never enter the output directory.
"""

from __future__ import annotations

import email.utils
import html
import json
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit
from .schema import CATEGORY_LABELS as CATEGORIES, PRIORITIES, PRODUCTS, CONFIDENCES, PUBLIC_STATES, UPDATE_CHARS
from .util import canonical_url, parse_utc as _date, format_utc as _iso


ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
ASSET_FILES = ("style.css", "mark.svg")
ATOM_NS = "http://www.w3.org/2005/Atom"
ET.register_namespace("atom", ATOM_NS)


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _text(value: object, limit: int) -> str:
    """Constrain untrusted display fields while retaining ordinary Unicode."""
    if not isinstance(value, str):
        return ""
    clean = "".join(char for char in value if char in "\t\n\r" or 0x20 <= ord(char) <= 0xD7FF or 0xE000 <= ord(char) <= 0xFFFD or 0x10000 <= ord(char) <= 0x10FFFF)
    # Truncation may land on a space. Keep normalization idempotent so a final
    # candidate cannot change between review and its guarded commit.
    return " ".join(clean.split())[:limit].rstrip()


def _public_url(value: object) -> str:
    """The same citation rules as collection; an unsafe link is dropped, not published."""
    try:
        return canonical_url(value)
    except (TypeError, ValueError, UnicodeError):
        return ""


def _time(value: str, *, full: bool = False) -> str:
    date = _date(value)
    label = date.strftime("%b %d, %Y · %H:%M UTC" if full else "%b %d, %Y")
    return f'<time datetime="{_iso(date)}" title="{date.strftime("%Y-%m-%d %H:%M UTC")}">{label}</time>'


def _label(value: str) -> str:
    return value.replace("-", " ").capitalize()


def _sources(values: list, limit: int) -> list[dict]:
    sources = {}
    for source in values[:limit]:
        if not isinstance(source, dict):
            continue
        url = _public_url(source.get("url"))
        if url and url not in sources:
            sources[url] = {"url": url, "title": _text(source.get("title"), 200) or urlsplit(url).hostname}
    return list(sources.values())


def _update(value: object) -> dict | None:
    """One dated update with its own citations; a malformed entry is dropped."""
    if not isinstance(value, dict) or not isinstance(value.get("sources"), list):
        return None
    try:
        at = _iso(_date(value.get("at")))
    except ValueError:
        return None
    text, sources = _text(value.get("text"), UPDATE_CHARS), _sources(value["sources"], 3)
    return {"at": at, "text": text, "sources": sources} if text and sources else None


def _prepare_story(story: dict, *, editorial: dict | None = None) -> dict:
    story_id = story.get("id", "")
    if not isinstance(story_id, str) or not ID_PATTERN.fullmatch(story_id):
        raise ValueError("Unsafe story ID")
    category = story.get("category", "network")
    priority = story.get("priority", "normal")
    confidence = story.get("confidence", "reported")
    state = story.get("state", "developing")
    if category not in CATEGORIES or priority not in PRIORITIES or confidence not in CONFIDENCES or state not in PUBLIC_STATES:
        raise ValueError("Invalid public story classification")
    title = _text(story.get("title"), 180)
    summary = _text(story.get("summary"), 1600)
    if not title or not summary:
        raise ValueError("Published stories require a title and summary")
    sources = _sources(story["sources"], 20)
    if not sources:
        raise ValueError("Published stories require at least one safe source URL")
    # Only schema values reach the page, so one malformed stored field cannot break a build.
    tags = list(dict.fromkeys(tag for tag in [category, *story.get("tags", [])] if isinstance(tag, str) and tag in CATEGORIES))
    published = _date(story.get("published_at"))
    updated = _date(story.get("updated_at"))
    if updated < published:
        updated = published
    public = {
        "id": story_id, "title": title, "summary": summary,
        "why_it_matters": _text(story.get("why_it_matters"), 800),
        "category": category, "priority": priority, "confidence": confidence,
        "state": state, "tags": tags, "sources": sources,
        "products": [product for product in story.get("products", []) if isinstance(product, str) and product in PRODUCTS],
        "published_at": _iso(published), "updated_at": _iso(updated),
        # When Onion Flash first published the story; older records fall back to the source date.
        "added_at": _iso(_date(story.get("added_at") or story.get("published_at"))),
    }
    updates = story.get("updates")
    updates = [entry for entry in map(_update, updates if isinstance(updates, list) else []) if entry]
    # Kept in stored order. A retracted story keeps them privately and shows none.
    if updates and (editorial or {}).get("status") != "retracted":
        public["updates"] = updates
    if editorial:  # built only from the operator ledger, never from source or model output
        public["editorial"] = editorial
    return public


def _permalink(base: str, story: dict) -> str:
    return f'{base}news/{story["id"]}/'


def _badges(story: dict) -> str:
    parts = [f'<span class="category-label">{CATEGORIES[story["category"]]}</span>']
    notice = story.get("editorial")
    if notice:
        parts.append(f'<span class="editorial-badge">{"Retracted" if notice["status"] == "retracted" else "Corrected"}</span>')
        if notice["status"] == "retracted":
            return '<div class="story-labels">' + "".join(parts) + "</div>"
    if story["priority"] in {"critical", "high"}:
        parts.append(f'<span class="priority priority-{story["priority"]}">{_label(story["priority"])} priority</span>')
    parts.append(f'<span class="evidence-label">{_label(story["confidence"])}</span>')
    return '<div class="story-labels">' + "".join(parts) + "</div>"


def _source_links(story: dict, *, expanded: bool = False) -> str:
    if expanded:
        return '<ol class="source-list">' + "".join(
            f'<li><a href="{_escape(source["url"])}" rel="noopener noreferrer">{_escape(source["title"])}</a> '
            f'<span class="source-domain">{_escape(urlsplit(source["url"]).hostname)}</span></li>'
            for source in story["sources"]
        ) + "</ol>"
    links = "".join(
        f'<a href="{_escape(source["url"])}" rel="noopener noreferrer" title="{_escape(source["title"])}">'
        f'{_escape(urlsplit(source["url"]).hostname.removeprefix("www."))}<span aria-hidden="true"> ↗</span></a>'
        for source in story["sources"][:3]
    )
    return f'<div class="story-sources"><span class="sources-heading">Sources</span>{links}</div>'


def _newest_updates(story: dict) -> list[dict]:
    # Stored order is append order, so the later entry comes first on a tie.
    return sorted(reversed(story.get("updates", [])), key=lambda update: update["at"], reverse=True)


def _latest_update(story: dict) -> str:
    if not story.get("updates"):
        return ""
    latest = _newest_updates(story)[0]
    return f'<p class="latest-update"><strong>Update · {_time(latest["at"])}</strong> {_escape(latest["text"])}</p>'


def _update_list(story: dict) -> str:
    if not story.get("updates"):
        return ""
    rows = "".join(
        f'<li>{_time(update["at"], full=True)}<p>{_escape(update["text"])}</p><span class="update-sources">'
        + " · ".join(f'<a href="{_escape(source["url"])}" rel="noopener noreferrer">{_escape(source["title"])}</a>' for source in update["sources"])
        + "</span></li>" for update in _newest_updates(story))
    return f'<section class="article-updates"><h2>Updates</h2><ul class="update-list">{rows}</ul></section>'


def _card(story: dict, base: str) -> str:
    # Cards show when Onion Flash added the story, which orders the homepage, and
    # the latest dated update instead of the update date.
    updated = ""
    if story["updated_at"] > story["added_at"] and not story.get("updates"):
        updated = f'<span class="updated-note">Updated {_time(story["updated_at"])}</span>'
    return f'''<article class="story" id="story-{story['id']}">
      <div class="story-topline">{_badges(story)}<span class="story-date">{_time(story['added_at'])}</span></div>
      <h2><a href="{_escape(_permalink(base, story))}">{_escape(story['title'])}</a></h2>
      {_editorial_notice(story)}
      <p class="story-summary">{_escape(story['summary'])}</p>{_latest_update(story)}
      {f'<p class="why"><strong>Why it matters</strong> {_escape(story["why_it_matters"])}</p>' if story['why_it_matters'] else ''}
      <div class="story-bottom">{_source_links(story)}{updated}</div>
    </article>'''


def _editorial_notice(story: dict) -> str:
    notice = story.get("editorial")
    if not notice:
        return ""
    label = {"correct": "Correction", "retract": "Retraction", "restore": "Restored"}[notice["action"]]
    reason = "" if notice["status"] == "retracted" else " " + _escape(notice["reason"])
    return f'<p class="editorial-notice"><strong>{label} · {_time(notice["at"], full=True)}</strong>{reason}</p>'


def _editorial_history(story: dict) -> str:
    notice = story.get("editorial")
    if not notice:
        return ""
    rows = []
    labels = {"correct": "Corrected", "retract": "Retracted", "restore": "Restored", "unlock": "Automated updates resumed"}
    for entry in notice["history"]:
        previous = entry.get("superseded")
        old_text = ""
        if previous:
            old_text = ('<details class="superseded-text"><summary>Superseded public text — not current reporting</summary>'
                        f'<h3>{_escape(previous["title"])}</h3><p>{_escape(previous["summary"])}</p>'
                        + (f'<p><strong>Previous context:</strong> {_escape(previous["why_it_matters"])}</p>' if previous["why_it_matters"] else "")
                        + "".join(f'<p><strong>Previous update · {_time(update["at"])}</strong> {_escape(update["text"])}</p>' for update in previous.get("updates", []))
                        + '</details>')
        rows.append(f'<li><strong>Revision {int(entry["revision"])}: {labels[entry["action"]]}</strong> · {_time(entry["created_at"], full=True)}<p>{_escape(entry["reason"])}</p>{old_text}</li>')
    total = int(notice["revision"])
    older = f'<p>Showing the latest {len(rows)} of {total} changes. Earlier revision records are retained by the publisher.</p>' if total > len(rows) else ""
    return f'<details class="editorial-history" data-nosnippet><summary>Editorial history ({total})</summary><ol>{"".join(rows)}</ol>{older}</details>'


def _health_details(health: list[dict]) -> str:
    rows = []
    for item in health:
        if not isinstance(item, dict):
            continue
        name = _text(item.get("name") or item.get("id"), 100)
        if not name:
            continue
        # Only freshness is public; operators get times and errors from `onionflash status`.
        degraded = bool(item.get("stale"))
        url = _public_url(item.get("website_url"))
        source = f'<a href="{_escape(url)}">{_escape(name)}</a>' if url else f'<span>{_escape(name)}</span>'
        rows.append(f'<li><div>{source}<span class="health-state{" delayed" if degraded else ""}">{"Delayed" if degraded else "Collected"}</span></div></li>')
    if not rows:
        return ""
    return '<details class="source-health"><summary>Source availability</summary><p>Collection status, not the status of the Tor network.</p><ul>' + "".join(rows) + "</ul></details>"


def _navigation(base: str) -> str:
    links = (
        ("Home", "https://1aeo.com/"),
        ("Onion Vanity", "https://1aeo.com/onionvanity/"),
        ("Blog", "https://1aeo.com/blog/"),
        ("Onion Flash", base),
        ("Metrics", "https://metrics.1aeo.com"),
        ("Exit DNS Health", "https://exitdnshealth.1aeo.com"),
        ("AROI Validator", "https://aroivalidator.1aeo.com"),
        ("RouteFluxMap", "https://routefluxmap.1aeo.com"),
        ("Contact", "https://1aeo.com/#contact"),
    )
    items = " ".join(
        f'<a href="{_escape(url)}"' + (' aria-current="true"' if label == "Onion Flash" else "") + f'>{label}</a>'
        for label, url in links
    )
    return ('<nav class="site-nav" aria-label="1AEO websites">'
            f'<div class="site-nav-links site-nav-desktop">{items}</div>'
            '<details class="site-nav-mobile"><summary>Menu</summary>'
            f'<div class="site-nav-links">{items}</div></details></nav>')


def _shell(site: dict, base: str, title: str, description: str, body: str, canonical: str, *,
           redirect: str | None = None) -> str:
    name = _text(site["title"], 80)
    repository = _public_url(site["repository_url"])
    repository_link = f'<a href="{_escape(repository)}">Source code ↗</a>' if repository else ""
    refresh = f'<meta http-equiv="refresh" content="0; url={_escape(redirect)}">' if redirect else ""
    return f'''<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_escape(title)}</title><meta name="description" content="{_escape(description)}">
<meta name="theme-color" content="#121212"><link rel="canonical" href="{_escape(canonical)}">{refresh}
<link rel="icon" href="{_escape(base)}mark.svg" type="image/svg+xml">
<link rel="stylesheet" href="{_escape(base)}style.css">
<link rel="alternate" type="application/rss+xml" title="{_escape(name)} RSS" href="{_escape(base)}feed.xml">
<link rel="alternate" type="application/feed+json" title="{_escape(name)} JSON Feed" href="{_escape(base)}feed.json">
</head><body>
<a class="skip-link" href="#main">Skip to news</a>
{_navigation(base)}
<header class="masthead"><div class="masthead-inner">
<a class="brand" href="{_escape(base)}" aria-label="{_escape(name)} home"><img src="{_escape(base)}mark.svg" alt="" width="42" height="42"><span>{_escape(name)}</span></a>
<span class="edition">Independent Tor news<br><span>by 1AEO</span></span>
<a class="rss-button" href="{_escape(base)}feed.xml">RSS feed</a>
</div></header>
{body}
<footer class="footer"><div><a class="footer-name" href="{_escape(base)}">{_escape(name)}</a><p>AI-assisted summaries. Original sources linked. Independently published; not affiliated with the Tor Project.</p></div>
<div class="footer-links">{repository_link}<a href="{_escape(base)}feed.xml">RSS feed</a><span>© 1AEO. Code licensed Apache 2.0.</span></div></footer>
</body></html>'''


def _rss_channel(site: dict, base: str, path: str, latest: str | None, category: str | None = None) -> ET.Element:
    channel = ET.Element("channel")
    title = _text(site["title"], 80)
    if category:
        title += " · " + CATEGORIES[category]
    for key, value in {
        "title": title, "link": base,
        "description": _text(site["description"], 400),
        "language": "en",
    }.items():
        ET.SubElement(channel, key).text = value
    ET.SubElement(channel, f"{{{ATOM_NS}}}link", href=base + path, rel="self", type="application/rss+xml")
    if latest:
        ET.SubElement(channel, "lastBuildDate").text = email.utils.format_datetime(_date(latest), usegmt=True)
    return channel


def _rss_item(story: dict, base: str) -> ET.Element:
    item = ET.Element("item")
    ET.SubElement(item, "title").text = story["title"]
    ET.SubElement(item, "link").text = _permalink(base, story)
    ET.SubElement(item, "guid", isPermaLink="true").text = _permalink(base, story)
    ET.SubElement(item, "pubDate").text = email.utils.format_datetime(_date(story["published_at"]), usegmt=True)
    for tag in story["tags"]:
        ET.SubElement(item, "category").text = tag
    description = _editorial_notice(story) + f'<p>{_escape(story["summary"])}</p>' + _latest_update(story)
    if story["why_it_matters"]:
        description += f'<p><strong>Why it matters:</strong> {_escape(story["why_it_matters"])}</p>'
    if story.get("editorial", {}).get("status") != "retracted":
        description += f'<p>{_label(story["confidence"])} · {_label(story["priority"])} priority · {_label(story["state"])}</p>'
    description += _source_links(story, expanded=True)
    ET.SubElement(item, "description").text = description
    return item


def rss_header(site: dict, base: str, path: str, latest: str | None, category: str | None = None) -> bytes:
    return b'<?xml version="1.0" encoding="utf-8"?>\n<rss xmlns:atom="http://www.w3.org/2005/Atom" version="2.0"><channel>' + b"".join(ET.tostring(child, encoding="utf-8") for child in _rss_channel(site, base, path, latest, category))


def _json_feed_item(story: dict, base: str) -> dict:
    content = story["summary"]
    notice = story.get("editorial")
    if notice:
        content = f'{notice["action"].capitalize()} · {notice["at"]}: {notice["reason"]}\n\n' + content
    if story.get("updates"):
        latest = _newest_updates(story)[0]
        content += f'\n\nUpdate · {latest["at"]}: {latest["text"]}'
    if story["why_it_matters"]:
        content += "\n\nWhy it matters: " + story["why_it_matters"]
    content += "\n\nSources:\n" + "\n".join(source["url"] for source in story["sources"])
    return {"id": _permalink(base, story), "url": _permalink(base, story), "title": story["title"], "content_text": content, "date_published": story["published_at"], "date_modified": story["updated_at"], "tags": story["tags"]}


def json_feed_header(site: dict, base: str) -> bytes:
    metadata = {"version": "https://jsonfeed.org/version/1.1", "title": _text(site["title"], 80), "home_page_url": base, "feed_url": base + "feed.json", "description": _text(site["description"], 400), "language": "en"}
    return (json.dumps(metadata, ensure_ascii=False)[:-1] + ', "items": [').encode("utf-8")


def _page_url(base: str, page: int, topic: str | None = None) -> str:
    if topic is not None:
        if topic not in CATEGORIES:
            raise ValueError("Unknown topic")
        base += f"topics/{topic}/"
    return base if page == 1 else f"{base}page/{page}/"


def _pagination(base: str, page: int, pages: int, topic: str | None = None) -> str:
    if pages <= 1:
        return ""
    previous = f'<a href="{_escape(_page_url(base, page - 1, topic))}" rel="prev">← Newer stories</a>' if page > 1 else ""
    following = f'<a href="{_escape(_page_url(base, page + 1, topic))}" rel="next">Older stories →</a>' if page < pages else ""
    return f'<nav class="pagination" aria-label="News pages">{previous}<span>Page {page} of {pages}</span>{following}</nav>'


def index_html(site: dict, base: str, homepage: list[dict], source_health: list[dict], *, total: int, page: int = 1, pages: int = 1, latest: str | None = None, topic: str | None = None) -> str:
    canonical = _page_url(base, page, topic)
    topics = " ".join(
        f'<a href="{_escape(_page_url(base, 1, key))}"' + (' aria-current="page"' if key == topic else '') + f'>{label}</a>'
        for key, label in [(None, "All news"), *CATEGORIES.items()]
    )
    topic_label = CATEGORIES[topic] if topic else None
    heading = f"{topic_label} news" if topic else "Tor news, distilled."
    feed_path = f"tags/{topic}.xml" if topic else "feed.xml"
    feed_label = f"{topic_label} RSS feed" if topic else "Subscribe via RSS"
    latest_label = f'Latest story update {_time(latest, full=True)}' if latest else 'No stories published yet'
    cards = "".join(_card(story, base) for story in homepage)
    if not cards:
        empty_heading = "No stories in this topic yet." if topic else "The feed is getting started."
        cards = f'<section class="empty-state"><h2>{empty_heading}</h2><p>Stories appear here after collection and source checks. Subscribe to the RSS feed for new stories.</p></section>'
    body = f'''<main id="main" class="page">
<section class="intro"><div><p class="eyebrow">Security. Releases. The network.</p><h1>{heading}</h1><p class="intro-copy">The developments that matter, with the sources to understand them.</p></div>{f'<div class="edition-note"><span class="live-dot" aria-hidden="true"></span>{latest_label}</div>' if page == 1 else ''}</section>
<div class="news-layout"><section class="news-column" aria-label="Latest news">
<nav class="topics" aria-label="News topics">{topics}</nav>
<div class="section-heading"><h2>Latest dispatches</h2><span>{len(homepage)} {'story' if len(homepage) == 1 else 'stories'}</span></div>
<div class="news-list">{cards}</div>
{_pagination(base, page, pages, topic)}
{f'<p class="archive-note">{total} stories in the complete {topic_label.lower() + " " if topic else ""}history.</p>' if pages > 1 else ''}
</section><aside class="sidebar" aria-label="About this feed">
<section class="subscribe-box"><span class="sidebar-kicker">Follow the feed</span><h2>Stay in the loop.</h2><p>Important Tor developments, delivered to your feed reader.</p><a class="subscribe-link" href="{_escape(base + feed_path)}">{feed_label}</a><a class="secondary-feed" href="{_escape(base)}feed.json">All news JSON Feed</a></section>
<section class="about-feed"><h2>Context comes first.</h2><p>Reports, fixes, and releases are grouped into concise stories. Every summary links to its sources.</p><p>Labels distinguish confirmed findings from reports and suspected incidents.</p></section>
{_health_details(source_health)}
<p class="sidebar-footnote">An independent project by <a href="https://1aeo.com/">1AEO</a>.</p>
</aside></div></main>'''
    title = _text(site["title"], 80)
    title += " — " + (heading if topic else "Tor news, distilled")
    if page > 1:
        title += f", page {page}"
    description = _text(site["description"], 400)
    return _shell(site, base, title, description, body, canonical)


def article_html(site: dict, base: str, story: dict) -> str:
    body = f'''<main id="main" class="page article-page"><a class="back-link" href="{_escape(base)}">← All dispatches</a>
<article class="full-story">{_badges(story)}<h1>{_escape(story['title'])}</h1>
{_editorial_notice(story)}
<div class="article-dates">First published {_time(story['added_at'], full=True)}{f' <span>·</span> Last updated {_time(story["updated_at"], full=True)}' if story['updated_at'] > story['added_at'] else ''}</div>
<p class="article-summary">{_escape(story['summary'])}</p>
{f'<section class="article-context"><h2>Why it matters</h2><p>{_escape(story["why_it_matters"])}</p></section>' if story['why_it_matters'] else ''}{_update_list(story)}
<p class="event-state"><span>Event status</span> {"Retracted" if story.get("editorial", {}).get("status") == "retracted" else _label(story['state'])}</p>
<section class="article-sources"><h2>Read the sources</h2>{_source_links(story, expanded=True)}</section>
{_editorial_history(story)}
<p class="article-note">This is an AI-assisted summary of the linked public sources. Consult the original reports for details and operator guidance.</p></article></main>'''
    title = _text(site["title"], 80)
    return _shell(site, base, f"{story['title']} — {title}", story["summary"][:300], body, _permalink(base, story))


def pointer_json(base: str, story_id: str, survivor_id: str) -> dict:
    if not isinstance(story_id, str) or not ID_PATTERN.fullmatch(story_id):
        raise ValueError("Unsafe story ID")
    if not isinstance(survivor_id, str) or not ID_PATTERN.fullmatch(survivor_id):
        raise ValueError("Unsafe survivor story ID")
    root = base.rstrip("/") + "/"
    return {"id": story_id, "merged_into": survivor_id, "url": f"{root}news/{survivor_id}/"}


def pointer_html(site: dict, base: str, survivor_id: str) -> str:
    if not isinstance(survivor_id, str) or not ID_PATTERN.fullmatch(survivor_id):
        raise ValueError("Unsafe survivor story ID")
    root = base.rstrip("/") + "/"
    target = f"{root}news/{survivor_id}/"
    body = (
        f'<main id="main" class="page article-page"><a class="back-link" href="{_escape(root)}">← All dispatches</a>'
        '<article class="full-story"><h1>This story has moved</h1>'
        '<p class="article-summary">Onion Flash combined this report with its coverage of the same event.</p>'
        f'<p><a href="{_escape(target)}">Read the combined story</a></p></article></main>'
    )
    title = _text(site["title"], 80)
    return _shell(
        site,
        root,
        f"This story has moved — {title}",
        "Onion Flash combined this report with its coverage of the same event.",
        body,
        target,
        redirect=target,
    )


def headers_text(base: str) -> str:
    prefix = urlsplit(base).path.rstrip("/")
    policy = "default-src 'none'; script-src 'none'; style-src 'self'; img-src 'self'; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    # Browser XML viewers style feeds with inline CSS and data: icons. Cloudflare
    # applies rules in order and joins repeated values, so the last rule drops the
    # inherited CSP. Feeds keep the default XML type: Firefox downloads
    # application/rss+xml and Chrome shows it as plain text.
    feed_policy = policy.replace("style-src 'self'; img-src 'self'", "style-src 'unsafe-inline'; img-src data:")
    return f'''{prefix}/*
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Content-Security-Policy: {policy}
  Permissions-Policy: camera=(), microphone=(), geolocation=()
  Cache-Control: public, max-age=60, must-revalidate

{prefix}/*.xml
  ! Content-Security-Policy
  Content-Security-Policy: {feed_policy}
'''

