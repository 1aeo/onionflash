"""Deterministic, dependency-free static news publishing.

Only the public story fields are rendered. Raw source bodies, evidence excerpts,
errors, credentials, and database records never enter the output directory.
"""

from __future__ import annotations

import email.utils
import html
import json
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

from .schema import (
    CATEGORY_LABELS as CATEGORIES,
    CONFIDENCES,
    FIELD_LIMITS,
    PRIORITIES,
    PRODUCTS,
    PUBLIC_STATES,
    SOFTWARE,
    STORY_ID_RE,
    UPDATE_CHARS,
)
from .util import format_utc as _iso, parse_utc as _date, safe_canonical_url, software_from_sources

ASSET_FILES = {"style.css": "text/css; charset=utf-8", "mark.svg": "image/svg+xml"}
ATOM_NS = "http://www.w3.org/2005/Atom"
ET.register_namespace("atom", ATOM_NS)
_NOTICE_LABELS = {"correct": "Correction", "retract": "Retraction", "restore": "Restored"}
_public_url = safe_canonical_url


def public_json_text(payload: dict) -> str:
    """Serialize a public story or pointer object as canonical trailing-newline JSON."""
    return json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n"


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _story_id(value: object, label: str = "story ID") -> str:
    if not isinstance(value, str) or not STORY_ID_RE.fullmatch(value):
        raise ValueError(f"Unsafe {label}")
    return value


def _retracted(story: dict) -> bool:
    return (story.get("editorial") or {}).get("status") == "retracted"


def story_software(story: dict) -> list[str]:
    """Return validated schema software slugs associated with `story` in order."""
    return [product for product in (story.get("products") or ()) if isinstance(product, str) and product in SOFTWARE]


def feed_path(topic: str | None = None, software: str | None = None) -> str:
    """Return the relative RSS feed path for `software`, `topic`, or `feed.xml` for all news."""
    if topic is not None and topic not in CATEGORIES:
        raise ValueError("Unknown topic")
    if software is not None:
        if software not in SOFTWARE:
            raise ValueError("Unknown software")
        return f"software/{software}.xml"
    if topic is not None:
        return f"tags/{topic}.xml"
    return "feed.xml"


def _text(value: object, limit: int) -> str:
    """Constrain untrusted display fields while retaining ordinary Unicode."""
    if not isinstance(value, str):
        return ""
    clean = "".join(
        char for char in value
        if char in "\t\n\r" or 0x20 <= ord(char) <= 0xD7FF or 0xE000 <= ord(char) <= 0xFFFD or 0x10000 <= ord(char) <= 0x10FFFF
    )
    # Truncation may land on a space. Keep normalization idempotent so a final
    # candidate cannot change between review and its guarded commit.
    return " ".join(clean.split())[:limit].rstrip()


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
            sources[url] = {"url": url, "title": _text(source.get("title"), FIELD_LIMITS["source_title"]) or urlsplit(url).hostname}
    return list(sources.values())


def _update(value: object) -> dict | None:
    """One dated update with its own citations; a malformed entry is dropped."""
    if not isinstance(value, dict) or not isinstance(value.get("sources"), list):
        return None
    try:
        at = _iso(_date(value.get("at")))
    except ValueError:
        return None
    text, sources = _text(value.get("text"), UPDATE_CHARS), _sources(value["sources"], FIELD_LIMITS["max_update_sources"])
    return {"at": at, "text": text, "sources": sources} if text and sources else None


def prepare_story(story: dict, *, editorial: dict | None = None, allow_empty_sources: bool = False) -> dict:
    """Validate and normalize a stored story dictionary into its public representation."""
    story_id = _story_id(story.get("id", ""))
    category = story.get("category", "network")
    priority = story.get("priority", "normal")
    confidence = story.get("confidence", "reported")
    state = story.get("state", "developing")
    if category not in CATEGORIES or priority not in PRIORITIES or confidence not in CONFIDENCES or state not in PUBLIC_STATES:
        raise ValueError("Invalid public story classification")
    title = _text(story.get("title"), FIELD_LIMITS["title"])
    summary = _text(story.get("summary"), FIELD_LIMITS["summary"])
    if not title or not summary:
        raise ValueError("Published stories require a title and summary")
    is_retracted = (editorial or {}).get("status") == "retracted"
    sources = _sources(story["sources"], FIELD_LIMITS["max_sources"])
    if not sources and not (is_retracted or allow_empty_sources):
        raise ValueError("Published stories require at least one safe source URL")
    # Only schema values reach the page, so one malformed stored field cannot break a build.
    tags = list(dict.fromkeys(tag for tag in [category, *story.get("tags", [])] if isinstance(tag, str) and tag in CATEGORIES))
    published = _date(story.get("published_at"))
    updated = max(published, _date(story.get("updated_at")))
    explicit_products = list(dict.fromkeys(product for product in story.get("products", []) if isinstance(product, str) and product in PRODUCTS))
    products = (
        explicit_products
        if story.get("origin") == "network-health"
        else list(dict.fromkeys([*explicit_products, *software_from_sources(sources)]))
    )
    public = {
        "id": story_id, "title": title, "summary": summary,
        "why_it_matters": _text(story.get("why_it_matters"), FIELD_LIMITS["why_it_matters"]),
        "category": category, "priority": priority, "confidence": confidence,
        "state": state, "tags": tags, "sources": sources,
        "products": products,
        "published_at": _iso(published), "updated_at": _iso(updated),
        # When Onion Flash first published the story; older records fall back to the source date.
        "added_at": _iso(_date(story.get("added_at") or story.get("published_at"))),
    }
    updates = story.get("updates")
    updates = [entry for entry in map(_update, updates if isinstance(updates, list) else []) if entry]
    if updates and not is_retracted:
        public["updates"] = updates
    raw_notes = story.get("alert_notes")
    notes = [note for note in (_text(item, 600) for item in (raw_notes if isinstance(raw_notes, list) else [])[:FIELD_LIMITS["max_alert_notes"]]) if note]
    if notes and not is_retracted:
        public["alert_notes"] = list(dict.fromkeys(notes))
    if story.get("origin") == "network-health":
        public["origin"] = "network-health"
    if editorial:  # built only from the operator ledger, never from source or model output
        public["editorial"] = editorial
    return public


def _permalink(base: str, story_or_id: dict | str) -> str:
    sid = story_or_id["id"] if isinstance(story_or_id, dict) else story_or_id
    return f'{base.rstrip("/")}/news/{sid}/'


def _badges(story: dict, base: str) -> str:
    retracted = _retracted(story)
    parts = [f'<span class="category-label">{CATEGORIES[story["category"]]}</span>']
    if not retracted:
        for sw in story_software(story):
            parts.append(f'<a class="software-label" href="{_escape(_page_url(base, 1, software=sw))}">{_escape(sw)}</a>')
    if story.get("editorial"):
        parts.append(f'<span class="editorial-badge">{"Retracted" if retracted else "Corrected"}</span>')
    if not retracted:
        if story["priority"] in {"critical", "high"}:
            parts.append(f'<span class="priority priority-{story["priority"]}">{_label(story["priority"])} priority</span>')
        parts.append(f'<span class="evidence-label">{_label(story["confidence"])}</span>')
    return '<div class="story-labels">' + "".join(parts) + "</div>"


def _source_links(story: dict, *, expanded: bool = False) -> str:
    if not story["sources"]:
        return ""
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
    return sorted(reversed(story.get("updates") or ()), key=lambda update: update["at"], reverse=True)


def _latest_update(story: dict) -> str:
    if not (updates := _newest_updates(story)):
        return ""
    return f'<p class="latest-update"><strong>Update · {_time(updates[0]["at"])}</strong> {_escape(updates[0]["text"])}</p>'


def _update_list(story: dict) -> str:
    if not (updates := _newest_updates(story)):
        return ""
    rows = "".join(
        f'<li>{_time(update["at"], full=True)}<p>{_escape(update["text"])}</p><span class="update-sources">'
        + " · ".join(f'<a href="{_escape(source["url"])}" rel="noopener noreferrer">{_escape(source["title"])}</a>' for source in update["sources"])
        + "</span></li>" for update in updates)
    return f'<section class="article-updates"><h2>Updates</h2><ul class="update-list">{rows}</ul></section>'


def _alert_notes(story: dict) -> str:
    notes = story.get("alert_notes") or []
    if not notes:
        return ""
    paragraphs = "".join(f"<p>{_escape(note)}</p>" for note in notes)
    return f'<section class="article-context"><h2>About this alert</h2>{paragraphs}</section>'


def _card(story: dict, base: str) -> str:
    # Cards show when Onion Flash added the story, which orders the homepage, and
    # the latest dated update instead of the update date.
    updated = ""
    if story["updated_at"] > story["added_at"] and not story.get("updates"):
        updated = f'<span class="updated-note">Updated {_time(story["updated_at"])}</span>'
    return f'''<article class="story" id="story-{story['id']}">
      <div class="story-topline">{_badges(story, base)}<span class="story-date">{_time(story['added_at'])}</span></div>
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
    reason = "" if _retracted(story) else " " + _escape(notice["reason"])
    return f'<p class="editorial-notice"><strong>{_NOTICE_LABELS[notice["action"]]} · {_time(notice["at"], full=True)}</strong>{reason}</p>'


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


def _article_shell(site: dict, base: str, heading: str, description: str, inner: str, canonical: str, *,
                   redirect: str | None = None) -> str:
    root = base.rstrip("/") + "/"
    body = f'<main id="main" class="page article-page"><a class="back-link" href="{_escape(root)}">← All dispatches</a>\n<article class="full-story">{inner}</article></main>'
    return _shell(site, root, f"{heading} — {_text(site['title'], 80)}", description, body, canonical, redirect=redirect)


def _rss_item(story: dict, base: str) -> ET.Element:
    item, url = ET.Element("item"), _permalink(base, story)
    ET.SubElement(item, "title").text = story["title"]
    ET.SubElement(item, "link").text = url
    ET.SubElement(item, "guid", isPermaLink="true").text = url
    ET.SubElement(item, "pubDate").text = email.utils.format_datetime(_date(story["published_at"]), usegmt=True)
    for tag in story["tags"]:
        ET.SubElement(item, "category").text = tag
    description = _editorial_notice(story) + f'<p>{_escape(story["summary"])}</p>' + _latest_update(story)
    if story["why_it_matters"]:
        description += f'<p><strong>Why it matters:</strong> {_escape(story["why_it_matters"])}</p>'
    for note in story.get("alert_notes", []):
        description += f'<p><strong>About this alert:</strong> {_escape(note)}</p>'
    if not _retracted(story):
        description += f'<p>{_label(story["confidence"])} · {_label(story["priority"])} priority · {_label(story["state"])}</p>'
    description += _source_links(story, expanded=True)
    ET.SubElement(item, "description").text = description
    return item


def rss_header(
    site: dict,
    base: str,
    path: str,
    latest: str | None,
    category: str | None = None,
    software: str | None = None,
) -> bytes:
    """Render the opening UTF-8 XML and `<channel>` metadata bytes for an RSS feed."""
    if software is not None and software not in SOFTWARE:
        raise ValueError("Unknown software")
    if category is not None and category not in CATEGORIES:
        raise ValueError("Unknown topic")
    channel = ET.Element("channel")
    suffix = f" · {software}" if software else (f" · {CATEGORIES[category]}" if category else "")
    title = _text(site["title"], 80) + suffix
    for key, value in {"title": title, "link": base, "description": _text(site["description"], 400), "language": "en"}.items():
        ET.SubElement(channel, key).text = value
    ET.SubElement(channel, f"{{{ATOM_NS}}}link", href=base + path, rel="self", type="application/rss+xml")
    if latest:
        ET.SubElement(channel, "lastBuildDate").text = email.utils.format_datetime(_date(latest), usegmt=True)
    return b'<?xml version="1.0" encoding="utf-8"?>\n<rss xmlns:atom="http://www.w3.org/2005/Atom" version="2.0"><channel>' + b"".join(ET.tostring(child, encoding="utf-8") for child in channel)


def _json_feed_item(story: dict, base: str) -> dict:
    content = story["summary"]
    if notice := story.get("editorial"):
        suffix = "" if _retracted(story) else f': {notice["reason"]}'
        content = f'{_NOTICE_LABELS[notice["action"]]} · {notice["at"]}{suffix}\n\n' + content
    if updates := _newest_updates(story):
        content += f'\n\nUpdate · {updates[0]["at"]}: {updates[0]["text"]}'
    if story["why_it_matters"]:
        content += "\n\nWhy it matters: " + story["why_it_matters"]
    for note in story.get("alert_notes", []):
        content += "\n\nAbout this alert: " + note
    if story["sources"]:
        content += "\n\nSources:\n" + "\n".join(source["url"] for source in story["sources"])
    url = _permalink(base, story)
    return {"id": url, "url": url, "title": story["title"], "content_text": content, "date_published": story["published_at"], "date_modified": story["updated_at"], "tags": story["tags"]}


def json_feed_header(site: dict, base: str) -> bytes:
    """Render the opening UTF-8 JSON Feed 1.1 metadata prefix before `items`."""
    metadata = {"version": "https://jsonfeed.org/version/1.1", "title": _text(site["title"], 80), "home_page_url": base, "feed_url": base + "feed.json", "description": _text(site["description"], 400), "language": "en"}
    return (json.dumps(metadata, ensure_ascii=False)[:-1] + ', "items": [').encode("utf-8")


def _page_url(base: str, page: int, topic: str | None = None, software: str | None = None) -> str:
    url = (base.rstrip("/") + "/") if base else ""
    if topic is not None:
        if topic not in CATEGORIES:
            raise ValueError("Unknown topic")
        url += f"topics/{topic}/"
    if software is not None:
        if software not in SOFTWARE:
            raise ValueError("Unknown software")
        url += f"software/{software}/"
    return url if page == 1 else f"{url}page/{page}/"


def _pagination(base: str, page: int, pages: int, topic: str | None = None, software: str | None = None) -> str:
    if pages <= 1:
        return ""
    previous = f'<a href="{_escape(_page_url(base, page - 1, topic, software))}" rel="prev">← Newer stories</a>' if page > 1 else ""
    following = f'<a href="{_escape(_page_url(base, page + 1, topic, software))}" rel="next">Older stories →</a>' if page < pages else ""
    return f'<nav class="pagination" aria-label="News pages">{previous}<span>Page {page} of {pages}</span>{following}</nav>'


def index_html(
    site: dict,
    base: str,
    homepage: list[dict],
    source_health: list[dict],
    *,
    total: int,
    page: int = 1,
    pages: int = 1,
    latest: str | None = None,
    topic: str | None = None,
    software: str | None = None,
) -> str:
    """Render a paginated homepage, topic, software, or combined listing HTML document."""
    root = (base.rstrip("/") + "/") if base else ""
    canonical = _page_url(root, page, topic, software)
    topics = " ".join(
        f'<a href="{_escape(_page_url(root, 1, key, software))}"' + (' aria-current="page"' if key == topic else '') + f'>{label}</a>'
        for key, label in [(None, "All news"), *CATEGORIES.items()]
    )
    software_filters = " ".join(
        f'<a href="{_escape(_page_url(root, 1, topic, key))}"' + (' aria-current="page"' if key == software else '') + f'>{_escape(label)}</a>'
        for key, label in [(None, "All software"), *((slug, slug) for slug in SOFTWARE)]
    )
    topic_label = CATEGORIES[topic] if topic else None
    if topic_label and software:
        heading = f"{topic_label} · {software} news"
        empty_heading = "No stories in this view yet."
        archive_scope = f"{topic_label.lower()} {software} "
        feed_label = f"{software} RSS feed"
    elif software:
        heading = f"{software} news"
        empty_heading = "No stories for this software yet."
        archive_scope = f"{software} "
        feed_label = f"{software} RSS feed"
    elif topic_label:
        heading = f"{topic_label} news"
        empty_heading = "No stories in this topic yet."
        archive_scope = f"{topic_label.lower()} "
        feed_label = f"{topic_label} RSS feed"
    else:
        heading = "Tor news, distilled."
        empty_heading = "The feed is getting started."
        archive_scope = ""
        feed_label = "Subscribe via RSS"
    latest_label = f'Latest story update {_time(latest, full=True)}' if latest else 'No stories published yet'
    cards = "".join(_card(story, root) for story in homepage)
    if not cards:
        cards = f'<section class="empty-state"><h2>{empty_heading}</h2><p>Stories appear here after collection and source checks. Subscribe to the RSS feed for new stories.</p></section>'
    body = f'''<main id="main" class="page">
<section class="intro"><div><p class="eyebrow">Security. Releases. The network.</p><h1>{heading}</h1><p class="intro-copy">The developments that matter, with the sources to understand them.</p></div>{f'<div class="edition-note"><span class="live-dot" aria-hidden="true"></span>{latest_label}</div>' if page == 1 else ''}</section>
<div class="news-layout"><section class="news-column" aria-label="Latest news">
<div class="filter-bars"><nav class="topics" aria-label="News topics">{topics}</nav><nav class="software-filters" aria-label="Software">{software_filters}</nav></div>
<div class="section-heading"><h2>Latest dispatches</h2><span>{len(homepage)} {'story' if len(homepage) == 1 else 'stories'}</span></div>
<div class="news-list">{cards}</div>
{_pagination(root, page, pages, topic, software)}
{f'<p class="archive-note">{total} stories in the complete {archive_scope}history.</p>' if pages > 1 else ''}
</section><aside class="sidebar" aria-label="About this feed">
<section class="subscribe-box"><span class="sidebar-kicker">Follow the feed</span><h2>Stay in the loop.</h2><p>Important Tor developments, delivered to your feed reader.</p><a class="subscribe-link" href="{_escape(root + feed_path(topic, software))}">{feed_label}</a><a class="secondary-feed" href="{_escape(root)}feed.json">All news JSON Feed</a></section>
<section class="about-feed"><h2>Context comes first.</h2><p>Reports, fixes, and releases are grouped into concise stories. Every summary links to its sources.</p><p>Labels distinguish confirmed findings from reports and suspected incidents.</p></section>
{_health_details(source_health)}
<p class="sidebar-footnote">An independent project by <a href="https://1aeo.com/">1AEO</a>.</p>
</aside></div></main>'''
    title = _text(site["title"], 80) + " — " + (heading if (topic or software) else "Tor news, distilled")
    if page > 1:
        title += f", page {page}"
    return _shell(site, root, title, _text(site["description"], 400), body, canonical)


def article_html(site: dict, base: str, story: dict) -> str:
    """Render the standalone article permalink HTML page for `story`."""
    note_text = (
        "This alert uses fixed wording; only the names, times and counts come from the linked DocTor reports. "
        "Consult the original reports for details."
        if story.get("origin") == "network-health"
        else "This is an AI-assisted summary of the linked public sources. Consult the original reports for details and operator guidance."
    )
    inner = f'''{_badges(story, base)}<h1>{_escape(story['title'])}</h1>
{_editorial_notice(story)}
<div class="article-dates">First published {_time(story['added_at'], full=True)}{f' <span>·</span> Last updated {_time(story["updated_at"], full=True)}' if story['updated_at'] > story['added_at'] else ''}</div>
<p class="article-summary">{_escape(story['summary'])}</p>
{f'<section class="article-context"><h2>Why it matters</h2><p>{_escape(story["why_it_matters"])}</p></section>' if story['why_it_matters'] else ''}{_alert_notes(story)}{_update_list(story)}
<p class="event-state"><span>Event status</span> {"Retracted" if _retracted(story) else _label(story['state'])}</p>
{f'<section class="article-sources"><h2>Read the sources</h2>{_source_links(story, expanded=True)}</section>' if story['sources'] else ''}
{_editorial_history(story)}
<p class="article-note">{note_text}</p>'''
    return _article_shell(site, base, story["title"], story["summary"][:300], inner, _permalink(base, story))


def pointer_json(base: str, story_id: str, survivor_id: str) -> dict:
    """Build the public JSON redirect record for a merged story permalink."""
    _story_id(story_id)
    _story_id(survivor_id, "survivor story ID")
    return {"id": story_id, "merged_into": survivor_id, "url": _permalink(base, survivor_id)}


def pointer_html(site: dict, base: str, survivor_id: str) -> str:
    """Render the HTML redirect page pointing a merged story permalink to `survivor_id`."""
    _story_id(survivor_id, "survivor story ID")
    target = _permalink(base, survivor_id)
    description = "Onion Flash combined this report with its coverage of the same event."
    inner = (
        "<h1>This story has moved</h1>"
        f'<p class="article-summary">{description}</p>'
        f'<p><a href="{_escape(target)}">Read the combined story</a></p>'
    )
    return _article_shell(site, base, "This story has moved", description, inner, target, redirect=target)


def headers_text(base: str) -> str:
    """Render the static `_headers` security and caching rules for `base`."""
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
