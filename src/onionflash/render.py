"""Deterministic, dependency-free static news publishing.

Only the public story fields are rendered. Raw source bodies, evidence excerpts,
errors, credentials, and database records never enter the output directory.
"""

from __future__ import annotations

import email.utils
import html
import ipaddress
import json
import re
import shutil
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit
from zoneinfo import ZoneInfo
from .schema import CATEGORY_LABELS as CATEGORIES, PRIORITIES, CONFIDENCES, STATES
from .util import parse_utc as _date, format_utc as _iso


ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
ASSET_FILES = ("style.css", "app.js", "mark.svg")
ATOM_NS = "http://www.w3.org/2005/Atom"
ET.register_namespace("atom", ATOM_NS)


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _text(value: object, limit: int) -> str:
    """Constrain untrusted display fields while retaining ordinary Unicode."""
    if not isinstance(value, str):
        return ""
    clean = "".join(char for char in value if char in "\t\n\r" or 0x20 <= ord(char) <= 0xD7FF or 0xE000 <= ord(char) <= 0xFFFD or 0x10000 <= ord(char) <= 0x10FFFF)
    return " ".join(clean.split())[:limit]


def _safe_url(value: object, *, allow_local: bool = False) -> str:
    if not isinstance(value, str) or len(value) > 4096:
        return ""
    if any(ord(char) < 32 or ord(char) == 127 for char in value) or "\\" in value:
        return ""
    try:
        value.encode("utf-8")
        parsed = urlsplit(value)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            return ""
        if parsed.username is not None or parsed.password is not None:
            return ""
        _ = parsed.port  # Reject malformed and out-of-range ports.
        hostname = parsed.hostname.lower().rstrip(".")
        if not allow_local:
            try:
                if not ipaddress.ip_address(hostname).is_global:
                    return ""
            except ValueError:
                numeric_parts = hostname.split(".")
                alternate_ip = all(re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)", part) for part in numeric_parts)
                if alternate_ip or "." not in hostname or hostname.endswith((".localhost", ".local", ".internal", ".home", ".test")):
                    return ""
        return value
    except (TypeError, ValueError, UnicodeError):
        return ""


def _site_base(value: object) -> str:
    url = _safe_url(value, allow_local=True)
    if not url:
        raise ValueError("site.base_url must be an absolute HTTP(S) URL without credentials")
    parsed = urlsplit(url)
    if parsed.query or parsed.fragment or any(part in {".", ".."} for part in unquote(parsed.path).split("/")):
        raise ValueError("site.base_url must contain a clean path without query or fragment")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/") + "/", "", ""))


def _time(value: str, *, full: bool = False) -> str:
    date = _date(value)
    label = date.strftime("%b %d, %Y · %H:%M UTC" if full else "%b %d, %Y")
    return f'<time datetime="{_iso(date)}" title="{date.strftime("%Y-%m-%d %H:%M UTC")}">{label}</time>'


def _label(value: str) -> str:
    return value.replace("-", " ").capitalize()


def _limit(value: object, default: int, maximum: int) -> int:
    if isinstance(value, bool):
        return default
    try:
        return max(1, min(int(value), maximum))
    except (TypeError, ValueError, OverflowError):
        return default


def _prepare_story(story: dict) -> dict:
    story_id = story.get("id", "")
    if not isinstance(story_id, str) or not ID_PATTERN.fullmatch(story_id):
        raise ValueError("Unsafe story ID")
    category = story.get("category", "network")
    priority = story.get("priority", "normal")
    confidence = story.get("confidence", "reported")
    state = story.get("state", "developing")
    if category not in CATEGORIES or priority not in PRIORITIES or confidence not in CONFIDENCES or state not in STATES:
        raise ValueError("Invalid public story classification")
    title = _text(story.get("title"), 180)
    summary = _text(story.get("summary"), 1600)
    if not title or not summary:
        raise ValueError("Published stories require a title and summary")
    sources = []
    for source in story.get("sources", [])[:20]:
        if not isinstance(source, dict):
            continue
        url = _safe_url(source.get("url"))
        if url and all(existing["url"] != url for existing in sources):
            sources.append({"url": url, "title": _text(source.get("title"), 200) or urlsplit(url).hostname})
    if not sources:
        raise ValueError("Published stories require at least one safe source URL")
    tags = []
    for tag in [category, *story.get("tags", [])[:20], *story.get("products", [])[:10]]:
        if isinstance(tag, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,39}", tag) and tag not in tags:
            tags.append(tag)
    published = _date(story.get("published_at"))
    updated = _date(story.get("updated_at"))
    if updated < published:
        updated = published
    return {
        "id": story_id, "title": title, "summary": summary,
        "why_it_matters": _text(story.get("why_it_matters"), 800),
        "category": category, "priority": priority, "confidence": confidence,
        "state": state, "tags": tags, "sources": sources,
        "published_at": _iso(published), "updated_at": _iso(updated),
    }


def _permalink(base: str, story: dict) -> str:
    return f'{base}news/{story["id"]}/'


def _badges(story: dict) -> str:
    parts = [f'<span class="category-label">{CATEGORIES[story["category"]]}</span>']
    if story["priority"] in {"critical", "high"}:
        parts.append(f'<span class="priority priority-{story["priority"]}">{_label(story["priority"])} priority</span>')
    parts.append(f'<span class="evidence-label">{_label(story["confidence"])}</span>')
    return '<div class="story-labels">' + "".join(parts) + "</div>"


def _source_links(story: dict, *, expanded: bool = False) -> str:
    if expanded:
        return '<ol class="source-list">' + "".join(
            f'<li><a href="{_escape(source["url"])}" rel="noopener noreferrer">{_escape(source["title"])}</a>'
            f'<span class="source-domain">{_escape(urlsplit(source["url"]).hostname)}</span></li>'
            for source in story["sources"]
        ) + "</ol>"
    links = "".join(
        f'<a href="{_escape(source["url"])}" rel="noopener noreferrer" title="{_escape(source["title"])}">'
        f'{_escape(urlsplit(source["url"]).hostname.removeprefix("www."))}<span aria-hidden="true"> ↗</span></a>'
        for source in story["sources"][:3]
    )
    return f'<div class="story-sources"><span class="sources-heading">Sources</span>{links}</div>'


def _card(story: dict, base: str) -> str:
    search = " ".join([story["title"], story["summary"], *story["tags"]])
    updated = ""
    if story["updated_at"] != story["published_at"]:
        updated = f'<span class="updated-note">Updated {_time(story["updated_at"])}</span>'
    return f'''<article class="story" id="story-{story['id']}" data-tags="{_escape(' '.join(story['tags']))}" data-search="{_escape(search.casefold())}">
      <div class="story-topline">{_badges(story)}<span class="story-date">{_time(story['published_at'])}</span></div>
      <h2><a href="{_escape(_permalink(base, story))}">{_escape(story['title'])}</a></h2>
      <p class="story-summary">{_escape(story['summary'])}</p>
      {f'<p class="why"><strong>Why it matters</strong> {_escape(story["why_it_matters"])}</p>' if story['why_it_matters'] else ''}
      <div class="story-bottom">{_source_links(story)}{updated}</div>
    </article>'''


def _health_details(health: list[dict]) -> str:
    rows = []
    for item in health:
        if not isinstance(item, dict):
            continue
        name = _text(item.get("name") or item.get("id"), 100)
        if not name:
            continue
        last = "Not collected yet"
        if item.get("last_success"):
            try:
                last = "Last success " + _time(item["last_success"], full=True)
            except ValueError:
                last = "Last collection time unavailable"
        degraded = bool(item.get("stale") or item.get("error"))
        label = "Delayed" if degraded else ("Collected" if item.get("last_success") else "Pending")
        url = _safe_url(item.get("website_url"))
        source = f'<a href="{_escape(url)}">{_escape(name)}</a>' if url else f'<span>{_escape(name)}</span>'
        rows.append(f'<li><div>{source}<span class="health-state{ " delayed" if degraded else ""}">{label}</span></div><small>{last}</small></li>')
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
    items = "".join(
        f'<a href="{_escape(url)}"' + (' aria-current="true"' if label == "Onion Flash" else "") + f'>{label}</a>'
        for label, url in links
    )
    return ('<nav class="site-nav" id="site-nav" aria-label="1AEO websites">'
            '<button class="site-nav-toggle" id="site-nav-toggle" type="button" '
            'aria-expanded="false" aria-controls="site-nav-links" hidden>'
            '<span aria-hidden="true">☰</span> <span>Menu</span></button>'
            f'<div class="site-nav-links" id="site-nav-links">{items}</div></nav>')


def _shell(site: dict, base: str, title: str, description: str, body: str, canonical: str) -> str:
    name = _text(site.get("title", "Onion Flash"), 80)
    repository = _safe_url(site.get("repository_url", "https://github.com/1aeo/onionflash"))
    year = datetime.now(ZoneInfo("America/Los_Angeles")).year
    repository_link = f'<a href="{_escape(repository)}">Source code ↗</a>' if repository else ""
    return f'''<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_escape(title)}</title><meta name="description" content="{_escape(description)}">
<meta name="theme-color" content="#121212"><link rel="canonical" href="{_escape(canonical)}">
<link rel="icon" href="{_escape(base)}mark.svg" type="image/svg+xml">
<link rel="stylesheet" href="{_escape(base)}style.css">
<link rel="alternate" type="application/rss+xml" title="{_escape(name)} RSS" href="{_escape(base)}feed.xml">
<link rel="alternate" type="application/feed+json" title="{_escape(name)} JSON Feed" href="{_escape(base)}feed.json">
<script src="{_escape(base)}app.js" defer></script>
</head><body>
<a class="skip-link" href="#main">Skip to news</a>
{_navigation(base)}
<header class="masthead"><div class="masthead-inner">
<a class="brand" href="{_escape(base)}" aria-label="{_escape(name)} home"><img src="{_escape(base)}mark.svg" alt="" width="42" height="42"><span>{_escape(name)}</span></a>
<span class="edition">Independent Tor news<br><span>by 1AEO</span></span>
<a class="rss-button" href="{_escape(base)}feed.xml"><span class="rss-icon" aria-hidden="true">◔</span> Subscribe via RSS</a>
</div></header>
{body}
<footer class="footer"><div><a class="footer-name" href="{_escape(base)}">{_escape(name)}</a><p>AI-assisted summaries. Original sources linked. Independently published; not affiliated with the Tor Project.</p></div>
<div class="footer-links">{repository_link}<a href="{_escape(base)}feed.xml">RSS feed</a><span>© <span data-copyright-year>{year}</span> 1AEO. Code licensed Apache 2.0.</span></div></footer>
</body></html>'''


def _rss(site: dict, base: str, stories: list[dict], path: str, category: str | None = None) -> bytes:
    root = ET.Element("rss", version="2.0")
    channel = ET.SubElement(root, "channel")
    title = _text(site.get("title", "Onion Flash"), 80)
    if category:
        title += " · " + CATEGORIES[category]
    for key, value in {
        "title": title, "link": base,
        "description": _text(site.get("description", "Important Tor news, distilled."), 400),
        "language": "en",
    }.items():
        ET.SubElement(channel, key).text = value
    ET.SubElement(channel, f"{{{ATOM_NS}}}link", href=base + path, rel="self", type="application/rss+xml")
    if stories:
        ET.SubElement(channel, "lastBuildDate").text = email.utils.format_datetime(max(_date(s["updated_at"]) for s in stories), usegmt=True)
    for story in stories:
        item = ET.SubElement(channel, "item")
        ET.SubElement(item, "title").text = story["title"]
        ET.SubElement(item, "link").text = _permalink(base, story)
        ET.SubElement(item, "guid", isPermaLink="true").text = _permalink(base, story)
        ET.SubElement(item, "pubDate").text = email.utils.format_datetime(_date(story["published_at"]), usegmt=True)
        for tag in story["tags"]:
            ET.SubElement(item, "category").text = tag
        description = f'<p>{_escape(story["summary"])}</p>'
        if story["why_it_matters"]:
            description += f'<p><strong>Why it matters:</strong> {_escape(story["why_it_matters"])}</p>'
        description += f'<p>{_label(story["confidence"])} · {_label(story["priority"])} priority · {_label(story["state"])}</p>'
        description += _source_links(story, expanded=True)
        ET.SubElement(item, "description").text = description
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def render_site(config: dict, stories: list[dict], source_health: list[dict], output_dir: Path) -> None:
    """Render a complete self-contained release into a new, empty directory."""
    output_dir = Path(output_dir).absolute()
    if output_dir.is_symlink():
        raise ValueError("Output directory must not be a symlink")
    # Resolve trusted parent directories (macOS /tmp and /var are symlinks).
    output_dir = output_dir.resolve()
    if output_dir.exists() and (not output_dir.is_dir() or any(output_dir.iterdir())):
        raise ValueError("Output directory must be empty")
    site = config.get("site", {})
    base = _site_base(site.get("base_url", "https://1aeo.com/onionflash/"))
    public = [_prepare_story(story) for story in stories]
    if len({story["id"] for story in public}) != len(public):
        raise ValueError("Duplicate story IDs")
    public.sort(key=lambda story: (story["updated_at"], story["published_at"], story["id"]), reverse=True)
    page_size = _limit(site.get("page_size"), 100, 1000)
    feed_size = _limit(site.get("feed_size"), 50, 1000)
    output_dir.mkdir(parents=True, exist_ok=True)
    assets = Path(__file__).with_name("assets")
    for name in ASSET_FILES:
        shutil.copyfile(assets / name, output_dir / name)
    filters = '<button type="button" class="filter active" data-filter="all" aria-pressed="true">All news</button>'
    for key, label in CATEGORIES.items():
        if any(key in story["tags"] for story in public):
            filters += f'<button type="button" class="filter" data-filter="{key}" aria-pressed="false">{label}</button>'
    latest = public[0]["updated_at"] if public else None
    latest_label = f'Latest story update {_time(latest, full=True)}' if latest else 'First edition coming soon'
    cards = "".join(_card(story, base) for story in public[:page_size])
    if not cards:
        cards = '<section class="empty-state"><span class="empty-mark" aria-hidden="true">↗</span><h2>The feed is getting started.</h2><p>Stories appear here after collection and source checks. Subscribe to the RSS feed for the first edition.</p></section>'
    body = f'''<main id="main" class="page">
<section class="intro"><div><p class="eyebrow">Security. Releases. The network.</p><h1>Tor news, distilled.</h1><p class="intro-copy">The developments that matter, with the sources to understand them.</p></div><div class="edition-note"><span class="live-dot" aria-hidden="true"></span>{latest_label}</div></section>
<div class="news-layout"><section class="news-column" aria-label="Latest news">
<div class="tools" data-news-tools hidden><div class="filters" role="group" aria-label="Filter news by topic">{filters}</div>
<label class="search"><span class="sr-only">Search news</span><span aria-hidden="true">⌕</span><input id="news-search" type="search" placeholder="Search the feed" autocomplete="off" maxlength="200"></label></div>
<div class="section-heading"><h2>Latest dispatches</h2><span id="result-count" aria-live="polite">{len(public[:page_size])} {'story' if len(public[:page_size]) == 1 else 'stories'}</span></div>
<div id="news-list">{cards}</div><p id="no-results" class="no-results" hidden>No stories match. Try another topic or search.</p>
{f'<p class="archive-note">Showing the latest {page_size} stories. Individual story links remain available.</p>' if len(public) > page_size else ''}
</section><aside class="sidebar" aria-label="About this feed">
<section class="subscribe-box"><span class="sidebar-kicker">Follow the feed</span><h2>Stay in the loop.</h2><p>Important Tor developments, delivered to your feed reader.</p><a class="subscribe-link" href="{_escape(base)}feed.xml">Subscribe via RSS <span aria-hidden="true">↗</span></a><a class="secondary-feed" href="{_escape(base)}feed.json">JSON Feed</a></section>
<section class="about-feed"><h2>Context comes first.</h2><p>Reports, fixes, and releases are grouped into concise stories. Every summary links to its sources.</p><p>Labels distinguish confirmed findings from reports and suspected incidents.</p></section>
{_health_details(source_health)}
<p class="sidebar-footnote">An independent project by <a href="https://1aeo.com/">1AEO</a>.</p>
</aside></div></main>'''
    title = _text(site.get("title", "Onion Flash"), 80)
    description = _text(site.get("description", "Important Tor news, distilled."), 400)
    (output_dir / "index.html").write_text(_shell(site, base, f"{title} — Tor news, distilled", description, body, base), encoding="utf-8")
    for story in public:
        target = output_dir / "news" / story["id"]
        target.mkdir(parents=True)
        story_body = f'''<main id="main" class="page article-page"><a class="back-link" href="{_escape(base)}">← All dispatches</a>
<article class="full-story">{_badges(story)}<h1>{_escape(story['title'])}</h1>
<div class="article-dates">Published {_time(story['published_at'], full=True)}{f' <span>·</span> Updated {_time(story["updated_at"], full=True)}' if story['updated_at'] != story['published_at'] else ''}</div>
<p class="article-summary">{_escape(story['summary'])}</p>
{f'<section class="article-context"><h2>Why it matters</h2><p>{_escape(story["why_it_matters"])}</p></section>' if story['why_it_matters'] else ''}
<p class="event-state"><span>Event status</span> {_label(story['state'])}</p>
<section class="article-sources"><h2>Read the sources</h2>{_source_links(story, expanded=True)}</section>
<p class="article-note">This is an AI-assisted summary of the linked public sources. Consult the original reports for details and operator guidance.</p></article></main>'''
        (target / "index.html").write_text(_shell(site, base, f"{story['title']} — {title}", story["summary"][:300], story_body, _permalink(base, story)), encoding="utf-8")
    (output_dir / "feed.xml").write_bytes(_rss(site, base, public[:feed_size], "feed.xml"))
    (output_dir / "tags").mkdir()
    for category in CATEGORIES:
        path = f"tags/{category}.xml"
        (output_dir / path).write_bytes(_rss(site, base, [s for s in public if category in s["tags"]][:feed_size], path, category))
    feed = {"version": "https://jsonfeed.org/version/1.1", "title": title, "home_page_url": base, "feed_url": base + "feed.json", "description": description, "language": "en", "items": []}
    for story in public[:feed_size]:
        content = story["summary"]
        if story["why_it_matters"]:
            content += "\n\nWhy it matters: " + story["why_it_matters"]
        content += "\n\nSources:\n" + "\n".join(source["url"] for source in story["sources"])
        feed["items"].append({"id": _permalink(base, story), "url": _permalink(base, story), "title": story["title"], "content_text": content, "date_published": story["published_at"], "date_modified": story["updated_at"], "tags": story["tags"]})
    (output_dir / "feed.json").write_text(json.dumps(feed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    prefix = urlsplit(base).path.rstrip("/")
    headers = f'''{prefix}/*
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
  Permissions-Policy: camera=(), microphone=(), geolocation=()
  Cache-Control: public, max-age=60, must-revalidate
'''
    (output_dir / "_headers").write_text(headers, encoding="utf-8")
