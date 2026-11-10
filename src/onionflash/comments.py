"""Optional, anonymous, fail-closed enrichment of configured public GitLab issues.

Only sanitized, explicitly public non-system notes cross the response boundary.
The bounded cache holds scheduling metadata, never raw GraphQL responses. Existing
published issues rotate through a bounded query, independently of REST lookback.
"""

from __future__ import annotations

import json
import re
import time
from itertools import zip_longest
from urllib.parse import unquote, urlsplit, urlunsplit

from .transport import FetchError, HttpClient
from .util import after, backoff_seconds, canonical_url, digest, now_iso, plain_text, timestamp


QUERY = """query PublicIssueNotes($project: ID!, $iid: String!, $size: Int!, $before: String) {
  project(fullPath: $project) {
    id fullPath visibility webUrl
    issue(iid: $iid) {
      iid confidential webUrl
      notes(last: $size, before: $before) {
        nodes { id body createdAt updatedAt internal system url author { username } }
        pageInfo { startCursor hasPreviousPage }
      }
    }
  }
}"""


class CommentError(Exception):
    """Messages are fixed strings; never include upstream bodies or error text."""


def parse_note_id(value):
    """Return the shared numeric identity for explicitly supported public note GIDs."""
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"gid://gitlab/(?:Note|DiscussionNote)/([0-9]+)", value)
    return match[1] if match else None


def _initialize(store):
    store.db.executescript("""
        CREATE TABLE IF NOT EXISTS comment_cache (
          item_id TEXT PRIMARY KEY, source_key TEXT NOT NULL, checked_at TEXT NOT NULL,
          next_fetch_at TEXT NOT NULL, failures INTEGER NOT NULL DEFAULT 0, error TEXT
        );
        CREATE INDEX IF NOT EXISTS comment_cache_checked ON comment_cache(checked_at);
        CREATE TABLE IF NOT EXISTS comment_sources (
          source_id TEXT PRIMARY KEY, source_key TEXT NOT NULL, failures INTEGER NOT NULL DEFAULT 0,
          next_fetch_at TEXT, error TEXT, rotation_cursor TEXT NOT NULL DEFAULT '',
          recent_first INTEGER NOT NULL DEFAULT 0
        );
        DROP INDEX IF EXISTS comment_candidates;
        CREATE INDEX IF NOT EXISTS comment_history_rotation ON items(source_id,id) WHERE story_id IS NOT NULL;
        CREATE INDEX IF NOT EXISTS comment_recent_pending ON items(source_id,priority_score DESC,last_seen DESC,id) WHERE status='pending';
    """)
    if "recent_first" not in {row[1] for row in store.db.execute("PRAGMA table_info(comment_sources)")}:
        store.db.execute("ALTER TABLE comment_sources ADD COLUMN recent_first INTEGER NOT NULL DEFAULT 0")
        store.db.commit()


def _identity(source):
    project = source.get("gitlab_project", "")
    if not isinstance(project, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+", project):
        raise CommentError("Comments require a configured project identity")
    rest = urlsplit(canonical_url(source["url"]))
    match = re.fullmatch(r"/api/v4/projects/([^/]+)/issues", rest.path)
    if not match or (not match[1].isdigit() and unquote(match[1]) != project):
        raise CommentError("Configured REST project identity does not match")
    origin = urlunsplit((rest.scheme, rest.netloc, "", "", ""))
    endpoint = canonical_url(source.get("comments_graphql_url") or origin + "/api/graphql")
    parsed = urlsplit(endpoint)
    if parsed.query or parsed.fragment or (parsed.scheme, parsed.netloc) != (rest.scheme, rest.netloc):
        raise CommentError("GraphQL endpoint must be a clean same-origin URL")
    return project, origin, endpoint, match[1]


def _issue_identity(source, item):
    project, origin, endpoint, project_id = _identity(source)
    parsed = urlsplit(canonical_url(item["url"]))
    expected = urlsplit(origin)
    match = re.fullmatch(re.escape("/" + project) + r"/-/(?:issues|work_items)/(\d+)", parsed.path)
    if not match or parsed.query or parsed.fragment or parsed.netloc != expected.netloc:
        raise CommentError("Issue URL is outside its configured project")
    return project, origin, endpoint, project_id, match[1]


def _source_key(source):
    return digest([source["id"], *_identity(source)])


def fetch_comments(client, source, item, settings, *, observed=None):
    """Read a bounded newest-note window; discard partial responses on failure."""
    project, origin, endpoint, project_id, iid = _issue_identity(source, item)
    observed = timestamp(observed or now_iso())
    before, seen, notes = None, set(), {}
    truncated = False
    for _ in range(settings["max_pages"]):
        response = client.request("POST", endpoint, headers={"Accept": "application/json"},
                                  json_body={"query": QUERY, "variables": {
                                      "project": project, "iid": iid, "size": settings["page_size"], "before": before}})
        if canonical_url(response.url) != endpoint:
            raise CommentError("GraphQL endpoint redirected")
        data = response.json()
        if not isinstance(data, dict) or data.get("errors") or not isinstance(data.get("data"), dict):
            raise CommentError("GraphQL response unavailable")
        obj = data["data"].get("project")
        if (not isinstance(obj, dict) or obj.get("visibility") != "public"
                or obj.get("fullPath") != project or obj.get("webUrl") != origin + "/" + project
                or (project_id.isdigit() and obj.get("id") != "gid://gitlab/Project/" + project_id)):
            raise CommentError("Public project identity not verified")
        issue = obj.get("issue")
        if (not isinstance(issue, dict) or issue.get("confidential") is not False
                or issue.get("iid") != iid or not isinstance(issue.get("webUrl"), str)
                or canonical_url(issue["webUrl"]) != canonical_url(item["url"])):
            raise CommentError("Public issue identity not verified")
        connection = issue.get("notes")
        if not isinstance(connection, dict) or not isinstance(connection.get("nodes"), list):
            raise CommentError("Public notes unavailable")
        nodes, page = connection["nodes"], connection.get("pageInfo")
        if (len(nodes) > settings["page_size"] or not isinstance(page, dict)
                or type(page.get("hasPreviousPage")) is not bool):
            raise CommentError("Invalid notes pagination")
        for note in nodes:
            # Do not inspect, sanitize, log or persist a body before these flags.
            if not isinstance(note, dict):
                raise CommentError("Public note visibility is unknown")
            if note.get("internal") is True or note.get("system") is True:
                continue
            if note.get("internal") is not False or note.get("system") is not False:
                raise CommentError("Public note visibility is unknown")
            ident = note.get("id")
            note_id = parse_note_id(ident)
            if note_id is None:
                raise CommentError("Invalid public note identity")
            url = canonical_url(note.get("url", ""))
            if url != canonical_url(item["url"]) + "#note_" + note_id:
                raise CommentError("Public note URL does not match issue")
            author = note.get("author")
            if not isinstance(author, dict) or not isinstance(author.get("username"), str):
                raise CommentError("Public note attribution unavailable")
            if not isinstance(note.get("body"), str):
                raise CommentError("Invalid public note body")
            author = plain_text(author["username"], 100, html=False)
            created, updated = timestamp(note.get("createdAt")), timestamp(note.get("updatedAt"))
            if not author or updated < created:
                raise CommentError("Invalid public note attribution")
            if created > observed or updated > observed:
                # A malformed/future timestamp must not date or promote a story.
                continue
            body = plain_text(note["body"], settings["comment_chars"], html=False)
            previous = notes.get(note_id)
            if previous:
                if created != previous["created_at"] or (updated == previous["updated_at"] and body != previous["body"]):
                    raise CommentError("Conflicting public note versions")
                if updated < previous["updated_at"]:
                    continue
            notes[note_id] = {"id": ident, "url": url, "title": "Public comment by @" + author,
                            "author": author, "created_at": created, "updated_at": updated, "body": body}
        truncated = page["hasPreviousPage"]
        if not truncated:
            break
        cursor = page.get("startCursor")
        if not isinstance(cursor, str) or not cursor or len(cursor) > 8192 or cursor in seen:
            raise CommentError("Invalid notes pagination cursor")
        seen.add(cursor)
        before = cursor
    ordered = sorted(notes.values(), key=lambda n: (n["created_at"], n["id"]), reverse=True)
    selected, remaining = [], settings["total_chars"]
    for note in ordered:
        if remaining <= 0 or len(selected) >= settings["max_comments"]:
            truncated = True
            break
        if len(note["body"]) > remaining:
            note = {**note, "body": note["body"][:remaining]}
            truncated = True
        remaining -= len(note["body"])
        selected.append(note)
    return selected, truncated


def analysis_context(item, limit):
    """Reserve context for attributed note bodies instead of truncating them off.

    Return (actual evidence text, notes with exactly the supplied body prefixes).
    URL metadata stays complete; a long display URL cannot consume body space.
    """
    source = item.get("source_content", item.get("content", ""))
    notes = [n for n in item.get("public_comments", []) if n.get("body")]
    if not notes or limit < 500:
        return source[:limit], []
    heading = "\n\nPublic issue comments (untrusted attributed reports, not independent verification):\n"
    budget = int(limit * 0.6)
    selected = notes[:max(1, (budget - len(heading)) // 400)]
    share = max(1, (budget - len(heading)) // len(selected))
    blocks, supplied = [], []
    for note in selected:
        header = (f"@{note['author'][:60]} — {note['created_at']} (edited {note['updated_at']})\n"
                  f"{note['url'][:240]}\n")
        header = header[:max(1, share // 2)]
        body = note["body"][:max(1, share - len(header) - 2)]
        if not body:
            continue
        blocks.append(header + body)
        supplied.append({**note, "body": body})
    suffix = heading + "\n\n".join(blocks)
    return source[:max(0, limit - len(suffix))] + suffix, supplied


def analysis_content(item, limit):
    """Return the exact text shared by model input and evidence validation."""
    return analysis_context(item, limit)[0]


def _compose(item, notes, checked, truncated=False, *, source_key=None):
    result = dict(item)
    source_content = item.get("source_content", item.get("content"))
    if not isinstance(source_content, str):
        raise CommentError("Saved issue description is unavailable")
    result["source_content"] = source_content
    result["public_comments"] = notes
    result["comments_checked_at"] = checked
    result["comments_truncated"] = truncated
    # This marker is written only after a successful verified fetch, or copied
    # from an already verified stored snapshot. Scheduling failures cannot mint it.
    if source_key is not None:
        result["comments_source_key"] = source_key
    else:
        result.pop("comments_source_key", None)
    result["content"] = analysis_content(result, 60000)
    return result


def merge_cached_comments(store, item, source=None):
    """Keep a verified bounded snapshot while REST refreshes the description."""
    if item.get("kind") != "gitlab_issue" or source is None or not source.get("gitlab_project"):
        return item
    try:
        key = _source_key(source)
        _issue_identity(source, item)
    except (CommentError, ValueError):
        return item
    row = store.db.execute("SELECT payload FROM items WHERE url=?", (item["url"],)).fetchone()
    if row is None:
        return item
    try:
        old = json.loads(row["payload"])
        if (not isinstance(old, dict) or old.get("comments_source_key") != key
                or not isinstance(old.get("public_comments"), list)):
            return item
        checked = timestamp(old.get("comments_checked_at"))
        # Never make an older REST response appear current by combining it with
        # newer notes. A retained snapshot is historical, not freshly verified.
        if item["updated_at"] < old["updated_at"]:
            return _compose(old, old["public_comments"], checked,
                            old.get("comments_truncated", False), source_key=key)
        return _compose(item, old["public_comments"], checked,
                        old.get("comments_truncated", False), source_key=key)
    except (CommentError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return item


def _candidates(store, source, settings, observed, key):
    """Half recent candidates, half rotating published history, without a network scan."""
    limit = settings["max_issues_per_source"]
    state = store.db.execute("SELECT * FROM comment_sources WHERE source_id=?", (source["id"],)).fetchone()
    if state and state["source_key"] == key and state["next_fetch_at"] and state["next_fetch_at"] > observed:
        return []
    with store.db:
        if not state or state["source_key"] != key:
            store.db.execute("INSERT OR REPLACE INTO comment_sources(source_id,source_key) VALUES(?,?)", (source["id"], key))
    cursor = state["rotation_cursor"] if state and state["source_key"] == key else ""
    recent_first = bool(state["recent_first"]) if state and state["source_key"] == key else False
    due = "(c.item_id IS NULL OR c.source_key<>? OR c.next_fetch_at<=?)"
    select = "SELECT i.* FROM items i LEFT JOIN comment_cache c ON c.item_id=i.id WHERE i.source_id=? AND " + due
    args = (source["id"], key, observed)
    recent = store.db.execute(select + " AND i.status='pending' AND i.last_seen>=? ORDER BY i.priority_score DESC,i.last_seen DESC,i.id LIMIT ?",
                             (*args, after(-settings["candidate_days"] * 86400, observed), limit)).fetchall()
    published = store.db.execute(select + " AND i.story_id IS NOT NULL AND i.id>? ORDER BY i.id LIMIT ?", (*args, cursor, limit)).fetchall()
    if len(published) < limit:
        published += store.db.execute(select + " AND i.story_id IS NOT NULL AND i.id<=? ORDER BY i.id LIMIT ?", (*args, cursor, limit - len(published))).fetchall()
    groups = ([(row, False) for row in recent], [(row, True) for row in published])
    if not recent_first:
        groups = groups[::-1]
    selected = {}
    for pair in zip_longest(*groups):
        for entry in pair:
            if entry is not None:
                row, historical = entry
                selected.setdefault(row["id"], {**dict(row), "_comments_history": historical})
                if len(selected) >= limit:
                    return list(selected.values())
    return list(selected.values())


def enrich_comments(config, store, observed, *, deadline=None, client=None):
    """Optional post-collection phase. Failures never block REST/feed processing."""
    settings = config.get("comments", {})
    report = {"enabled": bool(settings.get("enabled")), "checked": 0, "changed": 0,
              "failed": 0, "skipped": 0, "budget_reached": False}
    if not report["enabled"]:
        return report
    _initialize(store)
    deadline = min(deadline or float("inf"), time.monotonic() + settings["run_budget_seconds"])
    sources = [s for s in config["sources"] if s.get("enabled", True) and s.get("kind") == "gitlab_issue"
               and s.get("gitlab_project") and s.get("comments_enabled", True)]
    # Rotate source order as well as issue history: a busy first project cannot
    # monopolize the global request budget indefinitely.
    last_source = store.get_meta("comments_source_cursor") or ""
    sources.sort(key=lambda s: (s["id"] <= last_source, s["id"]))
    with store.db:
        active = [s["id"] for s in sources]
        if active:
            placeholders = ",".join("?" for _ in active)
            store.db.execute(f"DELETE FROM comment_sources WHERE source_id NOT IN ({placeholders})", active)
        else:
            store.db.execute("DELETE FROM comment_sources")
    own_client = client is None
    # A fresh client has no cookies, authorization, proxy or application session.
    # The verified GraphQL URL is canonical. Refuse every redirect before a
    # redirected request could leave that endpoint, using the shared limit.
    client = client or HttpClient({**config["http"], "max_redirects": 0})
    old_deadline = getattr(client, "deadline", None)
    client.deadline = min(old_deadline or float("inf"), deadline)
    try:
        for source in sources:
            try:
                key = _source_key(source)
                rows = _candidates(store, source, settings, observed, key)
            except (CommentError, ValueError):
                report["failed"] += 1
                continue
            for row in rows:
                if report["checked"] + report["skipped"] >= settings["max_issues_per_run"] or time.monotonic() >= deadline:
                    report["budget_reached"] = True
                    return report
                store.set_meta(comments_source_cursor=source["id"])
                with store.db:
                    if row["_comments_history"]:
                        store.db.execute("UPDATE comment_sources SET rotation_cursor=?,recent_first=1 WHERE source_id=?",
                                         (row["id"], source["id"]))
                    else:
                        store.db.execute("UPDATE comment_sources SET recent_first=0 WHERE source_id=?", (source["id"],))
                try:
                    if not isinstance(row["payload"], str) or len(row["payload"]) > 1048576:
                        raise ValueError
                    item = json.loads(row["payload"])
                    if (not isinstance(item, dict) or item.get("kind") != "gitlab_issue"
                            or not isinstance(item.get("title"), str)
                            or not isinstance(item.get("source_content", item.get("content")), str)):
                        raise ValueError
                    json.dumps(item, ensure_ascii=False, allow_nan=False).encode("utf-8")
                    _issue_identity(source, item)
                except (CommentError, ValueError, TypeError, KeyError, RecursionError):
                    # A malformed/cold local item is not a provider outage and
                    # must not block other candidates or invent a description.
                    report["skipped"] += 1
                    with store.db:
                        store.db.execute("INSERT OR REPLACE INTO comment_cache VALUES(?,?,?,?,0,?)",
                                         (row["id"], key, observed, after(settings["interval_seconds"], observed),
                                          "Saved issue description unavailable"))
                    continue
                report["checked"] += 1
                try:
                    notes, truncated = fetch_comments(client, source, item, settings, observed=observed)
                    enriched = _compose(item, notes, observed, truncated, source_key=key)
                    changed = bool(store.ingest(enriched, observed))
                    report["changed"] += changed
                    with store.db:
                        if not changed:
                            # Refresh verified provenance without requeuing an
                            # unchanged or operator-dismissed source revision.
                            store.db.execute("UPDATE items SET payload=? WHERE id=? AND payload=? AND content_hash=?",
                                             (json.dumps(enriched, ensure_ascii=False), row["id"], row["payload"], row["content_hash"]))
                        store.db.execute("INSERT OR REPLACE INTO comment_cache VALUES(?,?,?,?,0,NULL)",
                                         (row["id"], key, observed, after(settings["interval_seconds"], observed)))
                        store.db.execute("UPDATE comment_sources SET failures=0,next_fetch_at=NULL,error=NULL WHERE source_id=?", (source["id"],))
                except (CommentError, FetchError, ValueError, TypeError, KeyError):
                    # No response or an unverifiable response is not evidence
                    # that old public notes disappeared. Keep the prior verified
                    # snapshot and its original verification time unchanged.
                    report["failed"] += 1
                    state = store.db.execute("SELECT failures FROM comment_sources WHERE source_id=?", (source["id"],)).fetchone()
                    failures = (state[0] if state else 0) + 1
                    due = after(backoff_seconds(failures, settings["failure_backoff_base_seconds"], settings["failure_backoff_cap_seconds"]), observed)
                    cached = store.db.execute("SELECT failures FROM comment_cache WHERE item_id=? AND source_key=?", (row["id"], key)).fetchone()
                    item_failures = (cached[0] if cached else 0) + 1
                    item_due = after(backoff_seconds(item_failures, settings["failure_backoff_base_seconds"], settings["failure_backoff_cap_seconds"]), observed)
                    with store.db:
                        store.db.execute("INSERT OR REPLACE INTO comment_cache VALUES(?,?,?,?,?,?)", (row["id"], key, observed, item_due, item_failures, "Public comments unavailable"))
                        store.db.execute("UPDATE comment_sources SET failures=?,next_fetch_at=?,error=? WHERE source_id=?", (failures, due, "Public comments unavailable", source["id"]))
                    break  # Do not multiply endpoint failures by issue count.
    finally:
        client.deadline = old_deadline
        if own_client:
            client.close()
        with store.db:
            store.db.execute("DELETE FROM comment_cache WHERE checked_at<?", (after(-settings["cache_days"] * 86400, observed),))
            store.db.execute("DELETE FROM comment_cache WHERE item_id IN (SELECT item_id FROM comment_cache ORDER BY checked_at DESC,item_id LIMIT -1 OFFSET ?)", (settings["max_cache_entries"],))
    return report


def status(store):
    """Read scheduling status without opening connections or creating tables."""
    tables = {row[0] for row in store.db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('comment_sources','comment_cache')")}
    if tables != {"comment_sources", "comment_cache"}:
        return {"watched_issues": 0, "sources": []}
    rows = store.db.execute("""SELECT s.source_id AS id,s.failures,s.error,s.next_fetch_at,
        COUNT(c.item_id) AS cached_issues,MAX(c.checked_at) AS last_checked_at
        FROM comment_sources s LEFT JOIN comment_cache c ON c.source_key=s.source_key
        GROUP BY s.source_id ORDER BY s.source_id""").fetchall()
    return {"watched_issues": store.db.execute("SELECT COUNT(*) FROM comment_cache").fetchone()[0],
            "sources": [dict(row) for row in rows]}
