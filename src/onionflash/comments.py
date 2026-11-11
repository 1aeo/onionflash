"""Optional, anonymous, fail-closed enrichment of configured public GitLab issues.

Only sanitized, explicitly public non-system notes cross the response boundary.
The bounded cache holds scheduling metadata, never raw GraphQL responses. Existing
published issues rotate through a bounded query, independently of REST lookback.
REST activity on an issue of any status requests a check.
"""

from __future__ import annotations

import json
import re
import time
from itertools import zip_longest
from urllib.parse import unquote, urlsplit, urlunsplit

from .transport import FetchError, HttpClient
from .util import after, backoff_seconds, canonical_url, digest, now_iso, plain_text, timestamp


QUERY = """query PublicIssueNotes($project: ID!, $iid: String!, $size: Int!) {
  project(fullPath: $project) {
    id fullPath visibility webUrl
    issue(iid: $iid) {
      iid confidential webUrl
      notes(last: $size) { nodes { id body createdAt internal system url author { username } } }
    }
  }
}"""
NOTE_WINDOW = 40  # the newest notes read per issue in one request, system notes included
INPUT_CHARS = 14000  # the writer's fixed source window: description plus note bodies
MAX_COMMENTS, COMMENT_CHARS, TOTAL_CHARS = 12, 2000, 8000  # notes kept per issue, text per note and per issue
MAX_ISSUES_PER_RUN, MAX_ISSUES_PER_SOURCE = 12, 4  # checks per run and per project
CANDIDATE_DAYS = 14  # a pending issue seen this recently is a new candidate
RUN_BUDGET_SECONDS = 30  # the phase's share of the collection window
INTERVAL_SECONDS = 1800  # refresh after a verified check
CACHE_DAYS = 30  # scheduling metadata expires, which also ends retries of an issue that never verifies
BACKOFF_BASE_SECONDS, BACKOFF_CAP_SECONDS = 300, 21600  # failure backoff


class CommentError(Exception):
    """Messages are fixed strings; never include upstream bodies or error text."""


class EndpointError(CommentError):
    """The answer is unusable for every issue of the project, not just this one."""


def _identity(source):
    project = source.get("gitlab_project", "")
    if not isinstance(project, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+", project):
        raise CommentError("Comments require a configured project identity")
    rest = urlsplit(canonical_url(source["url"]))
    match = re.fullmatch(r"/api/v4/projects/([^/]+)/issues", rest.path)
    if not match or (not match[1].isdigit() and unquote(match[1]) != project):
        raise CommentError("Configured REST project identity does not match")
    origin = urlunsplit((rest.scheme, rest.netloc, "", "", ""))
    # GitLab serves the REST path above, and so GraphQL, at the origin's root.
    return project, origin, origin + "/api/graphql", match[1]


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


def fetch_comments(client, source, item):
    """Read the newest-note window in one request; any unusable part rejects the answer."""
    project, origin, endpoint, project_id, iid = _issue_identity(source, item)
    response = client.request("POST", endpoint, headers={"Accept": "application/json"},
                              json_body={"query": QUERY, "variables": {"project": project, "iid": iid, "size": NOTE_WINDOW}})
    received = now_iso()
    data = response.json()
    if not isinstance(data, dict) or data.get("errors") or not isinstance(data.get("data"), dict):
        raise EndpointError("GraphQL response unavailable")
    obj = data["data"].get("project")
    if (not isinstance(obj, dict) or obj.get("visibility") != "public"
            or obj.get("fullPath") != project or obj.get("webUrl") != origin + "/" + project
            or (project_id.isdigit() and obj.get("id") != "gid://gitlab/Project/" + project_id)):
        raise EndpointError("Public project identity not verified")
    issue = obj.get("issue")
    if (not isinstance(issue, dict) or issue.get("confidential") is not False
            or issue.get("iid") != iid or not isinstance(issue.get("webUrl"), str)
            or canonical_url(issue["webUrl"]) != canonical_url(item["url"])):
        raise CommentError("Public issue identity not verified")
    connection = issue.get("notes")
    if not isinstance(connection, dict) or not isinstance(connection.get("nodes"), list):
        raise CommentError("Public notes unavailable")
    notes = {}
    for note in connection["nodes"]:
        # Do not inspect, sanitize, log or persist a body before these flags.
        if not isinstance(note, dict):
            raise CommentError("Public note visibility is unknown")
        if note.get("internal") is True or note.get("system") is True:
            continue
        if note.get("internal") is not False or note.get("system") is not False:
            raise CommentError("Public note visibility is unknown")
        ident = note.get("id")
        # Note and DiscussionNote GIDs of one note share its numeric identity.
        match = re.fullmatch(r"gid://gitlab/(?:Note|DiscussionNote)/([0-9]+)", ident) if isinstance(ident, str) else None
        if match is None:
            raise CommentError("Invalid public note identity")
        url = canonical_url(note.get("url", ""))
        if url != canonical_url(item["url"]) + "#note_" + match[1]:
            raise CommentError("Public note URL does not match issue")
        author = note.get("author")
        if not isinstance(author, dict) or not isinstance(author.get("username"), str):
            raise CommentError("Public note attribution unavailable")
        if not isinstance(note.get("body"), str):
            raise CommentError("Invalid public note body")
        author, created = plain_text(author["username"], 100, html=False), timestamp(note.get("createdAt"))
        if not author:
            raise CommentError("Invalid public note attribution")
        body = plain_text(note["body"], COMMENT_CHARS, html=False)
        # Skip an empty note, and one dated after this response: it must not date or promote a story.
        if body and created <= received:
            notes[match[1]] = {"id": ident, "url": url, "title": "Public comment by @" + author,
                               "author": author, "created_at": created, "body": body}
    selected, remaining = [], TOTAL_CHARS
    for note in sorted(notes.values(), key=lambda n: (n["created_at"], n["id"]), reverse=True):
        if remaining <= 0 or len(selected) >= MAX_COMMENTS:
            break
        note["body"] = note["body"][:remaining]
        remaining -= len(note["body"])
        selected.append(note)
    return selected


def analysis_context(item):
    """Return the writer's description window and the notes it sees verbatim, newest first.

    Notes are structured entries, so a body cannot pose as another author's note.
    """
    notes = [{key: note[key] for key in ("author", "created_at", "body")} for note in item.get("public_comments") or []]
    room = max(0, INPUT_CHARS - sum(len(note["body"]) for note in notes))
    # Payloads stored before descriptions moved back to content keep it in source_content.
    return item.get("source_content", item.get("content", ""))[:room], notes


def _compose(item, notes, checked, *, source_key):
    result = dict(item)
    content = result.pop("source_content", result.get("content"))
    if not isinstance(content, str):
        raise CommentError("Saved issue description is unavailable")
    # Callers pass a key only for a verified fetch or an already verified stored snapshot.
    result.update(content=content, public_comments=notes, comments_checked_at=checked, comments_source_key=source_key)
    return result


def merge_cached_comments(store, item, source, observed=None):
    """Keep the verified snapshot on a REST refresh; Store.ingest rejects stale revisions.

    Collection calls this only while comments are enabled. GitLab updates an issue
    when a note is added, but the kept snapshot leaves the content hash unchanged.
    So REST activity observed after the last check, or an issue without a snapshot,
    requests a check whatever the issue's status.
    """
    if item.get("kind") != "gitlab_issue" or not source.get("gitlab_project"):
        return item
    row = store.db.execute("SELECT id,payload FROM items WHERE url=?", (item["url"],)).fetchone()
    if row is None:
        return item
    old, key = json.loads(row["payload"]), _source_key(source)
    current = old.get("comments_source_key") == key
    if observed and (not current or item["updated_at"] > old["comments_checked_at"]):
        with store.db:  # next_fetch_at=checked_at marks a request; an unserved request keeps its place, a failing issue its backoff.
            store.db.execute("INSERT OR REPLACE INTO comment_cache SELECT ?,?,?,?,0,NULL WHERE NOT EXISTS(SELECT 1 FROM comment_cache"
                             " WHERE item_id=? AND source_key=? AND (failures>0 OR next_fetch_at<=checked_at))",
                             (row["id"], key, observed, observed, row["id"], key))
    if not current:
        return item
    return _compose(item, old["public_comments"], old["comments_checked_at"], source_key=key)


def _candidates(store, source, observed, key):
    """Requested checks, then half recent candidates, half rotating published history.

    No network scan. A locked story's issues wait for unlock.
    """
    limit = MAX_ISSUES_PER_SOURCE
    state = store.db.execute("SELECT * FROM comment_sources WHERE source_id=?", (source["id"],)).fetchone()
    if state and state["source_key"] == key and state["next_fetch_at"] and state["next_fetch_at"] > observed:
        return []
    with store.db:
        if not state or state["source_key"] != key:
            store.db.execute("INSERT OR REPLACE INTO comment_sources(source_id,source_key) VALUES(?,?)", (source["id"], key))
    cursor = state["rotation_cursor"] if state and state["source_key"] == key else ""
    recent_first = bool(state["recent_first"]) if state and state["source_key"] == key else False
    due = "(c.item_id IS NULL OR c.source_key<>? OR c.next_fetch_at<=?)"
    unlocked = " AND NOT EXISTS(SELECT 1 FROM editorial_controls e WHERE e.story_id=i.story_id AND e.locked=1)"
    select = "SELECT i.* FROM items i LEFT JOIN comment_cache c ON c.item_id=i.id WHERE i.source_id=? AND " + due + unlocked
    args = (source["id"], key, observed)
    # Whatever the status: requests from merge_cached_comments (next_fetch_at<=checked_at), and retries
    # of failed checks of issues without a story, which the rotation below retries only while recent
    # and pending. CROSS JOIN keeps the bounded cache as the outer loop.
    requested = store.db.execute(
        "SELECT i.* FROM comment_cache c CROSS JOIN items i ON i.id=c.item_id WHERE c.next_fetch_at<=? AND i.source_id=?"
        " AND (c.next_fetch_at<=c.checked_at OR (c.failures>0 AND i.story_id IS NULL))" + unlocked +
        " ORDER BY i.status<>'pending',c.next_fetch_at,i.id LIMIT ?", (observed, source["id"], limit)).fetchall()
    recent = store.db.execute(select + " AND i.status='pending' AND i.last_seen>=? ORDER BY i.priority_score DESC,i.last_seen DESC,i.id LIMIT ?",
                             (*args, after(-CANDIDATE_DAYS * 86400, observed), limit)).fetchall()
    published = store.db.execute(select + " AND i.story_id IS NOT NULL AND i.id>? ORDER BY i.id LIMIT ?", (*args, cursor, limit)).fetchall()
    if len(published) < limit:
        published += store.db.execute(select + " AND i.story_id IS NOT NULL AND i.id<=? ORDER BY i.id LIMIT ?", (*args, cursor, limit - len(published))).fetchall()
    groups = ([(row, False) for row in recent], [(row, True) for row in published])
    if not recent_first:
        groups = groups[::-1]
    selected = {row["id"]: {**dict(row), "_comments_history": None} for row in requested}
    for pair in zip_longest(*groups):
        for row, historical in filter(None, pair):
            selected.setdefault(row["id"], {**dict(row), "_comments_history": historical})
    return list(selected.values())[:limit]


def enrich_comments(config, store, observed, *, deadline=None):
    """Optional post-collection phase. Failures never block REST/feed processing."""
    report = {"enabled": bool(config.get("comments", {}).get("enabled")), "checked": 0, "changed": 0,
              "failed": 0, "skipped": 0, "budget_reached": False}
    if not report["enabled"]:
        return report
    deadline = min(deadline or float("inf"), time.monotonic() + RUN_BUDGET_SECONDS)
    sources = [s for s in config["sources"] if s.get("enabled", True) and s.get("kind") == "gitlab_issue"
               and s.get("gitlab_project")]
    # Rotate source order as well as issue history: a busy first project cannot
    # monopolize the global request budget indefinitely.
    last_source = store.get_meta("comments_source_cursor") or ""
    sources.sort(key=lambda s: (s["id"] <= last_source, s["id"]))
    with store.db:
        store.db.execute(f"DELETE FROM comment_sources WHERE source_id NOT IN ({','.join('?' * len(sources))})",
                         [s["id"] for s in sources])
    # A fresh client has no cookies, authorization, proxy or application session.
    # It refuses every redirect, so a request cannot leave the verified endpoint.
    client = HttpClient({**config["http"], "max_redirects": 0})
    client.deadline = deadline
    try:
        for source in sources:
            try:
                key = _source_key(source)
                rows = _candidates(store, source, observed, key)
            except (CommentError, ValueError):
                report["failed"] += 1
                continue
            for row in rows:
                if report["checked"] + report["skipped"] >= MAX_ISSUES_PER_RUN or time.monotonic() >= deadline:
                    report["budget_reached"] = True
                    return report
                store.set_meta(comments_source_cursor=source["id"])
                with store.db:
                    if row["_comments_history"]:
                        store.db.execute("UPDATE comment_sources SET rotation_cursor=?,recent_first=1 WHERE source_id=?",
                                         (row["id"], source["id"]))
                    elif row["_comments_history"] is not None:  # a requested check takes no rotation turn
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
                                         (row["id"], key, observed, after(INTERVAL_SECONDS, observed),
                                          "Saved issue description unavailable"))
                    continue
                report["checked"] += 1
                try:
                    enriched = _compose(item, fetch_comments(client, source, item), observed, source_key=key)
                    changed = bool(store.ingest(enriched, observed))
                    report["changed"] += changed
                    with store.db:
                        if not changed:
                            # Refresh verified provenance without requeuing an
                            # unchanged or operator-dismissed source revision.
                            store.db.execute("UPDATE items SET payload=? WHERE id=? AND payload=? AND content_hash=?",
                                             (json.dumps(enriched, ensure_ascii=False), row["id"], row["payload"], row["content_hash"]))
                        store.db.execute("INSERT OR REPLACE INTO comment_cache VALUES(?,?,?,?,0,NULL)",
                                         (row["id"], key, observed, after(INTERVAL_SECONDS, observed)))
                        store.db.execute("UPDATE comment_sources SET failures=0,next_fetch_at=NULL,error=NULL WHERE source_id=?", (source["id"],))
                except (CommentError, FetchError, ValueError, TypeError, KeyError) as exc:
                    # No response or an unverifiable response is not evidence
                    # that old public notes disappeared. Keep the prior verified
                    # snapshot and its original verification time unchanged.
                    report["failed"] += 1
                    state = store.db.execute("SELECT failures FROM comment_sources WHERE source_id=?", (source["id"],)).fetchone()
                    failures = (state[0] if state else 0) + 1
                    due = after(backoff_seconds(failures, BACKOFF_BASE_SECONDS, BACKOFF_CAP_SECONDS), observed)
                    # Keeping checked_at lets CACHE_DAYS end retries of an issue that never verifies.
                    cached = store.db.execute("SELECT failures,checked_at FROM comment_cache WHERE item_id=? AND source_key=?",
                                              (row["id"], key)).fetchone() or (0, observed)
                    item_failures = cached[0] + 1
                    item_due = after(backoff_seconds(item_failures, BACKOFF_BASE_SECONDS, BACKOFF_CAP_SECONDS), observed)
                    with store.db:
                        store.db.execute("INSERT OR REPLACE INTO comment_cache VALUES(?,?,?,?,?,?)", (row["id"], key, cached[1], item_due, item_failures, "Public comments unavailable"))
                        if not isinstance(exc, (FetchError, EndpointError)):
                            continue  # The verified project answered; only this issue backs off.
                        store.db.execute("UPDATE comment_sources SET failures=?,next_fetch_at=?,error=? WHERE source_id=?", (failures, due, "Public comments unavailable", source["id"]))
                    break  # Do not multiply endpoint failures by issue count.
    finally:
        client.close()
        with store.db:
            store.db.execute("DELETE FROM comment_cache WHERE checked_at<?", (after(-CACHE_DAYS * 86400, observed),))
    return report


def status(store):
    """Read scheduling status without opening connections."""
    # A requested check (next_fetch_at<=checked_at) has not run yet.
    rows = store.db.execute("""SELECT s.source_id AS id,s.failures,s.error,s.next_fetch_at,
        COUNT(c.item_id) AS cached_issues,MAX(CASE WHEN c.next_fetch_at>c.checked_at THEN c.checked_at END) AS last_checked_at
        FROM comment_sources s LEFT JOIN comment_cache c ON c.source_key=s.source_key
        GROUP BY s.source_id ORDER BY s.source_id""").fetchall()
    return {"watched_issues": store.db.execute("SELECT COUNT(*) FROM comment_cache").fetchone()[0],
            "sources": [dict(row) for row in rows]}
