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

from .transport import DeadlineReached, FetchError, HttpClient
from .util import (
    DIRAUTH_GITLAB_USERS, after, backoff_seconds, canonical_url, digest, is_dirauth_item, now_iso,
    plain_text, saved_object, timestamp,
)


QUERY = """query PublicIssueNotes($project: ID!, $iid: String!, $size: Int!) {
  project(fullPath: $project) {
    id fullPath visibility webUrl
    issue(iid: $iid) {
      iid confidential webUrl
      notes(last: $size) { nodes { id body createdAt lastEditedAt internal system url author { username } } }
    }
  }
}"""
NOTE_WINDOW = 40  # the newest notes read per issue in one request, system notes included
INPUT_CHARS = 14000  # the writer's fixed source window: description plus note bodies
MAX_COMMENTS, COMMENT_CHARS, TOTAL_CHARS = 12, 2000, 8000  # notes kept per issue, text per note and per issue
MAX_DIRAUTH_NOTES = 64  # durable authority-reply markers kept outside the newest-note body window
MAX_ISSUES_PER_RUN, MAX_ISSUES_PER_SOURCE = 12, 4  # checks per run and per project
CANDIDATE_DAYS = 14  # a pending issue seen this recently is a new candidate
RUN_BUDGET_SECONDS = 30  # the phase's share of the collection window
INTERVAL_SECONDS = 1800  # refresh after a verified check
CACHE_DAYS = 30  # scheduling metadata expires, which also ends retries of an issue that never verifies
BACKOFF_BASE_SECONDS, BACKOFF_CAP_SECONDS = 300, 21600  # failure backoff
NOTE_GID_RE = re.compile(r"gid://gitlab/(?:Note|DiscussionNote)/([0-9]+)\Z")


class CommentError(Exception):
    """Messages are fixed strings; never include upstream bodies or error text."""


class EndpointError(CommentError):
    """The answer is unusable for every issue of the project, not just this one."""


class _CommentWindow(list):
    """Verified newest-note slice carrying whether older public notes were excluded."""

    def __init__(self, notes, *, truncated: bool = False):
        super().__init__(notes)
        self.truncated = bool(truncated)


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


def note_key(ident: object) -> str:
    """Normalize GitLab Note and DiscussionNote GIDs to their shared numeric note ID."""
    if not isinstance(ident, str):
        return ""
    match = NOTE_GID_RE.fullmatch(ident)
    return match[1] if match else ident


def prior_notes(raw_comments: object) -> dict[str, dict]:
    """Index saved public comments by normalized note key."""
    items = raw_comments if isinstance(raw_comments, list) else ()
    return {note_key(n["id"]): n for n in items if isinstance(n, dict) and isinstance(n.get("id"), str)}


def is_budget_clipped_prefix(prev_notes: dict[str, dict] | list | None, curr_notes: list[dict]) -> bool:
    """Return True when the oldest retained note is an unedited prefix clipped by TOTAL_CHARS."""
    if not curr_notes or sum(len(n.get("body") or "") for n in curr_notes if isinstance(n, dict)) < TOTAL_CHARS:
        return False
    prior = prev_notes if isinstance(prev_notes, dict) else prior_notes(prev_notes)
    tail = curr_notes[-1]
    old = prior.get(note_key(tail.get("id"))) if isinstance(tail, dict) else None
    old_body, new_body = (old.get("body") if old else None), (tail.get("body") if isinstance(tail, dict) else None)
    return (old is not None and tail.get("edited_at") == old.get("edited_at")
            and isinstance(old_body, str) and isinstance(new_body, str)
            and len(new_body) < len(old_body) and old_body.startswith(new_body))


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
        match = NOTE_GID_RE.fullmatch(ident) if isinstance(ident, str) else None
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
        raw_edited = note.get("lastEditedAt")
        if raw_edited is not None and not isinstance(raw_edited, str):
            raise CommentError("Invalid public note timestamp")
        edited = min(max(timestamp(raw_edited), created), received) if raw_edited is not None else created
        if not author:
            raise CommentError("Invalid public note attribution")
        body = plain_text(note["body"], COMMENT_CHARS, html=False)
        # Skip an empty note, and one dated after this response: it must not date or promote a story.
        if body and created <= received:
            entry = {"id": ident, "url": url, "title": "Public comment by @" + author,
                     "author": author, "created_at": created, "body": body}
            if edited > created:
                entry["edited_at"] = edited
            notes[match[1]] = entry
    prior = prior_notes(item.get("public_comments"))
    selected, remaining = [], TOTAL_CHARS
    for note in sorted(notes.values(), key=lambda n: (n["created_at"], n["id"]), reverse=True):
        if remaining <= 0 or len(selected) >= MAX_COMMENTS:
            break
        note["body"] = note["body"][:remaining]
        remaining -= len(note["body"])
        selected.append(note)
    clipped_tail = is_budget_clipped_prefix(prior, selected)
    for index, note in enumerate(selected):
        old_note = prior.get(note_key(note["id"]))
        if old_note is not None and (old_note.get("body") == note["body"] or (clipped_tail and index == len(selected) - 1)):
            note.pop("edited_at", None)
            if isinstance(old_note.get("edited_at"), str) and old_note["edited_at"] > note["created_at"]:
                note["edited_at"] = old_note["edited_at"]
    window_truncated = len(connection["nodes"]) >= NOTE_WINDOW or len(selected) < len(notes)
    return _CommentWindow(selected, truncated=window_truncated)


def analysis_context(item):
    """Return the writer's description window and the notes it sees verbatim, newest first.

    Notes are structured entries, so a body cannot pose as another author's note.
    """
    notes = [{key: note[key] for key in ("author", "created_at", "body")} for note in item.get("public_comments") or []]
    room = max(0, INPUT_CHARS - sum(len(note["body"]) for note in notes))
    # Payloads stored before descriptions moved back to content keep it in source_content.
    return item.get("source_content", item.get("content", ""))[:room], notes


def _note_newer(a: dict, b: dict) -> bool:
    if a["created_at"] != b["created_at"]:
        return a["created_at"] > b["created_at"]
    akey, bkey = note_key(a["id"]), note_key(b["id"])
    if akey.isdigit() and bkey.isdigit():
        if int(akey) != int(bkey):
            return int(akey) > int(bkey)
    return a["id"] > b["id"]


def _reconcile_dirauth_notes(item: dict, composed_notes: list[dict], dirauth_users, *, truncated: bool) -> list[dict]:
    users = {
        u.strip().lower()
        for u in (DIRAUTH_GITLAB_USERS if dirauth_users is None else dirauth_users)
        if isinstance(u, str) and u.strip()
    }
    if not users:
        return []
    seeded: dict[str, dict] = {}
    for source_list in (item.get("public_comments"), item.get("dirauth_notes")):
        if not isinstance(source_list, list):
            continue
        for raw in source_list:
            if (
                isinstance(raw, dict)
                and all(isinstance(raw.get(f), str) and raw[f] for f in ("id", "author", "created_at"))
                and raw["author"].strip().lower() in users
                and (nkey := note_key(raw["id"]))
            ):
                seeded[nkey] = {"id": raw["id"], "author": raw["author"], "created_at": raw["created_at"]}
    present_keys = {note_key(n["id"]) for n in composed_notes if isinstance(n.get("id"), str)}
    floor = None
    for note in composed_notes:
        if floor is None or _note_newer(floor, note):
            floor = note
    retained: dict[str, dict] = {}
    for nkey, prev in seeded.items():
        if nkey in present_keys or not truncated:
            continue
        if floor is not None and _note_newer(prev, floor):
            continue
        retained[nkey] = prev
    for note in composed_notes:
        if note["author"].strip().lower() in users and (nkey := note_key(note["id"])):
            retained[nkey] = {"id": note["id"], "author": note["author"], "created_at": note["created_at"]}
    ordered = sorted(
        retained.values(),
        key=lambda n: (n["created_at"], int(k) if (k := note_key(n["id"])).isdigit() else -1, n["id"]),
        reverse=True,
    )
    return ordered[:MAX_DIRAUTH_NOTES]


def _compose(item, notes, checked, *, source_key, dirauth_users=None, window_truncated: bool | None = None):
    truncated = bool(getattr(notes, "truncated", False) if window_truncated is None else window_truncated)
    result = dict(item)
    content = result.pop("source_content", result.get("content"))
    if not isinstance(content, str):
        raise CommentError("Saved issue description is unavailable")
    prior = prior_notes(item.get("public_comments"))
    clipped_tail = is_budget_clipped_prefix(prior, notes)
    composed_notes = []
    for index, note in enumerate(notes):
        entry = dict(note)
        old_note = prior.get(note_key(entry.get("id")))
        if old_note is not None and old_note.get("body") != entry.get("body") and not (clipped_tail and index == len(notes) - 1):
            prev_time = old_note.get("edited_at") or entry["created_at"]
            if not isinstance(entry.get("edited_at"), str) or entry["edited_at"] <= prev_time:
                entry["edited_at"] = max(checked, prev_time)
        composed_notes.append(entry)
    dirauth_list = _reconcile_dirauth_notes(item, composed_notes, dirauth_users, truncated=truncated)
    # Callers pass a key only for a verified fetch or an already verified stored snapshot.
    result.update(
        content=content,
        public_comments=composed_notes,
        comments_checked_at=checked,
        comments_source_key=source_key,
        comments_truncated=truncated,
    )
    if dirauth_list:
        result["dirauth_notes"] = dirauth_list
    else:
        result.pop("dirauth_notes", None)
    if result.get("authority") == "development" and is_dirauth_item(result, dirauth_users):
        result["authority"] = "dirauth-operator"
    elif (
        result.get("authority") == "dirauth-operator"
        and (item.get("public_comments") or item.get("dirauth_notes"))
        and not is_dirauth_item({**result, "authority": "development"}, dirauth_users)
    ):
        result["authority"] = "development"
    return result


def merge_cached_comments(store, item, source, observed=None, *, dirauth_users=None):
    """Keep the verified snapshot on a REST refresh; Store.ingest rejects stale revisions.

    REST activity after the last check, or a missing snapshot, requests a check at any status.
    """
    if item.get("kind") != "gitlab_issue" or not source.get("gitlab_project"):
        return item
    row = store.db.execute("SELECT id,typeof(payload) AS payload_type,CAST(payload AS BLOB) AS payload FROM items WHERE url=?",
                           (item["url"],)).fetchone()
    if row is None:
        return item
    old = (saved_object(row["payload"]) if row["payload_type"] == "text" else None) or {}
    key = _source_key(source)
    req_fields = ("id", "url", "title", "author", "created_at", "body")
    dirauth_fields = ("id", "author", "created_at")
    valid_dirauth = "dirauth_notes" not in old or (
        isinstance(old["dirauth_notes"], list)
        and all(isinstance(n, dict) and all(isinstance(n.get(f), str) for f in dirauth_fields) for n in old["dirauth_notes"])
    )
    valid_trunc = "comments_truncated" not in old or type(old["comments_truncated"]) is bool
    valid_notes = (isinstance(old.get("comments_checked_at"), str) and isinstance(old.get("public_comments"), list)
                   and valid_dirauth and valid_trunc
                   and all(isinstance(n, dict) and all(isinstance(n.get(f), str) for f in req_fields) for n in old["public_comments"]))
    current = valid_notes and old.get("comments_source_key") == key
    if observed and (not current or item["updated_at"] > old["comments_checked_at"]):
        with store.db:
            _request(store.db, row["id"], key, observed)
        if not current:
            store._comment_requests[row["id"]] = observed
    if not current:
        return item
    seeded_item = {**item, **({"dirauth_notes": old["dirauth_notes"]} if "dirauth_notes" in old else {})}
    return _compose(
        seeded_item,
        old["public_comments"],
        old["comments_checked_at"],
        source_key=key,
        dirauth_users=dirauth_users,
        window_truncated=bool(old.get("comments_truncated")),
    )


def _request(db, item_id, key, observed):
    # next_fetch_at=checked_at marks a request; an unserved request keeps its place, a failing issue its backoff.
    db.execute("INSERT OR REPLACE INTO comment_cache SELECT ?,?,?,?,0,NULL WHERE NOT EXISTS(SELECT 1 FROM comment_cache"
               " WHERE item_id=? AND source_key=? AND (failures>0 OR next_fetch_at<=checked_at))",
               (item_id, key, observed, observed, item_id, key))


def request_check(db, config, row, observed):
    """Ask the next comments phase to check an unverified issue (caller owns the transaction)."""
    source = next((s for s in config["sources"] if s["id"] == row["source_id"]), None)
    if config["comments"]["enabled"] and source and source["enabled"] and source.get("gitlab_project"):
        _request(db, row["id"], _source_key(source), observed)


def _candidates(store, source, observed, key):
    """Requested checks, then half recent candidates, half rotating unlocked published history."""
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
    columns = "i.id,i.content_hash,CAST(i.payload AS BLOB) AS payload"
    select = f"SELECT {columns} FROM items i LEFT JOIN comment_cache c ON c.item_id=i.id WHERE i.source_id=? AND " + due + unlocked
    args = (source["id"], key, observed)
    # Serve explicit requests and unpublished retry backoffs; CROSS JOIN keeps comment_cache outer.
    requested = store.db.execute(
        f"SELECT {columns} FROM comment_cache c CROSS JOIN items i ON i.id=c.item_id WHERE c.next_fetch_at<=? AND i.source_id=?"
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


def _advance_rotation(db, source_id: str, row: dict) -> None:
    if row["_comments_history"]:
        db.execute("UPDATE comment_sources SET rotation_cursor=?,recent_first=1 WHERE source_id=?", (row["id"], source_id))
    elif row["_comments_history"] is not None:  # a requested check takes no rotation turn
        db.execute("UPDATE comment_sources SET recent_first=0 WHERE source_id=?", (source_id,))


def enrich_comments(config, store, observed, *, deadline=None):
    """Optional post-collection phase. Failures never block REST/feed processing."""
    report = {"enabled": bool(config.get("comments", {}).get("enabled")), "checked": 0, "changed": 0,
              "failed": 0, "skipped": 0, "budget_reached": False}
    if not report["enabled"]:
        return report
    deadline = min(deadline or float("inf"), time.monotonic() + RUN_BUDGET_SECONDS)
    sources = [s for s in config["sources"] if s.get("enabled", True) and s.get("kind") == "gitlab_issue" and s.get("gitlab_project")]
    last_source = store.get_meta("comments_source_cursor") or ""
    sources.sort(key=lambda s: (s["id"] <= last_source, s["id"]))
    with store.db:
        store.db.execute(f"DELETE FROM comment_sources WHERE source_id NOT IN ({','.join('?' * len(sources))})", [s["id"] for s in sources])
    # Fresh sessionless client refusing redirects so requests never leave the verified endpoint.
    dirauth_users = config.get("collection", {}).get("dirauth_gitlab_users")
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
                try:
                    item = saved_object(row["payload"]) if len(row["payload"]) <= 1048576 else None
                    if (item is None or item.get("kind") != "gitlab_issue"
                            or not isinstance(item.get("title"), str)
                            or not isinstance(item.get("source_content", item.get("content")), str)):
                        raise ValueError
                    _issue_identity(source, item)
                except (CommentError, ValueError, TypeError, KeyError, RecursionError):
                    report["skipped"] += 1
                    with store.db:
                        _advance_rotation(store.db, source["id"], row)
                        store.db.execute("INSERT OR REPLACE INTO comment_cache VALUES(?,?,?,?,0,?)",
                                         (row["id"], key, observed, after(INTERVAL_SECONDS, observed), "Saved issue description unavailable"))
                    continue
                try:
                    enriched = _compose(
                        item, fetch_comments(client, source, item), observed, source_key=key, dirauth_users=dirauth_users
                    )
                except DeadlineReached:
                    report["budget_reached"] = True
                    return report
                except (CommentError, FetchError, ValueError, TypeError, KeyError) as exc:
                    # Keep the prior verified snapshot and its original verification time on failure.
                    report["checked"] += 1
                    report["failed"] += 1
                    cached = store.db.execute("SELECT failures,checked_at FROM comment_cache WHERE item_id=? AND source_key=?",
                                              (row["id"], key)).fetchone() or (0, observed)
                    item_due = after(backoff_seconds(cached[0] + 1, BACKOFF_BASE_SECONDS, BACKOFF_CAP_SECONDS), observed)
                    is_endpoint = isinstance(exc, (FetchError, EndpointError))
                    with store.db:
                        _advance_rotation(store.db, source["id"], row)
                        store.db.execute("INSERT OR REPLACE INTO comment_cache VALUES(?,?,?,?,?,?)",
                                         (row["id"], key, cached[1], item_due, cached[0] + 1, "Public comments unavailable"))
                        if is_endpoint:
                            state = store.db.execute("SELECT failures FROM comment_sources WHERE source_id=?", (source["id"],)).fetchone()
                            failures = (state[0] if state else 0) + 1
                            due = after(backoff_seconds(failures, BACKOFF_BASE_SECONDS, BACKOFF_CAP_SECONDS), observed)
                            store.db.execute("UPDATE comment_sources SET failures=?,next_fetch_at=?,error=? WHERE source_id=?",
                                             (failures, due, "Public comments unavailable", source["id"]))
                    if is_endpoint:
                        break
                    continue
                report["checked"] += 1
                changed = bool(store.ingest(enriched, observed, dirauth_users=dirauth_users))
                report["changed"] += changed
                with store.db:
                    _advance_rotation(store.db, source["id"], row)
                    if not changed:
                        store.db.execute("UPDATE items SET payload=? WHERE id=? AND CAST(payload AS BLOB)=? AND content_hash=?",
                                         (json.dumps(enriched, ensure_ascii=False), row["id"], row["payload"], row["content_hash"]))
                    store.db.execute("INSERT OR REPLACE INTO comment_cache VALUES(?,?,?,?,0,NULL)",
                                     (row["id"], key, observed, after(INTERVAL_SECONDS, observed)))
                    store.db.execute("UPDATE comment_sources SET failures=0,next_fetch_at=NULL,error=NULL WHERE source_id=?", (source["id"],))
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
