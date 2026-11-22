"""Optional, anonymous, fail-closed enrichment of configured public GitLab issues.

Only sanitized, explicitly public non-system notes cross the response boundary.
The bounded cache holds scheduling metadata, never raw GraphQL responses. Existing
published issues rotate through a bounded query, independently of REST lookback.
REST activity on an issue of any status requests a check.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from itertools import zip_longest
from urllib.parse import unquote, urlsplit

from .transport import DeadlineReached, FetchError, HttpClient
from .util import (
    GITLAB_PROJECT_PATH, after, backoff_until, canonical_url, digest, dirauth_user_set,
    effective_authority, is_valid_gitlab_user, now_iso, plain_text, saved_object, timestamp,
    valid_note_list,
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

    def __init__(
        self,
        notes,
        *,
        truncated: bool = False,
        window_notes=None,
        graphql_truncated: bool | None = None,
        graphql_floor_key: tuple[str, int, str] | None = None,
        seen_node_keys: set[str] | frozenset[str] = frozenset(),
    ):
        super().__init__(notes)
        self.truncated = bool(truncated)
        self.window_notes = list(notes if window_notes is None else window_notes)
        self.graphql_truncated = self.truncated if graphql_truncated is None else bool(graphql_truncated)
        self.graphql_floor_key = graphql_floor_key
        self.seen_node_keys = frozenset(seen_node_keys)


def _identity(source):
    project = source.get("gitlab_project", "")
    if (
        not isinstance(project, str)
        or not re.fullmatch(GITLAB_PROJECT_PATH, project)
        or any(p in {".", ".."} for p in project.split("/"))
    ):
        raise CommentError("Comments require a configured project identity")
    rest = urlsplit(canonical_url(source["url"]))
    match = re.fullmatch(r"/api/v4/projects/([^/]+)/issues", rest.path)
    if not match or (not match[1].isdigit() and unquote(match[1]) != project):
        raise CommentError("Configured REST project identity does not match")
    origin = f"https://{rest.netloc}"
    # GitLab serves the REST path above, and so GraphQL, at the origin's root.
    return project, origin, origin + "/api/graphql", match[1]


def _issue_identity(source, item):
    project, origin, endpoint, project_id = _identity(source)
    issue_url = canonical_url(item["url"])
    parsed = urlsplit(issue_url)
    match = re.fullmatch(re.escape("/" + project) + r"/-/(?:issues|work_items)/(\d+)", parsed.path)
    if not match or parsed.query or parsed.fragment or f"https://{parsed.netloc}" != origin:
        raise CommentError("Issue URL is outside its configured project")
    return project, origin, endpoint, project_id, match[1], issue_url


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


def _note_sort_key(note: dict) -> tuple[str, int, str]:
    k = note_key(note["id"])
    return note["created_at"], int(k) if k.isascii() and k.isdigit() else -1, note["id"]


def _preserve_edited_at(note: dict, old_note: dict) -> None:
    note.pop("edited_at", None)
    if isinstance(old_note.get("edited_at"), str) and old_note["edited_at"] > note["created_at"]:
        note["edited_at"] = old_note["edited_at"]


def _body_sha256(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _valid_prior_comments(raw_comments: object) -> list[dict]:
    if isinstance(raw_comments, list) and all(
        isinstance(n, dict)
        and isinstance(n.get("id"), str)
        and isinstance(n.get("body"), str)
        and ("body_sha256" not in n or isinstance(n["body_sha256"], str))
        and ("body_clipped" not in n or type(n["body_clipped"]) is bool)
        for n in raw_comments
    ):
        return raw_comments
    return []


def _body_chars(notes: list[dict]) -> int:
    return sum(len(body) for n in notes if isinstance(n, dict) and isinstance(body := n.get("body"), str))


def _tail_was_clipped(notes: list[dict]) -> bool:
    if not notes or not isinstance(tail := notes[-1], dict):
        return False
    clipped = tail.get("body_clipped")
    if type(clipped) is bool:
        return clipped
    return _body_chars(notes) >= TOTAL_CHARS


def is_budget_clipped_prefix(prev_notes: dict[str, dict], curr_notes: list[dict]) -> bool:
    """Return True when the oldest retained note is an unedited prefix clipped by TOTAL_CHARS."""
    if not _tail_was_clipped(curr_notes):
        return False
    tail = curr_notes[-1]
    old = prev_notes.get(note_key(tail.get("id")))
    return (
        old is not None
        and isinstance(old_body := old.get("body"), str)
        and isinstance(new_body := tail.get("body"), str)
        and len(new_body) < len(old_body)
        and old_body.startswith(new_body)
    )


def budget_unchanged_note_ids(prev_comments: object, curr_notes: list[dict]) -> set[str]:
    """Return normalized note keys whose body length changed only from TOTAL_CHARS clipping."""
    prev_list = _valid_prior_comments(prev_comments)
    prev_map = prior_notes(prev_list)
    unchanged: set[str] = set()
    if is_budget_clipped_prefix(prev_map, curr_notes):
        unchanged.add(note_key(curr_notes[-1].get("id")))
    if (
        _tail_was_clipped(prev_list)
        and (tail_key := note_key((prev_tail := prev_list[-1]).get("id")))
        and isinstance(old_body := prev_tail.get("body"), str)
    ):
        old_sha = prev_tail.get("body_sha256") if isinstance(prev_tail.get("body_sha256"), str) else None
        for note in curr_notes:
            if (
                isinstance(note, dict)
                and note_key(note.get("id")) == tail_key
                and note.get("edited_at") == prev_tail.get("edited_at")
                and isinstance(new_body := note.get("body"), str)
                and len(new_body) > len(old_body)
                and new_body.startswith(old_body)
            ):
                curr_sha = note.get("body_sha256") if isinstance(note.get("body_sha256"), str) else _body_sha256(new_body)
                if old_sha is None or curr_sha == old_sha:
                    unchanged.add(tail_key)
    return unchanged


def _source_key(source):
    return digest([source["id"], *_identity(source)])


def fetch_comments(client, source, item):
    """Read the newest-note window in one request; any unusable part rejects the answer."""
    project, origin, endpoint, project_id, iid, issue_url = _issue_identity(source, item)
    req_base = (source.get("_request_urls") or {}).get(source["url"])
    request_endpoint = (
        f"https://{urlsplit(req_base).netloc}/api/graphql"
        if isinstance(req_base, str) and req_base
        else endpoint
    )
    response = client.request("POST", request_endpoint, headers={"Accept": "application/json"},
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
            or canonical_url(issue["webUrl"]) != issue_url):
        raise CommentError("Public issue identity not verified")
    connection = issue.get("notes")
    if not isinstance(connection, dict) or not isinstance(connection.get("nodes"), list):
        raise CommentError("Public notes unavailable")
    notes = {}
    node_floor_keys: list[tuple[str, int, str]] = []
    seen_node_keys: set[str] = set()
    for note in connection["nodes"]:
        # Do not inspect, sanitize, log or persist a body before these flags.
        if not isinstance(note, dict):
            raise CommentError("Public note visibility is unknown")
        if note.get("internal") is True or note.get("system") is True:
            if isinstance(raw_id := note.get("id"), str) and (nkey := note_key(raw_id)):
                seen_node_keys.add(nkey)
            if isinstance(raw_created := note.get("createdAt"), str):
                try:
                    created_ts = timestamp(raw_created)
                except ValueError:
                    created_ts = ""
                if created_ts and created_ts <= received:
                    raw_id = note.get("id") if isinstance(note.get("id"), str) else ""
                    node_floor_keys.append(_note_sort_key({"id": raw_id, "created_at": created_ts}))
            continue
        if note.get("internal") is not False or note.get("system") is not False:
            raise CommentError("Public note visibility is unknown")
        ident = note.get("id")
        match = NOTE_GID_RE.fullmatch(ident) if isinstance(ident, str) else None
        if match is None:
            raise CommentError("Invalid public note identity")
        seen_node_keys.add(match[1])
        url = canonical_url(note.get("url", ""))
        if url != issue_url + "#note_" + match[1]:
            raise CommentError("Public note URL does not match issue")
        author = note.get("author")
        if not isinstance(author, dict) or not isinstance(author.get("username"), str):
            raise CommentError("Public note attribution unavailable")
        if not isinstance(note.get("body"), str):
            raise CommentError("Invalid public note body")
        author, created = plain_text(author["username"], 100, html=False), timestamp(note.get("createdAt"))
        edited = min(max(timestamp(raw_edited), created), received) if (raw_edited := note.get("lastEditedAt")) is not None else created
        if not is_valid_gitlab_user(author):
            raise CommentError("Invalid public note attribution")
        body = plain_text(note["body"], COMMENT_CHARS, html=False)
        if created <= received:
            node_floor_keys.append(_note_sort_key({"id": ident, "created_at": created}))
        # Skip an empty note, and one dated after this response: it must not date or promote a story.
        if body and created <= received:
            entry = {"id": ident, "url": url, "title": "Public comment by @" + author,
                     "author": author, "created_at": created, "body": body}
            if edited > created:
                entry["edited_at"] = edited
            notes[match[1]] = entry
    prev_list = _valid_prior_comments(item.get("public_comments"))
    prior = prior_notes(prev_list)
    prev_tail_key = note_key(prev_list[-1]["id"]) if _tail_was_clipped(prev_list) else ""
    window_notes = sorted(notes.values(), key=_note_sort_key, reverse=True)
    selected, remaining = [], TOTAL_CHARS
    clipped_baselines: dict[str, str | None] = {}
    for raw_note in window_notes:
        nkey = note_key(raw_note["id"])
        old_note = prior.get(nkey)
        raw_body = raw_note["body"]
        raw_sha = _body_sha256(raw_body)
        old_body = old_note.get("body") if old_note is not None and isinstance(old_note.get("body"), str) else None
        old_full_sha = (
            old_note["body_sha256"]
            if old_note is not None and isinstance(old_note.get("body_sha256"), str)
            else (_body_sha256(old_body) if old_note is not None and nkey != prev_tail_key and old_body is not None else None)
        )
        if old_note is not None and (
            old_body == raw_body
            or (old_full_sha is not None and old_full_sha == raw_sha)
            or (
                old_body is not None
                and (
                    (
                        nkey == prev_tail_key
                        and raw_body.startswith(old_body)
                        and raw_note.get("edited_at") == old_note.get("edited_at")
                    )
                    or (
                        0 < remaining < len(old_body)
                        and len(raw_body) > remaining
                        and len(selected) < MAX_COMMENTS
                        and old_body.startswith(raw_body[:remaining])
                    )
                )
            )
        ):
            _preserve_edited_at(raw_note, old_note)
        if remaining <= 0 or len(selected) >= MAX_COMMENTS:
            continue
        was_clipped = len(raw_body) > remaining
        clipped = {**raw_note, "body": raw_body[:remaining]}
        if was_clipped:
            clipped["body_clipped"] = True
            clipped["body_sha256"] = raw_sha
            clipped_baselines[nkey] = old_full_sha
        elif len(raw_body) == remaining:
            clipped["body_clipped"] = False
        remaining -= len(clipped["body"])
        selected.append(clipped)
    unchanged_ids = budget_unchanged_note_ids(prev_list, selected)
    for note in selected:
        old_note = prior.get(nkey := note_key(note["id"]))
        if old_note is not None and (old_note.get("body") == note["body"] or nkey in unchanged_ids):
            _preserve_edited_at(note, old_note)
            if nkey in clipped_baselines:
                # Keep the digest of the last unclipped or visibly exposed full body so
                # hidden-tail edits made while clipped are detected upon later unclipping.
                old_full_sha = clipped_baselines[nkey]
                if old_full_sha is not None:
                    note["body_sha256"] = old_full_sha
                else:
                    note.pop("body_sha256", None)
    graphql_truncated = len(connection["nodes"]) >= NOTE_WINDOW
    window_truncated = graphql_truncated or len(selected) < len(window_notes)
    return _CommentWindow(
        selected,
        truncated=window_truncated,
        window_notes=window_notes,
        graphql_truncated=graphql_truncated,
        graphql_floor_key=min(node_floor_keys, default=None),
        seen_node_keys=seen_node_keys,
    )


def analysis_context(item):
    """Return the writer's description window and the notes it sees verbatim, newest first.

    Notes are structured entries, so a body cannot pose as another author's note.
    """
    notes = [{key: note[key] for key in ("author", "created_at", "body")} for note in item.get("public_comments") or []]
    room = max(0, INPUT_CHARS - sum(len(note["body"]) for note in notes))
    # Payloads stored before descriptions moved back to content keep it in source_content.
    return item.get("source_content", item.get("content", ""))[:room], notes


def _dirauth_marker(note: dict) -> dict:
    return {"id": note["id"], "author": note["author"], "created_at": note["created_at"]}


def _reconcile_dirauth_notes(
    item: dict,
    composed_notes: list[dict],
    dirauth_users,
    *,
    truncated: bool,
    floor_key: tuple[str, int, str] | None = None,
    seen_node_keys: set[str] | frozenset[str] = frozenset(),
) -> list[dict]:
    users = dirauth_user_set(dirauth_users)
    if not users:
        return []
    if truncated:
        present_keys = {note_key(n["id"]) for n in composed_notes if isinstance(n.get("id"), str)}
        effective_floor = (
            floor_key
            if floor_key is not None
            else min((_note_sort_key(n) for n in composed_notes), default=None)
        )
        retained = {
            nkey: _dirauth_marker(raw)
            for notes in (item.get("public_comments"), item.get("dirauth_notes")) if isinstance(notes, list)
            for raw in notes
            if isinstance(raw, dict) and all(isinstance(raw.get(f), str) and raw[f] for f in ("id", "author", "created_at"))
            and raw["author"].strip().lower() in users and (nkey := note_key(raw["id"]))
            and nkey not in present_keys and nkey not in seen_node_keys
            and (
                effective_floor is None
                or (
                    _note_sort_key(raw)[:2] < effective_floor[:2]
                    if floor_key is not None
                    else _note_sort_key(raw) <= effective_floor
                )
            )
        }
    else:
        retained = {}
    for note in composed_notes:
        if note["author"].strip().lower() in users and (nkey := note_key(note["id"])):
            retained[nkey] = _dirauth_marker(note)
    return sorted(retained.values(), key=_note_sort_key, reverse=True)[:MAX_DIRAUTH_NOTES]


def _compose(
    item,
    notes,
    checked,
    *,
    source_key,
    dirauth_users=None,
    tor_core_users=None,
    window_truncated: bool | None = None,
):
    truncated = bool(getattr(notes, "truncated", False) if window_truncated is None else window_truncated)
    result = dict(item)
    content = result.pop("source_content", result.get("content"))
    if not isinstance(content, str):
        raise CommentError("Saved issue description is unavailable")
    prev_list = _valid_prior_comments(item.get("public_comments"))
    prior = prior_notes(prev_list)
    budget_unchanged = budget_unchanged_note_ids(prev_list, notes)
    composed_notes = []
    for note in notes:
        entry = dict(note)
        nkey = note_key(entry.get("id"))
        old_note = prior.get(nkey)
        if old_note is not None and old_note.get("body") != entry.get("body") and nkey not in budget_unchanged:
            prev_edit = old_note.get("edited_at")
            prev_time = prev_edit if isinstance(prev_edit, str) and prev_edit else entry["created_at"]
            if not isinstance(entry.get("edited_at"), str) or entry["edited_at"] <= prev_time:
                entry["edited_at"] = max(checked, prev_time)
        composed_notes.append(entry)
    if isinstance(notes, _CommentWindow) and window_truncated is None:
        dirauth_source, dirauth_truncated, dirauth_floor, seen_node_keys = (
            notes.window_notes, notes.graphql_truncated, notes.graphql_floor_key, notes.seen_node_keys
        )
    else:
        dirauth_source, dirauth_truncated, dirauth_floor, seen_node_keys = composed_notes, truncated, None, frozenset()
    dirauth_list = _reconcile_dirauth_notes(
        item, dirauth_source, dirauth_users,
        truncated=dirauth_truncated, floor_key=dirauth_floor, seen_node_keys=seen_node_keys,
    )
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
    if result.get("authority") == "development":
        result["authority"] = effective_authority(result, dirauth_users, tor_core_users)
    elif (
        result.get("authority") in {"dirauth-operator", "tor-core"}
        and (item.get("public_comments") or item.get("dirauth_notes"))
    ):
        recomputed = effective_authority({**result, "authority": "development"}, dirauth_users, tor_core_users)
        if recomputed in {"development", "tor-core", "dirauth-operator"}:
            result["authority"] = recomputed
    return result


def merge_cached_comments(store, item, source, observed=None, *, dirauth_users=None, tor_core_users=None):
    """Keep the verified snapshot on a REST refresh; Store.ingest rejects stale revisions.

    REST activity after the last check, or a missing snapshot, requests a check at any status.
    """
    if item.get("kind") != "gitlab_issue" or not source.get("gitlab_project"):
        return item
    row = store.db.execute(
        "SELECT id,CASE WHEN typeof(payload)='text' THEN CAST(payload AS BLOB) END AS payload FROM items WHERE url=?",
        (item["url"],),
    ).fetchone()
    if row is None:
        return item
    old = saved_object(row["payload"]) or {}
    key = _source_key(source)
    valid_notes = (
        isinstance(old.get("comments_checked_at"), str)
        and ("comments_truncated" not in old or type(old["comments_truncated"]) is bool)
        and valid_note_list(old.get("public_comments"), ("id", "url", "title", "author", "created_at", "body"), allow_none=False)
        and ("dirauth_notes" not in old or valid_note_list(old["dirauth_notes"], ("id", "author", "created_at"), allow_none=False))
    )
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
        tor_core_users=tor_core_users,
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
    state = store.db.execute("SELECT * FROM comment_sources WHERE source_id=? AND source_key=?", (source["id"], key)).fetchone()
    if state and state["next_fetch_at"] and state["next_fetch_at"] > observed:
        return []
    if not state:
        with store.db:
            store.db.execute("INSERT OR REPLACE INTO comment_sources(source_id,source_key) VALUES(?,?)", (source["id"], key))
    cursor, recent_first = (state["rotation_cursor"], bool(state["recent_first"])) if state else ("", False)
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


def _finish_check(
    db, source_id: str, row: dict, key: str, checked_at: str, next_fetch_at: str, *, failures: int = 0, error: str | None = None
) -> None:
    if row["_comments_history"]:
        db.execute("UPDATE comment_sources SET rotation_cursor=?,recent_first=1 WHERE source_id=?", (row["id"], source_id))
    elif row["_comments_history"] is not None:  # a requested check takes no rotation turn
        db.execute("UPDATE comment_sources SET recent_first=0 WHERE source_id=?", (source_id,))
    db.execute("INSERT OR REPLACE INTO comment_cache VALUES(?,?,?,?,?,?)", (row["id"], key, checked_at, next_fetch_at, failures, error))


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
    tor_core_users = config.get("collection", {}).get("tor_core_gitlab_users")
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
                        _finish_check(
                            store.db, source["id"], row, key, observed, after(INTERVAL_SECONDS, observed),
                            error="Saved issue description unavailable",
                        )
                    continue
                try:
                    enriched = _compose(
                        item, fetch_comments(client, source, item), observed,
                        source_key=key, dirauth_users=dirauth_users, tor_core_users=tor_core_users,
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
                    item_due = backoff_until(cached[0] + 1, BACKOFF_BASE_SECONDS, BACKOFF_CAP_SECONDS, observed)
                    is_endpoint = isinstance(exc, (FetchError, EndpointError))
                    with store.db:
                        _finish_check(
                            store.db, source["id"], row, key, cached[1], item_due,
                            failures=cached[0] + 1, error="Public comments unavailable",
                        )
                        if is_endpoint:
                            state = store.db.execute("SELECT failures FROM comment_sources WHERE source_id=?", (source["id"],)).fetchone()
                            failures = (state[0] if state else 0) + 1
                            due = backoff_until(failures, BACKOFF_BASE_SECONDS, BACKOFF_CAP_SECONDS, observed)
                            store.db.execute("UPDATE comment_sources SET failures=?,next_fetch_at=?,error=? WHERE source_id=?",
                                             (failures, due, "Public comments unavailable", source["id"]))
                    if is_endpoint:
                        break
                    continue
                report["checked"] += 1
                changed = bool(store.ingest(enriched, observed, dirauth_users=dirauth_users, tor_core_users=tor_core_users))
                report["changed"] += changed
                with store.db:
                    if not changed:
                        store.db.execute("UPDATE items SET payload=? WHERE id=? AND CAST(payload AS BLOB)=? AND content_hash=?",
                                         (json.dumps(enriched, ensure_ascii=False), row["id"], row["payload"], row["content_hash"]))
                    _finish_check(store.db, source["id"], row, key, observed, after(INTERVAL_SECONDS, observed))
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
