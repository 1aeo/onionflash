"""Incremental permanent publication with a bounded article queue.

The SQLite catalog retains compact last-good public JSON for offline recovery.
Raw evidence is excluded. Published article files are never removed when the
private source row changes or disappears.
"""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
import hashlib
import itertools
import json
import logging
import os
from pathlib import Path
import re
import stat
import tempfile

from . import editorial, render, store as store_mod
from .util import digest, now_iso, saved_object


def public_files() -> set[str]:
    """Fixed files the application renders (story, listing and topic paths vary)."""
    return {"index.html", "feed.xml", "feed.json", "_headers", *render.ASSET_FILES}


_ARTICLE = r"news/[A-Za-z0-9_-]{1,64}/(?:index\.html|story\.json)"
_TOPIC = "(?:" + "|".join(re.escape(topic) for topic in render.CATEGORIES) + ")"
_FIXED = "|".join(re.escape(name) for name in sorted(public_files()))
_PATH = re.compile(
    r"(?:" + _ARTICLE + r"|tags/" + _TOPIC + r"\.xml|(?:topics/" + _TOPIC
    + r"/)?(?:page/[1-9][0-9]{0,8}/)?index\.html|" + _FIXED + r")\Z"
)


def public_path_allowed(relative: str) -> bool:
    """Return whether `relative` matches a permitted generated output file path."""
    return isinstance(relative, str) and bool(_PATH.fullmatch(relative))


def initialize(db) -> None:
    """Create publication ledger, catalog, topic, and render-queue tables and triggers."""
    editorial.initialize(db)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS public_artifacts (
            path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
            content_type TEXT NOT NULL, updated_at TEXT NOT NULL,
            uploaded_sha256 TEXT
        );
        CREATE TABLE IF NOT EXISTS public_catalog (
            story_id TEXT PRIMARY KEY, published_at TEXT NOT NULL,
            updated_at TEXT NOT NULL, added_at TEXT NOT NULL, source_hash TEXT NOT NULL,
            template_hash TEXT NOT NULL, json_sha256 TEXT NOT NULL,
            public_json TEXT NOT NULL
        );
        CREATE TRIGGER IF NOT EXISTS public_catalog_permanent BEFORE DELETE ON public_catalog BEGIN
            SELECT RAISE(ABORT, 'Published stories are permanent; correct or retract them instead');
        END;
        DROP INDEX IF EXISTS public_catalog_published;
        CREATE INDEX IF NOT EXISTS public_catalog_added ON public_catalog(added_at DESC,updated_at DESC,story_id DESC);
        CREATE INDEX IF NOT EXISTS public_catalog_updated ON public_catalog(updated_at DESC,published_at DESC,story_id DESC);
        CREATE INDEX IF NOT EXISTS public_catalog_template ON public_catalog(template_hash);
        CREATE TABLE IF NOT EXISTS public_catalog_checks (
            story_id TEXT PRIMARY KEY, template_hash TEXT NOT NULL,
            json_sha256 TEXT NOT NULL, omitted INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS public_catalog_checks_omitted
            ON public_catalog_checks(template_hash,omitted,story_id);
        CREATE TRIGGER IF NOT EXISTS public_catalog_checks_invalidate
            AFTER UPDATE OF template_hash, json_sha256, public_json ON public_catalog BEGIN
            DELETE FROM public_catalog_checks WHERE story_id=NEW.story_id;
        END;
        CREATE TABLE IF NOT EXISTS public_story_topics (
            topic TEXT NOT NULL, story_id TEXT NOT NULL,
            added_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            PRIMARY KEY(topic,story_id)
        );
        CREATE INDEX IF NOT EXISTS public_story_topics_added
            ON public_story_topics(topic,added_at DESC,updated_at DESC,story_id DESC);
        CREATE INDEX IF NOT EXISTS public_story_topics_story ON public_story_topics(story_id);
        CREATE TABLE IF NOT EXISTS public_render_queue (
            story_id TEXT PRIMARY KEY, last_error TEXT
        );
        CREATE INDEX IF NOT EXISTS public_render_queue_pending ON public_render_queue(last_error);
        DROP TRIGGER IF EXISTS public_story_insert;
        DROP TRIGGER IF EXISTS public_story_update;
        DROP TRIGGER IF EXISTS public_story_delete;
        CREATE TRIGGER IF NOT EXISTS public_queue_insert AFTER INSERT ON stories BEGIN
            DELETE FROM public_render_queue WHERE story_id=NEW.id;
            INSERT INTO public_render_queue(rowid,story_id) SELECT IFNULL(MIN(rowid),0)-1,NEW.id FROM public_render_queue;
        END;
        CREATE TRIGGER IF NOT EXISTS public_queue_update AFTER UPDATE OF payload ON stories
            WHEN OLD.payload IS NOT NEW.payload BEGIN
            DELETE FROM public_render_queue WHERE story_id=NEW.id;
            INSERT INTO public_render_queue(rowid,story_id) SELECT IFNULL(MIN(rowid),0)-1,NEW.id FROM public_render_queue;
        END;
        CREATE TRIGGER IF NOT EXISTS public_queue_delete AFTER DELETE ON stories BEGIN
            UPDATE public_render_queue SET last_error=NULL WHERE story_id=OLD.id;
        END;
    """)


def template_identity(site: dict) -> str:
    """Compute a digest of rendering modules and site metadata to detect template changes."""
    root = Path(__file__).parent
    files = [(name, _file_hash(root / name)) for name in ("render.py", "publication.py", "editorial.py", "schema.py", "util.py")]
    return digest([files, {key: site.get(key) for key in ("title", "description", "base_url", "repository_url")}])


def _owned_output(value: str) -> tuple[Path, bool]:
    output = Path(value).absolute()
    if output.is_symlink():
        raise ValueError("Public output must not be a symlink")
    output = output.resolve()
    owner = output.parent / ("." + output.name + ".onionflash-owner")
    if owner.is_symlink() or (output.exists() and not output.is_dir()):
        raise ValueError("Unsafe public output ownership marker or directory")
    if owner.exists() and not owner.is_file():
        raise ValueError("Output ownership marker must be a regular file")
    if output.exists() and any(output.iterdir()) and not owner.exists():
        raise ValueError("Refusing to replace a nonempty directory not owned by Onion Flash")
    missing = not output.exists() or not owner.exists() or not (output / "feed.xml").is_file()
    output.mkdir(parents=True, exist_ok=True)
    if not owner.exists():
        fd = os.open(owner, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write("Onion Flash generated output\n")
    return output, missing


def _target(output: Path, relative: str) -> Path:
    if not public_path_allowed(relative):
        raise ValueError("Unsafe public artifact path")
    target = output / relative
    for parent in reversed(target.parents):
        if parent == output or output in parent.parents:
            if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
                raise ValueError("Public artifact parent is not a real directory")
            parent.mkdir(exist_ok=True)
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise ValueError("Public artifact must be a regular file")
    return target


def _file_hash(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


TEMPORARY_PREFIX = ".onionflash-"


class Artifacts:
    """Atomic staged writer tracking generated public files in `public_artifacts`."""

    def __init__(self, db, output: Path, observed: str):
        self.db, self.output, self.observed = db, output, observed
        self.staging = output.parent / ("." + output.name + ".onionflash-staging")
        if not self.staging.is_symlink():
            self.staging.mkdir(mode=0o700, exist_ok=True)
        info = os.lstat(self.staging)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ValueError("Unsafe public staging directory")
        for stale in self.staging.glob(TEMPORARY_PREFIX + "*"):
            if stale.is_file():
                stale.unlink()

    @contextmanager
    def stream(self, relative: str, content_type: str):
        """Stream bytes into a staged temporary file and replace `relative` only on change."""
        target = _target(self.output, relative)
        descriptor, temporary_name = tempfile.mkstemp(prefix=TEMPORARY_PREFIX, dir=self.staging)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                sink = _Sink(stream)
                yield sink
                value, size = sink.checksum.hexdigest(), sink.size
                old = self.db.execute("SELECT sha256,size,content_type FROM public_artifacts WHERE path=?", (relative,)).fetchone()
                changed = old is None or tuple(old) != (value, size, content_type)
                if changed or not target.is_file() or _file_hash(target) != value:
                    stream.flush()
                    os.fsync(stream.fileno())
                    os.chmod(temporary, 0o644)
                    os.replace(temporary, target)
            if changed:
                self.db.execute("""INSERT INTO public_artifacts(path,sha256,size,content_type,updated_at)
                    VALUES(?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET
                    sha256=excluded.sha256,size=excluded.size,content_type=excluded.content_type,updated_at=excluded.updated_at""",
                    (relative, value, size, content_type, self.observed))
                store_mod.set_meta(self.db, publication_dirty="1")
        finally:
            temporary.unlink(missing_ok=True)

    def write(self, relative: str, chunks, content_type: str) -> str:
        """Write byte `chunks` to `relative` and return its SHA-256 hex digest."""
        with self.stream(relative, content_type) as sink:
            for chunk in chunks:
                sink.write(chunk)
        return sink.checksum.hexdigest()

    def text(self, relative: str, text: str, content_type: str) -> str:
        """Write UTF-8 `text` to `relative` and return its SHA-256 hex digest."""
        return self.write(relative, [text.encode("utf-8")], content_type)

    def write_article(self, story_id: str, html_body: str, payload: dict) -> tuple[str, str]:
        """Write paired `index.html` and `story.json` files and return `(public_json, sha256)`."""
        public_json = render.public_json_text(payload)
        self.text(f"news/{story_id}/index.html", html_body, "text/html; charset=utf-8")
        return public_json, self.text(f"news/{story_id}/story.json", public_json, "application/json; charset=utf-8")


class _Sink:
    def __init__(self, stream):
        self.stream, self.checksum, self.size = stream, hashlib.sha256(), 0

    def write(self, chunk: bytes) -> None:
        self.stream.write(chunk)
        self.checksum.update(chunk)
        self.size += len(chunk)


def _public_story(row, current: str | None = None, *, warn: bool = True) -> dict | None:
    """A verified catalog snapshot, checked again unless the `current` template rendered it."""
    payload = row["public_json"]
    if not isinstance(payload, str) or hashlib.sha256(payload.encode("utf-8")).hexdigest() != row["json_sha256"]:
        raise ValueError("Accepted public story snapshot is missing or changed")
    story = json.loads(payload)
    if row["template_hash"] != current:
        try:
            story = render.prepare_story(story, editorial=story.get("editorial"))
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            if current is None:
                raise
            if warn:
                logging.getLogger(__name__).warning("Left story %s out of listings and feeds (%s)", row["story_id"], type(exc).__name__)
            return None
    if story["id"] != row["story_id"]:
        raise ValueError("Accepted story identity differs from its catalog entry")
    return story


def _catalog_row(db, story_id: str):
    return db.execute("SELECT * FROM public_catalog WHERE story_id=?", (story_id,)).fetchone()


def _dequeue(db, story_id: str) -> None:
    db.execute("DELETE FROM public_render_queue WHERE story_id=?", (story_id,))


def _render_accepted(db, site: dict, base: str, accepted) -> tuple[dict, str]:
    meta = editorial.public_metadata(db, accepted["story_id"])
    payload = accepted["public_json"]
    if not isinstance(payload, str) or hashlib.sha256(payload.encode("utf-8")).hexdigest() != accepted["json_sha256"]:
        raise ValueError("Accepted public story snapshot is missing or changed")
    raw = json.loads(payload)
    if not isinstance(raw, dict):
        raise ValueError("Accepted public story snapshot is missing or changed")
    if meta is not None and (raw.get("editorial") or {}).get("revision") != meta["revision"]:
        if meta["status"] == "retracted":
            retracted_raw = {
                **raw,
                **editorial.retracted_fields(meta["reason"]),
                "category": raw["category"] if isinstance(raw.get("category"), str) and raw["category"] in render.CATEGORIES else "network",
                "confidence": raw["confidence"] if isinstance(raw.get("confidence"), str) and raw["confidence"] in render.CONFIDENCES else "reported",
                "state": raw["state"] if isinstance(raw.get("state"), str) and raw["state"] in render.PUBLIC_STATES else "developing",
                "updated_at": meta["at"],
            }
            story = render.prepare_story(retracted_raw, editorial=meta)
        else:
            rev_row = db.execute(
                "SELECT CAST(after_public_json AS BLOB) FROM editorial_revisions WHERE story_id=? AND revision=? AND typeof(after_public_json)='text'",
                (accepted["story_id"], meta["revision"]),
            ).fetchone()
            after_obj = saved_object(rev_row[0], allow_surrogates=True) if rev_row else None
            if after_obj is None:
                raise ValueError("Editorial revision snapshot is missing or unreadable")
            story = render.prepare_story(after_obj, editorial=meta)
    else:
        story = _public_story(accepted)
    if story["id"] != accepted["story_id"]:
        raise ValueError("Accepted story identity differs from its catalog entry")
    article = render.article_html(site, base, story)
    render.public_json_text(story).encode("utf-8")
    article.encode("utf-8")
    return story, article


def _accepted(db, *, order: str = "added_at", batch_size: int = 100, topic: str | None = None):
    cursor = None
    secondary = "updated_at" if order == "added_at" else "published_at"
    current = store_mod.get_meta(db, "publication_template")
    prefix = "t." if topic else "c."
    from_sql = (
        "FROM public_story_topics t JOIN public_catalog c ON c.story_id=t.story_id WHERE t.topic=? AND "
        if topic
        else "FROM public_catalog c WHERE "
    )
    while True:
        cursor_sql = f" AND ({prefix}{order},{prefix}{secondary},{prefix}story_id) < (?,?,?)" if cursor else ""
        params = (*((topic,) if topic else ()), *(cursor or ()), batch_size)
        rows = db.execute(
            f"""SELECT c.story_id,c.published_at,c.updated_at,c.added_at,c.template_hash,c.json_sha256,c.public_json
                {from_sql}{prefix}story_id NOT IN (SELECT story_id FROM story_aliases){cursor_sql}
                ORDER BY {prefix}{order} DESC,{prefix}{secondary} DESC,{prefix}story_id DESC LIMIT ?""",
            params,
        ).fetchall()
        if not rows:
            return
        for row in rows:
            if (story := _public_story(row, current)) is not None:
                yield story
        cursor = (rows[-1][order], rows[-1][secondary], rows[-1]["story_id"])


def _feeds(artifacts: Artifacts, db, site: dict, base: str) -> None:
    with ExitStack() as stack:
        writers = {
            category: stack.enter_context(artifacts.stream(render.feed_path(category), "application/rss+xml; charset=utf-8"))
            for category in (None, *render.CATEGORIES)
        }
        counts = dict.fromkeys(writers, 0)
        json_writer = stack.enter_context(artifacts.stream("feed.json", "application/feed+json; charset=utf-8"))
        json_writer.write(render.json_feed_header(site, base))
        for story in _accepted(db, order="updated_at"):
            xml = None
            for category, writer in writers.items():
                if category and category not in story["tags"]:
                    continue
                if not counts[category]:
                    writer.write(render.rss_header(site, base, render.feed_path(category), story["updated_at"], category))
                if xml is None:
                    xml = render.ET.tostring(render._rss_item(story, base), encoding="utf-8")
                writer.write(xml)
                if category is None:
                    if counts[None]:
                        json_writer.write(b",\n")
                    json_writer.write(json.dumps(render._json_feed_item(story, base), ensure_ascii=False).encode("utf-8"))
                counts[category] += 1
        for category, writer in writers.items():
            if not counts[category]:
                writer.write(render.rss_header(site, base, render.feed_path(category), None, category))
            writer.write(b"</channel></rss>")
        json_writer.write(b"]}\n")


def _remove_obsolete_pages(artifacts: Artifacts, pages: int, topic: str | None = None) -> None:
    for page in itertools.count(pages + 1):
        relative = render._page_url("", page, topic) + "index.html"
        if artifacts.db.execute("SELECT 1 FROM public_artifacts WHERE path=?", (relative,)).fetchone() is None:
            return
        _target(artifacts.output, relative).unlink(missing_ok=True)
        artifacts.db.execute("DELETE FROM public_artifacts WHERE path=?", (relative,))
        store_mod.set_meta(artifacts.db, publication_dirty="1")


def _listing(artifacts: Artifacts, site: dict, base: str, health: list, *, count: int,
             latest: str | None, refresh: bool, topic: str | None = None) -> None:
    page_size = site["page_size"]
    pages = max(1, (count + page_size - 1) // page_size)
    stories = _accepted(artifacts.db, topic=topic)
    for page in range(1, pages + 1 if refresh else 2):
        batch = list(itertools.islice(stories, page_size))
        relative = render._page_url("", page, topic) + "index.html"
        artifacts.text(
            relative,
            render.index_html(site, base, batch, health if page == 1 else [], total=count, page=page, pages=pages, latest=latest, topic=topic),
            "text/html; charset=utf-8",
        )
    if refresh:
        _remove_obsolete_pages(artifacts, pages, topic)


def _pointer(artifacts: Artifacts, db, site: dict, base: str, identity: str, story_id: str, survivor_id: str) -> None:
    accepted = _catalog_row(db, story_id)
    if accepted is None:
        with db:
            _dequeue(db, story_id)
        return
    article = render.pointer_html(site, base, survivor_id)
    pointer = render.pointer_json(base, story_id, survivor_id)
    with db:
        public_json, checksum = artifacts.write_article(story_id, article, pointer)
        removed = db.execute("DELETE FROM public_story_topics WHERE story_id=?", (story_id,)).rowcount
        if accepted["json_sha256"] != checksum or accepted["template_hash"] == "" or removed:
            store_mod.bump_meta(db, "publication_catalog_revision")
        db.execute(
            "UPDATE public_catalog SET template_hash=?,json_sha256=?,public_json=? WHERE story_id=?",
            (identity, checksum, public_json, story_id),
        )
        _dequeue(db, story_id)


def _sync_catalog_checks(db, identity: str, *, batch_size: int = 100) -> list[str]:
    """Incrementally validate unchecked stale catalog snapshots for `identity` and return omitted IDs."""
    has_stale = db.execute(
        "SELECT 1 FROM public_catalog WHERE template_hash<? OR template_hash>? LIMIT 1",
        (identity, identity),
    ).fetchone()
    if has_stale is None:
        if db.execute("SELECT 1 FROM public_catalog_checks LIMIT 1").fetchone() is not None:
            with db:
                db.execute("DELETE FROM public_catalog_checks")
        return []
    with db:
        db.execute(
            "DELETE FROM public_catalog_checks WHERE template_hash!=? OR story_id IN (SELECT story_id FROM story_aliases)",
            (identity,),
        )
    cursor: str | None = None
    while True:
        cursor_sql = " AND c.story_id>?" if cursor is not None else ""
        params = (identity, identity, *((cursor,) if cursor is not None else ()), batch_size)
        rows = db.execute(
            f"""SELECT c.story_id, c.template_hash, c.json_sha256, c.public_json
                FROM public_catalog c
                WHERE c.template_hash!=?
                  AND c.story_id NOT IN (SELECT story_id FROM story_aliases)
                  AND NOT EXISTS (
                      SELECT 1 FROM public_catalog_checks chk
                      WHERE chk.story_id=c.story_id
                        AND chk.template_hash=?
                        AND chk.json_sha256=c.json_sha256
                  ){cursor_sql}
                ORDER BY c.story_id LIMIT ?""",
            params,
        ).fetchall()
        if not rows:
            break
        checks = [
            (cat_row["story_id"], identity, cat_row["json_sha256"], int(_public_story(cat_row, identity, warn=False) is None))
            for cat_row in rows
        ]
        with db:
            db.executemany(
                """INSERT INTO public_catalog_checks(story_id,template_hash,json_sha256,omitted)
                   VALUES(?,?,?,?) ON CONFLICT(story_id) DO UPDATE SET
                   template_hash=excluded.template_hash,json_sha256=excluded.json_sha256,omitted=excluded.omitted""",
                checks,
            )
        cursor = rows[-1]["story_id"]
    return [
        row[0]
        for row in db.execute(
            """SELECT c.story_id
               FROM public_catalog_checks chk
               JOIN public_catalog c ON c.story_id=chk.story_id
               WHERE chk.template_hash=?
                 AND chk.omitted=1
                 AND c.template_hash!=?
                 AND c.json_sha256=chk.json_sha256
                 AND c.story_id NOT IN (SELECT story_id FROM story_aliases)
               ORDER BY c.story_id""",
            (identity, identity),
        ).fetchall()
    ]


def build(config: dict, store, *, force: bool = False) -> dict:
    """Update changed artifacts; the caller holds the existing database lock."""
    db, site = store.db, config["site"]
    initialize(db)
    output, output_missing = _owned_output(config["storage"]["output_dir"])
    base = site["base_url"].rstrip("/") + "/"
    observed = now_iso()
    identity = template_identity(site)
    with db:
        store_mod.set_meta(db, publication_build_pending="1")
    template_changed = store_mod.get_meta(db, "publication_template") != identity
    queued = db.execute("SELECT COUNT(*) FROM public_render_queue WHERE last_error IS NULL").fetchone()[0]
    restart_rebuild = template_changed or output_missing or (
        force and (store_mod.get_meta(db, "publication_rebuild_active") != identity or not queued)
    )
    if restart_rebuild:
        with db:
            db.execute(
                "INSERT INTO public_render_queue(story_id) SELECT id FROM stories "
                "UNION SELECT story_id FROM public_catalog WHERE true "
                "ON CONFLICT(story_id) DO UPDATE SET last_error=NULL"
            )
            store_mod.set_meta(db, publication_template=identity, publication_rebuild_active=identity)
    artifacts = Artifacts(db, output, observed)
    limit = config["storage"]["render_batch_size"]
    candidates = db.execute(
        """SELECT public_render_queue.story_id AS id,
                  stories.id IS NOT NULL AS has_story,
                  CASE WHEN typeof(stories.payload)='text' THEN CAST(stories.payload AS BLOB) END AS payload
           FROM public_render_queue
           LEFT JOIN stories ON stories.id=public_render_queue.story_id
           WHERE public_render_queue.last_error IS NULL ORDER BY public_render_queue.rowid LIMIT ?""",
        (limit,),
    ).fetchall()
    for row in candidates:
        alias = editorial.retired(db, story_id=row["id"])
        if alias is not None:
            if alias[1] is not None:
                _pointer(artifacts, db, site, base, identity, row["id"], alias[1])
            else:
                with db:
                    removed_topics = db.execute("DELETE FROM public_story_topics WHERE story_id=?", (row["id"],)).rowcount
                    _dequeue(db, row["id"])
                    if removed_topics or _catalog_row(db, row["id"]) is not None:
                        store_mod.bump_meta(db, "publication_catalog_revision")
                        store_mod.set_meta(db, publication_dirty="1")
            continue
        quarantined = False
        accepted = None
        if not row["has_story"]:
            accepted = _catalog_row(db, row["id"])
            if accepted is None:
                with db:
                    _dequeue(db, row["id"])
                continue
        try:
            if accepted is not None:
                story, article = _render_accepted(db, site, base, accepted)
            else:
                if (parsed_payload := saved_object(row["payload"], allow_surrogates=True)) is None:
                    raise ValueError("Damaged story payload")
                story = render.prepare_story(parsed_payload, editorial=editorial.public_metadata(db, row["id"]))
                if story["id"] != row["id"]:
                    raise ValueError("Story identity differs from its database row")
                article = render.article_html(site, base, story)
                render.public_json_text(story).encode("utf-8")
                article.encode("utf-8")
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
            with db:
                db.execute("UPDATE public_render_queue SET last_error=? WHERE story_id=?", (type(exc).__name__, row["id"]))
            logging.getLogger(__name__).warning("Quarantined unrenderable story %s (%s)", row["id"], type(exc).__name__)
            if accepted is not None or (accepted := _catalog_row(db, row["id"])) is None:
                if accepted is not None:
                    with db:
                        if db.execute("DELETE FROM public_story_topics WHERE story_id=?", (row["id"],)).rowcount:
                            store_mod.bump_meta(db, "publication_catalog_revision")
                            store_mod.set_meta(db, publication_dirty="1")
                continue
            try:
                story, article = _render_accepted(db, site, base, accepted)
            except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
                with db:
                    if db.execute("DELETE FROM public_story_topics WHERE story_id=?", (row["id"],)).rowcount:
                        store_mod.bump_meta(db, "publication_catalog_revision")
                        store_mod.set_meta(db, publication_dirty="1")
                continue
            quarantined = True
        with db:
            public_json, checksum = artifacts.write_article(story["id"], article, story)
            previous = accepted or _catalog_row(db, story["id"])
            expected_topics = [(topic, story["id"], story["added_at"], story["updated_at"]) for topic in story["tags"]]
            topics_stale = previous is None or previous["json_sha256"] != checksum or {
                tuple(topic_row)
                for topic_row in db.execute(
                    "SELECT topic,story_id,added_at,updated_at FROM public_story_topics WHERE story_id=?",
                    (story["id"],),
                )
            } != set(expected_topics)
            if topics_stale:
                store_mod.bump_meta(db, "publication_catalog_revision")
                db.execute("DELETE FROM public_story_topics WHERE story_id=?", (story["id"],))
                db.executemany(
                    "INSERT INTO public_story_topics(topic,story_id,added_at,updated_at) VALUES(?,?,?,?)",
                    expected_topics,
                )
            db.execute(
                """INSERT INTO public_catalog(story_id,published_at,updated_at,added_at,source_hash,template_hash,json_sha256,public_json)
                   VALUES(?,?,?,?,'',?,?,?) ON CONFLICT(story_id) DO UPDATE SET
                   published_at=excluded.published_at,updated_at=excluded.updated_at,added_at=excluded.added_at,
                   template_hash=excluded.template_hash,json_sha256=excluded.json_sha256,public_json=excluded.public_json""",
                (story["id"], story["published_at"], story["updated_at"], story["added_at"], identity, checksum, public_json),
            )
            if not quarantined:
                _dequeue(db, story["id"])
    with db:
        if db.execute("DELETE FROM public_story_topics WHERE story_id IN (SELECT story_id FROM story_aliases)").rowcount:
            store_mod.bump_meta(db, "publication_catalog_revision")
            store_mod.set_meta(db, publication_dirty="1")
    omitted_ids = _sync_catalog_checks(db, identity)
    total_catalog, active_catalog, latest = db.execute(
        """SELECT COUNT(*),
                  COALESCE(SUM(story_id NOT IN (SELECT story_id FROM story_aliases)), 0),
                  MAX(CASE WHEN story_id NOT IN (SELECT story_id FROM story_aliases) THEN updated_at END)
           FROM public_catalog"""
    ).fetchone()
    retired_catalog = total_catalog - active_catalog
    not_omitted_sql = (
        "NOT EXISTS (SELECT 1 FROM public_catalog_checks chk JOIN public_catalog pc ON pc.story_id=chk.story_id "
        "WHERE chk.story_id={col} AND chk.template_hash=? AND chk.omitted=1 "
        "AND pc.template_hash!=? AND pc.json_sha256=chk.json_sha256)"
    )
    if omitted_ids:
        count, latest = db.execute(
            f"""SELECT COUNT(*), MAX(c.updated_at)
                FROM public_catalog c
                WHERE c.story_id NOT IN (SELECT story_id FROM story_aliases)
                  AND {not_omitted_sql.format(col='c.story_id')}""",
            (identity, identity),
        ).fetchone()
    else:
        count = active_catalog
    pending, skipped = db.execute(
        "SELECT COALESCE(SUM(last_error IS NULL), 0), COALESCE(SUM(last_error IS NOT NULL), 0) FROM public_render_queue"
    ).fetchone()
    if not total_catalog and skipped and not pending:
        raise ValueError("No stored story can be rendered")
    if not total_catalog and not pending:
        news = output / "news"
        if news.is_symlink() or next(news.glob("*/index.html"), None) is not None:
            raise ValueError("Refusing an empty catalog over existing published articles; restore publication history")
    views = digest([site, identity, store_mod.get_meta(db, "publication_catalog_revision"), retired_catalog, omitted_ids])
    refresh = restart_rebuild or store_mod.get_meta(db, "publication_views") != views
    health = store.health(config["sources"], config["collection"]["stale_after_seconds"], observed)
    with db:
        for name, content_type in render.ASSET_FILES.items():
            path = Path(render.__file__).parent / "assets" / name
            artifacts.write(name, [path.read_bytes()], content_type)
        artifacts.text("_headers", render.headers_text(base), "text/plain; charset=utf-8")
        _listing(artifacts, site, base, health, count=count, latest=latest, refresh=refresh)
        if refresh:
            for topic in render.CATEGORIES:
                if omitted_ids:
                    t_count, t_latest = db.execute(
                        f"""SELECT COUNT(*), MAX(t.updated_at)
                            FROM public_story_topics t
                            WHERE t.topic=?
                              AND t.story_id NOT IN (SELECT story_id FROM story_aliases)
                              AND {not_omitted_sql.format(col='t.story_id')}""",
                        (topic, identity, identity),
                    ).fetchone()
                else:
                    t_count, t_latest = db.execute(
                        "SELECT COUNT(*),MAX(updated_at) FROM public_story_topics WHERE topic=? AND story_id NOT IN (SELECT story_id FROM story_aliases)",
                        (topic,),
                    ).fetchone()
                _listing(artifacts, site, base, [], count=t_count, latest=t_latest, refresh=True, topic=topic)
            _feeds(artifacts, db, site, base)
        changed = store_mod.get_meta(db, "publication_dirty") == "1"
        if changed:
            store_mod.bump_meta(db, "publication_generation")
        meta_updates = {
            "publication_views": views,
            "publication_dirty": "0",
            "publication_build_pending": "0",
            "published_stories": str(count),
        }
        if not pending:
            meta_updates["publication_rebuild_active"] = ""
        store_mod.set_meta(db, **meta_updates)
    result = {"public_changed": changed, "published_stories": count, "stories_skipped": skipped}
    if pending:
        result["articles_pending"] = pending
    return result
