"""Incremental permanent publication with a bounded article queue.

The SQLite catalog retains compact last-good public JSON for offline recovery.
Raw evidence is excluded. Published article files are never removed when the
private source row changes or disappears.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
from pathlib import Path

from . import editorial, render
from .util import digest, now_iso


SCHEMA_VERSION = "4"
_ARTICLE = r"news/[A-Za-z0-9_-]{1,64}/(?:index\.html|story\.json)"
_TOPIC = "(?:" + "|".join(re.escape(topic) for topic in render.CATEGORIES) + ")"
_PATH = re.compile(r"(?:" + _ARTICLE + r"|page/[1-9][0-9]*/index\.html|topics/" + _TOPIC
                   + r"/(?:page/[1-9][0-9]*/)?index\.html|tags/" + _TOPIC
                   + r"\.xml|index\.html|feed\.(?:xml|json)|style\.css|mark\.svg|_headers)\Z")


def initialize(db) -> None:
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
        CREATE INDEX IF NOT EXISTS public_catalog_published ON public_catalog(published_at DESC,updated_at DESC,story_id DESC);
        CREATE INDEX IF NOT EXISTS public_catalog_updated ON public_catalog(updated_at DESC,published_at DESC,story_id DESC);
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
        CREATE TRIGGER IF NOT EXISTS public_story_insert AFTER INSERT ON stories BEGIN
            INSERT INTO public_render_queue(story_id,last_error) VALUES(NEW.id,NULL)
            ON CONFLICT(story_id) DO UPDATE SET last_error=NULL;
        END;
        CREATE TRIGGER IF NOT EXISTS public_story_update AFTER UPDATE OF payload ON stories
            WHEN OLD.payload IS NOT NEW.payload BEGIN
            INSERT INTO public_render_queue(story_id,last_error) VALUES(NEW.id,NULL)
            ON CONFLICT(story_id) DO UPDATE SET last_error=NULL;
        END;
        CREATE TRIGGER IF NOT EXISTS public_story_delete AFTER DELETE ON stories BEGIN
            DELETE FROM public_render_queue WHERE story_id=OLD.id;
        END;
    """)
    columns = {row[1] for row in db.execute("PRAGMA table_info(public_catalog)")}
    if "public_json" not in columns:
        db.execute("ALTER TABLE public_catalog ADD COLUMN public_json TEXT")
        db.commit()
    if "added_at" not in columns:
        db.execute("ALTER TABLE public_catalog ADD COLUMN added_at TEXT")
        db.commit()
    while True:
        rows = db.execute("SELECT story_id,published_at,public_json FROM public_catalog WHERE added_at IS NULL LIMIT 100").fetchall()
        if not rows:
            break
        with db:
            for row in rows:
                payload = json.loads(row["public_json"]) if row["public_json"] else {}
                added = render._iso(render._date(payload.get("added_at") or row["published_at"]))
                db.execute("UPDATE public_catalog SET added_at=? WHERE story_id=?", (added, row["story_id"]))
    db.execute("CREATE INDEX IF NOT EXISTS public_catalog_added ON public_catalog(added_at DESC,updated_at DESC,story_id DESC)")
    db.commit()
    if _meta(db, "publication_schema") != SCHEMA_VERSION:
        with db:
            db.execute("INSERT OR IGNORE INTO public_render_queue(story_id) SELECT id FROM stories UNION SELECT story_id FROM public_catalog")
            _set_meta(db, "publication_schema", SCHEMA_VERSION)


def _meta(db, key: str) -> str | None:
    row = db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
    return row[0] if row else None


def _set_meta(db, key: str, value: str) -> None:
    db.execute("INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


def publication_year() -> int:
    return datetime.now(timezone.utc).year


def template_identity(site: dict) -> str:
    root = Path(__file__).parent
    files = [(name, hashlib.sha256((root / name).read_bytes()).hexdigest()) for name in ("render.py", "publication.py", "editorial.py", "schema.py", "util.py")]
    return digest([SCHEMA_VERSION, files, publication_year(), {key: site.get(key) for key in ("title", "description", "base_url", "repository_url")}])


def _owned_output(value: str) -> Path:
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
    output.mkdir(parents=True, exist_ok=True)
    if not owner.exists():
        fd = os.open(owner, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write("Onion Flash generated output\n")
    return output


def _target(output: Path, relative: str) -> Path:
    if not _PATH.fullmatch(relative):
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
        result = hashlib.sha256()
        for block in iter(lambda: stream.read(65536), b""):
            result.update(block)
        return result.hexdigest()


class Artifacts:
    def __init__(self, db, output: Path, observed: str):
        self.db, self.output, self.observed = db, output, observed
        self.changed = 0

    @contextmanager
    def stream(self, relative: str, content_type: str):
        target = _target(self.output, relative)
        descriptor, temporary_name = tempfile.mkstemp(prefix=".onionflash-", dir=target.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                sink = _Sink(stream)
                yield sink
                stream.flush()
                os.fsync(stream.fileno())
            value, size = sink.checksum.hexdigest(), sink.size
            old = self.db.execute("SELECT sha256,size,content_type FROM public_artifacts WHERE path=?", (relative,)).fetchone()
            changed = old is None or tuple(old) != (value, size, content_type)
            if changed or not target.is_file() or _file_hash(target) != value:
                os.chmod(temporary, 0o644)
                os.replace(temporary, target)
            if changed:
                self.db.execute("""INSERT INTO public_artifacts(path,sha256,size,content_type,updated_at)
                    VALUES(?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET
                    sha256=excluded.sha256,size=excluded.size,content_type=excluded.content_type,updated_at=excluded.updated_at""",
                    (relative, value, size, content_type, self.observed))
                self.changed += 1
                _set_meta(self.db, "publication_dirty", "1")
        finally:
            temporary.unlink(missing_ok=True)

    def write(self, relative: str, chunks, content_type: str) -> str:
        with self.stream(relative, content_type) as sink:
            for chunk in chunks:
                sink.write(chunk)
        return sink.checksum.hexdigest()

    def text(self, relative: str, text: str, content_type: str) -> str:
        return self.write(relative, [text.encode("utf-8")], content_type)


class _Sink:
    def __init__(self, stream):
        self.stream, self.checksum, self.size = stream, hashlib.sha256(), 0

    def write(self, chunk: bytes) -> None:
        self.stream.write(chunk)
        self.checksum.update(chunk)
        self.size += len(chunk)


def _public_story(row) -> dict:
    payload = row["public_json"]
    if not isinstance(payload, str) or hashlib.sha256(payload.encode("utf-8")).hexdigest() != row["json_sha256"]:
        raise ValueError("Accepted public story snapshot is missing or changed")
    decoded = json.loads(payload)
    story = render._prepare_story(decoded, editorial=decoded.get("editorial"))
    if story["id"] != row["story_id"]:
        raise ValueError("Accepted story identity differs from its catalog entry")
    return story


def _accepted(db, *, order: str = "added_at", batch_size: int = 100, topic: str | None = None):
    if order not in {"added_at", "updated_at"}:
        raise ValueError("Invalid catalog ordering")
    if topic is not None and (topic not in render.CATEGORIES or order != "added_at"):
        raise ValueError("Invalid topic catalog ordering")
    cursor = None
    secondary = "updated_at" if order == "added_at" else "published_at"
    while True:
        if topic is None:
            where = "" if cursor is None else f"WHERE ({order},{secondary},story_id) < (?,?,?)"
            parameters = (batch_size,) if cursor is None else (*cursor, batch_size)
            query = f"SELECT story_id,published_at,updated_at,added_at,json_sha256,public_json FROM public_catalog {where} ORDER BY {order} DESC,{secondary} DESC,story_id DESC LIMIT ?"
        else:
            where = "" if cursor is None else "AND (t.added_at,t.updated_at,t.story_id) < (?,?,?)"
            parameters = (topic, *(() if cursor is None else cursor), batch_size)
            query = f"""SELECT c.story_id,c.published_at,c.updated_at,c.added_at,c.json_sha256,c.public_json
                FROM public_story_topics t JOIN public_catalog c ON c.story_id=t.story_id
                WHERE t.topic=? {where} ORDER BY t.added_at DESC,t.updated_at DESC,t.story_id DESC LIMIT ?"""
        rows = db.execute(query, parameters).fetchall()
        if not rows:
            return
        for row in rows:
            yield _public_story(row)
        cursor = (rows[-1][order], rows[-1][secondary], rows[-1]["story_id"])


def _story_topics(db, story: dict) -> set[str]:
    old = {row[0] for row in db.execute("SELECT topic FROM public_story_topics WHERE story_id=?", (story["id"],))}
    topics = {story["category"], *story["tags"]}
    db.execute("DELETE FROM public_story_topics WHERE story_id=?", (story["id"],))
    db.executemany("INSERT INTO public_story_topics(topic,story_id,added_at,updated_at) VALUES(?,?,?,?)",
                   [(topic, story["id"], story["added_at"], story["updated_at"]) for topic in topics])
    return old | topics


def _backfill_topics(db) -> None:
    if _meta(db, "publication_topics") == "1":
        return
    cursor = ""
    while True:
        rows = db.execute("SELECT * FROM public_catalog WHERE story_id>? ORDER BY story_id LIMIT 100", (cursor,)).fetchall()
        if not rows:
            break
        with db:
            for row in rows:
                _story_topics(db, _public_story(row))
        cursor = rows[-1]["story_id"]
    with db:
        _set_meta(db, "publication_topics", "1")


def _backfill_public_json(db, output: Path) -> None:
    # Upgrade early publication catalogs from their verified on-disk snapshots.
    while True:
        rows = db.execute("SELECT story_id,json_sha256 FROM public_catalog WHERE public_json IS NULL LIMIT 100").fetchall()
        if not rows:
            return
        with db:
            for row in rows:
                path = _target(output, f"news/{row['story_id']}/story.json")
                if not path.is_file() or _file_hash(path) != row["json_sha256"]:
                    raise ValueError("Cannot migrate missing last-good story snapshot")
                payload = path.read_text(encoding="utf-8")
                decoded = json.loads(payload)
                story = render._prepare_story(decoded, editorial=decoded.get("editorial"))
                if story["id"] != row["story_id"]:
                    raise ValueError("Invalid last-good story identity")
                db.execute("UPDATE public_catalog SET public_json=? WHERE story_id=?", (payload, row["story_id"]))


def _feeds(artifacts: Artifacts, db, site: dict, base: str, limit: int) -> None:
    # Fan out one bounded catalog pass instead of rereading it for every topic.
    with ExitStack() as stack:
        writers = {category: stack.enter_context(artifacts.stream(
            "feed.xml" if category is None else f"tags/{category}.xml",
            "application/rss+xml; charset=utf-8")) for category in (None, *render.CATEGORIES)}
        counts = dict.fromkeys(writers, 0)
        json_writer = stack.enter_context(artifacts.stream("feed.json", "application/feed+json; charset=utf-8"))
        json_writer.write(render.json_feed_header(site, base))
        for story in _accepted(db, order="updated_at"):
            xml = None
            for category, writer in writers.items():
                if (category and category not in story["tags"]) or (limit and counts[category] >= limit):
                    continue
                if not counts[category]:
                    path = "feed.xml" if category is None else f"tags/{category}.xml"
                    writer.write(render.rss_header(site, base, path, story["updated_at"], category))
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
                path = "feed.xml" if category is None else f"tags/{category}.xml"
                writer.write(render.rss_header(site, base, path, None, category))
            writer.write(b"</channel></rss>")
        json_writer.write(b"]}\n")


def _remove_owned_file(artifacts: Artifacts, row, target: Path) -> None:
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise ValueError("Retired public artifact must be a regular file")
    if target.exists() and _file_hash(target) != row["sha256"]:
        raise ValueError("Retired public artifact changed outside the builder")
    target.unlink(missing_ok=True)
    artifacts.db.execute("DELETE FROM public_artifacts WHERE path=?", (row["path"],))
    artifacts.changed += 1
    _set_meta(artifacts.db, "publication_dirty", "1")


def _retire_script(artifacts: Artifacts) -> None:
    target = artifacts.output / "app.js"
    row = artifacts.db.execute("SELECT path,sha256 FROM public_artifacts WHERE path='app.js'").fetchone()
    if row is not None:
        _remove_owned_file(artifacts, row, target)
    elif target.exists() or target.is_symlink():
        raise ValueError("Refusing to remove an untracked legacy app.js")


def _migration_ready(artifacts: Artifacts, identity: str, pending: int) -> bool:
    if _meta(artifacts.db, "publication_no_browser_js_ready") == "1":
        return True
    if pending or artifacts.db.execute("SELECT 1 FROM public_catalog WHERE template_hash<>? LIMIT 1", (identity,)).fetchone():
        return False
    # An archived article may have no local HTML. Its ledger record still owns
    # a permanent URL and must have a current accepted catalog entry.
    orphan = artifacts.db.execute("""SELECT a.path FROM public_artifacts a LEFT JOIN public_catalog c
        ON c.story_id=substr(a.path,6,length(a.path)-16)
        WHERE a.path GLOB 'news/*/index.html' AND c.story_id IS NULL LIMIT 1""").fetchone()
    if orphan is not None:
        raise ValueError("Unverified article artifact; restore publication history before removing browser JavaScript")
    news = artifacts.output / "news"
    if news.is_symlink() or (news.exists() and not news.is_dir()):
        raise ValueError("Published article directory must be a real directory")
    if news.exists():
        with os.scandir(news) as entries:
            for entry in entries:
                if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                    raise ValueError("Unexpected existing article path; restore publication history")
                page = Path(entry.path) / "index.html"
                if not page.exists() and not page.is_symlink():
                    continue
                row = artifacts.db.execute("""SELECT a.sha256 FROM public_catalog c JOIN public_artifacts a
                    ON a.path='news/' || c.story_id || '/index.html'
                    WHERE c.story_id=? AND c.template_hash=?""", (entry.name, identity)).fetchone()
                if row is None or page.is_symlink() or not page.is_file() or _file_hash(page) != row[0]:
                    raise ValueError("Unverified existing article; restore publication history before removing browser JavaScript")
    return True


def _remove_obsolete_pages(artifacts: Artifacts, pages: int, topic: str | None = None) -> None:
    # Pagination is a view, not a story permalink. Its old pages can disappear
    # when the configured page size grows; article artifacts are never removed.
    prefix = "page/" if topic is None else f"topics/{topic}/page/"
    cursor = ""
    while True:
        rows = artifacts.db.execute("SELECT path,sha256 FROM public_artifacts WHERE path LIKE ? AND path>? ORDER BY path LIMIT 100", (prefix + "%", cursor)).fetchall()
        if not rows:
            return
        cursor = rows[-1]["path"]
        for row in rows:
            match = re.fullmatch(re.escape(prefix) + r"([1-9][0-9]*)/index\.html", row["path"])
            if not match or int(match[1]) <= pages:
                continue
            target = _target(artifacts.output, row["path"])
            _remove_owned_file(artifacts, row, target)


def _listing(artifacts: Artifacts, site: dict, base: str, health: list, *, count: int,
             latest: str | None, refresh: bool, topic: str | None = None) -> None:
    page_size = site["page_size"]
    pages = max(1, (count + page_size - 1) // page_size)
    stories = iter(_accepted(artifacts.db, topic=topic))
    prefix = "" if topic is None else f"topics/{topic}/"
    for page in range(1, pages + 1 if refresh else 2):
        batch = []
        for _ in range(page_size):
            try:
                batch.append(next(stories))
            except StopIteration:
                break
        relative = prefix + ("index.html" if page == 1 else f"page/{page}/index.html")
        artifacts.text(relative, render.index_html(site, base, batch, health if page == 1 else [],
                       total=count, page=page, pages=pages, latest=latest, topic=topic), "text/html; charset=utf-8")
    if refresh:
        _remove_obsolete_pages(artifacts, pages, topic)


def build(config: dict, store, *, force: bool = False) -> dict:
    """Update changed artifacts; the caller holds the existing database lock."""
    db, site = store.db, config["site"]
    initialize(db)
    output_missing = not Path(config["storage"]["output_dir"]).exists()
    output = _owned_output(config["storage"]["output_dir"])
    _backfill_public_json(db, output)
    base = site["base_url"].rstrip("/") + "/"  # validated by load_config
    observed = now_iso()
    identity = template_identity(site)
    with db:
        _set_meta(db, "publication_build_pending", "1")
        if _meta(db, "publication_no_browser_js_ready") is None:
            _set_meta(db, "publication_no_browser_js_ready", "0")
    template_changed = _meta(db, "publication_template") != identity
    queued = db.execute("SELECT COUNT(*) FROM public_render_queue WHERE last_error IS NULL").fetchone()[0]
    restart_rebuild = template_changed or output_missing or (force and (
        _meta(db, "publication_rebuild_active") != identity or not queued
    ))
    if restart_rebuild:
        with db:
            db.execute("INSERT OR REPLACE INTO public_render_queue(story_id,last_error) SELECT id,NULL FROM stories UNION SELECT story_id,NULL FROM public_catalog")
            _set_meta(db, "publication_template", identity)
            _set_meta(db, "publication_rebuild_active", identity)
    artifacts = Artifacts(db, output, observed)
    limit = config["storage"].get("render_batch_size", 250)
    candidates = db.execute("""SELECT public_render_queue.story_id AS id,stories.payload FROM public_render_queue
        LEFT JOIN stories ON stories.id=public_render_queue.story_id
        WHERE public_render_queue.last_error IS NULL ORDER BY public_render_queue.rowid LIMIT ?""", (limit,)).fetchall()
    for row in candidates:
        quarantined = False
        source_hash = digest(row["payload"])
        accepted = None
        if row["payload"] is None:
            accepted = db.execute("SELECT * FROM public_catalog WHERE story_id=?", (row["id"],)).fetchone()
            if accepted is None:
                with db:
                    db.execute("DELETE FROM public_render_queue WHERE story_id=?", (row["id"],))
                continue
            source_hash = accepted["source_hash"]
        try:
            story = _public_story(accepted) if accepted is not None else render._prepare_story(
                json.loads(row["payload"]), editorial=editorial.public_metadata(db, row["id"]))
            if story["id"] != row["id"]:
                raise ValueError("Story identity differs from its database row")
            article = render.article_html(site, base, story)
            public_json = json.dumps(story, ensure_ascii=False, sort_keys=True) + "\n"
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            with db:
                db.execute("UPDATE public_render_queue SET last_error=? WHERE story_id=?", (type(exc).__name__, row["id"]))
            logging.getLogger(__name__).warning("Quarantined unrenderable story (%s)", type(exc).__name__)
            accepted = db.execute("SELECT * FROM public_catalog WHERE story_id=?", (row["id"],)).fetchone()
            if accepted is None:
                continue
            # Restore the last accepted version even if the latest private
            # source revision is corrupt. It remains visibly quarantined.
            try:
                story = _public_story(accepted)
                article = render.article_html(site, base, story)
            except (ValueError, TypeError, KeyError, AttributeError):
                continue
            public_json, source_hash = accepted["public_json"], accepted["source_hash"]
            quarantined = True
        with db:
            artifacts.text(f"news/{story['id']}/index.html", article, "text/html; charset=utf-8")
            checksum = artifacts.text(f"news/{story['id']}/story.json", public_json, "application/json; charset=utf-8")
            previous = db.execute("SELECT json_sha256 FROM public_catalog WHERE story_id=?", (story["id"],)).fetchone()
            changed = previous is None or previous[0] != checksum
            if changed:
                revision = str(int(_meta(db, "publication_catalog_revision") or 0) + 1)
                _set_meta(db, "publication_catalog_revision", revision)
                for topic in _story_topics(db, story):
                    _set_meta(db, "publication_topic_revision:" + topic, revision)
            db.execute("""INSERT INTO public_catalog(story_id,published_at,updated_at,added_at,source_hash,template_hash,json_sha256,public_json)
                VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(story_id) DO UPDATE SET
                published_at=excluded.published_at,updated_at=excluded.updated_at,added_at=excluded.added_at,source_hash=excluded.source_hash,
                template_hash=excluded.template_hash,json_sha256=excluded.json_sha256,public_json=excluded.public_json""",
                (story["id"], story["published_at"], story["updated_at"], story["added_at"], source_hash, identity, checksum, public_json))
            if not quarantined:
                db.execute("DELETE FROM public_render_queue WHERE story_id=?", (story["id"],))
    # Repair this bounded queue batch before validating historical snapshots.
    # A damaged catalog row later in the queue can then recover on a subsequent
    # run, while the incomplete-build marker keeps partial work unpublished.
    _backfill_topics(db)
    count = db.execute("SELECT COUNT(*) FROM public_catalog").fetchone()[0]
    pending = db.execute("SELECT COUNT(*) FROM public_render_queue WHERE last_error IS NULL").fetchone()[0]
    skipped = db.execute("SELECT COUNT(*) FROM public_render_queue WHERE last_error IS NOT NULL").fetchone()[0]
    if not count and skipped and not pending:
        raise ValueError("No stored story can be rendered")
    if not count and not pending:
        news = output / "news"
        if news.is_symlink() or next(news.glob("*/index.html"), None) is not None:
            raise ValueError("Refusing an empty catalog over existing published articles; restore publication history")
    latest = db.execute("SELECT MAX(updated_at) FROM public_catalog").fetchone()[0]
    page_size, feed_size = site["page_size"], site.get("feed_size", 0)
    index_settings = digest([page_size, site, identity])
    revision = _meta(db, "publication_catalog_revision") or "0"
    refresh_requested = force and restart_rebuild
    refresh_all = template_changed or output_missing or refresh_requested or _meta(db, "publication_indexes") != index_settings
    refresh_indexes = refresh_all or _meta(db, "publication_index_revision") != revision
    health = store.health(config["sources"], config["collection"]["stale_after_seconds"], observed)
    with db:
        for name in render.ASSET_FILES:
            path = Path(render.__file__).parent / "assets" / name
            content_type = {"style.css": "text/css; charset=utf-8", "mark.svg": "image/svg+xml"}[name]
            artifacts.write(name, [path.read_bytes()], content_type)
        artifacts.text("_headers", render.headers_text(base), "text/plain; charset=utf-8")
        _listing(artifacts, site, base, health, count=count, latest=latest, refresh=refresh_indexes)
        for topic in render.CATEGORIES:
            topic_revision = _meta(db, "publication_topic_revision:" + topic) or "0"
            if refresh_all or _meta(db, "publication_topic_index:" + topic) != topic_revision:
                stats = db.execute("SELECT COUNT(*),MAX(updated_at) FROM public_story_topics WHERE topic=?", (topic,)).fetchone()
                _listing(artifacts, site, base, [], count=stats[0], latest=stats[1], refresh=True, topic=topic)
                _set_meta(db, "publication_topic_index:" + topic, topic_revision)
        feed_settings = digest([feed_size, site, identity])
        if output_missing or refresh_requested or _meta(db, "publication_feeds") != feed_settings or _meta(db, "publication_feed_revision") != revision:
            _feeds(artifacts, db, site, base, feed_size)
            _set_meta(db, "publication_feeds", feed_settings)
            _set_meta(db, "publication_feed_revision", revision)
        _set_meta(db, "publication_indexes", index_settings)
        _set_meta(db, "publication_index_revision", revision)
        ready = _migration_ready(artifacts, identity, pending)
        if ready:
            _retire_script(artifacts)
            _set_meta(db, "publication_no_browser_js_ready", "1")
        changed = _meta(db, "publication_dirty") == "1"
        if changed:
            _set_meta(db, "publication_generation", str(int(_meta(db, "publication_generation") or 0) + 1))
        _set_meta(db, "publication_dirty", "0")
        _set_meta(db, "publication_build_pending", "0")
        if not pending:
            _set_meta(db, "publication_rebuild_active", "")
        _set_meta(db, "public_skipped", str(skipped))
        _set_meta(db, "published_stories", str(count))
    result = {"public_changed": changed, "published_stories": count, "stories_skipped": skipped, "no_browser_js_ready": ready}
    if pending:
        result["articles_pending"] = pending
    return result
