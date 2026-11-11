"""Private consensus-health observations and candidates for source corroboration.

Repeated monitor reports do not establish significance or operational impact.
Only the ordinary source-backed news pipeline can publish an account.
"""

from __future__ import annotations

from itertools import islice

from .alert_formats import parse_alerts
from .util import after, canonical_url, digest, format_utc, parse_utc


DOCUMENT_CONDITIONS = {
    "authority-missing": "a missing authority in a consensus",
    "signature-missing": "a missing authority signature",
    "descriptor-missing": "a missing authority descriptor",
    "stale-consensus": "an outdated consensus document",
    **{f"flag-{flag.lower()}": f"a {flag}-flag discrepancy" for flag in (
        "Authority", "BadExit", "Exit", "Fast", "Guard", "HSDir", "Running",
        "Stable", "V2Dir", "Valid",
    )},
}
# Only recognized voting directory authorities enter the private observation set.
DIRECTORY_AUTHORITIES = frozenset(
    "bastet dannenberg dizum faravahar gabelmoo longclaw maatuska moria1 tor26".split())
MIN_REPORTS, MIN_SPAN_SECONDS = 10, 3600
CANDIDATE_WINDOW_SECONDS, WINDOW_SECONDS, MAX_FUTURE_SECONDS = 86400, 172800, 300
QUALIFYING_CONDITIONS = ("authority-missing", "signature-missing", "stale-consensus")
MAX_OBSERVATIONS, MAX_GROUPS = 10000, 2000
MAX_CANDIDATE_VIEW = 100
# Keep the former publication counter for report compatibility; it remains zero.
COUNTERS = ("observations", "duplicates", "rejected", "unsupported", "capacity", "published", "candidates")


def initialize(db) -> None:
    db.executescript("""
        CREATE TABLE IF NOT EXISTS monitoring_groups (
            group_key TEXT PRIMARY KEY, monitor_id TEXT NOT NULL,
            format TEXT NOT NULL, target TEXT NOT NULL, kind TEXT NOT NULL,
            state TEXT NOT NULL, episode_start TEXT NOT NULL,
            highwater TEXT NOT NULL, conditions TEXT NOT NULL, story_id TEXT
        );
        CREATE TABLE IF NOT EXISTS monitoring_observations (
            group_key TEXT NOT NULL REFERENCES monitoring_groups(group_key),
            stamp TEXT NOT NULL, condition TEXT NOT NULL, state TEXT NOT NULL,
            url TEXT NOT NULL, title TEXT NOT NULL,
            PRIMARY KEY(group_key, stamp, condition, state)
        );
        CREATE INDEX IF NOT EXISTS monitoring_observations_stamp
            ON monitoring_observations(stamp);
        DROP TABLE IF EXISTS monitoring_counters;
    """)


def _eligible(observation: dict) -> bool:
    # Private retention is a narrow allowlist, independent of parser output.
    return observation["condition"] in DOCUMENT_CONDITIONS and observation["target"] in DIRECTORY_AUTHORITIES


def _qualified(db, observed: str, monitor_id: str | None = None):
    """Count each authority/condition independently, without inferring impact."""
    observed = format_utc(parse_utc(observed))
    parameters = [after(-CANDIDATE_WINDOW_SECONDS, observed), observed, *QUALIFYING_CONDITIONS,
                  *sorted(DIRECTORY_AUTHORITIES)]
    monitor_filter = ""
    if monitor_id is not None:
        monitor_filter = " AND g.monitor_id=?"
        parameters.append(monitor_id)
    parameters.extend((MIN_REPORTS, MAX_GROUPS * len(QUALIFYING_CONDITIONS)))
    rows = db.execute(f"""SELECT g.group_key,g.monitor_id,g.target,g.episode_start,g.story_id,
        o.condition,COUNT(DISTINCT o.stamp) AS reports,MIN(o.stamp) AS first_report,MAX(o.stamp) AS last_report
        FROM monitoring_observations o JOIN monitoring_groups g ON g.group_key=o.group_key
        WHERE o.stamp>=? AND o.stamp<=? AND o.state='firing'
        AND g.format='consensus' AND g.kind='document'
        AND o.condition IN ({','.join('?' for _ in QUALIFYING_CONDITIONS)})
        AND g.target IN ({','.join('?' for _ in DIRECTORY_AUTHORITIES)}){monitor_filter}
        GROUP BY g.group_key,o.condition HAVING COUNT(DISTINCT o.stamp)>=?
        ORDER BY last_report DESC,g.monitor_id,g.target,o.condition LIMIT ?""", parameters)
    for row in rows:
        if (parse_utc(row["last_report"]) - parse_utc(row["first_report"])).total_seconds() >= MIN_SPAN_SECONDS:
            yield row


def candidates(db, observed: str, *, monitor_id: str | None = None) -> list[dict]:
    """Inspect current private candidates; this never creates or edits news."""
    result = []
    for row in islice(_qualified(db, observed, monitor_id), MAX_CANDIDATE_VIEW):
        sources = db.execute("""SELECT url,title FROM monitoring_observations
            WHERE group_key=? AND condition=? AND state='firing' AND stamp IN (?,?)
            ORDER BY stamp,url LIMIT 2""", (row["group_key"], row["condition"], row["first_report"], row["last_report"]))
        result.append({"monitor_id": row["monitor_id"], "authority": row["target"],
                       "condition": row["condition"], "description": DOCUMENT_CONDITIONS[row["condition"]],
                       "reports": row["reports"], "first_report": row["first_report"], "last_report": row["last_report"],
                       "episode_start": row["episode_start"], "story_id": row["story_id"],
                       "status": "needs-source-context", "sources": [dict(source) for source in sources]})
    return result

def ingest(db, source: dict, items: list[dict], observed: str) -> dict:
    """Fold one feed batch into private groups, never directly into articles.

    The observation window and episode identities remain independent of the
    shorter candidate window. Existing article rows and links are untouched.
    """
    observed = format_utc(parse_utc(observed))
    cutoff, future = after(-WINDOW_SECONDS, observed), after(MAX_FUTURE_SECONDS, observed)
    report = dict.fromkeys(COUNTERS, 0)
    batch = []
    for item in items:
        try:
            stamp = format_utc(parse_utc(item["published_at"]))
            url = canonical_url(item["url"])
            if not cutoff <= stamp <= future:
                raise ValueError("Notification is outside the current observation window")
        except (KeyError, TypeError, ValueError):
            report["rejected"] += 1
            continue
        observations, unsupported = parse_alerts(item, source["alert_format"])
        report["unsupported"] += unsupported
        title = " ".join(str(item.get("title")).split())[:200]
        for observation in observations:
            if not _eligible(observation):
                report["unsupported"] += 1
            elif len(batch) >= MAX_OBSERVATIONS:
                report["capacity"] += 1
            else:
                batch.append((stamp, url, title, observation))
    # Backfilled feed entries are normally newest-first. Process history in time order.
    batch.sort(key=lambda row: (row[0], row[1], row[3]["condition"]))
    with db:
        db.execute("DELETE FROM monitoring_observations WHERE stamp<?", (cutoff,))
        db.execute("DELETE FROM monitoring_groups WHERE highwater<?", (cutoff,))
        observation_count = db.execute("SELECT COUNT(*) FROM monitoring_observations").fetchone()[0]
        group_count = db.execute("SELECT COUNT(*) FROM monitoring_groups").fetchone()[0]
        for stamp, url, title, fact in batch:
            condition = fact["condition"]
            # Unchanged from when other kinds were kept, so existing groups continue.
            key = digest([source["monitor_id"], source["alert_format"], "document", fact["target"], "documents"])
            group = db.execute("SELECT highwater FROM monitoring_groups WHERE group_key=?", (key,)).fetchone()
            if (group is not None and stamp < group["highwater"]) or db.execute(
                "SELECT 1 FROM monitoring_observations WHERE group_key=? AND stamp=? AND condition=?",
                (key, stamp, condition),
            ).fetchone():
                report["duplicates"] += 1
                continue
            if observation_count >= MAX_OBSERVATIONS or (group is None and group_count >= MAX_GROUPS):
                report["capacity"] += 1
                continue
            if group is None:
                db.execute(
                    "INSERT INTO monitoring_groups VALUES(?,?,?,?,'document','firing',?,?,'[]',NULL)",
                    (key, source["monitor_id"], source["alert_format"], fact["target"], stamp, stamp),
                )
                group_count += 1
            db.execute("UPDATE monitoring_groups SET highwater=? WHERE group_key=?", (stamp, key))
            db.execute("INSERT INTO monitoring_observations VALUES(?,?,?,'firing',?,?)", (key, stamp, condition, url, title))
            observation_count += 1
            report["observations"] += 1
        report["candidates"] = sum(1 for _ in _qualified(db, observed, source["monitor_id"]))
    return report

