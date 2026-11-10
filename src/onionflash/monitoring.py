"""Deterministic monitoring observations; never an LLM news source.

Only repeated consensus document warnings publish. A story is frozen once
published, so an hourly notification does not become an hourly RSS update.
"""

from __future__ import annotations

import json

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
# Voting directory authorities. Only these names can appear in public prose; an
# unknown name stays private until it is added here.
DIRECTORY_AUTHORITIES = frozenset(
    "bastet dannenberg dizum faravahar gabelmoo longclaw maatuska moria1 tor26".split())
MIN_REPORTS, MIN_SPAN_SECONDS, WINDOW_SECONDS, MAX_FUTURE_SECONDS = 2, 3600, 172800, 300
MAX_SOURCE_LINKS, MAX_OBSERVATIONS, MAX_GROUPS = 3, 10000, 2000
COUNTERS = ("observations", "duplicates", "rejected", "unsupported", "capacity", "published")


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


def _eligible(observation: dict, alert_format: str) -> bool:
    # Public eligibility is a narrow allowlist, independent of parser output.
    return observation["kind"] != "document" or (
        alert_format == "consensus" and observation["condition"] in DOCUMENT_CONDITIONS
        and observation["target"] in DIRECTORY_AUTHORITIES)


def _promote(db, group, source, cutoff, observed) -> bool:
    if group["kind"] != "document" or group["story_id"]:
        return False
    rows = db.execute(
        """SELECT stamp,condition,url,title FROM monitoring_observations
        WHERE group_key=? AND stamp>=? ORDER BY stamp,url,condition""",
        (group["group_key"], cutoff),
    ).fetchall()
    conditions, qualified_reports, links = [], [], {}
    for condition in sorted({row["condition"] for row in rows}):
        reports = [row for row in rows if row["condition"] == condition]
        stamps = sorted({row["stamp"] for row in reports})
        if len(stamps) < MIN_REPORTS or (
            parse_utc(stamps[-1]) - parse_utc(stamps[0])
        ).total_seconds() < MIN_SPAN_SECONDS:
            continue
        # Cite the first and last report of every described condition. A bundle can
        # support several conditions; extra uncited scope stays private.
        boundaries = {row["url"]: {"url": row["url"], "title": row["title"]}
                      for row in (reports[0], reports[-1])}
        if len(links | boundaries) <= MAX_SOURCE_LINKS:
            conditions.append(condition)
            qualified_reports.extend(reports)
            links.update(boundaries)
    if not conditions:
        return False
    stamps = sorted({row["stamp"] for row in qualified_reports})
    label = " ".join(str(source["name"]).split())[:100]
    cluster = "monitoring:" + digest([group["group_key"], group["episode_start"]])
    story_id = digest(cluster)[:24]
    facts = "; ".join(DOCUMENT_CONDITIONS[condition] for condition in conditions)
    payload = {
        "id": story_id,
        "title": f"Consensus-health notifications report repeated warnings for {group['target']}",
        "summary": (
            f"Across {len(stamps)} notifications dated {stamps[0]} through {stamps[-1]}, "
            f"{label} reported {facts} for {group['target']}. These are reports from a monitoring "
            "feed; the notifications do not establish a continuous outage, its cause, "
            "or its operational impact."
        ),
        "why_it_matters": "The repeated document checks provide a source-linked monitoring observation for further investigation; the cause and wider impact remain unestablished.",
        "category": "directory-authority", "products": ["network"],
        "priority": "normal", "confidence": "observed-anomaly", "state": "developing",
        "tags": ["directory-authority", "network"], "sources": list(links.values()),
        "published_at": stamps[0], "updated_at": stamps[-1],
        "added_at": observed,  # when Onion Flash published it; orders the homepage
    }
    db.execute(
        "INSERT INTO stories(id,cluster_key,payload,published_at,updated_at) VALUES(?,?,?,?,?)",
        (story_id, cluster, json.dumps(payload, ensure_ascii=False), stamps[0], stamps[-1]),
    )
    db.execute("UPDATE monitoring_groups SET story_id=? WHERE group_key=?", (story_id, group["group_key"]))
    return True


def ingest(db, source: dict, items: list[dict], observed: str) -> dict:
    """Fold one feed batch into private groups and frozen, conservative stories.

    Intake rejects notifications older than the window, so rows and groups that
    leave it can never replay and are deleted; a later recurrence is a new episode.
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
            if not _eligible(observation, source["alert_format"]):
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
        affected = set()
        for stamp, url, title, fact in batch:
            kind, condition = fact["kind"], fact["condition"]
            key = digest([source["monitor_id"], source["alert_format"], kind,
                          fact["target"], "documents" if kind == "document" else condition])
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
                    "INSERT INTO monitoring_groups VALUES(?,?,?,?,?,'firing',?,?,'[]',NULL)",
                    (key, source["monitor_id"], source["alert_format"], fact["target"], kind, stamp, stamp),
                )
                group_count += 1
            db.execute("UPDATE monitoring_groups SET highwater=? WHERE group_key=?", (stamp, key))
            db.execute("INSERT INTO monitoring_observations VALUES(?,?,?,'firing',?,?)", (key, stamp, condition, url, title))
            observation_count += 1
            report["observations"] += 1
            affected.add(key)
        for key in sorted(affected):
            group = db.execute("SELECT * FROM monitoring_groups WHERE group_key=?", (key,)).fetchone()
            report["published"] += int(_promote(db, group, source, cutoff, observed))
    return report


def status(db, observed: str) -> dict:
    cutoff = after(-WINDOW_SECONDS, format_utc(parse_utc(observed)))
    row = db.execute("""SELECT COUNT(*) AS groups,
        COALESCE(SUM(story_id IS NULL),0) AS held,
        COALESCE(SUM(story_id IS NOT NULL),0) AS published,
        COALESCE(SUM(kind='monitor'),0) AS monitor_failures,
        COALESCE(SUM(kind='service'),0) AS service_observations
        FROM monitoring_groups WHERE highwater>=?""", (cutoff,)).fetchone()
    result = dict(row)
    # Only the window counts; expired rows wait for the next ingest to delete them.
    result["observations"] = db.execute(
        "SELECT COUNT(*) FROM monitoring_observations WHERE stamp>=?", (cutoff,)).fetchone()[0]
    result["at_capacity"] = result["groups"] >= MAX_GROUPS or result["observations"] >= MAX_OBSERVATIONS
    return result
