"""Bounded, deterministic monitoring observations; never an LLM news source.

Repeats are private evidence. Public stories change only at promotion or explicit
recovery, so an hourly notification does not become an hourly RSS update.
"""

from __future__ import annotations

import json
import re

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
COUNTERS = ("observations", "duplicates", "rejected", "unsupported", "capacity", "published", "recovered")


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
        CREATE TABLE IF NOT EXISTS monitoring_counters (
            name TEXT PRIMARY KEY, count INTEGER NOT NULL
        );
    """)


def _normalized(observation: dict, alert_format: str) -> dict | None:
    if not isinstance(observation, dict) or set(observation) != {"target", "condition", "kind", "state"}:
        return None
    if any(not isinstance(value, str) for value in observation.values()):
        return None
    target = " ".join(observation["target"].split())
    condition, kind, state = (observation[key] for key in ("condition", "kind", "state"))
    if not target or len(target) > 512 or not re.fullmatch(r"[a-z0-9-]{1,80}", condition):
        return None
    if kind not in {"document", "monitor", "service"} or state not in {"firing", "resolved"}:
        return None
    # Public eligibility is a narrow allowlist, independent of parser output.
    if kind == "document" and (
        alert_format != "consensus" or condition not in DOCUMENT_CONDITIONS
        or not re.fullmatch(r"[a-z0-9_-]{1,64}", target)
    ):
        return None
    return {**observation, "target": target}


def _promote(db, group, source, settings, cutoff) -> bool:
    if group["kind"] != "document" or group["state"] != "firing" or group["story_id"]:
        return False
    active = set(json.loads(group["conditions"]))
    rows = [row for row in db.execute(
        """SELECT stamp,condition,url,title FROM monitoring_observations
        WHERE group_key=? AND stamp>=? AND state='firing' ORDER BY stamp,url,condition""",
        (group["group_key"], max(cutoff, group["episode_start"])),
    ) if row["condition"] in active]
    conditions = []
    qualified_reports = []
    links = {}
    for condition in sorted({row["condition"] for row in rows}):
        resolved = db.execute(
            "SELECT MAX(stamp) FROM monitoring_observations WHERE group_key=? AND condition=? AND state='resolved'",
            (group["group_key"], condition),
        ).fetchone()[0]
        reports = [row for row in rows if row["condition"] == condition and (resolved is None or row["stamp"] > resolved)]
        stamps = sorted({row["stamp"] for row in reports})
        if len(stamps) < settings["min_reports"] or (
            parse_utc(stamps[-1]) - parse_utc(stamps[0])
        ).total_seconds() < settings["min_span_seconds"]:
            continue
        # Retain boundary evidence for every condition we describe. A bundle can
        # support several conditions; extra uncited scope stays private.
        boundaries = {row["url"]: {"url": row["url"], "title": row["title"]}
                      for row in (reports[0], reports[-1])}
        if len(set(links) | set(boundaries)) <= settings["max_source_links"]:
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
    }
    db.execute(
        "INSERT INTO stories(id,cluster_key,payload,published_at,updated_at) VALUES(?,?,?,?,?)",
        (story_id, cluster, json.dumps(payload, ensure_ascii=False), stamps[0], stamps[-1]),
    )
    db.execute("UPDATE monitoring_groups SET story_id=? WHERE group_key=?", (story_id, group["group_key"]))
    return True


def _recover(db, group, stamp, url, title, max_links) -> bool:
    if not group["story_id"]:
        return False
    row = db.execute("SELECT payload FROM stories WHERE id=?", (group["story_id"],)).fetchone()
    if row is None:
        return False
    payload = json.loads(row["payload"])
    payload["summary"] += f" A later notification explicitly reported the monitored conditions resolved at {stamp}."
    payload["state"] = "resolved"
    payload["updated_at"] = stamp
    payload["sources"] = ([{"url": url, "title": title}] + [
        source for source in payload["sources"] if source["url"] != url
    ])[:max_links]
    db.execute("UPDATE stories SET payload=?,updated_at=? WHERE id=?", (json.dumps(payload, ensure_ascii=False), stamp, group["story_id"]))
    return True


def ingest(db, source: dict, items: list[dict], settings: dict, observed: str) -> dict:
    """Fold one bounded feed batch into private groups and conservative stories.

    High-water marks outlive observation retention. New groups fail closed at
    capacity rather than evicting those marks and allowing old alerts to replay.
    Source URLs and notification counts are frozen once a story is promoted.
    """
    observed = format_utc(parse_utc(observed))
    cutoff = after(-settings["window_seconds"], observed)
    future = after(settings.get("max_future_seconds", 300), observed)
    report = dict.fromkeys(COUNTERS, 0)
    batch = []
    for item in items:
        try:
            stamp = format_utc(parse_utc(item["published_at"]))
            url = canonical_url(item["url"])
            if not cutoff <= stamp <= future:
                raise ValueError("Notification is outside the current observation window")
        except (KeyError, TypeError, ValueError, UnicodeError):
            report["rejected"] += 1
            continue
        observations, unsupported = parse_alerts(item, source["alert_format"], limit=settings["max_alerts_per_item"])
        report["unsupported"] += unsupported
        title = " ".join(str(item.get("title", "Monitoring notification")).split())[:200]
        for observation in observations:
            normalized = _normalized(observation, source["alert_format"])
            if normalized is None:
                report["unsupported"] += 1
            elif len(batch) >= settings["max_observations"]:
                report["capacity"] += 1
            else:
                batch.append((stamp, url, title, normalized))
    # Mixed states within a group at the same timestamp provide no all-clear.
    # In particular, resolving one document condition while another starts must
    # not briefly resolve the public story or start a new authority episode.
    def notification_group(row):
        stamp, _, _, fact = row
        return (stamp, fact["target"], fact["kind"],
                "documents" if fact["kind"] == "document" else fact["condition"])

    states = {}
    for row in batch:
        states.setdefault(notification_group(row), set()).add(row[3]["state"])
    conflicts = {identity for identity, values in states.items() if len(values) > 1}
    if conflicts:
        accepted = [row for row in batch if notification_group(row) not in conflicts]
        report["rejected"] += len(batch) - len(accepted)
        batch = accepted
    # Backfilled feed entries are normally newest-first. Process history in time order.
    batch.sort(key=lambda row: (row[0], row[3]["state"] == "firing", row[1], row[3]["condition"]))
    with db:
        retention = max(settings["retention_days"] * 86400, settings["window_seconds"])
        db.execute("DELETE FROM monitoring_observations WHERE stamp<?", (after(-retention, observed),))
        observation_count = db.execute("SELECT COUNT(*) FROM monitoring_observations").fetchone()[0]
        group_count = db.execute("SELECT COUNT(*) FROM monitoring_groups").fetchone()[0]
        affected = set()
        for stamp, url, title, fact in batch:
            kind, condition, state = (fact[key] for key in ("kind", "condition", "state"))
            key = digest([source["monitor_id"], source["alert_format"], kind,
                          fact["target"], "documents" if kind == "document" else condition])
            group = db.execute("SELECT * FROM monitoring_groups WHERE group_key=?", (key,)).fetchone()
            if group is not None and (stamp < group["highwater"] or (
                group["state"] == "resolved" and stamp <= group["highwater"]
            )):
                report["duplicates"] += 1
                continue
            duplicate = db.execute(
                "SELECT 1 FROM monitoring_observations WHERE group_key=? AND stamp=? AND condition=? AND state=?",
                (key, stamp, condition, state),
            ).fetchone()
            if duplicate:
                report["duplicates"] += 1
                continue
            # A recovery at an already-seen warning timestamp is ambiguous, not an all-clear.
            if group is not None and state == "resolved" and stamp == group["highwater"] and db.execute(
                "SELECT 1 FROM monitoring_observations WHERE group_key=? AND stamp=? AND state='firing' LIMIT 1",
                (key, stamp),
            ).fetchone():
                report["rejected"] += 1
                continue
            if observation_count >= settings["max_observations"] or (group is None and group_count >= settings["max_groups"]):
                report["capacity"] += 1
                continue
            if group is None:
                db.execute(
                    "INSERT INTO monitoring_groups VALUES(?,?,?,?,?,?,?,?,?,NULL)",
                    (key, source["monitor_id"], source["alert_format"], fact["target"], kind, state, stamp, stamp, "[]"),
                )
                group_count += 1
                group = db.execute("SELECT * FROM monitoring_groups WHERE group_key=?", (key,)).fetchone()
            elif group["state"] == "resolved" and state == "firing":
                db.execute("UPDATE monitoring_groups SET episode_start=?,story_id=NULL,conditions='[]' WHERE group_key=?", (stamp, key))
                group = db.execute("SELECT * FROM monitoring_groups WHERE group_key=?", (key,)).fetchone()
            conditions = set(json.loads(group["conditions"]))
            if state == "firing":
                conditions.add(condition)
            else:
                conditions.discard(condition)
            group_state = "firing" if conditions else "resolved"
            if group_state == "resolved" and group["state"] == "firing":
                report["recovered"] += int(_recover(db, group, stamp, url, title, settings["max_source_links"]))
            db.execute(
                "UPDATE monitoring_groups SET state=?,highwater=?,conditions=? WHERE group_key=?",
                (group_state, stamp, json.dumps(sorted(conditions)), key),
            )
            db.execute("INSERT INTO monitoring_observations VALUES(?,?,?,?,?,?)", (key, stamp, condition, state, url, title))
            observation_count += 1
            report["observations"] += 1
            affected.add(key)
        for key in sorted(affected):
            group = db.execute("SELECT * FROM monitoring_groups WHERE group_key=?", (key,)).fetchone()
            report["published"] += int(_promote(db, group, source, settings, cutoff))
        for key in ("unsupported", "rejected", "capacity"):
            if report[key]:
                db.execute("""INSERT INTO monitoring_counters VALUES(?,?)
                    ON CONFLICT(name) DO UPDATE SET count=count+excluded.count""", (key, report[key]))
    return report


def status(db, settings: dict, observed: str) -> dict:
    cutoff = after(-settings["stale_after_seconds"], format_utc(parse_utc(observed)))
    row = db.execute("""SELECT COUNT(*) AS groups,
        COALESCE(SUM(state='firing'),0) AS active,
        COALESCE(SUM(state='firing' AND story_id IS NULL),0) AS held,
        COALESCE(SUM(state='firing' AND story_id IS NOT NULL),0) AS published,
        COALESCE(SUM(state='resolved'),0) AS resolved,
        COALESCE(SUM(state='firing' AND kind='monitor'),0) AS monitor_failures,
        COALESCE(SUM(state='firing' AND kind='service'),0) AS service_observations,
        COALESCE(SUM(state='firing' AND highwater<?),0) AS stale FROM monitoring_groups""", (cutoff,)).fetchone()
    result = dict(row)
    result["observations"] = db.execute("SELECT COUNT(*) FROM monitoring_observations").fetchone()[0]
    counters = dict(db.execute("SELECT name,count FROM monitoring_counters"))
    result.update({key: counters.get(key, 0) for key in ("unsupported", "rejected", "capacity")})
    result["at_capacity"] = result["groups"] >= settings["max_groups"] or result["observations"] >= settings["max_observations"]
    return result
