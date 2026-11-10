"""Bounded, deterministic observations from known monitoring message templates.

These parsers describe what a monitor reported. They never infer attacks or
recovery, and authority names do not become independent monitors.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit


_AUTHORITY = r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}"
_LIST = rf"{_AUTHORITY}(?:, {_AUTHORITY})*"
_LEVEL = r"(?:ERROR|WARNING|NOTICE): "
_FLAG = re.compile(_LEVEL + rf"({_AUTHORITY}) had [0-9]+ ([A-Za-z][A-Za-z0-9]{{0,31}}) flags in its vote but the consensus had [0-9]+")
_CONSENSUS = [(re.compile(_LEVEL + pattern), condition, kind) for pattern, condition, kind in (
    (rf"The following authorities are missing from the consensus: ({_LIST})", "authority-missing", "document"),
    (rf"Consensus fetched from {_AUTHORITY} was missing the following authority signatures: ({_LIST})", "signature-missing", "document"),
    (rf"{_AUTHORITY} is missing the server descriptor of ({_AUTHORITY})", "descriptor-missing", "document"),
    (rf"The consensuses published by the following directory authorities are more than one hour old and therefore not fresh anymore: ({_LIST})", "stale-consensus", "document"),
    (rf"Unable to retrieve the consensus from ({_AUTHORITY}) \([^\n]+\):[^\n]*", "consensus-retrieval-failed", "monitor"),
    (rf"Unable to retrieve the vote from ({_AUTHORITY}) \([^\n]+\):[^\n]*", "vote-retrieval-failed", "monitor"),
    (rf"Unable to reach the ORPort of ({_AUTHORITY}) \([^\n]+\):[^\n]*", "orport-unreachable", "monitor"),
    (rf"Downloading the consensus from ({_AUTHORITY}) took [0-9]+(?:\.[0-9]+)?s\. Median download time is [^\n]+", "download-latency", "monitor"),
    (rf"The following directory authorities are not reporting bandwidth scanner results: ({_LIST})", "bandwidth-results-missing", "service"),
    (r"Authorities disagree about the BadExit flag for ([A-Fa-f0-9]{40}) \(with flag: [^\n]+, without flag: [^\n]+\)", "badexit-disagreement", "service"),
)]
MAX_ALERTS = 100  # distinct observations per message


def _observation(target: str, condition: str, kind: str) -> dict:
    return {"target": target, "condition": condition, "kind": kind}


def _consensus(text: str) -> tuple[list[dict], int]:
    observations, unsupported = [], 0
    for line in text.split("\n"):
        line = line.strip()
        if not line:
            continue
        flag = _FLAG.fullmatch(line)
        if flag:
            observations.append(_observation(flag[1].lower(), "flag-" + flag[2].lower(), "document"))
            continue
        for pattern, condition, kind in _CONSENSUS:
            match = pattern.fullmatch(line)
            if match:
                observations.extend(_observation(target.lower(), condition, kind) for target in match[1].split(", "))
                break
        else:
            unsupported += 1
    return observations, unsupported


def _endpoint(value: str) -> str | None:
    """Validate a label's endpoint syntax without resolving or contacting it."""
    if len(value) > 250 or any(c.isspace() for c in value) or "\\" in value:
        return None
    try:
        parsed = urlsplit("http://" + value)
        host, port = parsed.hostname, parsed.port
        if not host or not port or parsed.username is not None or parsed.password is not None or parsed.path or parsed.query or parsed.fragment:
            return None
        try:
            address = ipaddress.ip_address(host)
            host = f"[{address.compressed}]" if address.version == 6 else address.compressed
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host):
                return None
        return f"{host}:{port}"  # urlsplit lowercases the host
    except ValueError:
        return None


def _website(value: str) -> str | None:
    if len(value) > 300 or any(ord(c) < 33 for c in value) or "\\" in value:
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
            return None
        endpoint = _endpoint(parsed.netloc if parsed.port is not None else parsed.netloc + (":443" if parsed.scheme == "https" else ":80"))
        if endpoint is None:
            return None
        return urlunsplit((parsed.scheme, parsed.netloc.lower(), parsed.path, parsed.query, ""))
    except ValueError:
        return None


def _censorship_condition(summary: str, description: str) -> dict | None:
    match = re.fullmatch(r"([A-Za-z][A-Za-z -]{0,59}) Vantage Point Offline", summary)
    if match:
        country = match[1]
        detail = re.fullmatch(re.escape(country) + r" Vantage Point (\S+) was Offline for at least [1-9][0-9]{0,5} hours", description)
        endpoint = _endpoint(detail[1]) if detail else None
        return _observation(f"{country} / {endpoint}", "monitor-offline", "monitor") if endpoint else None
    match = re.fullmatch(r"The builtin bridge (\S+) is unreachable", summary)
    if match and description == "Unable to connect to the builtin bridge TCP port " + match[1]:
        endpoint = _endpoint(match[1])
        return _observation(endpoint, "bridge-unreachable", "service") if endpoint else None
    match = re.fullmatch(r"HTTP for (\S+) is unreachable", summary)
    if match and description == "Unable to connect to HTTP port or response code is not the expected for " + match[1]:
        website = _website(match[1])
        return _observation(website, "http-unreachable", "service") if website else None
    if summary == "There is a considerable drop on snowflake client polls" and description == "This might mean a problem in our signaling channels, or some other thing blocking clients to reach the broker":
        return _observation("snowflake", "snowflake-poll-drop", "service")
    if summary == "There might be a problem with the email delivery.":
        for target, wording in (("email-distributor", "been sent from the email distributor"), ("gettor", "arrived to gettor")):
            if re.fullmatch("No email has " + wording + r" for the last [1-9][0-9]{0,5} hours", description):
                return _observation(target, "email-distributor-silence", "service")
    return None


def _censorship(text: str) -> tuple[list[dict], int]:
    # Only firing alerts are read; no resolved notification has appeared on the list.
    lines = [line.strip() for line in text.split("\n") if line.strip()]
    total = re.fullmatch(r"Total firing alerts: ([0-9]{1,4})", lines[0])
    if not total:
        return [], 1
    started, block, observations, unsupported, firing = False, None, [], 0, 0
    for line in lines[1:]:
        if line == "## Firing Alerts" and not started:
            started = True
        elif line == "-----" and started:
            if block is None:
                block = []
                continue
            firing += 1
            # Known blocks may also carry a display-only title annotation; the
            # Summary/Description pair alone determines the observation.
            fields = {}
            for field in block:
                key, separator, value = field.partition(": ")
                if not separator or key in fields:
                    return [], unsupported + 1
                fields[key] = value
            required = {"Time", "Summary", "Description", "playbook"}
            if not required <= fields.keys() or fields.keys() - required - {"title"}:
                return [], unsupported + 1
            observation = _censorship_condition(fields["Summary"], fields["Description"])
            if observation:
                observations.append(observation)
            else:
                unsupported += 1
            block = None
        elif block is not None:
            block.append(line)
        else:
            return [], unsupported + 1
    if block is not None or firing != int(total[1]) or not started:
        return [], unsupported + 1
    return observations, unsupported


def parse_alerts(item: dict, format: str) -> tuple[list[dict], int]:
    """Return deduplicated bounded observations and the unsupported-unit count."""
    text, title = item.get("content"), item.get("title")
    if not isinstance(text, str) or not isinstance(title, str) or not text.strip() or len(text) > 65536:
        return [], 1
    if format == "consensus" and re.fullmatch(r"(?:\[tor-consensus-health\] )?Consensus issues", title, re.I):
        observations, unsupported = _consensus(text)
    elif format == "censorship" and not re.match(r"(?:re|fwd?):", re.sub(r"^\[[^\]\r\n]{1,80}\]\s*", "", title), re.I):
        observations, unsupported = _censorship(text)
    else:
        return [], 1
    unique = {(o["target"], o["condition"], o["kind"]): o for o in observations}
    if len(unique) > MAX_ALERTS:
        return [], unsupported + 1
    return list(unique.values()), unsupported
