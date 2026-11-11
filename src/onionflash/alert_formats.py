"""Bounded, deterministic observations from consensus-health notifications.

Only directory-document warnings are retained for private candidate checks.
The parser describes what the monitor reported; it never infers impact,
attacks or recovery, and authority names do not become independent monitors.
"""

from __future__ import annotations

import re


_AUTHORITY = r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}"
_LIST = rf"{_AUTHORITY}(?:, {_AUTHORITY})*"
_LEVEL = r"(?:ERROR|WARNING|NOTICE): "
_FLAG = re.compile(_LEVEL + rf"({_AUTHORITY}) had [0-9]+ ([A-Za-z][A-Za-z0-9]{{0,31}}) flags in its vote but the consensus had [0-9]+")
_DOCUMENTS = [(re.compile(_LEVEL + pattern), condition) for pattern, condition in (
    (rf"The following authorities are missing from the consensus: ({_LIST})", "authority-missing"),
    (rf"Consensus fetched from {_AUTHORITY} was missing the following authority signatures: ({_LIST})", "signature-missing"),
    (rf"{_AUTHORITY} is missing the server descriptor of ({_AUTHORITY})", "descriptor-missing"),
    (rf"The consensuses published by the following directory authorities are more than one hour old and therefore not fresh anymore: ({_LIST})", "stale-consensus"),
)]
MAX_ALERTS = 100  # distinct observations per message


def _consensus(text: str) -> tuple[list[dict], int]:
    """Monitor-side failures and service checks count as unsupported lines."""
    observations, unsupported = [], 0
    for line in text.split("\n"):
        line = line.strip()
        if not line:
            continue
        flag = _FLAG.fullmatch(line)
        if flag:
            observations.append({"target": flag[1].lower(), "condition": "flag-" + flag[2].lower()})
            continue
        for pattern, condition in _DOCUMENTS:
            match = pattern.fullmatch(line)
            if match:
                observations.extend({"target": target.lower(), "condition": condition} for target in match[1].split(", "))
                break
        else:
            unsupported += 1
    return observations, unsupported


def parse_alerts(item: dict, format: str) -> tuple[list[dict], int]:
    """Return deduplicated bounded observations and the unsupported-unit count."""
    text, title = item.get("content"), item.get("title")
    if not isinstance(text, str) or not isinstance(title, str) or not text.strip() or len(text) > 65536:
        return [], 1
    if format != "consensus" or not re.fullmatch(r"(?:\[tor-consensus-health\] )?Consensus issues", title, re.I):
        return [], 1
    observations, unsupported = _consensus(text)
    unique = {(o["target"], o["condition"]): o for o in observations}
    if len(unique) > MAX_ALERTS:
        return [], unsupported + 1
    return list(unique.values()), unsupported
