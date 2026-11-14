"""Shared editorial vocabulary for configuration, analysis and rendering."""

import re

CATEGORY_LABELS = {
    "security": "Security", "release": "Releases", "dos": "DoS",
    "directory-authority": "Authorities", "relay": "Relays",
    "protocol": "Protocol", "feature": "Features", "network": "Network",
}
CATEGORIES = list(CATEGORY_LABELS)
PRIORITIES = ["critical", "high", "normal", "low"]
CONFIDENCES = ["confirmed", "reported", "suspected", "observed-anomaly"]
CONFIDENCE_LEVELS = CONFIDENCES
STATES = ["developing", "mitigation-available", "fixed", "resolved", "released", "merged", "tagged"]
# Pages and operators may also use states the writer never chooses.
PUBLIC_STATES = STATES + ["no-longer-listed"]
PRODUCTS = ["tor", "arti", "tor-browser", "torspec", "network"]
UPDATE_CHARS = 300  # the text of one dated update

STORY_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
ITEM_ID_RE = re.compile(r"[0-9a-f]{24}\Z")
SHA256_RE = re.compile(r"[a-f0-9]{64}\Z")
FIELD_LIMITS = {
    "title": 180, "summary": 1600, "why_it_matters": 800, "source_title": 200,
    "max_sources": 20, "max_update_sources": 3, "max_alert_notes": 3,
}
# Writer fields a review may repair; their order is part of the review policy hash.
SEMANTIC_FIELDS = ("title", "summary", "why_it_matters", "category", "priority", "confidence", "state", "products", "tags")
LABEL_FIELDS = SEMANTIC_FIELDS[3:]
UPDATE_FIELDS = (*LABEL_FIELDS, "updates")
