"""Shared editorial vocabulary for configuration, analysis and rendering."""

CATEGORY_LABELS = {
    "security": "Security", "release": "Releases", "dos": "DoS",
    "directory-authority": "Authorities", "relay": "Relays",
    "protocol": "Protocol", "feature": "Features", "network": "Network",
}
CATEGORIES = list(CATEGORY_LABELS)
PRIORITIES = ["critical", "high", "normal", "low"]
CONFIDENCES = ["confirmed", "reported", "suspected", "observed-anomaly"]
STATES = ["developing", "mitigation-available", "fixed", "resolved", "released", "merged", "tagged"]
# Pages and operators may also use states the writer never chooses.
PUBLIC_STATES = STATES + ["no-longer-listed"]
PRODUCTS = ["tor", "arti", "tor-browser", "torspec", "network"]
UPDATE_CHARS = 300  # the text of one dated update
