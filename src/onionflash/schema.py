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
PRODUCTS = ["tor", "arti", "tor-browser", "torspec", "network"]
