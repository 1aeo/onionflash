# Grouped monitoring observations

The consensus-health and anti-censorship mailing lists are collected through the
normal bounded HTTP/feed path, including retries, backoff and source health.
Their `alert_format` selects a deterministic parser. These messages never enter
the LLM analysis queue, even when a template is unknown.

## What can become news

Only recognized consensus **document** discrepancies are eligible: missing
authorities, signatures or descriptors; outdated consensus documents; and known
flag discrepancies. Each condition needs at least two distinct notification
times at least one hour apart, inside a two-day window. Only the voting directory
authorities' names can appear in public prose; any other name stays private.

Several authorities mentioned in one notification are not independent monitors.
Mirrors must share a `monitor_id`; the message URL is not an observation's
identity. The same dated facts at a different URL cannot establish persistence.
Notification times describe reports, not the onset or uninterrupted duration of
an incident. Undated, future-dated and out-of-window messages cannot promote news.

Public prose is generated from fixed templates, attributed to the monitoring
feed and labeled `observed-anomaly`. It does not establish an attack, compromise,
blocking, cause, or impact on users, and it gives no invented operator actions.
The first and last qualifying reports are linked for every included condition.

One authority group gets one stable story URL/RSS GUID for its episode. Ordinary
repeats only update private evidence. The published text, source links and dates
remain stable; additional uncited conditions stay private. This prevents hourly
RSS churn as well as duplicate headlines. An episode ends after two days without
a notification; a later warning starts a new episode and can publish a new story.

## What stays private

- Monitor/vantage-point outages, failed document retrieval and ORPort checks.
- Single-system bridge/HTTP probe failures, Snowflake poll drops and missing
  email-distribution activity.
- Routine scanner warnings, BadExit disagreements, unknown formats, malformed
  messages, and observations that have not met the persistence threshold.

The current censorship-alert feed does not supply healthy independent-vantage
or control-test evidence. Repetition, the number of targets in an alert bundle,
or labels such as “China” and “critical” cannot provide that missing evidence.
There is intentionally no configuration switch that converts those probe
failures into confirmed censorship news. Independent incident announcements and
investigations remain available through the ordinary news sources.

## Recovery, freshness and limits

Silence, an HTTP failure/304, a missing entry in a rolling feed, or an absent
warning never mean recovery, and a published story is never marked resolved.
DocTor suppresses some notifications and can skip checks when retrieval fails.
Neither feed has sent an explicit all-clear; only firing alerts are read.

`onionflash status --config config.toml` includes `monitoring` counts for groups
seen within the window (held, published, monitor failures, service observations),
stored observations and `at_capacity`. Each `onionflash run` result reports
per-source alert counts, including unsupported and rejected input. Source
availability's **Collected** label only confirms retrieval.

Private observations and groups are deleted once they leave the two-day window.
Notifications older than the window are rejected on intake, so deleted records
cannot replay. At most 10,000 observations and 2,000 groups are kept; at capacity,
new records are held back and `at_capacity` is reported instead of evicting active
groups. These limits are constants in `monitoring.py`; source URLs are configured
in `config.example.toml`.

## Upstream formats

- [DocTor message templates](https://gitlab.torproject.org/tpo/network-health/doctor/-/blob/master/data/consensus_health.cfg)
- [DocTor notification suppression](https://gitlab.torproject.org/tpo/network-health/doctor/-/blob/master/consensus_health_checker.py)
- [Vantage-point heartbeat rules](https://gitlab.torproject.org/tpo/tpa/prometheus-alerts/-/blob/main/rules.d/logcollector.rules)
- [Bridge and service probe rules](https://gitlab.torproject.org/tpo/tpa/prometheus-alerts/-/blob/main/rules.d/rdsys.rules)
- [Snowflake monitoring rules](https://gitlab.torproject.org/tpo/tpa/prometheus-alerts/-/blob/main/rules.d/snowflake.rules)
