# Grouped monitoring observations

The consensus-health mailing list is collected through the normal bounded
HTTP/feed path, including retries, backoff and source health. Its
`alert_format = "consensus"` selects a deterministic parser. These messages never
enter the LLM analysis queue, even when a template is unknown.

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
repeats only update the private evidence behind it. The published text, source
links and dates remain stable; additional uncited conditions are not added. This prevents hourly
RSS churn as well as duplicate headlines. An episode ends after two days without
a notification; a later warning starts a new episode and can publish a new story.

## What is not kept

Monitor-side failures (failed consensus or vote retrieval, ORPort checks, slow
downloads), routine scanner warnings, BadExit disagreements, unknown formats and
malformed messages describe the monitor's own reach or routine checks. They cannot
establish an outage, compromise or attack, so they are counted as unsupported in
each run's result and not stored. Anti-censorship alerts (`alert_format =
"censorship"`) are no longer collected for the same reason: the feed supplies no
healthy independent-vantage or control-test evidence. A source that still sets
that format loads disabled, with a warning. Independent incident announcements
and investigations remain available through the ordinary news sources.

## Recovery, freshness and limits

Silence, an HTTP failure/304, a missing entry in a rolling feed, or an absent
warning never mean recovery, and a published story is never marked resolved.
DocTor suppresses some notifications and can skip checks when retrieval fails,
and it sends no explicit all-clear.

Each `onionflash run` result reports per-source alert counts: observations,
duplicates, rejected and unsupported input, records held back at capacity, and
stories published. Source availability's **Collected** label only confirms
retrieval.

Observations and groups are deleted once they leave the two-day window.
Notifications older than the window are rejected on intake, so deleted records
cannot replay. At most 10,000 observations and 2,000 groups are kept; at capacity,
new records are held back and counted instead of evicting active groups. These
limits are constants in `monitoring.py`; source URLs are configured in
`config.example.toml`.

## Upstream formats

- [DocTor message templates](https://gitlab.torproject.org/tpo/network-health/doctor/-/blob/master/data/consensus_health.cfg)
- [DocTor notification suppression](https://gitlab.torproject.org/tpo/network-health/doctor/-/blob/master/consensus_health_checker.py)
