# Source coverage and remaining features

Reviewed November 9, 2026. Endpoints were checked against public upstream
responses; successful feeds were parsed as XML. Source classification describes
where a report came from, not whether its claims are independently established.

## Sources selected for this update

The original fourteen streams cover Tor/Arti tags, their public issues and merged
changes, Tor Blog, official announcements, relay operators, Network Health and
protocol changes. The additional configured streams are:

| Source | Configuration | Why it matters |
| --- | --- | --- |
| [Tor Browser Security-labeled public issues](https://gitlab.torproject.org/api/v4/projects/472/issues?labels=Security) | `tor-browser-security`, enabled | Earlier visibility into Browser security work; labels do not establish confirmed vulnerabilities or completed fixes. |
| [Anti-Censorship team issues](https://gitlab.torproject.org/api/v4/projects/549/issues) | `anti-censorship-team`, enabled | Human investigations of blocking and bridge/transport availability, including unlabeled reports. |
| [Tor Metrics Timeline repository](https://gitlab.torproject.org/tpo/network-health/metrics/timeline) | `tor-metrics-news`, enabled hourly | Curated event rows from the maintained README; validated repository snapshots replace the stale Atom feed. |
| [Tor Project Development Mailing List](https://lists.torproject.org/mailman3/hyperkitty/list/tor-dev@lists.torproject.org/) | `tor-dev`, enabled every five minutes | Proposal and protocol-change discussions; the normal importance and evidence checks filter routine messages. |
| [Consensus-health monitoring](https://lists.torproject.org/mailman3/hyperkitty/list/tor-consensus-health@lists.torproject.org/) | `consensus-health-alerts`, enabled | Deterministic grouping; persistent directory-document warnings may publish as attributed observations. |
| [Anti-censorship monitoring alerts](https://lists.torproject.org/mailman3/hyperkitty/list/anti-censorship-alerts@lists.torproject.org/) | `anti-censorship-alerts`, enabled for private grouping | Monitor outages and single-system service failures remain held; they do not establish network attacks or country-wide blocking. |

Browser release announcements were already present in Tor Blog and tor-announce.
The Browser issue stream is deliberately filtered; it does not replace those
announcements or promise comprehensive vulnerability coverage.

All source URLs, fallback URLs, intervals and enable flags are editable in TOML.
The REST issue-note API currently returns 401 anonymously. Do not assume that
issue descriptions include later confirmations or mitigations posted in comments.

### Tor Metrics timeline

The maintained [timeline repository](https://gitlab.torproject.org/tpo/network-health/metrics/timeline)
is the active source. On November 9, 2026 the former Atom feed's newest event was
March 9; the repository contained November updates. The Atom feed is no longer
configured, including as a fallback.

The `metrics_timeline` adapter reads the GitLab file JSON API for `README.md`.
It validates the base64 content, declared size, SHA-256, repository revision and
seven-column table. It does not clone the repository, execute upstream scripts
or fetch the row's external references. The timeline data is CC0; the upstream
BSD-licensed helper scripts are not bundled or executed.

The November 10 repository check found 804 rows, including the October 28 Tor
0.4.9.15 event and November 4 Tor 0.4.9.16 event missing from the Atom feed.
`max_items = 1000` bounds the complete table; exceeding it produces an explicit
source warning. HTTP response limits, retries and backoff also apply. Conditional
HTTP requests avoid parsing unchanged snapshots.

Rows qualify through the configured event-date lookback (14 days by default):
a recent start or explicit end can qualify, but an old `ongoing` row or a recent
repository commit cannot. Raw dates, approximation markers, country/protocol
scope and the unknown-cause `X` marker remain in analysis context. The README
does not specify a timezone; UTC-normalized values are ordering keys, not claims
of precise event time. Retrospective changes outside this event window remain
outside ordinary collection.

Each citation points to the exact repository commit and table line. Private
entry identities use the repository/file, normalized start date and scope;
line movement, description edits, changed references and repository revisions
do not create a new identity. Because upstream has no event IDs, distinct rows
sharing that key are ambiguous: recent collisions are skipped with a warning,
while unambiguous rows continue. They are never silently merged.

Repository revision time orders corrections separately from event dates.
Unchanged row content is not reanalyzed when another row changes. Timeline
context can update its own story, but cannot replace a richer existing news
summary merely because the repository was edited later. Release-version
clustering still adds corroborating citations to existing release stories.

## Important sources that need more handling first

| Source | Reason for keeping it outside automatic news publication for now |
| --- | --- |
| [Metrics alerts](https://lists.torproject.org/mailman3/hyperkitty/list/metrics-alerts@lists.torproject.org/feed/) | Collector failures need to remain distinct from network failures. |
| [TPA infrastructure issues](https://gitlab.torproject.org/tpo/tpa/team) | Useful incidents mixed with substantial routine administration; add if infrastructure coverage is desired. |
| [Tor Browser tags](https://gitlab.torproject.org/tpo/applications/tor-browser/-/tags?format=atom) | Mixes Browser/base-browser and stable/alpha/build tags; needs explicit product/version filtering. |

## Remaining features, in priority order

1. **Operator corrections/retractions and revision history.** Source-linked model
   summaries remain fallible. An explicit durable correction/withdrawal workflow
   is preferable to automatically deleting a story whenever one later analysis
   says `publish=false`; a story may have multiple sources. This is particularly
   important before adding personal urgent alerts.
2. **Public-only authenticated discussion updates.** Comments can carry crucial
   confirmations or fixes. A future connector must explicitly exclude private or
   confidential records even if its token can read them.
3. **Independent monitoring corroboration.** Grouping is implemented; promoting
   censorship/probe failures requires additional evidence of functioning
   independent monitoring locations or controls. The current feed lacks it.
4. **Long-term measurement and retention.** The current audit reconstructs first
   verified publication from immutable receipts. Dedicated per-revision timing
   records would support long-term latency reporting and bounded receipt
   retention. Keep source timestamps distinct from observation/publication time.
5. **A review queue for repeatedly rejected model output.** Invalid evidence and
   unsupported factual claims must remain rejected. The current CLI and audit
   expose queue/error counts; an explicit operator workflow would make these
   cases easier to resolve.

Tag publication and scheduler jitter are addressed in this update rather than
left as roadmap items. Tags receive deterministic attributed notices without
inference and remain `tagged` until an actual release announcement supplies that
context. Harmless duplicate model labels are normalized; invalid labels and
unsupported evidence remain rejected.

Personal push/email alerts remain intentionally deferred. Storage-bucket isolation
is a deployment configuration choice; see the deployment repository's guide.
