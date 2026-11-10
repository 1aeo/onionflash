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
| [Tor Metrics news Atom](https://metrics.torproject.org/news.atom) | `tor-metrics-news`, enabled hourly | Curated network events and explanations of measurement changes; treated conservatively as telemetry/context. |
| [Tor Project Development Mailing List](https://lists.torproject.org/mailman3/hyperkitty/list/tor-dev@lists.torproject.org/) | `tor-dev`, enabled every five minutes | Proposal and protocol-change discussions; the normal importance and evidence checks filter routine messages. |

Browser release announcements were already present in Tor Blog and tor-announce.
The Browser issue stream is deliberately filtered; it does not replace those
announcements or promise comprehensive vulnerability coverage.

All source URLs, fallback URLs, intervals and enable flags are editable in TOML.
The public issue-note API currently returns 401 anonymously. Do not assume that
issue descriptions include later confirmations or mitigations posted in comments.

### Tor Metrics timeline caveats

The [news page](https://metrics.torproject.org/news.html) and Atom feed are useful
for interpreting network changes, blocking, bridge outages and measurement bugs.
On November 9, 2026 the served feed contained 799 entries (about 1.06 MB), but its
newest event was March 9. The [backing timeline repository](https://gitlab.torproject.org/tpo/network-health/metrics/timeline)
had newer November updates, so this is supplementary context, not a reliable
breaking-news channel. Its timestamps describe event dates rather than the time
an entry became publicly available. Historical "to present" notes must not be
assumed to describe current conditions.

The hourly source allows 1,000 entries within the existing response/XML limits.
The normal recent-event cutoff prevents importing the old archive as new news.
Because upstream timestamps are event dates, retrospective edits outside that
window can be missed by the ordinary feed collector.
There is no verified Atom fallback: the HTML page and Markdown repository are
different formats. A future repository adapter could provide fresher timeline
data without pretending either is a feed mirror.

The feed also contains duplicate Atom IDs for distinct events. When an Atom ID
is used because there is no alternate link, conflicting recent entries sharing
that URL and update timestamp are skipped with a coverage
warning instead of silently replacing one another; unambiguous entries continue
through the normal pipeline. Old entries outside the lookback do not trigger
that warning. Long entry titles are retained in the bounded analysis context.

## Important sources that need more handling first

| Source | Reason for keeping it outside automatic news publication for now |
| --- | --- |
| [Consensus-health alerts](https://lists.torproject.org/mailman3/hyperkitty/list/tor-consensus-health@lists.torproject.org/feed/) | Repeated hourly warnings need grouping by authority/condition and persistence/resolution tracking. A missing vote is not proof of compromise. |
| [Anti-censorship alerts](https://lists.torproject.org/mailman3/hyperkitty/list/anti-censorship-alerts@lists.torproject.org/feed/) | A monitoring vantage point going offline must not become a claim that Tor is blocked. |
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
3. **Grouped telemetry incidents.** This enables the automated alert streams above
   without duplicate noise or unsupported claims about attacks.
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
