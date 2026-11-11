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
| [Tor Metrics Timeline repository](https://gitlab.torproject.org/tpo/network-health/metrics/timeline) | `tor-metrics-news`, enabled | Curated event rows from the maintained README; validated repository snapshots replace the stale Atom feed. |
| [Tor Project Development Mailing List](https://lists.torproject.org/mailman3/hyperkitty/list/tor-dev@lists.torproject.org/) | `tor-dev`, enabled | Proposal and protocol-change discussions; the normal importance and evidence checks filter routine messages. |

Browser release announcements were already present in Tor Blog and tor-announce.
The Browser issue stream is deliberately filtered; it does not replace those
announcements or promise comprehensive vulnerability coverage.

All source URLs, fallback URLs, intervals and enable flags are editable in TOML.
The REST issue-note API currently returns 401 anonymously. The optional public
GraphQL discussion adapter below reads verified public notes without authentication.

### Anonymous public GitLab discussion updates

Reviewed November 10, 2026 against the configured Tor, Arti, Network Health
Analysis, Network Health Team, Tor Browser, and Anti-Censorship Team projects.
Anonymous GraphQL requests succeeded for all six projects. The live issue-note
connection returns the newest notes with `last`; it does not support a `sort`
argument. [GitLab documents anonymous query access, null authorization responses,
and the `/api/graphql` endpoint](https://docs.gitlab.com/api/graphql/).

Set `[comments].enabled = true` to opt in. Only issue sources that declare their
exact `gitlab_project` take part, each read through its own origin's
`/api/graphql`, and the adapter accepts no password, token, authorization header
or session cookie. A response must match the configured project and its public
visibility, the issue must match and be non-confidential, and only notes whose
`internal` and `system` flags are both false are kept. Raw responses and upstream
error text are never saved or logged. Each check reads an issue's newest notes in
one bounded request; checks repeat after 30 minutes and share fixed per-run
limits, so older notes can be missing. A failed or unverifiable check keeps the
last verified notes. Notes stay attributed, untrusted reports with their authors,
creation dates and exact URLs. A new, edited or deleted note queues the issue for
analysis again, and only a newly cited note moves the story's date, to the time
the note was written. Once comments are turned off, or a source loses its
`gitlab_project`, an issue's next revision is analyzed without its notes.

### Tor Metrics timeline

The maintained [timeline repository](https://gitlab.torproject.org/tpo/network-health/metrics/timeline)
is the active source. On November 9, 2026 the former Atom feed's newest event was
March 9; the repository contained November updates. The Atom feed is no longer
configured, including as a fallback.

The `metrics_timeline` adapter reads the GitLab file JSON API for `README.md`.
It checks the base64 content, file path, repository revision and seven-column
table structure. It does not clone the repository, execute upstream scripts
or fetch the row's external references. The timeline data is CC0; the upstream
BSD-licensed helper scripts are not bundled or executed.

The November 10 repository check found 804 rows, including the October 28 Tor
0.4.9.15 event and November 4 Tor 0.4.9.16 event missing from the Atom feed.
The HTTP response-size limit bounds the table; retries and backoff also apply.
Conditional HTTP requests avoid parsing unchanged snapshots.

Rows qualify through the fixed 14-day event-date lookback:
a recent start or explicit end can qualify, and the date that qualified a row
dates its item. An old `ongoing` row or a recent repository commit cannot qualify
a row. Every row's dates must parse, but other fields of historical rows are read
as leniently as upstream's own parser, so one unusual old row cannot block the
snapshot. Raw dates, approximation markers, country/protocol
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
summary merely because the repository was edited later. A row that
release-version clustering groups with an existing release story is skipped if
it adds no new information; the story keeps its text and existing citations.

## Important sources that need more handling first

| Source | Reason for keeping it outside automatic news publication for now |
| --- | --- |
| [TPA infrastructure issues](https://gitlab.torproject.org/tpo/tpa/team) | Useful incidents mixed with substantial routine administration; add if infrastructure coverage is desired. |
| [Tor Browser tags](https://gitlab.torproject.org/tpo/applications/tor-browser/-/tags?format=atom) | Mixes Browser/base-browser and stable/alpha/build tags; needs explicit product/version filtering. |

## Remaining work

1. **Broader discussion coverage.** Merge-request discussions and older comments
   beyond the bounded newest-note window remain outside the anonymous issue adapter.
2. **Long-term measurement.** Dedicated per-revision timing records would support
   latency reporting. Keep source timestamps distinct from observation and
   publication time. Accuracy and preserved articles take priority over latency analytics.

Personal push/email alerts remain intentionally deferred. Storage-bucket isolation
is a deployment configuration choice; see the deployment repository's guide.

## Retired monitoring sources

A source entry with a non-empty `alert_format` loads disabled, with a warning;
remove it. The unused `monitor_id` key and the retired `[monitoring]` settings
are accepted and ignored. Opening a database leaves any unused monitoring tables
in place; nothing reads or writes them. Automated notice lists, such as
tor-consensus-health and metrics-alerts, report checker or collector state
rather than network news; do not add them as news feeds.
