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
exact `gitlab_project` participate, and each is read through its own origin's
`/api/graphql`. No password, personal token, authorization header, or session
cookie is accepted by this adapter. It creates a fresh public HTTP client; the
transport discards cookies between requests and applies its normal DNS checks,
timeout, retries, response-size bound and run deadline.

The response must explicitly match the configured project path, numeric project
ID (when configured in the REST URL), project URL and public visibility. The
issue identity must match and `confidential` must be exactly false. Only notes
whose `internal` and `system` flags are both exactly false are eligible. Missing,
null or mismatched visibility/identity is rejected; unknown note flags reject
the snapshot before their bodies are processed. Raw responses and upstream error strings
are never saved or logged. Notes are attributed to their authors, retain their
creation dates and exact note URLs, and remain untrusted reports rather than
confirmation of the underlying claim. Notes created after the response arrived
are excluded; a malformed creation date fails closed.

The fixed limits are 12 issues per run, four per source, the newest 40 notes read
in one request (system notes count toward that window), 12 retained comments per
issue, 2,000 characters per comment and 8,000 comment characters per issue. The
newest bounded window is refreshed after 30 minutes; old notes outside that window
can be omitted. Replacing a snapshot handles note edits and deletions within the
inspected window. An unavailable or unverifiable response is not a
new snapshot: it preserves the last verified public evidence and its original
verification time, applies bounded backoff, and leaves normal collection
running. An unusable answer about one issue backs off only that issue; transport,
redirect, response and project identity failures back off its source. A verified
public snapshot with no eligible notes can remove previous note enrichment; a
transport failure cannot masquerade as that deletion.

GitLab updates an issue when a note is added, so the REST scan returns it even
when nothing else changed. Activity after an issue's last check, or on an issue
without a snapshot, requests a check whatever the issue's status, and changed
notes queue a new revision for analysis. Requested checks go first, pending
issues first, then in the order first requested. A failed check of an issue
without a story is retried the same way until its scheduling metadata expires.
Recent pending issues and a rotating selection of issues already tied to
published stories alternate under the shared budget, including single-slot runs.
History cursors advance only for attempted rows. Old published issues remain
eligible when their description and publication date do not change. Indexed,
bounded candidate queries avoid making a request for every historical story.
Project order also rotates under the shared budget. Scheduling metadata expires
after 30 days; note count/text is bounded in each ordinary item snapshot.
Verified source identity/time live with that snapshot, so expired scheduling
metadata or an outage cannot strip it or requeue unchanged content. Malformed or
cold local records are skipped without marking the whole provider unavailable.
Cache state never contains unfiltered note responses.

`content` keeps the issue description and `public_comments` the sanitized
attributed notes. Fresh REST descriptions retain eligible cached notes, while
stale descriptions cannot roll the item backwards. Once comments are turned off,
or a source loses its `gitlab_project`, an issue's next REST revision is stored
and analyzed without its notes. A new, edited or deleted note
requeues analysis under the original issue identity without changing the issue's
source publication or update timestamp; a reaction that only moves a note's update
time requeues nothing. The writer sees the stored notes verbatim, newest first, as
entries that carry their authors and creation dates, and the description fills the
rest of its fixed input window. A story cites the earliest note stating a quote that
the title and description do not, and only such a newly cited note moves the
story's date, to the time the note was written. A separate `comments_checked_at` is
observation metadata, not the event date.

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
summary merely because the repository was edited later. Release-version
clustering still adds corroborating citations to existing release stories.

## Important sources that need more handling first

| Source | Reason for keeping it outside automatic news publication for now |
| --- | --- |
| [TPA infrastructure issues](https://gitlab.torproject.org/tpo/tpa/team) | Useful incidents mixed with substantial routine administration; add if infrastructure coverage is desired. |
| [Tor Browser tags](https://gitlab.torproject.org/tpo/applications/tor-browser/-/tags?format=atom) | Mixes Browser/base-browser and stable/alpha/build tags; needs explicit product/version filtering. |

## Operator controls and remaining work

Durable [corrections, retractions and revision history](EDITORIAL.md) protect
operator decisions from later automation. A later `publish=false` result does
not automatically delete a previously published story, which may have multiple
sources. The [rejected-analysis CLI](REJECTED_ANALYSES.md) provides explicit
inspection, retry and dismissal without bypassing validation. These workflows
serve different purposes: a false claim that passed validation needs a story
correction, not a rejected-item retry.

[Permanent publication](PERMANENT_HISTORY.md) retains every article URL and
paginates the full history. Optional private-evidence retention and Spaces
publication are documented in the deployment repository.

1. **Broader discussion coverage.** Merge-request discussions and older comments
   beyond the bounded newest-note window remain outside the anonymous issue adapter.
2. **Long-term measurement.** Dedicated per-revision timing records would support
   latency reporting. Keep source timestamps distinct from observation and
   publication time. Accuracy and preserved articles take priority over latency analytics.

Tag drafts are deterministic and remain `tagged` until an actual release
announcement supplies that context. They still need the
[editorial and factual publication reviews](FINAL_REVIEW.md). Harmless duplicate
model labels are normalized; invalid labels and unsupported evidence are rejected.

Personal push/email alerts remain intentionally deferred. Storage-bucket isolation
is a deployment configuration choice; see the deployment repository's guide.

## Retired monitoring sources

Automated monitoring collection and private candidate tracking have been removed.
Old source entries with `alert_format = "consensus"` or `"censorship"` still load,
but are disabled with a warning before collection. Any saved pending items from
those configured sources are ignored when the queue reaches them; they do not
fall back to news analysis. Remove these source entries from updated configurations.
The unused `monitor_id` key and retired `[monitoring]` settings remain accepted.

The obsolete private observation and group tables are removed when the database
opens. Published stories, their permanent URLs and editorial history remain
intact; retirement does not silently delete or retract them. Source-backed
incident reports and release announcements continue through ordinary collection.
