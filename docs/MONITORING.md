# Private monitoring candidates

The consensus-health mailing list uses the normal bounded HTTP/feed collector,
including retries, backoff and source health. `alert_format = "consensus"`
selects a deterministic parser. Raw notifications never enter the model queue
or create standalone articles, including when their template is unknown.

## Qualification and publication

A private candidate requires **ten distinct notification timestamps for the same
authority and condition within a rolling 24 hours**, spanning at least one hour.
Only missing-authority, missing-signature and stale-consensus conditions qualify.
Descriptor and flag discrepancies never qualify independently, regardless of
how often they repeat. Their recognized observations remain private to preserve
existing episode continuity.

A qualifying candidate means **source context is needed**, not that an outage,
attack, compromise or meaningful operational impact has been established. Counts
alone are insufficient: notifications from one checker are correlated, and an
unrelated problem can cause an email to repeat other current warnings.

Significant incident announcements and investigations continue through the
ordinary source-backed news and final-review pipeline. That account is the public
story; a matching monitoring candidate does not generate a duplicate headline.
Authority-name matches alone do not prove corroboration, so the application does
not automatically link candidates to unrelated news, append unreviewed citations,
or infer significance from another article's priority label.

Existing monitoring articles retain their URLs and original content. This change
does not silently delete, rewrite or retract them. Operators can use the separate
[editorial workflow](EDITORIAL.md) when an existing article needs correction or
retraction. Existing private group-to-story references are preserved until their
normal episode expiry.

## Inspection

`onionflash status --config config.toml` includes `monitoring_candidates`, a
read-only view of up to 100 current candidates, newest supporting report first.
Each entry identifies its monitor, authority and condition, the distinct report
count, first/last qualifying timestamps, episode start and boundary source links.
`story_id`, when present, refers to a legacy article; it is not a new publication.
The candidate status is `needs-source-context`.

Each run's per-source alert result reports observations, duplicates, rejected and
unsupported input, records held back at capacity, and a `candidates` gauge. That
gauge counts currently qualifying authority/condition pairs for the monitor, not
new incidents or posts. The legacy `published` counter remains zero. Candidates
are computed from the saved observations and disappear from the view when their
qualifying reports leave the 24-hour window. This is not evidence of recovery.

## Deduplication, episodes and limits

Several authorities or warning lines in one notification are not independent
monitors. Mirrors share `monitor_id`; a different message URL does not give the
same timestamped authority/condition another vote. Conditions and authorities
are counted separately. Notifications older than a group's latest accepted time
are ignored, and a backfilled batch is processed chronologically.

The existing **48-hour observation and quiet-gap window** is unchanged and is
independent of the shorter candidate window. Recognized routine observations
still keep an authority episode alive. After 48 hours without a notification,
the private episode expires; a later warning starts another private episode.
This preserves the existing group identity and deduplication behavior.

Only known directory-authority names and recognized document conditions are
retained. Undated messages, invalid timestamps and unsafe URLs are rejected.
Intake tolerates a source clock up to five minutes ahead, but future reports do
not count toward qualification before their timestamp.

Unknown formats, monitor-side retrieval failures and routine service checks are
counted as unsupported and not stored. Retired `alert_format = "censorship"`
sources continue to load disabled. A monitor failure, HTTP error/304, missing
rolling-feed entry or absent warning never establishes a network incident or
recovery. Source availability's **Collected** label only confirms retrieval.

Observations and groups are pruned outside the 48-hour window during intake.
Old notifications cannot replay after expiry. Capacity remains bounded at 10,000
observations and 2,000 groups; new input is held at capacity instead of evicting
active evidence. Qualification and resource limits are constants in
`monitoring.py`; the existing retired monitoring settings remain ignored.
Source URLs, enable flags and monitor identities remain in the source config.

## Upstream formats

- [DocTor message templates](https://gitlab.torproject.org/tpo/network-health/doctor/-/blob/master/data/consensus_health.cfg)
- [DocTor notification suppression](https://gitlab.torproject.org/tpo/network-health/doctor/-/blob/master/consensus_health_checker.py)
