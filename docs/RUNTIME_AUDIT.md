# Runtime and publication-delay audit

Baseline captured **November 9, 2026 at 07:32:19 PST** (15:32:19 UTC), before
the improvements identified in this review. Production data was inspected
read-only; a consistent SQLite backup and the available publication receipts
were copied into a private audit directory outside the repositories. No live
database compaction, pruning, configuration change, or schedule change was made
by this audit.

## What the timing evidence can establish

The database contains upstream publication/update timestamps, an `items.first_seen`
field, and cached-analysis timestamps. The deployed implementation assigns the
**collection cycle's start time** to `first_seen`, rather than recording each
HTTP fetch completion. Successful publication receipts contain the verified
publication time and a manifest of story-page hashes. The earliest receipt
containing a story permalink therefore supplies its earliest recorded verified
publication, rather than relying on the story's source-derived `published_at`.

The source's **first availability time is not recorded**. An upstream timestamp
is only a proxy: an old GitLab issue can be updated today, and a tag Atom entry
can use a commit timestamp that predates tag creation. In an earlier live check,
Tor 0.4.9.16's Atom timestamp was 13:55:43 UTC on November 4, while the tag API's
`created_at` was 15:00:18 UTC. Neither proves when the feed first exposed it.

Changed cached payloads are excluded from first-discovery timestamp comparisons,
because their original source revision is no longer available in the item row.
This avoids combining a later source update with an earlier discovery time.

## Measured baseline

The snapshot covers 7.33 hours, with 259 cached source items, 15 published stories,
and 11 successful publication receipts. Of the source items, 242 are initial or
historical backfill; 17 were first observed after the startup period. Those 17
include four newly published source items and 13 older records updated later.

| Measurement | Sample | Result |
| --- | ---: | --- |
| Newly published source timestamp → first collection-cycle marker | 4 items | Median 4m 06s; maximum 7m 53s |
| Updated older source timestamp → first collection-cycle marker | 13 items | Median 2m 30s; maximum 4m 44s |
| Post-start item → first verified publication | 1 resurfaced issue | 3m 18.75s after its collection-cycle marker |
| Unchanged initial payload → first verified publication | 9 stories | Median 41m 52s; maximum 1h 31m 25s |

The single post-start published example is
[Arti issue 2746](https://gitlab.torproject.org/tpo/core/arti/-/work_items/2746):

| Event | November 9, 2026, PST |
| --- | --- |
| Upstream `updated_at` | 07:23:01 |
| First collection-cycle marker | 07:25:01 |
| First verified publication | 07:28:19.75 |

That is **5m 18.75s from the reported source update to verified publication**.
The issue was originally created on September 22; this is a resurfaced update,
not proof that a new incident first appeared on November 9. All four newly
published source items were classified as irrelevant by the current model;
this timing audit did not rejudge those editorial decisions. They provide
collection timings but no published-news
latency sample. Consequently there is **no defensible fresh-news end-to-end
p95/SLA yet**. Across all 14 initially observed story URLs, including those
whose payload later changed, the longest URL-first-seen-to-publication span was
2h 48m 45s. That is not a same-revision queue delay; the source could have gained
newsworthy information later. The startup backfill also included manual prepublication review
and prompt corrections, so its delays are not steady-state performance.

Under a hypothetical healthy, exact five-minute polling interval with uniform
arrival phase, detection alone averages 2m 30s, has a 4m 45s p95, and is below
five minutes. Network, queue, analysis, and deployment time must be added. This
is a scheduling model, not a measured publication guarantee.

## Concrete issues found

1. **Scheduler jitter can double the poll gap.** At 07:31, all sources had a
   `last_success` of 07:30:02 and `next_fetch_at` of 07:35:02. At 07:39, those
   fields were unchanged even though the 07:35 scheduled run had completed
   successfully at 07:35:03.85. A run beginning a second before `next_fetch_at`
   skips healthy collection until the following five-minute start. A controlled
   simulation alternating start offsets of two and one seconds reproduces
   ten-minute collection gaps. A small bounded tolerance for normal healthy
   intervals should not be applied to failure cooldowns or server Retry-After.
2. **Tag inputs are not guaranteed to become tag notices.** All three tag items
   in this snapshot—Tor 0.4.9.15, Tor 0.4.9.16 and Arti 2.8.0—were `ignored`
   with priority score zero. Release announcements were published through other
   sources. A deterministic, attributed *tag detected* notice can avoid both
   LLM rejection and the false claim that a tag proves an announced release.
3. **Eight invalid outputs remain pending.** Four failed tag validation, three
   failed source-evidence matching, and one asserted an unsupported completed
   action. Each had seven attempts and originated in the initial batch. They
   are rejected rather than silently published, but clearer terminal/review
   status and cheap normalization of harmless duplicate tags could reduce
   repeated inference. Invalid factual claims must remain rejected.

These findings were reported to the implementation owner. This document records
the baseline, not a claim that the later fixes have already passed acceptance.

## SQLite size and growth

| Baseline metric | Value |
| --- | ---: |
| Live main database | 999,424 bytes, approximately 0.95 MiB |
| Page size / allocated pages | 4,096 bytes / 244 |
| Freelist pages | 0 |
| WAL file at the live measurement | Not present |
| Items / analysis-cache rows / stories | 259 / 267 / 15 |
| Item table | 708,608 bytes |
| Analysis-cache table | 114,688 bytes |
| Story table | 32,768 bytes |
| Streaming gzip of consistent database snapshot | 267,133 bytes, approximately 26.7% of the original |

Production uses WAL mode. The standalone audit snapshot's journal mode is not
evidence of a change to the live database. Transactions store changed source
payloads and an analysis cache; unchanged items do not create duplicate rows.
An updated URL replaces its current item payload, while new content/model/prompt
cache keys can add analysis rows. Published summaries and source links are held
separately from raw input. The database is local; visitors read static files.

Every stored story is considered for rendering (`storage.max_stories` is retired and
ignored); records that cannot be rendered safely are skipped and reported as
`stories_skipped`. Nothing limits **database retention**. Items, analysis-cache entries and stories have no age-based
deletion policy. Long-term growth is therefore expected, but the measured scale
does not justify compressing the live SQL data or running frequent VACUUM.

The current whole-database mix averages about 3.77 KiB per cached source item,
including its share of cached analyses, published stories and indexes:

| Hypothetical new cached items per day | Added storage per year at today's mix |
| ---: | ---: |
| 25 | About 34 MiB |
| 100 | About 134 MiB |
| 500 | About 672 MiB |

These are **scenarios, not forecasts** from a seven-hour sample. Source length,
update frequency, analysis policy, Unicode content and future sources can change
the mix. The early sample also includes bulk upstream edits to old issues.
The scenarios concern SQLite only. The 11 full-manifest publication receipts
occupy another 33,864 bytes and currently have no retention policy; at a much
larger archive size, their repeated manifests also deserve a storage review.

The existing backup path already writes gzip-compressed archives. Keep the live
database uncompressed and measure its size, cache growth and WAL periodically.
SQLite performs automatic WAL checkpoints by default; long-lived readers can
prevent a WAL from being fully checkpointed. Avoid long read transactions in
monitoring jobs. [SQLite WAL documentation](https://www.sqlite.org/wal.html).

With zero freelist pages and a sub-megabyte database, **no immediate compaction
is indicated**. If retention or substantial deletion is introduced later,
measure freelist/page utilization before choosing a maintenance window for
compaction. VACUUM rewrites the file and can reclaim deleted or fragmented
space; it is not compression or a retention policy. Do not run it on every
poll. [SQLite VACUUM documentation](https://www.sqlite.org/lang_vacuum.html).

## Reproduce the read-only audit

Create a consistent backup with SQLite's backup API and copy the deployment's
`state/receipts/` directory to a private audit directory. Do not copy only the
main file of an active WAL database. Keep all snapshots and raw reports out of
Git and public output.

```sh
python tools/audit_history.py \
  --database /private/audit/onionflash.sqlite3 \
  --receipts /private/audit/receipts \
  --captured-at 2026-11-09T15:32:19.628022Z \
  --immutable-snapshot \
  --compression-sample
```

Use `--immutable-snapshot` only for an offline, consistent backup with committed
WAL data already included. The tool does not fetch sources, call the LLM,
publish, compact, prune, or modify the audited database. It reports exact
available observations separately from source-timestamp proxies and controlled
polling simulations. `--poll-seconds` changes the hypothetical polling model;
it does not change the running service. Regression tests cover the distinctions and verify
that read-only auditing leaves the input bytes unchanged.

## Post-update acceptance

Version 0.2.0 was published on November 9 at 09:45:22 PST. All 16 enabled
sources fetched successfully. The previously ignored tag entries were processed
without an inference client and merged into existing release stories.

A subsequent live check observed Tor tag polls at **09:55:02 and 10:00:02 PST**,
exactly **300 seconds** apart, with no source error. This is an acceptance sample,
not an end-to-end latency percentile. New items use post-fetch observation times;
the database metadata records the boundary so older cycle-start timestamps are
not silently relabeled.

The new next-fetch deadline was 10:05:01 PST. With the configured 300-second
interval, that implies a 10:00:01 cycle start—one second before the preceding
10:00:02 deadline. The healthy-source tolerance allowed this poll; the previous
strict comparison would have skipped it.

The database measured 1,056,768 bytes (about 1.01 MiB) after the update, and its
integrity check passed. A new private backup restored 17 stories and verified
32 public-file hashes. No compaction or history pruning was performed.
