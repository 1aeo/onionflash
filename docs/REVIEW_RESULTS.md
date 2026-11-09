# Review results — November 9, 2026

The requested model was **Gemini 4 Argon (High)**, routed as
`gemini-4-argon-high` through `routerctl`'s `antigravity_gemini` lane. Model
attribution was verified in the routing receipts. These were read-only static
reviews; the implementation owner adjudicated findings and ran the tests.
Private routing packets, full reports and production snapshots remain outside
the repositories and public website.

## Three substantive critique passes

| Pass | Scope | Disposition |
| --- | --- | --- |
| 1 | Publication, rollback, locking, backups and atomic state | Six findings assessed; accepted recovery/privacy/consistency fixes with failure-path tests. |
| 2 | Collection, analysis, tag handling, deadlines and simplification | Four grouped findings accepted; one JSON-recursion claim rejected because the existing transport response parser already converted that error safely. |
| 3 | Revised recovery, backup and shared-helper interactions | Two additional failure paths fixed; rollback intent wording clarified; a proposed stale-version optimization rejected. |

The initial whole-codebase attempt timed out without a report and is **not counted
as a completed critique**. Focused passes returned actionable critiques. Passes
2 and 3 exceeded the provider's output budget and produced malformed delivery
envelopes; their complete critiques were recovered, checked, and followed by
successful concise report-format repairs using the same requested model.
The repairs are not additional independent critiques.

## Agreed fixes

- Private backup failure cleanup removes only the newly named object; failures
  remain visible. Explicit private ACLs and anonymous-access checks remain
  necessary; the review did not demonstrate an actual public backup exposure.
- Due backups are independent of held/failed publication. Invalid generated
  public files are excluded and recorded in the snapshot manifest while the
  validated SQLite data can still be backed up.
- Administrative lock contention returns a nonzero result instead of a false
  success. Scheduled overlapping work may still skip safely. Logs and job-result
  writes are protected by the job lock; status remains readable.
- A durable transition journal precedes activation. Publication and rollback
  share verified reconciliation; unknown external versions are not overwritten.
  Version receipts are archived before advancing the current pointer.
- A held but unfinished transition is an error, not a healthy paused run.
  Rollback intent is marked `rollback requested`; completion is recorded only
  after verification. The early hold remains a deliberate safety measure.
- Backup creation and public snapshots use one application lock. SQLite handles
  close explicitly, output files are private from creation, and partial failed
  database copies are removed. A separate snapshot manifest identifies any
  difference from the last published version.
- Backup markers include their destination, and `backup --force` supports an
  immediate verification backup after a bucket/credential change. Retention
  failures do not falsely advance the completed-backup interval.
- JSON state writes use unique private temporary files and directory fsync.
- Incomplete HTML tails and CRLF are handled consistently. XML depth, element,
  declaration and HTTP-size limits remain intact; capped feeds retain bounded
  useful items and a coverage warning.
- Tag notices are independent of inference and cannot overwrite richer grouped
  stories. Their cached prose no longer depends on an omitted source-name field.
- Deadline handling no longer defers finished, skipped or already-deferred rows.
- Deep malformed JSON is converted into bounded source/model failure paths,
  allowing configured fallbacks and the rest of the pipeline to continue.

The measured audit independently found and drove the healthy polling-jitter fix,
deterministic tag coverage, benign duplicate-label normalization and improved
observation timestamps. See [RUNTIME_AUDIT.md](RUNTIME_AUDIT.md).

## Simplification passes and tradeoffs

1. **Shared transport, backup and ingestion paths.** The publisher now reuses the
   application's checked HTTP client and retry calculation. SQLite backup logic
   and the repeated successful/partial-ingestion loop are also shared.
2. **Shared rules and less processing.** UTC parsing/formatting, persisted
   backoff, schema validation limits and source-state updates are consolidated.
   Story counts use a bounded SQL count instead of loading/deserializing the
   archive. Feed cutoff comparisons avoid per-entry datetime parsing.
3. **Shared editorial vocabulary and guarded recovery.** Analysis, configuration
   and rendering use one vocabulary. Renderer cache identity includes the shared
   dependencies. Publication and rollback share transition helpers. A proposed
   cached remote-version shortcut was rejected because it could miss a change
   made during verification.

These reduce duplication and runtime work, but **this update is not a net source
size reduction**: the new recovery guarantees, tag path and regression coverage
add code. Removing those safeguards to meet a line-count target would conflict
with preserving the required behavior. The final checklist records the measured
size comparison and deployment checks.

No finite review or test suite establishes universal bug-freedom or factual
correctness of generated summaries. The documented coverage and editorial limits
remain, including the need for an explicit operator correction/retraction path.
