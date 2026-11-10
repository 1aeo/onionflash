# Onion Flash improvement checklist

Started November 9, 2026. Scope: the application and deployment repositories;
GitHub identity `1aeo`; preserve existing functionality and publication history.

| Item | Status | Completion evidence |
| --- | --- | --- |
| Explain polling frequency and configuration | Complete | Five-minute cron (`interval_minutes=5`), per-source default 300 s; healthy jitter bug reproduced, fixed and deployed. |
| Match the established 1AEO color theme | Complete | Dark/green palette deployed; live browser, HTTP color/hash and contrast checks passed. |
| Backtest source-to-publication delay | Complete | See RUNTIME_AUDIT.md and repeatable read-only audit tool; source availability remains unknown, n=1 post-start published example. |
| Audit important source coverage | Complete | See SOURCE_COVERAGE.md; 20 active sources, including consensus-health and anti-censorship alerts with deterministic grouping and publication gates. |
| Audit SQLite size, efficiency and maintenance | Complete | 0.95 MiB, zero freelist pages; gzip snapshot 26.7%; no immediate VACUUM/compression; growth scenarios documented. |
| Verify hostedopen cron | Complete | Existing */5 cron verified; successful current run/publication receipts observed. |
| Identify remaining key features | Complete | SOURCE_COVERAGE.md prioritizes corrections, public-only comments, grouped telemetry, long-term timing/retention, rejected-analysis workflow. |
| Gemini 4 Argon adversarial review — pass 1 | Complete | Model attested; six findings assessed and agreed fixes validated with failure-path tests. |
| Gemini 4 Argon adversarial review — pass 2 | Complete | Four grouped findings fixed; one false positive rejected; concise format repair succeeded with the same model. |
| Gemini 4 Argon adversarial review — pass 3 | Complete | Two recovery edges fixed, rollback-intent wording clarified; unsafe remote-state caching shortcut rejected; report-format repair succeeded. |
| Simplification critique — pass 1 | Complete | Shared ingest, SQLite backup, and HTTP/retry helpers; removed duplicated network implementation and trivial branching. |
| Simplification critique — pass 2 | Complete | Shared timestamp/schema helpers, one source-state update and bounded SQL story counts; regressions passed. |
| Simplification critique — pass 3 | Complete, with size tradeoff | Shared editorial vocabulary and rendering dependencies; safety checks retained. Net size increased for recovery guarantees; comparison below. |
| Deploy and verify completed changes | Complete | Version 0.2.0 deployed; commits under `1aeo`; private upgrade checkpoint, live page/feed checks, restored backup and successful scheduled runs verified. |

Private runtime snapshots, source evidence and routing packets stay outside the
repositories and public output. Reviewer suggestions are assessed, not applied
automatically. No claims of complete security or factual correctness are implied.

## Verification

147 application tests, 47 deployment tests, 8 JavaScript tests, and 40 subtests passed.
Fresh wheel installation and installer bootstrap passed. Dependency audits reported
no known vulnerabilities in the checked Python/runtime and npm dependencies.

## Runtime Python source size

This comparison excludes tests, documentation, configuration and assets. It is a
transparent size check, not a claim of net shrinkage. Shared rules and bounded SQL
counts reduce duplication and processing; the recovery fixes add necessary code.

| Repository | Before lines | After lines | Before bytes | After bytes |
| --- | ---: | ---: | ---: | ---: |
| onionflash | 2717 | 2800 | 114622 | 119320 |
| onionflash-deploy | 662 | 840 | 36009 | 44071 |

## Live acceptance

- Application 0.2.0 and deployment updates were installed under the project job lock.
- All 16 enabled sources fetched successfully; the new Browser Security and Anti-Censorship streams are healthy.
- The three previously ignored tags were processed without an inference client and merged into existing release stories.
- Website/RSS hashes and the live dark/green theme were verified. Existing homepage/blog hashes stayed unchanged.
- A fresh private Spaces backup restored successfully: 17 stories, 32 public files, matching snapshot manifest; anonymous access returned 403.
- The five-minute cron was restored; other cron entries were unchanged; post-upgrade scheduled runs completed without degraded status.
- Tor tags fetched at 17:55:02 UTC and 18:00:02 UTC on November 9: an observed 300-second gap with no error. This is one acceptance interval, not an end-to-end latency SLA.
- Runtime database after the update: 1,056,768 bytes (about 1.01 MiB), integrity check OK.

The remaining feature roadmap is in SOURCE_COVERAGE.md. Personal alerts remain deferred.
