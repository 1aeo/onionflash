# Onion Flash improvement checklist

Started November 9, 2026. Scope: the application and deployment repositories;
GitHub identity `1aeo`; preserve existing functionality and publication history.

| Item | Status | Completion evidence |
| --- | --- | --- |
| Explain polling frequency and configuration | Complete | Five-minute cron (`interval_minutes=5`), per-source default 300 s; healthy jitter bug reproduced and fixed pending rollout. |
| Match the established 1AEO color theme | Ready for deployment | Dark/green palette verified against all four live sites; local browser and contrast checks passed. |
| Backtest source-to-publication delay | Complete | See RUNTIME_AUDIT.md and repeatable read-only audit tool; source availability remains unknown, n=1 post-start published example. |
| Audit important source coverage | Complete; additions pending rollout | See SOURCE_COVERAGE.md; Browser Security issues and Anti-Censorship team enabled in example, tor-dev optional. |
| Audit SQLite size, efficiency and maintenance | Complete | 0.95 MiB, zero freelist pages; gzip snapshot 26.7%; no immediate VACUUM/compression; growth scenarios documented. |
| Verify hostedopen cron | Complete | Existing */5 cron verified; successful current run/publication receipts observed. |
| Identify remaining key features | Complete | SOURCE_COVERAGE.md prioritizes corrections, public-only comments, grouped telemetry, long-term timing/retention, rejected-analysis workflow. |
| Gemini 4 Argon adversarial review — pass 1 | Complete | Model attested; six findings assessed and agreed fixes validated with failure-path tests. |
| Gemini 4 Argon adversarial review — pass 2 | Complete | Four grouped findings fixed; one false positive rejected; concise format repair succeeded with the same model. |
| Gemini 4 Argon adversarial review — pass 3 | Complete | Two recovery edges fixed, rollback-intent wording clarified; unsafe remote-state caching shortcut rejected; report-format repair succeeded. |
| Simplification critique — pass 1 | Complete | Shared ingest, SQLite backup, and HTTP/retry helpers; removed duplicated network implementation and trivial branching. |
| Simplification critique — pass 2 | Complete | Shared timestamp/schema helpers, one source-state update and bounded SQL story counts; regressions passed. |
| Simplification critique — pass 3 | Complete, with size tradeoff | Shared editorial vocabulary and rendering dependencies; safety checks retained. Net size increased for recovery guarantees; comparison below. |
| Deploy and verify completed changes | Pending | Tests, GitHub commits under `1aeo`, protected installation, public page/feed checks and scheduled run. |

Private runtime snapshots, source evidence and routing packets stay outside the
repositories and public output. Reviewer suggestions are assessed, not applied
automatically. No claims of complete security or factual correctness are implied.

## Final local verification before rollout

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
