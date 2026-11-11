# Contributor rules

These rules apply to every change, whether a person or a coding agent makes it.

## Releases

Agent-run GitHub operations use `1aeo` and its public noreply commit identity.
Open a pull request, address all review feedback, and wait for the automated code
review of the latest commit to finish with no new findings. Merge the reviewed
change before deploying it. Never deploy unmerged work.

## Public text

This repository is public, and GitHub keeps every revision of PR and issue text.
Commit messages, PR titles and descriptions, issues, code comments and docs must
not contain:

- host names, IP addresses, bucket names, or paths of a real deployment;
- schedules or time zones of a real deployment;
- production sizes or counts (stories, articles, feed entries, rows, files),
  costs, or rollout state ("enabled in production", "waiting for access");
- names of internal tools, model routes or review services;
- security exposures that are not fixed yet.

Describe tests, rehearsals and reviews generically, for example: "a rehearsal on
a copy of a real catalog preserved every story and permalink." Rollout and
operations steps go to the operator, not into PR text.

## Settings

A setting exists only for a real operator choice: for example the site's
identity, paths and page sizes, the sources, and the model endpoint, model,
network allowlist, timeout and items per run (see `OPERATOR_SETTINGS` and
`config.example.toml`). Other budgets, limits, timeouts, retries, batch and cache
sizes belong in code as constants. Some sections, such as `[comments]` and
`[review]`, still expose such values; add no more, and remove one only together
with the code that reads it.

When a section setting is removed, add its key to `RETIRED` so existing files
keep loading. A section that loses its last setting stays in `DEFAULTS` as an
empty table, as `monitoring` does, so files that still contain it load. Source
entries have no such list: keep a removed source key in the allowed set and
ignore it, or existing files stop loading.

## Code

- Make the smallest change that solves the problem, and delete code that loses
  its last caller.
- Do not add migrations for a schema that no merged version created.
- Keep each fact in one document and link to it instead of restating it.
- Tests pin behavior, not implementation details. Run `python -m pytest -q`
  before every push; the deployment repository's tests must also keep passing,
  because it reads the publication tables and command output.
