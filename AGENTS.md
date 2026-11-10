# Contributor rules

These rules apply to every change, whether a person or a coding agent makes it.

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

A setting exists only for a real operator choice: the site's identity and paths,
the sources, the model endpoint, model and network allowlist, and the two limits
that depend on the operator's model, `llm.timeout_seconds` and
`llm.max_items_per_run` (`OPERATOR_SETTINGS` in `src/onionflash/config.py`). Other
budgets, limits, timeouts, retries, batch and cache sizes are constants in the
module that uses them. When a setting is removed, add its key to `RETIRED` so
existing files keep loading.

## Code

- Make the smallest change that solves the problem, and delete code that loses
  its last caller.
- Do not add migrations for a schema that no merged version created.
- Keep each fact in one document and link to it instead of restating it.
- Tests pin behavior, not implementation details. Run `python -m pytest -q`
  before every push; the deployment repository's tests must also keep passing,
  because it reads the publication tables and command output.
