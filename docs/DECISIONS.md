# Decision log

Onion Flash keeps a private record of every terminal decision in the
`decision_log` table of its database. Each outcome writes exactly one row, in the
same transaction that applies it, so the log always agrees with the item states:

- the pipeline publishes an item, skips it, holds it for the operator, or stops
  retrying it after its third failure or because its saved copy is damaged;
- an operator retries, dismisses or approves an item with the
  [rejected-item commands](REJECTED_ANALYSES.md).

A failure that will be retried, a stale candidate, an unfinished review and a
change in the collected source write no row. Rows are never edited or deleted.

The log is operator data. It never reaches public pages or feeds, but it is part
of the database and its backups. Each row keeps the time, the item (its
`subject`), content hash, source, story and code, and a bounded detail: the
item's title and URL, the verdicts of its reviews, the failed criteria of the
deciding review with the reviewer's reasons (for skips and holds), the error (for
failures), or the operator's reason and the item's previous status and error. It
never keeps the draft, the full review reply or the source's content. If a saved
record cannot be read, the row keeps the title and URL, or no detail; logging
never prevents the outcome.
Rows of publications, skips and holds also keep `writer_clears` when writer
validation cleared the draft's impact sentence, so a repeat hold counts the
clear again. Failure and operator rows do not keep it, and neither do the rows
of the new review that an operator retry starts with a kept draft.

The log starts empty: decisions made before it existed, or by an older release
after a rollback, are not in it.

## Codes

A code is `<outcome>.<stage>.<reason>` or `<outcome>.<reason>`. The outcome is
`published`, `skipped`, `held`, `failed` or `operator`. The stage names where the
decision was made: `gate` (the application's checks around the review), `review`
(the first review, or a request to repair release labels; in `failed` codes, any
request to the reviewer), `verification` (a fresh verification), `final_check` (the
[final checks](FINAL_REVIEW.md#final-checks) of a verified approval), `writer`,
or `app`. Codes are stable, so counts can be compared over time.

| Code | Meaning |
| --- | --- |
| `published.new` | The item became a new story. |
| `published.update` | The item updated an existing story. |
| `skipped.review.news_value` | The first review found no news value. |
| `skipped.review.new_information` | The first review found nothing new beyond existing coverage. |
| `skipped.review.new_information_and_news_value` | The first review failed both editorial criteria. |
| `skipped.verification.news_value` | The verification found no news value. |
| `skipped.verification.new_information` | The verification found nothing new beyond existing coverage. |
| `skipped.verification.new_information_and_news_value` | The verification failed both editorial criteria. |
| `skipped.gate.not_recent` | The item would start a new story, but its newest dated development is more than 14 days older than its collection. No model was asked. |
| `skipped.gate.retired_story` | The item maps to a retired story identity or cluster key, which is never recreated. No model was asked. |
| `held.gate.missing_sources` | Source material the candidate cites is unavailable. |
| `held.gate.repeat_hold` | The candidate was held before, for example after a source reverted. |
| `held.gate.story_locked` | The item updates a story that an editorial correction locked. |
| `held.review.model_hold` | The first review held the candidate, or could not confirm whether an official item was already covered. |
| `held.verification.model_hold` | A verification held the candidate, or refused it on news value or new information (a repair it proposes for an official item's facts is applied and verified instead). |
| `held.review.tag_repair` | The review proposed editing a literal tag notice. |
| `held.verification.tag_repair` | A verification proposed editing a literal tag notice. |
| `held.review.unusable_repair` | The review proposed a repair that cannot be applied. |
| `held.verification.unusable_repair` | A verification proposed a repair that cannot be applied. |
| `held.review.repeated_repair` | A release-label repair request proposed a text the item's reviews already refused. |
| `held.verification.repeated_repair` | A verification proposed a text the item's reviews already refused. |
| `held.review.disagreed_news` | A release-label repair request and the first review disagree on whether news value and new information both pass. |
| `held.verification.disagreed_news` | A verification and the first review disagree on whether news value and new information both pass. |
| `held.review.release_labels` | A release-label repair request held the candidate, or left a release label on a state that is not released or tagged. |
| `held.verification.release_labels` | A verification approved a release label on a state that is not released or tagged, with no attempt left to repair it. |
| `held.verification.official_not_news` | An official item, other than a tag, failed news value in a verification that passed its facts. |
| `held.verification.repairs_exhausted` | A verification still refused the candidate after the repair limit. |
| `held.final_check.completed_action` | A story written from an issue reports a completed action that its sources do not. |
| `held.final_check.compromise_headline` | The headline drops the sources' doubt about a compromise. |
| `held.final_check.confirmed_source` | The story is confirmed without an official announcement or a merged merge request. |
| `held.final_check.merge_state` | A story told only by merge requests is not marked merged. |
| `failed.writer.invalid_output` | The writer's draft did not match its schema. |
| `failed.writer.evidence_too_short` | A draft evidence quote was too short. |
| `failed.writer.evidence_not_exact` | A draft evidence quote was not an exact excerpt of the source. |
| `failed.writer.no_literal_evidence` | The source has no excerpt long enough to quote. |
| `failed.writer.invalid_input` | The writer request could not be encoded as UTF-8 JSON. |
| `failed.writer.truncated` | The writer reply was cut off or refused. |
| `failed.writer.invalid_json` | The writer reply was not a JSON object. |
| `failed.review.invalid_reply` | A review reply did not follow the review rules. |
| `failed.review.invalid_input` | The review request could not be encoded as UTF-8 JSON. |
| `failed.review.truncated` | A review reply was cut off or refused. |
| `failed.review.invalid_json` | A review reply was not a JSON object. |
| `failed.review.request_limit` | The item's durable review request budget is exhausted; no further request was sent. |
| `failed.app.invalid_tag_name` | A collected tag has an empty or overlong name. |
| `failed.app.unexpected` | Processing failed unexpectedly. |
| `failed.app.damaged_item` | The item's saved copy is damaged. |
| `failed.app.damaged_job` | The item's saved review job is damaged. |
| `operator.retried` | An operator retried a rejected, dismissed or failed item. |
| `operator.reconsidered` | An operator retried an ignored (skipped) item. |
| `operator.dismissed` | An operator dismissed an item. |
| `operator.approved` | An operator approved a held candidate whose facts passed fresh verification. |

A held update of a locked story leaves the item `published`: it maps to that
story and the story's held-update count grows. Unlocking the story does not apply
the update, so the summary lists the story under `awaiting_operator` until an
update of it is published after its latest hold.

## Commands

```sh
onionflash decisions summary --config config.toml --since 7d
onionflash decisions list --config config.toml --since 24h --code held.review --limit 50
```

Both only read and need no lock, so they work while a run is in progress. Like
the other inspection commands, they print JSON with non-ASCII characters escaped.
`--since` takes hours or days before now, such as `24h` or `7d` (the default), or
a timestamp with a time zone.

`summary` reports the decisions since that time:

- `outcomes`, `codes` and `sources`: counts by outcome, by code, and by source and
  outcome;
- `examples`: the three newest decisions of each code, with their detail;
- `awaiting_operator`: the number of rejected items, the 20 whose latest decision
  is oldest (with that decision's code; items rejected before the log existed
  come first), and the stories whose held updates still wait, each with its
  lifetime held-update count, as `story show` reports it;
- `retrying`: pending items that failed and will be retried;
- `story_actions`: editorial actions on published stories, by action;
- `feed`: the size of `feed.xml`, as recorded by the last build, against the
  deployment's 10 MiB per-file upload limit. From 5 MiB, `action` reads
  `ACTION: split the feeds by year`;
- `writer_clears`: the number of draft sentences that writer validation removed,
  as recorded with these decisions.

`list` prints the decisions since that time, newest first, with their detail.
`--code` takes a code or a dotted prefix of one (`held`, `held.review`), and
`--source` a source ID. Pages hold 1–200 decisions; pass the returned
`next_cursor` as `--after` for the next page.

`rejected show` lists the item's 20 newest decisions under `decisions`. They keep
its history when collecting a new revision clears its rejection reason.

## Run report and status

The run report's `decisions` counts the run's decisions by code. Holds count
there, not in `analysis_failed`, which counts failures and damaged items. `status`
reports `decisions_24h`, the decisions of the last 24 hours by outcome.
