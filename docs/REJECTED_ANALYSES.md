# Reviewing rejected analyses

Transient failures, such as an unavailable LLM endpoint, remain pending and use
the normal exponential backoff. Three terminal content/validation failures move
an item to `rejected`; automation stops retrying that source revision.

These local CLI commands act on one item at a time. They do not call the LLM,
publish a story, retract a story or unlock an editorial correction.

## Inspect

```sh
onionflash rejected list --config config.toml --limit 50
onionflash rejected list --config config.toml --limit 50 --after ITEM_ID
onionflash rejected show --config config.toml --item ITEM_ID
```

`list` includes the item ID, title, source URL, content hash, rejection reason,
attempt count and rejection count. It excludes transient pending failures and
returns a `next_cursor` for bounded ID-based pagination. Limits are 1–200 items.
Use `--status dismissed` to inspect dismissed revisions.

`show` explicitly includes the saved source item and up to 20 recent operator
actions. It is a private inspection command; its source text and operator reasons
are not published. It does not print raw stored model responses. Malformed or
oversized saved items produce an inspection error field rather than a source dump.

## Retry one rejected revision

```sh
onionflash rejected retry --config config.toml --item ITEM_ID \
  --expect-hash CURRENT_CONTENT_HASH --reason "The grounding rule was fixed"
```

Copy `CURRENT_CONTENT_HASH` from the inspected item. A changed hash or a status
other than `rejected` stops the action. Retry resets the attempt/rejection counts
and cooldown, then queues the item for the normal analysis pipeline. It does not
bypass validation or approve a publication. A missing or unreadable source body
must be restored or recollected before retrying.

The next scheduled run analyzes the queued item again; the runtime does not
reuse previous model results. If an analysis record already exists for the
current source/model/prompt/input-window key, retry preserves its complete prior value in the
private action audit as `superseded_analysis_key` and `superseded_analysis_json`,
then removes that record so the new attempt can save its own analysis. Other
analysis records and already accepted stories are unchanged.

## Dismiss one rejected revision

```sh
onionflash rejected dismiss --config config.toml --item ITEM_ID \
  --expect-hash CURRENT_CONTENT_HASH --reason "Routine discussion without news"
```

Dismiss sets the revision to `dismissed` and removes its retry schedule. The same
content, repeated polls, or an upstream timestamp-only edit cannot requeue it.
A change to source content or classification metadata can create a new pending
revision under the same item ID, resetting its counters through normal collection. The earlier dismissal
and its content hash remain in the audit history. A dismissal is therefore a
decision about that source revision, not a permanent ban on future reporting.

Both actions require a reason of 1–1,000 characters. Repeating an already-applied
action returns a state error without resetting the queue or adding another audit
record. Mutations run under the application's existing run lock and apply an
additional content-hash/state guard in SQLite. A failed audit write rolls back
the queue and analysis-record changes.

The private `rejection_actions` table records each reason, source-version hash,
timestamp, prior counters/error, and any superseded analysis evidence. Operator
commands return compact action metadata; these records never enter public pages
or feeds.
