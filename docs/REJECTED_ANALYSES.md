# Reviewing rejected analyses

Transient failures, such as an unavailable LLM endpoint, remain pending and use
the normal exponential backoff. Three terminal writer or final-review
content/validation failures, or unexpected processing errors, move an item to
`rejected`. A [final-review](FINAL_REVIEW.md) hold rejects the candidate
immediately; automation does not keep rewriting that source revision.

These local CLI commands act on one item at a time. They do not call the LLM,
publish a story, retract a story or unlock an editorial correction.
Retry and dismiss also accept a `pending` item that has already failed: its
attempt count must be positive and its saved error must be nonblank. This lets
an operator act on a reviewed failure without waiting for terminal rejection.
New or reset pending items and published items cannot be retried or dismissed
through these controls. A dismissed item can be retried, which reverses the
dismissal, but not dismissed again. Ignored items require the explicit
reconsideration option described below; ordinary retry and dismiss refuse them.

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

`show` prints the saved source item, up to 20 recent operator actions and, while
a final-review job exists, its stage, current candidate, numbered source packet
(for checking references such as `S1:P3`) and latest per-criterion verdict. That
verdict's `candidate_hash` names the text it evaluated; during `verify`, the
candidate shown is a repair that has not been verified yet. The output is private
operator data. `show` also accepts an explicit pending or ignored item ID;
inspect the saved source and decision before deciding whether to intervene.

## Retry one failed or dismissed revision

```sh
onionflash rejected retry --config config.toml --item ITEM_ID \
  --expect-hash CURRENT_CONTENT_HASH --reason "The grounding rule was fixed"
```

Copy `CURRENT_CONTENT_HASH` from the inspected item. A changed hash or an
ineligible queue state stops the action. Retry resets the attempt/rejection counts
and cooldown, then queues the item for the normal analysis pipeline. It does not
bypass validation or approve a publication. A missing or unreadable source body
must be restored or recollected before retrying.

The next scheduled run resumes the item. A completed writer draft in its current
review job is retained; the writer runs again only if its source or writer-input
identity changed. Retry then repeats the final review with the same draft,
candidate and source packet. An unchanged reviewer model and review policy
normally return the same verdict, so retry a held item after its source material,
`review.model` or the application's review policy changed. Review timeouts and
endpoint failures resume the unfinished review/verification stage automatically
using normal backoff; a malformed reply resumes it too, but counts toward the
three failures. A retry never treats a proposed repair as approval.

Retry does not change or delete private analysis records: a held review stays
there, and the new attempt adds its own record. Accepted stories are unchanged.

## Reconsider one ignored item

When inspection identifies worthwhile news previously ignored by the selection
policy, explicitly queue that saved revision for another decision:

```sh
onionflash rejected show --config config.toml --item ITEM_ID
onionflash rejected retry --config config.toml --item ITEM_ID \
  --reconsider-ignored --expect-hash CURRENT_CONTENT_HASH \
  --reason "Reviewed the saved source after a selection-policy correction"
```

The flag applies only to retry and permits `ignored` as an additional state.
It does not permit published, new pending or reset pending items. Repeating the
command immediately after a successful retry is refused. The existing hash,
readable-source and queue-state checks still apply, and the private audit records
the prior ignored state and the reason.
Saved review decisions for that item are invalidated, so even an identical draft
receives a fresh editorial decision. Unrelated cached decisions are preserved.
Only the selected item is queued; no source content or timestamps are invented,
and no historical items are reset automatically. The normal writer and review
pipeline decides whether to publish it and may ignore it again.

Reconsideration does not reactivate retired alert sources. An item whose configured
source still uses `alert_format = "consensus"` or `"censorship"` cannot be retried:
the CLI refuses it before changing queue state, audit records or saved evidence.
Existing pending alerts are still ignored by the normal run before drafting.
Use reconsideration for supported news sources.

## Dismiss one failed revision

```sh
onionflash rejected dismiss --config config.toml --item ITEM_ID \
  --expect-hash CURRENT_CONTENT_HASH --reason "Routine discussion without news"
```

Dismiss sets the revision to `dismissed` and removes its retry schedule. The same
content, repeated polls, or an upstream timestamp-only edit cannot requeue it; to
reverse a dismissal, retry it with the same hash. A change to source content or
classification metadata can create a new pending revision under the same item ID,
resetting its counters through normal collection. The earlier dismissal and its
content hash remain in the audit history. A dismissal is therefore a decision
about that source revision, not a permanent ban on future reporting.

Both actions require a reason of 1–1,000 characters. Repeating an already-applied
action returns a state error without resetting the queue or adding another audit
record. Mutations run under the application's existing run lock and apply an
additional content-hash, payload and queue-state guard in SQLite, including the
observed counters, error and cooldown. A failed audit write rolls back the whole
action.

The private `rejection_actions` table records each reason, source-version hash,
timestamp, and prior status, counters and error. Operator commands return compact
action metadata; these records never enter public pages or feeds.
