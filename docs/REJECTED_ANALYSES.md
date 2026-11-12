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
through these controls. A dismissed or ignored item can be retried, which
reverses the dismissal or reconsiders the item, but neither can be dismissed.

## Inspect

```sh
onionflash rejected list --config config.toml --limit 50
onionflash rejected list --config config.toml --limit 50 --after ITEM_ID
onionflash rejected show --config config.toml --item ITEM_ID
```

`list` includes the item ID, title, source URL, content hash, rejection reason,
attempt count and rejection count. It excludes transient pending failures and
returns a `next_cursor` for bounded ID-based pagination. Limits are 1–200 items.
Use `--status dismissed` to inspect dismissed revisions, or `--status ignored`
for items a review skipped; a skip's reason names the criteria that did not pass.

`show` prints the saved source item, up to 20 recent operator actions, the
item's 20 newest entries in the [decision log](DECISIONS.md), and the final
review's stage, current candidate, numbered source packet (for checking
references such as `S1:P3`), coverage background and latest per-criterion
verdict. They come from the item's review job or, once a commit has finished the
current revision, from the decision that commit recorded, with stage `finished`,
until the deployment's private evidence retention archives that record.
That verdict's `candidate_hash` names the text it evaluated; during `verify`, the
candidate shown is the unchanged draft or its one repair. The output is private
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
bypass validation or approve a publication. An item whose saved source is
incomplete or unreadable cannot be retried; this includes old ignored items whose
source body the deployment's private evidence retention removed. Analysis rejects
a damaged saved copy (not a JSON object in UTF-8 text) before any model call, as
`Stored source item is damaged`. Collection replaces the copy when it sees the
item again, and an unchanged revision keeps its status, so retry it then. For a
GitLab issue whose source takes part in comment checks, the first comment check
that succeeds adds its notes back and decides whether they changed.

The next scheduled run resumes the item. A completed writer draft in its current
review job is retained; the writer runs again only if its source or writer-input
identity changed, or the saved draft cannot be read. Retry then repeats the final
review with the same draft, candidate and source packet. An unchanged reviewer
model and review policy normally return the same verdict, so retry a held item
after its source material, `review.model` or the application's review policy
changed. Review timeouts and endpoint failures resume the unfinished
review/verification stage automatically using normal backoff, unless a story
published in the meantime changed the coverage background, which restarts the
critique; a malformed reply resumes it too, but counts toward the three failures.
A retry never treats a proposed repair as approval.

Retry does not change or delete private analysis records: a held review stays
there, and the new attempt adds its own record. Accepted stories are unchanged.

## Reconsider one ignored item

When inspection shows that a review skipped worthwhile news, retry the item as
above. The writer and review requests run again; with unchanged sources, models
and review policy they normally return the same decision, and the item may be
ignored again. The new review compares the item with the newest stories at
retry time, which may no longer include a story that the earlier decision
compared it with, so check that decision's coverage in `show` first.

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
timestamp, and prior status, counters and error, and each action is also a
[decision](DECISIONS.md). Operator commands return compact action metadata;
these records never enter public pages or feeds.
