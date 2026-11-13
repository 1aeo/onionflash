# Reviewing rejected analyses

Transient failures, such as an unavailable LLM endpoint, remain pending and use
the normal exponential backoff. Three terminal writer or final-review
content/validation failures, or unexpected processing errors, move an item to
`rejected`. A [final-review](FINAL_REVIEW.md) hold rejects the candidate
immediately; automation does not keep rewriting that source revision.

These local CLI commands act on one item at a time. They do not call the LLM,
retract a story or unlock an editorial correction; only `approve` commits a
story, publishing a held candidate exactly as reviewed.
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
review's stage, hold code, current candidate, `candidate_hash` and the draft it
started from (`base_candidate`), numbered source packet (for checking references
such as `S1:P3`), coverage background, every review of the current chain (its
phase, verdict, `candidate_hash`, failed criteria with their reasons, and
repair), the latest per-criterion verdict in full, any `operator_approval`
recorded on a finished approval, and (for a held job) `approval` with `eligible`,
`reason`, `hash`, `editorial_failures` and `new_coverage`. They come from the
item's review job or, once a commit has finished the current revision, from the
decision that commit recorded, with stage `finished`, until the deployment's
private evidence retention archives that record. Each `candidate_hash` names the
text that review evaluated; during `verify` or `repair`, the candidate shown is
the unchanged draft or its latest repair. The output is private operator data.
`show` also accepts an explicit pending or ignored item ID; inspect the saved
source and decision before deciding whether to intervene.

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
that succeeds adds its notes back and decides whether they changed. A review job
whose saved record cannot be read fails the item without a model call, as
`Saved review job is damaged`; retry starts its review again.

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
ignored again. See [publication review](FINAL_REVIEW.md) for how coverage
background includes the earlier skipped decision's stories.

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

The private `rejection_actions` table records each retry or dismiss reason,
source-version hash, timestamp, and prior status, counters and error, and each
action is also a [decision](DECISIONS.md). Operator commands return compact
action metadata; these records never enter public pages or feeds.

## Approve one held candidate as reviewed

```sh
onionflash rejected show --config config.toml --item ITEM_ID
onionflash rejected approve --config config.toml --item ITEM_ID \
  --approval-hash APPROVAL_HASH --reason "Concrete development worth publishing"
```

`approve` publishes `final_review.candidate` exactly as reviewed, without editing
its wording or calling a model. The operator decides only a disputed `news_value`
call; factual checks remain with the model reviews and deterministic guards.

An item is eligible only when all of these hold:

- the item is `rejected` and its review job is `held`;
- the exact held text (`final_review.candidate`) has at least one saved
  `verification` review;
- every saved review of that exact text re-validates against the current source
  packet, passes all seven factual criteria with `pass`, and cites at least one
  `source_support` reference;
- no review anywhere in the record (including the first review of an earlier
  base draft) failed `new_information`—already-covered items are dismissed, not
  approved;
- the reviews ran under the current `review` policy and packet;
- re-preparing the candidate from the saved draft matches the held base
  candidate, source packet and target story, with no missing sources and an
  unlocked, unretracted story;
- all deterministic [final checks](FINAL_REVIEW.md#final-checks) and release-label
  rules pass on the held candidate.

Factual refusals, including items held after the repair limit, cannot be
approved; they can only be retried or dismissed.

Copy `APPROVAL_HASH` from `final_review.approval.hash` in `rejected show`. It
binds the source revision, target story, lock and source bindings, current
coverage background, exact candidate text, its reviews and the review policy.
`final_review.approval.new_coverage` lists stories created or updated since the
review (compared by `id` and `updated_at`); inspect them for duplicates before
approving. If coverage, sources, story state or review policy changed after
`show`, `approve` refuses without writing anything; run `show` again.

Under the application run lock, `approve` commits the story, marks the item
`published`, deletes the review job, writes an `operator_approved` analysis audit
with `operator_approval` (returning its `analysis_key`), and logs
`operator.approved` in the [decision log](DECISIONS.md). It returns
`publication_pending: true`; the next `build` renders the permalink, listings and
feeds. A later upstream source edit re-queues the item through normal review
against the published story. The private reason and review audit never enter
public output.
