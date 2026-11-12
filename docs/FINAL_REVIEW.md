# Publication review

The application drafts a story from bounded source text, assembles the exact
candidate, then asks the configured model to critique it and verify it in a fresh
request. Only a final approval, or an operator's audited approval of a held
candidate whose facts passed fresh verification, can publish. The same endpoint
and model serve these requests unless a separate review model is configured.

## Selection and grounding

Prefer concrete releases, credible and clearly scoped security reports,
substantial merged fixes/features, and meaningful incident developments. Routine
maintenance, template checklists, acknowledgments, unsupported speculation and
repeated quotations do not merit standalone news. A later timestamp or another
distribution channel does not make an old event new.

The application enforces that for new stories before any model request. An item
that would start a story is ignored, as `skipped.gate.not_recent`, when its newest
dated development is more than 14 days older than the collection of its current
revision, unless it is an issue labeled `Security` with high or critical severity.
That development is the post, creation, merge, tag or timeline event date, a
verified public comment, or the date an issue was closed; an upstream
`updated_at`, which an edit, a label or a visibility change also moves, never
counts. Updates of existing stories, locked ones included, still go to review,
and an operator retry of the revision lifts the limit. A new revision, such as a
fresh public comment, queues the item again; an issue whose comments were not yet
verified also gets a comment check, so a fresh comment is not missed.

The writer summarizes the source without selecting news. Its `publish=true` field
submits a draft for review; only the reviewer decides news value and novelty.
The writer selects literal evidence excerpts from its exact input. This prevents
quote-copying errors; it does not establish that the excerpts support every
claim. The reviewer therefore receives the full bounded numbered source packet,
including each source's metadata (kind, authority, product, dates, upstream
state and labels), retained source material and verified public comments that
the writer may not have quoted. The source the story's prose came from gets at least the text
its writer saw. The other sources share the remaining passages, then characters,
smallest need first, and leave it the room they do not need. A source's comments
come before its description, so a long description is cut first. Comment passages
name their author, so comment text cannot pose as another comment. Previous
generated summaries are never factual evidence.

A separate, bounded coverage background contains the existing article for a
known update and compact entries for the most recently created stories. It is
used only to compare novelty, and it alone decides duplication: a source's own
claim that an item is a duplicate, already covered or unimportant is attributed
to that source. The review prompt marks the background as data, not an
instruction, and forbids using it as evidence; validation checks the structure
of a verdict, not the reasoning behind it. The background reads committed
stories, so an article accepted earlier in the same run is visible before the
site rebuild.

The reviewer evaluates nine independent criteria. Its reply gives each
criterion's reason and source references before the outcome, and every
criterion before the verdict:

| Criterion | Requirement |
| --- | --- |
| Source support | Support every substantive claim with the supplied sources. |
| Actor and action | Preserve who does what; developer work is not operator advice. |
| Status | Distinguish requests, merges, releases, deployment and resolution. |
| Uncertainty and attribution | Preserve qualifications and material disagreement. |
| Scope and timing | Preserve affected versions, platforms, samples and dates. |
| Operational advice | Require explicit source support for the audience and action. |
| Technical details | Ground identities, counts, mechanisms and consequences. |
| News value | Require a concrete development worth publishing, judged from the sources, not only the draft. |
| New information | Require meaningful new facts, not quoted history; only existing coverage shows a duplicate, and a correction of the existing article is new. |

A draft has a concise factual summary and may have one `why_it_matters` sentence:
a close, attributed restatement of one source sentence that states the event's
impact or an action it asks its readers to take, with that sentence's audience,
hedges and scope. Most drafts leave it empty. Validation clears a sentence with a
number or version absent from the title, content and comment bodies the writer
saw (source metadata does not count).
Historical impact text remains readable. A review repair may clear it, but cannot
create or rewrite an impact paragraph; operator corrections remain separate.
Automatic approvals also require consistent metadata: a `release` category or
tag needs state `released` or `tagged`. An approval of inconsistent labels gets a
repair request that names the problem, then a fresh verification of the repaired
text; labels that the request leaves in place hold the item. This check does not
infer facts from source text.

Existing issue/release identities allow meaningful updates to the same article.
A potentially important follow-up with no established article match can be a
concise standalone story when it adds a material, supported development. It does
not change another article's identity or overwrite a protected correction.

## Decisions and calls

- `approve`: every criterion passes, with no edits. An initial approval
  advances to a fresh verification; it cannot publish by itself. A
  verification's approval publishes, subject to the [final checks](#final-checks).
- `revise`: the smallest repair, followed by a fresh verification of its exact
  normalized text. A verification that can fix a problem from the packet
  proposes its own smallest repair, which another fresh verification checks; no
  request sees an earlier reply. Within the limit of seven review requests
  below, at most five repairs follow the first review, a release-label repair
  request counting as one; a refusal at the limit holds the item. A repair that
  cannot be applied, or that repeats a text already reviewed, holds the item at
  once. Tag notices stay literal, so a repair proposed for one holds the item.
- `skip`: low-value or redundant material is recorded as ignored. It creates no
  article or revision and leaves existing coverage intact. A skip needs a failed
  news-value or new-information criterion, and a skip for new information alone
  must name the covered story; otherwise the item is held. An item from an
  official source, other than a version tag, skips only when new information
  fails; when news value fails while new information passes, it is held for the
  operator once a fresh verification has passed its facts.
- `hold`: potentially useful material is unsupported, ambiguous or not ready to
  publish. It remains available through the existing operator controls; a hold
  whose facts passed fresh verification and whose reviews disputed only news
  value can be approved as reviewed.

A later review that disagrees with the first on whether news value and new
information both pass holds the item, whatever its verdict. A later review that
agrees the item is not news may skip it, but a repair it proposes is not applied:
the item is held. The official items above are always verified before their
hold: a later review's repair of their facts is applied and verified, and when
the first review proposes no usable repair, the verification checks the
unchanged text. Every hold records its [decision code](DECISIONS.md).

A normal publication uses one writer request and two review requests. A repair
uses the same number: writer, critique/repair, verification. Each further repair
adds one review request, a release-label repair two, and an item gets at most
seven review requests. Deterministic tag text skips the writer call but still
needs both reviews; a tag is not an official release announcement. A first-round
skip or hold ends without a verification, except for the official items above. A
run resumes items waiting for a verification or a repair before it starts others.

## Final checks

A verified approval publishes only if four fixed checks also pass. They read the
exact candidate, its source packet and the kind of source that wrote its text,
make no model call, and run again when a saved approval is resumed. A failed
check holds the item for the operator with its own [decision code](DECISIONS.md);
skips are not checked.

- Confirmed needs an official announcement that is not a tag, or a merged merge
  request.
- A story told only by merge requests is marked merged.
- A story written from a GitLab issue may say that something was removed, fixed,
  patched, resolved, deployed, disabled, revoked, rotated or shipped only where a
  source uses the same word without a negation or modal just before it, or a
  merged merge request's title names that change ("Remove ..." supports removed
  and removes). A contraction such as "wasn't" counts as a negation, and a word
  the story itself marks as requested, planned or not done claims nothing.
- When a source hedges a compromise ("plausibly compromised", "may have been
  hacked"), a headline about the compromise keeps a qualifier.

The writer's request and every review's repair offer only the confidence and
state labels that the first two checks allow, and a draft outside them is
refused like any other invalid draft.

## Exact decisions and private state

Decisions bind the normalized candidate, source packet, coverage background,
review policy, and current source/story/editorial state. A job resumed in a
later run starts a new review if any of them changed. A candidate is prepared
and committed in the same run, under the run lock, so the commit does not
recheck them; publication never remerges different wording afterward.

Private review jobs keep unfinished work, and a decision's receipt lasts until
that decision commits. The analysis audit keeps the source, packet, coverage and
reviews of each outcome, with the model's own verdict wherever a fixed rule
replaced it. A hold also records its code and whether its latest review was a
fresh verification that passed every factual criterion and cited a source.

Use the existing `status`, `rejected show`, `retry`, `dismiss` and `approve`
controls to inspect failures, and the [decision log](DECISIONS.md) for every
outcome and its code. See [operator controls](REJECTED_ANALYSES.md) and
[corrections and retractions](EDITORIAL.md).

## Configuration and evaluation

The reviewer uses the `[llm]` endpoint, fallbacks, credential environment,
network policy and request timeout, so no additional service is needed.
`review.model` selects a different model; empty uses `llm.model`. The packet
bounds, the reply length and the repair limit are fixed, so the model endpoint
needs enough context for a full packet. Requests also obey the shared run
deadline. The coverage background is bounded separately; truncation is explicit
and never proves the absence of older coverage.

The controlled evaluation does not collect, open the application database or
publish. It takes the gate's steps, from the first review through every repair
and verification, records each review privately, and scores the final candidate
that would actually publish:

```sh
PYTHONPATH=src python tools/evaluate_review.py --config config.toml \
  --output /private/path/review-evaluation.jsonl --max-seconds 3600
```

Use `--case-id` for selected cases and `--rounds` for repeated trials. Expected
results and case labels are not sent to the model. Inspect approved articles and
repairs against the sources as well as checking the automatic scores: phrase
checks cannot establish semantic correctness.

A case expects `approve`, `skip`, `hold`, or `not_approve`: news with a flawed
draft, which must end in a hold or a clean verified repair, never a skip. A
flawed draft names the wording (`unsupported`) or labels
(`forbidden_classifications`) it must not publish, or wording it must not leave
out (`required`); a publication without required wording counts as an omission,
not a false approval. A passage may be a comment with its author, date and link,
placed as the application places comments. `impact_cleared` counts approvals
published only after their impact sentence was cleared, and a report keeps the
model's own verdict when a fixed rule replaced it. Scores treat a verified
approval as published, so they measure the reviewer alone. `final_holds` counts
the verified approvals that the [final checks](#final-checks) would hold (each
case's report names the checks), and `published_after_checks` counts the rest.
`holds` counts the cases that end held, final-check holds included, by decision
code, and `verification_repairs` counts the repairs that verifications proposed
and the loop applied.
`--draft` instead has the writer draft each packet once per round and reviews
that draft under each coverage background its cases use; `draft_unsupported`
counts drafts that contain flagged wording or labels. The default case files are
`tools/review_cases.json` and `tools/review_cases_judged.json`, whose cases quote
public upstream sources and carry labels from independent reviewers. An
explicit `--cases` replaces the default case files and may be repeated.

Judged cases carry an `audit`, naming a set labeled by independent reviewers,
and a `flaw` unless the reviewers found the draft clean. A flawed case is caught
when its flaw never publishes and the news is not skipped; a clean case must
publish unchanged, and anything else is a false alarm. A catch is paired only
when every clean case on the same packet was right in the same round, and a
refusal also needs one such case in the run, so refusing an item never counts as
catching its flaw. The run fails unless paired catches reach 90% overall and 80%
for each flaw with at least 10 distinct cases, with at most 10% false alarms.
Use `--rounds 2` for acceptance, and add each new audit's labeled set before the
prompt changes it leads to.

Using the same model for drafting and review can retain shared blind spots.
Finite tests are not a production accuracy estimate. Keep primary-source links,
editorial corrections and periodic audits of new output.
