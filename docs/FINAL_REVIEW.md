# Publication review

The application drafts a story from bounded source text, assembles the exact
candidate, then asks the configured model to critique it and verify it in a fresh
request. Only a final approval can publish. The same endpoint and model serve
these requests unless a separate review model is configured.

## Selection and grounding

Prefer concrete releases, credible and clearly scoped security reports,
substantial merged fixes/features, and meaningful incident developments. Routine
maintenance, template checklists, acknowledgments, unsupported speculation and
repeated quotations do not merit standalone news. A later timestamp or another
distribution channel does not make an old event new.

The writer summarizes the source without selecting news. Its `publish=true` field
submits a draft for review; only the reviewer decides news value and novelty.
The writer selects literal evidence excerpts from its exact input. This prevents
quote-copying errors; it does not establish that the excerpts support every
claim. The reviewer therefore receives the full bounded numbered source packet,
including retained source material and verified public comments that the writer
may not have quoted. The source the story's prose came from gets at least the text
its writer saw. The other sources share the remaining passages, then characters,
smallest need first, and leave it the room they do not need. A source's comments
come before its description, so a long description is cut first. Comment passages
name their author, so comment text cannot pose as another comment. Previous
generated summaries are never factual evidence.

A separate, bounded coverage background contains the existing article for a
known update and compact recent articles. It is used only to compare novelty.
It is not an authoritative source or an instruction, and cannot support claims
missing from the source packet. The background reads committed stories, so an
article accepted earlier in the same run is visible before the site rebuild.

The reviewer evaluates nine independent criteria:

| Criterion | Requirement |
| --- | --- |
| Source support | Support every substantive claim with the supplied sources. |
| Actor and action | Preserve who does what; developer work is not operator advice. |
| Status | Distinguish requests, merges, releases, deployment and resolution. |
| Uncertainty and attribution | Preserve qualifications and material disagreement. |
| Scope and timing | Preserve affected versions, platforms, samples and dates. |
| Operational advice | Require explicit source support for the audience and action. |
| Technical details | Ground identities, counts, mechanisms and consequences. |
| News value | Require a concrete development worth publishing. |
| New information | Require meaningful new facts, not duplicate coverage or quoted history. |

New drafts have a concise factual summary and an empty `why_it_matters` field.
The request schema and response validation enforce this; the model cannot add a
separate impact paragraph. An explicitly sourced consequence or requested action
may appear in the summary with its audience, scope and prerequisites preserved.
Historical impact text remains readable. A review repair may clear it, but cannot
create or rewrite an impact paragraph; operator corrections remain separate.
Automatic approvals also require consistent metadata: a `release` category or
tag needs state `released` or `tagged`. An inconsistent approval is held, including
when loading a cached decision. This check does not infer facts from source text.

The model must not invent impact or advice to make a weak source seem important.
An open checklist cannot negate an explicit release announcement, and checked
conditional template steps do not prove that security fixes shipped. Counter
inactivity or unresponsive diagnostics alone do not establish an attack or a
mitigation bypass.

Existing issue/release identities allow meaningful updates to the same article.
Semantic similarity alone never merges unrelated events. A potentially important
follow-up with no established article match can be a concise standalone story
when it adds a material, supported development. It does not change another
article's identity or overwrite a protected correction.

## Decisions and calls

- `approve`: every criterion passes, with no issues or edits. An initial approval
  advances to fresh final verification; it cannot publish by itself.
- `revise`: one minimal repair is allowed, followed by fresh verification of its
  exact normalized text. No rewrite loop or second repair is applied.
- `skip`: low-value or redundant material is recorded as ignored. It creates no
  article or revision and leaves existing coverage intact.
- `hold`: potentially useful material is unsupported, ambiguous or not ready to
  publish. It remains available through the existing operator controls.

A normal publication uses one writer request and two review requests. A repair
uses the same number: writer, critique/repair, verification. Deterministic tag
text skips the writer call but still needs both reviews; a tag is not an official
release announcement. A first-round skip or hold ends without final verification.
Historical ignored drafts remain readable; new writer requests cannot silently
skip a source before editorial review.

Completed stages survive interruptions. Transport failures use the normal
backoff; malformed replies count against the item rather than retrying forever.
Human corrections and retractions retain their separate trusted, locked workflow.
Raw monitoring feeds are not collected or published.

## Exact decisions and private state

Decisions bind the normalized candidate, source packet, coverage background,
review policy, and current source/story/editorial state. The commit rechecks
these bindings in an immediate SQLite transaction. Changed context invalidates
the decision; publication never remerges different wording afterward.

Private review jobs retain unfinished work. The bounded decision cache and
analysis audit retain the source/context and reviews used for the decision.
Only a recorded successful final verification can authorize publication.
Skipped candidates are audited without changing articles or editorial controls.

Use the existing `status`, `rejected show`, `retry` and `dismiss` controls to
inspect failures. See [operator controls](REJECTED_ANALYSES.md) and
[corrections and retractions](EDITORIAL.md).

## Configuration and evaluation

The reviewer uses the `[llm]` endpoint, fallbacks, credential environment,
network policy and request timeout, so no additional service is needed.
`review.model` selects a different model; empty uses `llm.model`. The packet
bounds, the reply length and the single repair are fixed, so the model endpoint
needs enough context for a full packet. Requests also obey the shared run
deadline. The coverage background is bounded separately; truncation is explicit
and never proves the absence of older coverage.

The controlled evaluation does not collect, open the application database or
publish. It exercises both review rounds, records their outputs privately, and
scores the final candidate that would actually publish:

```sh
PYTHONPATH=src python tools/evaluate_review.py --config config.toml \
  --output /private/path/review-evaluation.jsonl --max-seconds 3600
```

Use `--case-id` for selected cases and `--rounds` for repeated trials. The older
`--verify-repairs` option remains accepted; final verification always runs.
Expected results and case labels are not sent to the model. Inspect approved
articles and repairs against the sources as well as checking the automatic
scores: phrase checks cannot establish semantic correctness.

Using the same model for drafting and review can retain shared blind spots.
Finite tests are not a production accuracy estimate. Keep primary-source links,
editorial corrections and periodic audits of new output.
