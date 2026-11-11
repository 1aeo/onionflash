# Final publication review

The reviewer evaluates the exact current story that would be published, including
wording retained from an existing grouped story. It never approves only an incoming
draft and then allows storage precedence to substitute different text afterward.
Operator corrections and retractions retain their separate, trusted local workflow.

## Workflow

1. Generate one structurally valid draft and save it privately.
2. Assemble the final candidate using existing identity, grouping, precedence,
   citation, date and editorial-lock rules.
3. Build a bounded packet of actual source material, with identifiers such as
   `S1:P3`. Include material supporting retained prior wording and verified public
   comments even when the writer did not quote them.
4. Make a fresh reviewer request containing the candidate and source packet.
5. Publish only an `approve` result with all seven criteria passing, no issues and
   no edits. A `revise` response may propose one minimal semantic repair. Normalize
   that repair, then send its exact text and sources in a fresh verification request.
6. Hold the update if required source material is unavailable, the review returns
   `hold`, a `revise` arrives while `max_repairs = 0`, a repair is missing,
   unchanged or invalid, or verification does not approve. Do not apply a second
   repair. A candidate that was held before stays held without another review,
   for example after a source reverts to a held revision.

The normal successful path uses two model calls: writer and reviewer. One repair
adds a third call. Transport failures may retry through configured endpoints or a
later scheduled run, but completed stages are retained rather than regenerated.
An ignored draft needs no publication review. A wholly deterministic final tag
notice does not need LLM review. An incoming tag is not an exemption when the
merged story retains model prose. Raw monitoring follows the separate
[private-candidate policy](MONITORING.md).

## Rubric

Every criterion has its own `pass`, `fail` or `insufficient` result and source
references. There is no averaged score or majority approval.

| Criterion | Required behavior |
| --- | --- |
| Source support | Every substantive current claim is supported by the packet. |
| Actor and action | Preserve who does what; developer work cannot become operator configuration advice. |
| Status | Distinguish requests, proposals, merges, releases, deployment and resolution. |
| Uncertainty and attribution | Preserve report/suspicion qualifiers and the actual speaker. |
| Scope and timing | Do not turn a single failed probe into country-wide blocking, or an old report into a current attack. |
| Operational advice | Require explicit source support for the stated audience and action. |
| Technical details | Ground versions, dates, counts, identities, causes and impacts. |

This is factual review. Supported wording is not rejected for repetition, brevity
or stylistic preference. `why_it_matters` can be an empty string or a faithful
restatement of a source concern; no extra impact statement is required. A repair
must remove or minimally correct unsupported claims, not add plausible advice.
Trusted editorial history labeled superseded is not current reporting.

Candidate and source content are untrusted data. The reviewer has no tools, and
its prompt tells it to disregard instructions, role claims and purported
approvals embedded in either. This reduces prompt-injection risk but does not
remove it. The response schema constrains references to identifiers in the
packet, and application validation checks the complete verdict, criteria,
references and repair fields again; that checks a verdict's structure, not why
the model reached it.

## Sources and exact approvals

The packet uses collected source text, not previous generated summaries as
evidence. Current source records are preferred when they match the cited URL.
Retained immutable citations can use exact saved historical snapshots with their
true dates and historical labels. Text from a newer immutable URL is never labeled
as the old citation.

Source and passage counts and text lengths are bounded. Truncation is explicit;
the model may not infer omitted material. Unknown legacy writers require the
retained source set to be available within those bounds. Source-link metadata
alone is not a substitute for a missing body needed to support a substantive claim.

Approvals bind the exact normalized candidate, supplied source packet, reviewer
policy and current item/source/story/editorial-lock fingerprints. A commit takes
an immediate SQLite transaction and checks those bindings again. Changed inputs
invalidate the approval. The approved candidate is written directly; no later
merge or semantic rewrite can restore an old unsupported sentence. Only a new
story's `added_at`, its publishing date, is set at commit instead, so a retried
review cannot backdate it.

## Configuration

The reviewer uses the `[llm]` endpoint, fallbacks, credential environment and
network policy, so no additional service is needed. `review.model` selects a
different model; empty uses `llm.model`. [`config.example.toml`](../config.example.toml)
lists the other `[review]` settings and their defaults. Raising the source limits
also needs a model endpoint with enough context and enough time in each run.

## Private state and operator inspection

Review jobs, approval receipts and review audits are private SQLite state; none
of them, and no source packet, is rendered into the public site.
`onionflash status` reports stage and cache counts. A hold enters `rejected`,
where [rejection controls](REJECTED_ANALYSES.md) inspect, retry or dismiss it.

## Evaluate the configured model

Mocked tests establish the publication contract and failure behavior. They do not
establish that a model's semantic judgments are accurate. The controlled corpus,
`tools/review_cases.json`, contains the saved bastet mistake and synthetic
negative/positive controls for each rubric area, including legitimate operator
instructions. Model-visible IDs and synthetic URLs are opaque; case names and
expected results are not sent.

After loading the same LLM environment used by the application:

```sh
PYTHONPATH=src python tools/evaluate_review.py --config config.toml \
  --output /private/path/review-evaluation.jsonl --max-seconds 1800
```

Add `--verify-repairs` to apply each proposed repair and send it to the same model
in the gate's verification request. A verified repair of a negative case that
still contains one of the case's `unsupported` phrases counts as a false approval,
because the gate would publish it. A verified repair of a positive case counts
as an approval for the same reason. That check compares wording only. It misses
paraphrases and new claims, and it also counts a faithful repair that keeps a
phrase inside a negation, such as "no evidence that ...". So read `repaired` in
the private report for every verified repair, including each one counted as a
false approval. Use `--case-id NAME` to select a case, or `--rounds 2` to repeat
controls. Output must be a new private file outside the public directory. The
tool does not collect sources, open the application database or publish stories.
It records errors and incomplete runs as failures, rather than counting them as
successful judgments.

Using the same model for writing and review can retain shared blind spots.
Keep the correction workflow and primary-source links, and evaluate changed
models or rubric versions before rollout. Passing a finite corpus is not a
guarantee that all future factual errors will be caught.
