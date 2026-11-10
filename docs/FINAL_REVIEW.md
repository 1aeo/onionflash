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
6. If verification does not approve, hold the update. Do not apply a second repair.

The normal successful path uses two model calls: writer and reviewer. One repair
adds a third call. Transport failures may retry through configured endpoints or a
later scheduled run, but completed stages are retained rather than regenerated.
An ignored draft needs no publication review. A wholly deterministic final tag
notice and the existing deterministic monitoring notices do not need LLM review.
An incoming tag is not an exemption when the merged story retains model prose.

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

Candidate and source content are untrusted data. The reviewer has no tools and
cannot treat instructions embedded in either as authority. The response schema
constrains references to identifiers in the packet, and application validation
checks the complete verdict, criteria, references and repair fields again.

## Sources and exact approvals

The packet uses collected source text, not previous generated summaries as
evidence. Current source records are preferred when they match the cited URL.
Retained immutable citations can use exact saved historical snapshots with their
true dates and historical labels. Text from a newer immutable URL is never labeled
as the old citation. Missing required material holds the update.

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

The reviewer uses the existing `[llm]` endpoint, fallbacks, credential environment
and network policy. It defaults to the writer's model. No additional service is
needed. These settings are configurable:

```toml
[review]
model = ""                 # Empty inherits llm.model.
timeout_seconds = 90
connect_timeout_seconds = 10
total_timeout_seconds = 120
max_output_tokens = 2200
max_source_chars = 24000
max_sources = 8
max_passages = 64
passage_chars = 1800
max_repairs = 1             # 0 or 1; never an unbounded rewrite loop.
max_cache_entries = 2000
```

The overall application deadline can cut a request short. That leaves its stage
queued with the normal backoff. Increasing model/source limits also requires a
model endpoint with enough context and sufficient time in the scheduled run.

## Private state and operator inspection

`review_jobs` retains one current job per item, including completed draft,
candidate, source packet, review result and pending verification. Superseded work
is preserved in private analysis audits before being replaced. Completed commits
clear their jobs transactionally.

`review_approvals` caches exact approval receipts. The configured cap applies to
reusable inactive receipts; unfinished approved jobs pin their receipt until
commit/recovery. Full bounded review evidence remains in `analyses.review_record`,
including after a job or reusable cache entry is removed. None of these tables or
source packets are rendered into the public site.

`onionflash status` includes stage/cache counts. A semantic refusal goes directly
to `rejected`, including a `revise` whose repair is missing, unchanged or invalid;
automated rewriting stops for that revision. A truncated or invalid reply keeps
its stage and, like an invalid draft, counts toward the item's three failed
attempts before it also moves there. Inspect rejected items using:

```sh
onionflash rejected list --config config.toml
onionflash rejected show --config config.toml --item ITEM_ID
```

On a deployment, the protected environment wrapper supplies the config:

```sh
./deploy.sh app rejected list
./deploy.sh app rejected show --item ITEM_ID
```

The private inspection output includes the current candidate, structured findings
and numbered passages. An explicit retry, with its current content hash and a
reason, resumes review while retaining the completed writer draft when its inputs
still match. It never bypasses the gate. See [rejection controls](REJECTED_ANALYSES.md).

Existing published articles remain available. Future automatic publications and
updates use this gate; unchanged history is not silently rewritten or retracted.
Locked operator decisions still take precedence. Regular private SQLite backups
include the review state and audit.

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
because the gate would publish it. That check compares wording only. It misses
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
