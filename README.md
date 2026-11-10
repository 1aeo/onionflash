# Onion Flash

**Important Tor news, distilled.** Onion Flash collects public feeds and GitLab
updates, uses a configurable LLM to produce concise source-linked summaries, and
builds a static website, RSS feeds, and JSON Feed. It is an independent 1AEO
project, not an official Tor Project publication.

One Python application, one TOML configuration file, and SQLite. The public site
does not call an LLM or need a database server. Deployment and scheduling live in
[`1aeo/onionflash-deploy`](https://github.com/1aeo/onionflash-deploy).

## Quick start

Requirements: **Python 3.11 or newer**, a Linux/macOS host, and an API endpoint
supporting chat completions with JSON Schema output. The endpoint and model are
configurable.

```bash
git clone https://github.com/1aeo/onionflash.git
cd onionflash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
cp config.example.toml config.toml
chmod 600 config.toml
# For local preview, edit config.toml: site.base_url = "http://localhost:8080/"

export ONIONFLASH_LLM_BASE_URL='https://your-inference-host.example/v1'
# Read your credential interactively so it does not enter shell history.
read -r -s ONIONFLASH_LLM_API_KEY
export ONIONFLASH_LLM_API_KEY

onionflash check --config config.toml
onionflash run --config config.toml
python -m http.server 8080 --directory build/public
```

The generated website is in `build/public/`. Open `http://localhost:8080/` after
setting that address as `site.base_url`. Change it to the real deployment URL
before publishing. `feed.xml` is the main RSS feed, `feed.json` is JSON Feed, and
`tags/security.xml` is one of the topic-specific RSS feeds.

The first run collects up to the configured lookback window and analyzes a
bounded number of items. More items remain queued for subsequent runs. An empty
first page can mean the LLM is not configured or the queue has not yielded a
publishable story yet; `onionflash status --config config.toml` explains queue
and source status. No sample stories are published.

For server installation, use the deployment repository's `install.sh` and quick
start. It installs the recurring job, protects credentials, checks publication,
and handles Cloudflare and DigitalOcean Spaces. Running `onionflash run` itself
only creates local files.

## Configuration

The deployment repository schedules `onionflash run` (`interval_minutes` in its
`deployment.toml`; apply changes with `./deploy.sh schedule`). Each source also
has `interval_seconds` (default 300), so a slower source can be polled less often
than the job runs; it cannot make the job run more often. A successful poll is
rescheduled a few seconds early (at most a tenth of the interval) to absorb
scheduler start jitter; failure and Retry-After cooldowns are never shortened.

All settings are shown in [`config.example.toml`](config.example.toml). Settings that
were removed (such as `http.requests_per_minute`) still load; each is logged as
ignored and can be deleted. Relative
database and output paths resolve against the configuration file's directory.
`${ENVIRONMENT_VARIABLE}` references are expanded for paths and LLM URLs.
The API key is read only from the `ONIONFLASH_LLM_API_KEY` environment variable.

| Section | Settings |
| --- | --- |
| `site` | Title, description, canonical URL, repository link, page/feed sizes |
| `storage` | Private SQLite path, owned public output directory and bounded article-render batch size |
| `comments` | Optional anonymous GitLab discussion enrichment, polling/backoff, per-run/page/text limits and bounded watch-cache size |
| `llm` | Base URL and fallback URLs, model, private-network allowlist (`allowed_networks`, `allow_http`), request timeout, items per run, chat-template flag |
| `sources` | Stream ID, display name, public website URL, kind, collection URL, fallback URLs, product, authority, optional interval/page/item overrides |

Collection, HTTP and other model limits (lookback, budgets, retries, response sizes,
backoff) are fixed defaults in `onionflash/config.py`; a file that still sets them
loads, with each one logged as ignored.

Public sources must use HTTPS. Private inference endpoints require explicit
`llm.allowed_networks` CIDRs and `llm.allow_http = true` when using HTTP. Prefer
exact `/32` or `/128` addresses. Default-route allowlists are rejected.
Do not commit a production configuration containing infrastructure details.
For a compatible provider other than vLLM, set
`llm.send_chat_template_kwargs = false` if it does not accept that extension.

To replace or add a source, edit its entry:

```toml
[[sources]]
id = "my-release-feed"
name = "My release announcements"
website_url = "https://example.org/releases/"
kind = "feed"                     # feed, tag, gitlab_issue, gitlab_mr, metrics_timeline
url = "https://example.org/feed.xml"
fallback_urls = ["https://mirror.example.org/feed.xml"]
product = "tor"                   # tor, arti, tor-browser, torspec, network
authority = "official"            # official, community, development, telemetry
interval_seconds = 300
max_pages = 5
max_items = 250
```

`name` is the descriptive label in Source availability. Optional `website_url`
links that label to a public page readers can browse, such as a mailing-list
archive or GitLab issue list; `url` remains the feed or API collection endpoint.

Fallback URLs must represent the **same logical stream**. A changed primary URL
resets that source's fetch cursor and conditional cache. Disabling a source stops
collection without erasing already published news. GitLab merged changes are
collected across branches, including maintenance branches.

The Metrics Timeline source uses `kind = "metrics_timeline"` with the maintained
repository's GitLab file JSON API URL and its repository root as `website_url`.
It reads the Markdown table without running upstream scripts, validates the
snapshot and uses conditional HTTP requests. The stale Metrics Atom feed is no
longer configured, including as a fallback.

### Public GitLab comments

Set `[comments].enabled = true` to enrich relevant GitLab issues with public
discussion. Each participating `gitlab_issue` source needs its exact
`gitlab_project`, such as `tpo/core/tor`; the example already identifies the Tor
projects. `comments_graphql_url` optionally overrides the same-origin GraphQL
endpoint, and `comments_enabled = false` excludes an individual source.

No GitLab account, token or browser session is used. The collector verifies the
project identity and public visibility, the issue's non-confidential status,
and each note's non-internal/non-system status. Unknown visibility never admits
new comment content. Comment authors and dates stay explicit, and the model's
grounding pass sees exactly the same bounded text used for evidence validation.

Comments default to a 30-minute per-issue interval. Per-run limits rotate across
projects and previously published issues, so this is bounded follow-up coverage,
not an exhaustive discussion mirror. The phase shares collection time and keeps
the configured analysis reserve; primary sources retain at least half the
collection window. `onionflash status` reports comment scheduling and failures.
See [source coverage](docs/SOURCE_COVERAGE.md#anonymous-public-gitlab-discussion-updates).

Timeline entries keep their event dates; repository revisions do not turn old
open-ended events into new incidents. Citations point to the exact commit and
table line. Ambiguous recent rows are skipped with a source warning. See
[timeline coverage and identity rules](docs/SOURCE_COVERAGE.md#tor-metrics-timeline).

### Automated monitoring alerts

Consensus-health and anti-censorship alerts use deterministic parsers selected
by `alert_format`, with a configured `monitor_id` shared by any mirrors of the
same monitor. They bypass the LLM. Unknown formats and undated messages cannot
become news stories.

The private SQLite incident records group repeated notifications. Eligible
directory-document warnings about a known directory authority need two reports
at least one hour apart within a two-day window before publication as
**observed anomalies**. Ordinary repeats do not create stories, change RSS GUIDs
or advance publication dates; a warning after two quiet days starts a new episode.
Missing alerts never establish recovery.

Probe outages, unreachable services and censorship-monitor failures are held
privately. The current alert feed does not provide independent healthy-vantage
or control-test evidence, so repeated failures cannot establish country-wide
blocking or an attack. `onionflash status --config config.toml` includes grouped
monitoring status. See [monitoring behavior and limits](docs/MONITORING.md).

## Commands

```sh
onionflash check --config config.toml            # Validate; no network requests
onionflash run --config config.toml              # Collect → analyze → build
onionflash build --config config.toml            # Offline build from saved news
onionflash build --config config.toml --force    # Queue a bounded full-history rebuild
onionflash status --config config.toml           # Source freshness and queue
onionflash story show --config config.toml --story STORY_ID
onionflash rejected list --config config.toml
```

### Correct or retract a story

Inspect the story first and copy its current `hash`. Put only the public fields
to change in a small JSON file, for example:

```json
{"why_it_matters":"The report says the existing keys cannot be trusted and requests removal of the current entry from the software."}
```

```sh
onionflash story correct --config config.toml --story STORY_ID \
  --expect-hash CURRENT_HASH --patch correction.json \
  --reason "The previous version included an unsupported operator instruction."
onionflash build --config config.toml
```

The correction is locked against later automation. The reason is public; previous
published text and the operator action are retained in revision history. A stale
hash fails without changing anything. Retraction keeps the same article URL with
a clear notice. Explicit restore and unlock commands are available; a retraction
must be restored before automation can resume. The next scheduled deployment
publishes pending changes, or use the deployer's `publish` command after building.
See [editorial commands and recovery](docs/EDITORIAL.md).

### Review a rejected analysis

`onionflash rejected list` shows terminally rejected items with their reason,
attempt count and current content hash. `rejected show --item ITEM_ID` includes
the saved source. Explicit `retry` and `dismiss` actions require that hash and a
private operator reason; neither action invokes the model or publishes anything.
A dismissed item stays dismissed while its content is unchanged. Substantive new
source content can queue it again. See [rejected-analysis commands](docs/REJECTED_ANALYSES.md).

Each command returns a compact JSON result. Invalid configuration or a build
failure returns nonzero. A partial source outage or queued analysis is reported
in the result and status without discarding the previous site. Runs and builds
use a nonblocking lock at `<database>.lock`: an overlapping run exits cleanly,
and a build that finds the lock held exits 75 without building. `status` only
reads and needs no lock.

The public output is a dedicated generated directory. Onion Flash refuses to
replace an existing nonempty directory without its ownership marker, kept next
to—not inside—the public directory. Its presence permits moving or restoring an
installation. Changed files are replaced atomically, and an unfinished build is
marked so the publisher keeps the preceding release. Publishers use the same
database lock while taking their upload snapshot.

## Reliability and editorial behavior

- Public HTTP and private inference share the same transport helper. It validates
  addresses at TCP connection time, pins connections to vetted IPs while retaining
  TLS hostname verification, rechecks redirects, and enforces compressed and
  decompressed response-size limits. Source content never executes commands.
- HTTP retries are limited to transient failures. Exponential backoff has a cap,
  jitter, and bounded `Retry-After`. Persisted source cooldowns and failed-analysis
  delays survive restarts. One failed source does not invalidate published news.
- GitLab scans read issues and merge requests in ascending `updated_at` order from
  one inclusive watermark. Each request starts a fresh query from the last row
  seen, so a record edited mid-scan cannot shift an offset and be skipped. The
  exception is a full page whose rows all share one timestamp, which takes 50
  records updated in the same millisecond, in practice a bulk update. GitLab
  offers no finer cursor, so such a tie is stepped by page, and an edit that
  moves one of its rows during the scan can shift another past it. A scan that
  is capped, cut off by its deadline or interrupted by an error resumes from the
  last row on the next run. An interrupted tie restarts from its first page, and
  a run whose whole page budget falls inside one tie skips the rest of it rather
  than repeat it forever. A completed scan moves the watermark to the poll start
  minus a 15-minute overlap. XML declarations/entities are rejected with an
  encoding-aware parser before feed parsing.
- New and changed items are saved before analysis. Private analysis records are
  identified by content hash, model, prompt version and input window; saved results
  are never reused to skip analysis. The application makes one model request
  at a time, with explicit per-run and token limits. Source polling reserves time
  for pending analysis so an unavailable source cannot monopolize every run.
- Explicit `kind = "tag"` streams produce attributed tag notices without an LLM
  request. These notices remain `tagged`, have a fixed queue-priority
  floor, and cannot replace a richer announcement already grouped with that
  version. Repeated identical model labels are normalized rather than retried;
  invalid labels and unsupported evidence are still rejected.
- Summaries need schema-valid fields and exact supporting excerpts from the
  supplied source. The excerpts stay private; public citations are created from
  collected URLs, never model-proposed URLs. Source text is treated as untrusted
  data. Evidence matching is an automated check, **not proof of factual accuracy**.
- Reports and suspected compromises retain explicit uncertainty; monitoring
  alerts publish only as attributed `observed-anomaly` notices. GitLab issue
  hosting alone does not establish confirmation. Tags
  are marked `tagged`; merges are marked `merged`. A later tag cannot downgrade an
  already announced release.
- Matching release versions/products, identical titled issue bodies, and
  canonical URLs provide conservative duplicate grouping. Semantic similarity
  alone does not combine unrelated incidents. Original publication dates and
  stable story IDs remain intact when stories are updated.
- Every run checks queued article changes and refreshes the homepage; only
  changed artifact bytes need publication. The public Source availability panel shows only
  Collected or Delayed (no success within two hours);
  `onionflash status` has current collection timestamps and errors.

## Deliberate limits

The collector reads feed entries and GitLab issue/MR titles and bodies, with
optional bounded public issue-comment enrichment.
It does not scrape arbitrary links, ingest private issues, or claim complete
coverage of every discussion comment. RSS feeds expose finite recent windows;
outages longer than those windows can leave gaps. GitLab pagination and source
health make incomplete scans visible, but upstream data can change while a scan
is in progress. Treat this as a news aid, not an incident-detection guarantee.

Published stories keep their pages indefinitely. The homepage covers the entire
history across numbered pages; `site.page_size` controls stories per page, not
retention. `site.feed_size = 0` includes the complete history in RSS, JSON Feed
and topic feeds. A positive feed size remains an optional reader-facing limit.
The retired `storage.max_stories` setting is accepted and ignored.

The incremental builder renders only changed articles, in batches controlled by
`storage.render_batch_size` (250 by default). Each accepted story has HTML and a
public `story.json`. The publication catalog retains compact last-good article
JSON so a damaged source record or database-only restore does not erase a
previously published page. A rejected source revision remains quarantined.

Full-history feeds are streamed from the catalog in bounded batches. Indexes and
feeds update when accepted content changes; normal polling does not rewrite old
article files. Template/year changes and `build --force` queue resumable rebuilds.
If `articles_pending` is nonzero, subsequent builds continue the work.

Keep the SQLite database, raw source content, analysis evidence and private
publication metadata outside the webroot. The deployment repository can publish
durable objects through DigitalOcean Spaces while preserving the existing URLs.
See [permanent history and recovery](docs/PERMANENT_HISTORY.md).

LLM availability and output quality depend on your model. The prompt and evidence
checks reduce unsupported statements, but important security conclusions should
always be checked against the linked primary source. Personal alert delivery is
intentionally outside this initial website/RSS release.

See [source coverage and remaining features](docs/SOURCE_COVERAGE.md).

## Development

```sh
python -m pip install -e '.[test]'
python -m pytest -q
node --test tests/*.mjs
```

Tests cover unsafe URLs and redirects, DNS rebinding, gzip expansion, timeouts,
retry caps, hostile XML, malformed responses, pagination recovery, durable queues,
deduplication/lifecycle changes, model validation, HTML/RSS escaping, and preserving
the previous site after failed rendering. Apache 2.0; see [`LICENSE`](LICENSE).
