# Onion Flash

**Important Tor news, distilled.** Onion Flash collects public feeds and GitLab
updates, uses a configurable LLM to produce concise source-linked summaries, and
builds a static website, RSS feeds, and JSON Feed. It is an independent 1AEO
project, not an official Tor Project publication.

One Python application, one TOML configuration file, and SQLite. The public site
uses HTML and CSS with no browser JavaScript or search service, and its Content
Security Policy blocks all scripts. It does not call an LLM or need a database
server. Deployment and scheduling live in
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
`tags/security.xml` is one of the topic-specific RSS feeds. Topic links open
static pages such as `topics/security/` that cover the whole history, including
secondary topic tags.

The first run collects up to the fixed lookback window and analyzes a
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
`${ENVIRONMENT_VARIABLE}` references are expanded for paths and LLM URLs; each
entry in `llm.fallback_base_urls` must expand to a nonempty URL.
The API key is read only from the `ONIONFLASH_LLM_API_KEY` environment variable.

| Section | Settings |
| --- | --- |
| `site` | Title, description, canonical URL, repository link, page size |
| `storage` | Private SQLite path and owned public output directory |
| `comments` | Optional anonymous GitLab discussion enrichment (`enabled`) |
| `llm` | Base URL and fallback URLs, model, private-network allowlist (`allowed_networks`, `allow_http`), request timeout, items per run, chat-template flag |
| `review` | Reviewer model override |
| `sources` | Stream ID, display name, public website URL, kind, collection URL, fallback URLs, product, authority, optional interval/page/item overrides |

Collection, HTTP, model, comment, final-review and publication limits (lookback,
budgets, retries, response sizes, backoff, source-packet bounds,
render batch) are fixed in code; a file that still sets one loads, with each one
logged as ignored.

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
collected across branches, including maintenance branches. Consensus-health
alert feeds (`alert_format = "consensus"`, requiring `website_url`) route DocTor
reports into fixed-text incident rules with `publish = false` dry-run mode by
default, while other legacy `alert_format` entries remain disabled; see
[network-health alerts and retired formats](docs/SOURCE_COVERAGE.md#network-health-alerts).

The Metrics Timeline source uses `kind = "metrics_timeline"` with the maintained
repository's GitLab file JSON API URL and its repository root as `website_url`.
It reads the Markdown table without running upstream scripts, validates the
snapshot and uses conditional HTTP requests. The stale Metrics Atom feed is no
longer configured, including as a fallback. Timeline entries keep their event
dates; repository revisions do not turn old open-ended events into new incidents.
Citations point to the exact commit and table line. Ambiguous recent rows are
skipped with a source warning. See
[timeline coverage and identity rules](docs/SOURCE_COVERAGE.md#tor-metrics-timeline).

### Public GitLab comments

Set `[comments].enabled = true` to add public discussion to GitLab issues. Each
participating `gitlab_issue` source needs its exact `gitlab_project`, such as
`tpo/core/tor`; the example already identifies the Tor projects. Leave out
`gitlab_project` to keep a source out. No GitLab account, token or browser
session is used. This is bounded follow-up coverage, not an exhaustive discussion
mirror; `onionflash status` reports comment scheduling and failures. See
[source coverage](docs/SOURCE_COVERAGE.md#anonymous-public-gitlab-discussion-updates).

## Commands

```sh
onionflash check --config config.toml            # Validate; no network requests
onionflash run --config config.toml              # Collect → analyze → build
onionflash build --config config.toml            # Offline build from saved news
onionflash build --config config.toml --force    # Queue a bounded full-history rebuild
onionflash status --config config.toml           # Source freshness and queue
onionflash story show --config config.toml --story STORY_ID
onionflash rejected list --config config.toml
onionflash decisions summary --config config.toml # Private decision counts for the last 7 days
```

Each command returns a compact JSON result. Invalid configuration or a build
failure returns nonzero. A partial source outage or queued analysis is reported
in the result and status without discarding the previous site. Runs and builds
use a nonblocking lock at `<database>.lock`: an overlapping run exits cleanly,
and a build that finds the lock held exits 75 without building. `status` only
reads and needs no lock.

The public output is a dedicated generated directory. Onion Flash refuses to
replace an existing nonempty directory without its ownership marker, kept next
to—not inside—the public directory. Its presence permits moving or restoring an
installation. Changed files are staged beside the public directory, on the same
filesystem, and replaced atomically. An unfinished build is marked so the
publisher keeps the preceding release. Publishers use the same database lock
while taking their upload snapshot.

### Editorial controls

`onionflash story show|history|correct|retract|restore|unlock` corrects or
retracts a published story; `onionflash rejected list|show|retry|dismiss|approve`
handles failed analyses and ignored items; `onionflash decisions summary|list`
reads the private log of every decision. See
[editorial commands and recovery](docs/EDITORIAL.md),
[rejected-analysis commands](docs/REJECTED_ANALYSES.md) and
[the decision log](docs/DECISIONS.md).

## Reliability and editorial behavior

Automatic stories, tag notices included, publish only after a model critique of
the exact candidate against its numbered sources and recent coverage, then a
fresh verification. See
[selection, final review and evaluation](docs/FINAL_REVIEW.md).

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
  exception is a full page whose rows all share one timestamp: 50 records updated
  in the same millisecond, or a source's `max_items` if that is smaller. With the
  default limits that means a bulk update. GitLab offers no finer cursor, so such a tie is stepped by page, and an edit that
  moves one of its rows during the scan can shift another past it. A scan that
  is capped, cut off by its deadline or interrupted by an error resumes from the
  last row on the next run. An interrupted tie restarts from its first page, and
  a run whose whole page budget falls inside one tie skips the rest of it rather
  than repeat it forever. A completed scan moves the watermark to the poll start
  minus a 15-minute overlap. XML declarations/entities are rejected with an
  encoding-aware parser before feed parsing.
- New and changed items are saved before analysis. Private analysis records remain
  an audit, not a general runtime analysis cache. The application makes one model
  request at a time, within the existing run budget, and preserves the analysis
  time reserve.
- Explicit `kind = "tag"` streams produce attributed drafts locally, then use the
  same publication reviews. These notices remain `tagged`, have a fixed queue-priority
  floor, and cannot replace a richer announcement already grouped with that
  version.
- Summaries need schema-valid fields and exact supporting excerpts from the
  supplied source. The excerpts stay private; public citations are created from
  collected URLs, never model-proposed URLs. Source text is treated as untrusted
  data. Repeated identical model labels are normalized rather than retried;
  invalid labels and unsupported evidence are still rejected.
- Reports and suspected compromises retain explicit uncertainty. Confirmed needs
  an official announcement (not a tag) or a merged merge request, so GitLab issue
  hosting alone does not establish confirmation. Tags are marked `tagged`, and a
  story told only by merge requests is `merged`. A later tag cannot downgrade an
  already announced release. See the [final checks](docs/FINAL_REVIEW.md#final-checks).
- Matching release versions/products, identical titled issue bodies, and
  canonical URLs provide conservative duplicate grouping, and reviewer-confirmed
  same-event candidates attach to existing stories instead of opening second
  headlines (see [editorial controls](docs/EDITORIAL.md)). Semantic similarity
  alone does not combine unrelated incidents. Follow-ups add short dated updates
  instead of rewriting a prose story; only a literal tag notice or timeline
  entry is replaced in place by a richer source. Original publication dates and
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

Published stories and editorial history are permanent and never expire:
numbered homepage and topic pages (`site.page_size` stories each) cover the
whole history, and erroneous stories are corrected or retracted rather than
deleted. Builds render only changed
articles, in bounded batches. Keep the SQLite database, raw source content,
analysis evidence and private publication metadata outside the webroot. See
[permanent history and recovery](docs/PERMANENT_HISTORY.md).

LLM availability and output quality depend on your model. The prompt, evidence
checks and final review reduce unsupported statements but are **not proof of
factual accuracy**; check important security conclusions against the linked
primary source. Personal alert delivery is intentionally outside this initial
website/RSS release.

See [source coverage and remaining features](docs/SOURCE_COVERAGE.md).

## Development

```sh
python -m pip install -e '.[test]'
python -m pytest -q
```

Tests cover unsafe URLs and redirects, DNS rebinding, gzip expansion, timeouts,
retry caps, hostile XML, malformed responses, pagination recovery, durable queues,
deduplication/lifecycle changes, model validation, HTML/RSS escaping, native HTML
navigation, full-history topic pages and safe script retirement. Apache 2.0; see
[`LICENSE`](LICENSE).
