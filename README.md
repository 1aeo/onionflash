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
supporting chat completions with JSON Schema output. The deployed model is Qwen
through vLLM; the endpoint and model are configurable.

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
and source status. No sample or invented news is published.

For server installation, use the deployment repository's `install.sh` and quick
start. It installs the recurring job, protects credentials, checks publication,
and handles Cloudflare and DigitalOcean Spaces. Running `onionflash run` itself
only creates local files.

## Configuration

The deployed scheduler runs every five minutes. Its `interval_minutes` setting
lives in the deployment repository's `deployment.toml`; apply schedule changes
with `./deploy.sh schedule`. Each source also has `interval_seconds` (default
300), so a slower source can be polled less often than the job runs. The source
interval cannot make a five-minute job execute more frequently. A small
`collection.healthy_poll_tolerance_seconds` handles scheduler start jitter only
after a successful poll; failure and Retry-After cooldowns remain intact.

All settings are shown in [`config.example.toml`](config.example.toml). Relative
database and output paths resolve against the configuration file's directory.
`${ENVIRONMENT_VARIABLE}` references are expanded for paths and LLM URLs.
The API key is read only from the variable named by `llm.api_key_env`.

| Section | Settings |
| --- | --- |
| `site` | Title, description, canonical URL, repository link, page/feed sizes |
| `storage` | Private SQLite path, dedicated public output directory, maximum published archive size |
| `collection` | Lookback, overlap, page/item limits, content limit, staleness, circuit backoff, total/source run budgets, reserved analysis time |
| `http` | Connect/read/total deadlines, attempts, exponential backoff base/cap/jitter, bounded `Retry-After`, redirect/byte/rate limits, user agent |
| `monitoring` | Alert persistence/window thresholds, freshness, private retention and storage/parser limits |
| `llm` | Base URL and fallback URLs, model, key environment variable, private-network allowlist, deadlines, output/input limits, items per run, failed-item retry backoff |
| `sources` | Stream ID, display name, public website URL, kind, collection URL, fallback URLs, product, authority, optional interval/page/item overrides |

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

Timeline entries keep their event dates; repository revisions do not turn old
open-ended events into new incidents. Citations point to the exact commit and
table line. Ambiguous recent rows are skipped with a source warning. See
[timeline coverage and identity rules](docs/SOURCE_COVERAGE.md#tor-metrics-timeline).

### Automated monitoring alerts

Consensus-health and anti-censorship alerts use deterministic parsers selected
by `alert_format`, with a configured `monitor_id` shared by any mirrors of the
same monitor. They bypass Qwen. Unknown formats and undated messages cannot
become news stories.

The private SQLite incident records group repeated notifications. By default,
eligible directory-document warnings need two reports at least one hour apart
within a two-day window before publication as **observed anomalies**. Ordinary
repeats do not create stories, change RSS GUIDs or advance publication dates.
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
onionflash build --config config.toml --force    # Refresh public status display
onionflash status --config config.toml           # Source freshness and queue
onionflash backup --config config.toml --output /private/new-backup.sqlite3
```

Each command returns a compact JSON result. Invalid configuration or a build
failure returns nonzero. A partial source outage or queued analysis is reported
in the result and status without discarding the previous site. Concurrent runs
use a nonblocking lock at `<database>.lock`; an overlapping run exits cleanly.

The public output is a dedicated generated directory. Onion Flash refuses to
replace an existing nonempty directory without its ownership marker, kept next
to—not inside—the public directory. Rendering completes in a new sibling
directory before replacement. A render failure preserves the previous output.
Publishers should use the same database lock while taking their upload snapshot.

## Reliability and editorial behavior

- Public HTTP and private inference share the same transport helper. It validates
  addresses at TCP connection time, pins connections to vetted IPs while retaining
  TLS hostname verification, rechecks redirects, and enforces compressed and
  decompressed response-size limits. Source content never executes commands.
- HTTP retries are limited to transient failures. Exponential backoff has a cap,
  jitter, and bounded `Retry-After`. Persisted source cooldowns and failed-analysis
  delays survive restarts. One failed source does not invalidate cached news.
- GitLab scans have fixed time windows, overlap, and persistent checkpoints.
  Issues use GitLab's keyset cursor when supplied. Merge requests use the API's
  offset pages; a configurable daily full-lookback reconciliation repairs gaps
  caused by records moving between pages while they are being edited.
  A capped scan resumes on the next run; its completed watermark advances only
  after the window finishes. XML declarations/entities are rejected with an
  encoding-aware parser before feed parsing.
- New and changed items are saved before analysis. Analysis results are cached by
  content hash, model, and prompt version. The application makes one model request
  at a time, with explicit per-run and token limits. Source polling reserves time
  for pending analysis so an unavailable source cannot monopolize every run.
- Explicit `kind = "tag"` streams produce attributed tag notices without an LLM
  request. These notices remain `tagged`, have a configurable queue-priority
  floor, and cannot replace a richer announcement already grouped with that
  version. Repeated identical model labels are normalized rather than retried;
  invalid labels and unsupported evidence are still rejected.
- Summaries need schema-valid fields and exact supporting excerpts from the
  supplied source. The excerpts stay private; public citations are created from
  collected URLs, never model-proposed URLs. Source text is treated as untrusted
  data. Evidence matching is an automated check, **not proof of factual accuracy**.
- Reports, suspected compromise, and telemetry anomalies retain explicit
  uncertainty. GitLab issue hosting alone does not establish confirmation. Tags
  are marked `tagged`; merges are marked `merged`. A later tag cannot downgrade an
  already announced release.
- Matching release versions/products, identical titled issue bodies, and
  canonical URLs provide conservative duplicate grouping. Semantic similarity
  alone does not combine unrelated incidents. Original publication dates and
  stable story IDs remain intact when stories are updated.
- Public files rebuild only when stories, rendering code, configuration, or
  meaningful source-health state change. A successful poll timestamp alone does
  not trigger a deployment. The Sources display therefore reflects the last
  public build; CLI status has current collection timestamps.

## Deliberate limits

The initial collector reads feed entries and GitLab issue/MR titles and bodies.
It does not scrape arbitrary links, ingest private issues, or claim complete
coverage of every discussion comment. RSS feeds expose finite recent windows;
outages longer than those windows can leave gaps. GitLab pagination and source
health make incomplete scans visible, but upstream data can change while a scan
is in progress. Treat this as a news aid, not an incident-detection guarantee.

The website publishes up to `storage.max_stories`; older records remain in SQLite
but are outside the generated archive until that limit is raised. Keep the SQLite
database, backups, raw source content, and analysis evidence private. The
deployment defaults place backups in private DigitalOcean Spaces storage.

LLM availability and output quality depend on your model. The prompt and evidence
checks reduce unsupported statements, but important security conclusions should
always be checked against the linked primary source. Personal alert delivery is
intentionally outside this initial website/RSS release.

## Measured behavior and review work

- [Tracked improvement checklist](docs/IMPROVEMENT_CHECKLIST.md)
- [Publication-delay backtest and SQLite growth audit](docs/RUNTIME_AUDIT.md)
- [Source coverage and remaining features](docs/SOURCE_COVERAGE.md)
- [Gemini critique results and simplification decisions](docs/REVIEW_RESULTS.md)

The historical audit distinguishes source timestamps, observation markers,
startup backfill and verified website publication. New collection runs record
post-fetch observation times and preserve a metadata boundary identifying the
older cycle-start markers. Source timestamps still do not prove when a feed
first made an item available. Backups are already gzip-compressed; the small
measured database does not currently need compression or routine compaction.

## Development

```sh
python -m pip install '.[test]'
python -m pytest -q
```

Tests cover unsafe URLs and redirects, DNS rebinding, gzip expansion, timeouts,
retry caps, hostile XML, malformed responses, pagination recovery, durable queues,
deduplication/lifecycle changes, model validation, HTML/RSS escaping, and preserving
the previous site after failed rendering. Apache 2.0; see [`LICENSE`](LICENSE).
