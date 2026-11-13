# Permanent publication

There is no article-count or age expiry. The whole history remains browsable
through `/`, `/page/2/`, and subsequent pages. Every story retains
`/news/<id>/`; its public structured representation is `/news/<id>/story.json`
(see [merging duplicate stories](EDITORIAL.md#merge-a-duplicate-story) for
merged pointers).
Paths are relative to `site.base_url`.

Static topic pages use `/topics/<topic>/` and
`/topics/<topic>/page/2/`. A story belongs when either its primary category or a
secondary tag matches. All eight topics have a page, including an explicit empty
state when there are no stories. Existing `/tags/<topic>.xml` RSS URLs remain the
same. Topic links, pagination, mobile navigation and editorial history require no
browser JavaScript.

`site.page_size` controls pagination. RSS and JSON Feed carry every story, and
each topic feed every story of its topic, most recently updated first. Homepage
ordering follows the date Onion Flash first published the story. Articles show
that date and the last update; RSS and JSON Feed keep the original source date
as the publication date. Older records without `added_at` keep their existing
date.

A story can carry dated updates, each with its own sources. Its article lists
them newest first and `story.json` includes them; homepage cards, RSS and JSON
Feed show the latest one. A story without updates has no `updates` key.

## Published stories are permanent

A published story keeps `/news/<id>/` and `/news/<id>/story.json`: to fix or
withdraw reporting, [correct or retract the story](EDITORIAL.md) instead of
deleting it or resetting publication state. Plain SQLite triggers created during
builds refuse deleting rows from `public_catalog` or `editorial_controls` and
refuse deleting, updating or replacing rows in `editorial_revisions`. Because
they call no application function, direct `sqlite3` sessions and earlier
releases after a rollback obey them too. Deleting a private `stories` row stays
allowed and the catalog keeps rendering the article, but after a private row is
deleted, you can correct or retract the story only after restoring its stored
record.

## Incremental work

SQLite queues a story when its stored payload changes. One build renders at most
250 articles, then refreshes the necessary views; the next build continues the
queue. No such limit applies to the stories the catalog retains. Upgrades that
change the publishing code, edits to `site.title`, `site.description`,
`site.base_url` or `site.repository_url`, a missing output directory and
`build --force` queue every article again. New and changed stories and editorial
actions render ahead of such a rebuild.

Unchanged article HTML and JSON are not rewritten. Feeds change when their
stories do, and pagination indexes when new stories shift page boundaries.
Neither requires rerunning the LLM.

An indexed topic-membership table keeps topic pagination bounded in memory.
Topic listings are regenerated with the homepage after a catalog change;
unchanged pages are not rewritten. Obsolete pagination views can be removed;
article pages are retained.

The private catalog stores timestamps, hashes and one compact last-good public
JSON snapshot per article. Raw source text and model evidence are not exported
to public JSON. Render failures quarantine the new source revision; an existing
accepted article remains available. Indexes and feeds are built from these snapshots; one
that a later release rejects is left out of them with a logged warning, and its
article remains.

`public_artifacts` records generated paths and their hashes. The deployer owns
`uploaded_sha256`; the builder preserves it so only changed objects need upload.
`publication_build_pending` and a generation number prevent an interrupted build
from being activated. These tables and markers stay in SQLite, never the webroot.
The deployment repository's
[permanent storage guide](https://github.com/1aeo/onionflash-deploy/blob/main/PERMANENT_STORAGE.md)
covers serving this history from durable storage under the same URLs, rollback
and the first migration.

## Restore and rebuild

Restore the private SQLite backup, configuration and credentials, then run:

```sh
onionflash build --config config.toml --force
```

Repeat while `articles_pending` is nonzero. A rebuild in progress is resumed
rather than restarted. The catalog's last-good public snapshots permit recovery
even when a later raw story revision is invalid. This works offline and requires
no LLM calls.

## Upgrade from the browser-script version

Upgrade the application and deployment repositories together, then build until
`no_browser_js_ready` is true and `articles_pending` is absent. The normal
scheduler can continue those bounded builds; the new deployer holds publication
until the transition is complete. It never activates a mixture of older
script-dependent articles and the new asset set.

The builder verifies the accepted article catalog and owned artifact hashes
before retiring the old `app.js`. A modified or untracked script, unsafe path or
unrepresented article blocks retirement instead of deleting unfamiliar data.
Restore or inspect the affected output before retrying. The private metadata
flag `publication_no_browser_js_ready` records the completed transition.

Later bounded rebuilds resume normally. Their
existing pages are already script-free. The deployer validates new HTML and
serves a script-blocking CSP; old immutable storage objects and prior deployment
versions remain available for rollback.
