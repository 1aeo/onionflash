# Permanent publication

There is no article-count or age expiry. The whole history remains browsable
through `/`, `/page/2/`, and subsequent pages. Every story retains
`/news/<id>/`; its public structured representation is `/news/<id>/story.json`.
Paths are relative to `site.base_url`.

Static topic pages use `/topics/<topic>/` and
`/topics/<topic>/page/2/`. A story belongs when either its primary category or a
secondary tag matches. All eight topics have a page, including an explicit empty
state when there are no stories. Existing `/tags/<topic>.xml` RSS URLs remain the
same. Topic links, pagination, mobile navigation and editorial history require no
browser JavaScript.

`site.page_size` controls pagination. RSS and JSON Feed carry the 100 most
recently updated stories, and each topic feed the 100 most recent of its topic;
the pages keep the whole history. Homepage ordering follows the date Onion Flash
added the story, with the original source date retained on the article and in
RSS. Older records without `added_at` keep their existing date.

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
accepted article remains available. Removing a private source row does not
remove an accepted article. Indexes and feeds are built from these snapshots; one
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
