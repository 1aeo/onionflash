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

`site.page_size` controls pagination. `site.feed_size = 0` includes all accepted
stories in RSS, JSON Feed and topic feeds. Homepage ordering follows the date
Onion Flash added the story, with the original source date retained on the
article and in RSS. Older records without `added_at` keep their existing date.

## Incremental work

SQLite queues a story when its stored payload changes. One build processes at
most `storage.render_batch_size` articles, then refreshes the necessary views.
The default is 250, adjustable from 1 to 1,000. There is no corresponding limit
on how many accepted stories the catalog retains. New and changed stories and
editorial actions render ahead of a template, year or forced rebuild.

Unchanged article HTML and JSON are not rewritten. Whole-history feeds require
a sequential pass when their content changes, but are streamed with bounded
memory. Pagination indexes can change when new stories shift page boundaries.
Neither operation requires rerunning the LLM.

An indexed topic-membership table keeps topic pagination bounded in memory.
Only affected topic listings are refreshed after a content or classification
change. Obsolete pagination views can be removed; article pages are retained.

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

## Durable hosting

The [deployment repository](https://github.com/1aeo/onionflash-deploy) can store
article pages, public JSON, pagination pages and feeds in Spaces. Cloudflare
retains the front page and small shared assets. The public URLs remain the same;
the Worker looks up immutable objects through a version-bound manifest.

Older objects are not removed when a newer publication is deployed. Switching
back to a previous Worker version selects that version's manifest and objects.
No private evidence or storage credentials are available through these routes.

## Restore and rebuild

Restore the private SQLite backup, configuration and credentials, then run:

```sh
onionflash build --config config.toml --force
```

Repeat while `articles_pending` is nonzero. A rebuild in progress is resumed
rather than restarted. Missing output directories also trigger reconstruction.
The catalog's last-good public snapshots permit recovery even when a later raw
story revision is invalid. This works offline and requires no LLM calls.

Before an installation first switches existing article paths to Spaces, drain
the render queue and verify every previously published permalink. The deployer
holds activation if a legacy article is absent from the verified object index.
Operational byte/time/batch limits hold unfinished work; they do not expire news.

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

Later bounded template and copyright-year rebuilds resume normally. Their
existing pages are already script-free. The deployer validates new HTML and
serves a script-blocking CSP; old immutable storage objects and prior deployment
versions remain available for rollback.
