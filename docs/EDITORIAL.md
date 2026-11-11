# Corrections, retractions and revision history

These commands are for a trusted operator on the collector host. They use the
configured SQLite database and the same process lock as collection. They do not
call the model or publish the site. Run the normal build and deployment after
reviewing the receipt. A scheduled build can also pick up the queued change.

Every change requires a reason and the hash of the version you reviewed. Reasons
are **public**: write a concise explanation for readers, without credentials,
private source material or internal operational details. The command fails if
another writer changed that version before the edit. Refresh the story, review
the difference and use its new hash instead of retrying an old edit blindly.

## Correct a story

Show the current text, editorial lock, revision and hash:

```sh
onionflash story show --config config.toml --story STORY_ID
```

Save only the fields to change in a UTF-8 JSON file, for example `correction.json`:

```json
{
  "why_it_matters": "The report requests removal of the old keys from the software."
}
```

Apply the correction using the hash returned by `show`:

```sh
onionflash story correct --config config.toml --story STORY_ID \
  --patch correction.json --expect-hash REVIEWED_HASH \
  --reason 'Removed an unsupported instruction to relay operators.'
onionflash build --config config.toml
```

Review the generated article and feeds, then use your normal deployment command.
The story keeps its ID, permalink, original source publication date and first
appearance date. Its update date becomes the operator action time. Only its
changed article and affected indexes/feeds need rebuilding.

Editable fields are `title`, `summary`, `why_it_matters`, `category`, `priority`,
`confidence`, `state`, `products`, `tags` and `sources`. Source replacements are
lists of objects containing only a public HTTPS `url` and `title`. The regular
classification vocabulary and public URL validation still apply. IDs, dates,
private collection metadata and editorial history cannot be patched.

The correction locks the story against automated replacement. Later source
analyses are saved privately and mapped to the existing story, while its accepted
text and sources stay unchanged. `show` reports the number of held automated
updates. This lock also covers deterministic monitoring stories and grouped
reports from another source. Public comments on the story's issues are not
checked while it is locked, so they add no held updates; checks resume after
unlock.

## Retract, restore or resume automation

Retraction replaces current reporting with a clearly labeled tombstone at the
same URL. The homepage, RSS and JSON Feed show the retraction and its reason.
While the story is retracted, its pages and feeds publish none of its earlier
headline or text, not even as superseded history or in earlier correction
reasons. Copies made before the retraction are not withdrawn: feed readers and
caches keep theirs, and so does an enabled permanent archive. The notice keeps
the story's source links: they are the upstream records it cited, not Onion
Flash's text. A correction keeps
replaced text public as superseded history; when text must not stay public,
retract:

```sh
onionflash story retract --config config.toml --story STORY_ID \
  --expect-hash REVIEWED_HASH --reason 'The source withdrew this report.'
```

Inspect private revision history in bounded pages:

```sh
onionflash story history --config config.toml --story STORY_ID --limit 20
onionflash story history --config config.toml --story STORY_ID --limit 20 --before 21
```

Use the returned `next_before` cursor for the next page. Each private revision
keeps the previous stored record, previous accepted public snapshot if one
existed, resulting text, reason, action time and before/after hashes. Revision
zero refers to the accepted public text before the first operator action; other
numbers refer to the text recorded by that operator revision.

Restore a reviewed earlier revision using a fresh current hash:

```sh
onionflash story restore --config config.toml --story STORY_ID --revision 1 \
  --expect-hash CURRENT_HASH --reason 'Restored the corrected, supported account.'
```

Restoring creates another revision; it does not erase the retraction or previous
history. It retains the story dates and ID, advances the update date, and leaves
the editorial lock on. A retraction tombstone cannot itself be used as the text
of a restored account. A retracted story must be explicitly restored before
automation can resume.

To allow future automated changes after review:

```sh
onionflash story unlock --config config.toml --story STORY_ID \
  --expect-hash CURRENT_HASH --reason 'The corrected source can now be followed automatically.'
```

Unlocking is explicit and recorded. It does not replay held analyses or rerun the
model; the next normal source update can change the story. The existing public
correction notice and revision history remain available after automated updates.

## What readers see and what stays private

The article displays the current correction/retraction notice and a native HTML
revision-history disclosure. It needs no JavaScript. Up to the latest 20 actions
are shown, with the total count when more exist. Previously accepted public text
is labeled **superseded** inside a separate disclosure, which a retracted story
omits until it is restored. Homepage and feed summaries contain the current
account and notice, never the obsolete full text. Canonical article JSON includes
the same public notice/history as its article.

All revisions remain in the private SQLite ledger; the history command reads it
in pages of at most 100. Raw collected sources, unaccepted drafts, model evidence
and private editorial metadata do not enter public history. If a stored draft is
invalid, a valid last-published snapshot can be used for a correction, while the
invalid original record remains private for investigation.

Back up the SQLite database with the normal deployment backup workflow. It
contains the complete operator ledger and last-good public snapshots, allowing
`build --force` to recover the article pages without model calls. Corrections
have no application-imposed history expiry.

After the editorial schema is installed, **database writers must use the current
application version**. SQLite guards use a connection-local permission function
which current `Store` connections register. Raw or older writers cannot silently
overwrite protected stories. Read-only inspection and SQLite backups still work.
The permission is granted only inside an operator transaction, reset before
commit and rolled back on failure; there is no durable bypass flag. Rolling back
Cloudflare frontend files is independent of the collector database version.

Public source/model output cannot supply the correction metadata. Notices are
constructed from the operator ledger, validated at the publication boundary and
HTML-escaped like the rest of the article.
