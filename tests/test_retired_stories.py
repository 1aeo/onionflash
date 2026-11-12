"""Retired story identities and cluster keys are permanent and never recreated."""

import json
import sqlite3

import pytest

from approval_helpers import finish_reviewed, verdict
from onionflash import candidate, cli, editorial, rejection, review_gate
from onionflash.analyze import cache_key
from onionflash.config import DEFAULTS
from onionflash.store import Store
from onionflash.util import after, digest, item_cluster
from test_core import analysis, config, item, source
from test_review_gate import Reviewer, Writer

DATE = "2026-11-11T15:00:00Z"
SKIPPED = "skipped.gate.retired_story"
LONG_BODY = (
    "A detailed public report describing circuit padding behavior across multiple hops "
    "with reproducible measurements from a local test network and exact packet counts "
    "recorded over several minutes of testing."
)


@pytest.fixture
def context(tmp_path):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        yield cfg, store


def add_alias(db, story_id: str, cluster_key: str, survivor_id: str | None = None, reason: str = "Retired fixture"):
    with db:
        db.execute("INSERT INTO story_aliases(story_id,cluster_key,survivor_id,reason,created_at) VALUES(?,?,?,?,?)",
                   (story_id, cluster_key, survivor_id, reason, DATE))


def logged(store):
    return [code for (code,) in store.db.execute("SELECT code FROM decision_log ORDER BY id")]


def test_story_aliases_are_insert_only_and_permanent(context):
    _, store = context
    columns = {row[1] for row in store.db.execute("PRAGMA table_info(story_aliases)")}
    assert columns == {"story_id", "cluster_key", "survivor_id", "reason", "created_at"}
    add_alias(store.db, "retired-story-1", "url:retired-cluster-1")
    with pytest.raises(sqlite3.IntegrityError, match="Story aliases are permanent"):
        store.db.execute("UPDATE story_aliases SET reason='changed' WHERE story_id='retired-story-1'")
    with pytest.raises(sqlite3.IntegrityError, match="Story aliases are permanent"):
        store.db.execute("DELETE FROM story_aliases WHERE story_id='retired-story-1'")
    for sid, ckey in (("retired-story-1", "url:other"), ("retired-story-2", "url:retired-cluster-1")):
        with pytest.raises(sqlite3.IntegrityError, match="Story aliases are permanent"):
            store.db.execute("INSERT OR REPLACE INTO story_aliases VALUES(?,?,NULL,?,?)", (sid, ckey, "replace", DATE))
        with pytest.raises(sqlite3.IntegrityError):
            add_alias(store.db, sid, ckey)


def test_stories_never_recreated_trigger_and_commit_candidate_rowcount(context):
    _, store = context
    store.ingest(item(url="https://example.org/live", title="Live story"), DATE)
    live_row = store.pending(1, DATE)[0]
    finish_reviewed(store, live_row, analysis(title="Live story"), cache_key(live_row, DEFAULTS["llm"]), DATE)
    live_id = store.stories()[0]["id"]
    add_alias(store.db, "retired-id", "url:retired-key")
    add_alias(store.db, "merged-id", "url:merged-key", live_id)

    upsert = """INSERT INTO stories(id,cluster_key,payload,published_at,updated_at)
        VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at"""
    for sid, ckey in (("retired-id", "url:another-key"), ("another-id", "url:retired-key"),
                      ("merged-id", "url:another-merged"), ("another-merged-id", "url:merged-key")):
        cursor = store.db.execute(upsert, (sid, ckey, "{}", DATE, DATE))
        assert cursor.rowcount == 0
        assert store.db.execute("SELECT 1 FROM stories WHERE id=?", (sid,)).fetchone() is None
    # Live story upserts and inserts remain unaffected.
    live_cluster = store.db.execute("SELECT cluster_key,payload FROM stories WHERE id=?", (live_id,)).fetchone()
    assert store.db.execute(upsert, (live_id, live_cluster[0], live_cluster[1], DATE, after(60, DATE))).rowcount == 1
    assert len(store.stories()) == 1

    # If an alias retires the prepared story_id under another cluster key after preparation,
    # existing_story sees None and commit_candidate refuses when the trigger ignores the upsert.
    store.ingest(item(url="https://example.org/raced", title="Raced story"), DATE)
    raced_row = store.pending(1, DATE)[0]
    draft = analysis(title="Raced story")
    prepared = store.prepare_candidate(raced_row, draft, DATE)
    key = review_gate._approval_key(prepared["candidate"], prepared, "policy")
    record = {"schema_version": 1, "writer": {"key": "w"}, "input_row": raced_row, "reviews": []}
    with store.db:
        store.db.execute("""INSERT INTO review_approvals
            (key,candidate_hash,source_hash,policy_hash,binding_hash,result_json,review_record_json,created_at,last_used_at)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (key, digest(prepared["candidate"]), prepared["source_hash"], "policy", prepared["binding_hash"],
             json.dumps(verdict()), json.dumps(record), DATE, DATE))
    add_alias(store.db, prepared["story_id"], "url:unmatched-retired-cluster")
    with pytest.raises(editorial.RetiredStory, match="retired"):
        store.commit_candidate(prepared, prepared["candidate"], "w", DATE, approval_key=key,
                               policy_hash="policy", review_record=record, decision="approve")
    assert store.db.execute("SELECT status,story_id FROM items WHERE id=?", (raced_row["id"],)).fetchone()[:] == ("pending", None)
    assert store.db.execute("SELECT 1 FROM stories WHERE id=?", (prepared["story_id"],)).fetchone() is None

    # A locked story retired after preparation is also refused before recording held_updates.
    editorial.correct(store.db, live_id, {"why_it_matters": "Reviewed note."}, reason="Correction",
                      expect_hash=editorial.show(store.db, live_id)["hash"], observed=DATE)
    store.ingest(item(url="https://example.org/live", title="Live story", content="Updated body text for lock test.",
                      updated_at=after(120, DATE)), after(120, DATE))
    locked_row = [r for r in store.pending(5, after(120, DATE)) if r["url"] == "https://example.org/live"][0]
    locked_prepared = store.prepare_candidate(locked_row, draft, after(120, DATE))
    assert locked_prepared["locked"] is True
    add_alias(store.db, live_id, live_cluster[0])
    with pytest.raises(editorial.RetiredStory, match="retired"):
        store.commit_candidate(locked_prepared, locked_prepared["candidate"], "w2", after(120, DATE), review_record=record)


def test_retired_resolver_follows_chains_and_guards_loops_and_editorial_actions(context, tmp_path):
    cfg, store = context
    assert issubclass(editorial.RetiredStory, ValueError)
    assert editorial.retired(store.db) is None
    assert editorial.retired(store.db, story_id="missing", cluster_key="url:missing") is None
    add_alias(store.db, "dead-1", "url:dead-1", None)
    add_alias(store.db, "merged-a", "url:merged-a", "merged-b")
    add_alias(store.db, "merged-b", "url:merged-b", "live-target")
    add_alias(store.db, "to-dead", "url:to-dead", "dead-1")
    assert editorial.retired(store.db, story_id="dead-1") == ("dead-1", None)
    assert editorial.retired(store.db, cluster_key="url:dead-1") == ("dead-1", None)
    assert editorial.retired(store.db, story_id="unknown", cluster_key="url:dead-1") == ("dead-1", None)
    assert editorial.retired(store.db, story_id="merged-a") == ("merged-a", "live-target")
    assert editorial.retired(store.db, cluster_key="url:merged-a") == ("merged-a", "live-target")
    assert editorial.retired(store.db, story_id="to-dead") == ("to-dead", None)

    # Exact hop boundary: MAX_ALIAS_HOPS succeeds, one hop further raises ValueError.
    for index in range(editorial.MAX_ALIAS_HOPS):
        add_alias(store.db, f"hop-{index}", f"url:hop-{index}",
                  "final-hop" if index + 1 == editorial.MAX_ALIAS_HOPS else f"hop-{index + 1}")
    assert editorial.retired(store.db, story_id="hop-0") == ("hop-0", "final-hop")
    add_alias(store.db, "final-hop", "url:final-hop", "too-far")
    with pytest.raises(ValueError, match="loop"):
        editorial.retired(store.db, story_id="hop-0")

    add_alias(store.db, "self-loop", "url:self-loop", "self-loop")
    with pytest.raises(ValueError, match="loop"):
        editorial.retired(store.db, story_id="self-loop")

    with pytest.raises(editorial.RetiredStory, match="Story is retired"):
        editorial.show(store.db, "dead-1")
    with pytest.raises(editorial.RetiredStory, match="merged into live-target"):
        editorial.show(store.db, "merged-a")
    with pytest.raises(editorial.RetiredStory, match="Story is retired"):
        editorial.retract(store.db, "dead-1", reason="Retract", expect_hash="0" * 64, observed=DATE)
    cfg_path = tmp_path / "cli-config.toml"
    cfg_path.write_text(
        f'[site]\ntitle="T"\ndescription="D"\nbase_url="https://example.org"\n'
        f'[storage]\ndatabase="{cfg["storage"]["database"]}"\noutput_dir="{cfg["storage"]["output_dir"]}"\n'
    )
    assert cli.main(["story", "show", "--config", str(cfg_path), "--story", "dead-1"]) == 2
    assert editorial.history(store.db, "dead-1") == {"story_id": "dead-1", "revisions": []}


def test_retired_item_and_cluster_are_ignored_with_zero_model_calls_across_recollections(context):
    cfg, store = context
    cfg["comments"]["enabled"] = True
    cfg["sources"] = [source(kind="gitlab_issue", url="https://gitlab.torproject.org/api/v4/projects/426/issues",
                             gitlab_project="tpo/core/tor")]
    first_item = item(kind="gitlab_issue", url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/999",
                      title="Routine test cleanup", content=LONG_BODY)
    assert item_cluster(first_item).startswith("body:")
    store.ingest(first_item, DATE)
    row = store.pending(1, DATE)[0]
    finish_reviewed(store, row, analysis(title="Routine test cleanup", summary=LONG_BODY, evidence=[LONG_BODY]),
                    cache_key(row, DEFAULTS["llm"]), DATE)
    story_id = store.stories()[0]["id"]
    retired_cluster = row["cluster_key"]

    # Retire the story as a tombstone and unlink its item.
    with store.db:
        store.db.execute("UPDATE items SET status='ignored',story_id=NULL WHERE id=?", (row["id"],))
        store.db.execute("DELETE FROM stories WHERE id=?", (story_id,))
        add_alias(store.db, story_id, retired_cluster)
    assert rejection.show_item(store, row["id"])["final_review"] is None

    # Same content hash: not queued.
    assert store.ingest({**first_item, "updated_at": after(60, DATE)}, after(60, DATE)) is False

    # Label edit: queued, then ignored at the gate before any model or comment check.
    label_edited = {**first_item, "labels": ["cleanup"], "updated_at": after(120, DATE)}
    assert store.ingest(label_edited, after(120, DATE)) is True
    pending_row = store.pending(1, after(120, DATE))[0]
    store.db.execute("""INSERT INTO review_jobs(item_id,writer_key,policy_hash,stage,record_json,prepared_at,updated_at)
        VALUES(?,?,?,?,?,?,?)""", (pending_row["id"], "old", "old", "drafted", "{}", DATE, DATE))
    writer, checker = Writer(), Reviewer()
    result = review_gate.process_item(cfg, store, pending_row, writer, checker, after(120, DATE))
    assert result == {"status": "ignored", "writer_calls": 0, "review_calls": 0, "cache_hit": False}
    assert writer.calls == [] and checker.calls == []
    assert store.db.execute("SELECT status,story_id,last_error FROM items WHERE id=?", (row["id"],)).fetchone()[:] == (
        "ignored", None, "Retired story; never recreated")
    assert store.db.execute("SELECT COUNT(*) FROM review_jobs").fetchone()[0] == 0
    assert store.db.execute("SELECT COUNT(*) FROM comment_cache").fetchone()[0] == 0
    assert logged(store)[-1] == SKIPPED

    # Two successive body edits change item_cluster(edited), yet keep the retired cluster_key and make 0 model calls.
    for step in (1, 2):
        stamp = after(120 + step * 60, DATE)
        body_edited = {**label_edited, "content": f"{LONG_BODY} Revision {step}.", "updated_at": stamp}
        assert item_cluster(body_edited) != retired_cluster
        assert store.ingest(body_edited, stamp) is True
        queued = store.pending(1, stamp)[0]
        assert queued["cluster_key"] == retired_cluster
        res = review_gate.process_item(cfg, store, queued, Writer(), Reviewer(), stamp)
        assert res["status"] == "ignored" and res["writer_calls"] == res["review_calls"] == 0

    # A new item at another URL sharing the retired body cluster is also ignored with 0 model calls.
    same_body_other_url = item(kind="gitlab_issue", url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/1000",
                               title="Routine test cleanup", content=LONG_BODY, updated_at=after(300, DATE))
    assert item_cluster(same_body_other_url) == retired_cluster
    assert store.ingest(same_body_other_url, after(300, DATE)) is True
    other_row = store.pending(1, after(300, DATE))[0]
    assert review_gate.process_item(cfg, store, other_row, Writer(), Reviewer(), after(300, DATE))["status"] == "ignored"

    # An operator retry of a retired item repeats the gate skip at zero model cost.
    current = dict(store.db.execute("SELECT id,content_hash FROM items WHERE id=?", (other_row["id"],)).fetchone())
    rejection.retry_item(store, current["id"], current["content_hash"], "Attempt retry", after(360, DATE))
    retried = store.pending(1, after(360, DATE))[0]
    assert review_gate.process_item(cfg, store, retried, Writer(), Reviewer(), after(360, DATE))["status"] == "ignored"
    assert store.stories() == []


def test_computed_retired_story_id_and_concurrent_change_are_refused(context):
    cfg, store = context
    fresh = item(url="https://example.org/fresh-item", title="Fresh item")
    store.ingest(fresh, DATE)
    row = store.pending(1, DATE)[0]
    computed_id = digest(row["cluster_key"])[:24]
    # Retire that story_id under a different cluster_key: both prepare and process_item still refuse it.
    add_alias(store.db, computed_id, "url:different-cluster")
    with pytest.raises(editorial.RetiredStory):
        candidate.prepare(store.db, row, analysis(), DATE)
    # If the item row changes concurrently before process_item updates it, process_item returns "stale" cleanly.
    stale_copy = dict(row)
    with store.db:
        store.db.execute("UPDATE items SET content_hash='concurrently-changed' WHERE id=?", (row["id"],))
    assert review_gate.process_item(cfg, store, stale_copy, Writer(), Reviewer(), DATE)["status"] == "stale"
    assert logged(store) == []
    with store.db:
        store.db.execute("UPDATE items SET content_hash=? WHERE id=?", (row["content_hash"], row["id"]))
    assert review_gate.process_item(cfg, store, row, Writer(), Reviewer(), DATE)["status"] == "ignored"
    assert logged(store) == [SKIPPED]


def test_merged_alias_resolves_to_live_survivor_or_refuses_missing_survivor(context):
    _, store = context
    store.ingest(item(url="https://example.org/survivor", title="Survivor story"), DATE)
    s_row = store.pending(1, DATE)[0]
    finish_reviewed(store, s_row, analysis(title="Survivor story"), cache_key(s_row, DEFAULTS["llm"]), DATE)
    survivor = store.stories()[0]
    survivor_cluster = store.db.execute("SELECT cluster_key FROM stories WHERE id=?", (survivor["id"],)).fetchone()[0]
    add_alias(store.db, "merged-dup", "url:merged-dup-cluster", survivor["id"])

    # Both an item mapped to merged-dup and an item with url:merged-dup-cluster resolve to the survivor.
    store.ingest(item(url="https://example.org/followup", title="Followup"), DATE)
    f_row = store.pending(1, DATE)[0]
    with store.db:
        store.db.execute("UPDATE items SET story_id='merged-dup' WHERE id=?", (f_row["id"],))
    by_id = dict(store.db.execute("SELECT * FROM items WHERE id=?", (f_row["id"],)).fetchone())
    by_id["payload"] = f_row["payload"]
    assert candidate.existing_story(store.db, by_id)["id"] == survivor["id"]
    prepared = candidate.prepare(store.db, by_id, analysis(title="Followup"), after(60, DATE))
    assert (prepared["story_id"], prepared["cluster_key"]) == (survivor["id"], survivor_cluster)

    with store.db:
        store.db.execute("UPDATE items SET story_id=NULL,cluster_key='url:merged-dup-cluster' WHERE id=?", (f_row["id"],))
    by_cluster = dict(store.db.execute("SELECT * FROM items WHERE id=?", (f_row["id"],)).fetchone())
    by_cluster["payload"] = f_row["payload"]
    assert candidate.existing_story(store.db, by_cluster)["id"] == survivor["id"]

    # If a survivor row is absent from stories, existing_story refuses rather than recreating the alias ID.
    add_alias(store.db, "dangling-dup", "url:dangling-cluster", "missing-survivor")
    with pytest.raises(editorial.RetiredStory):
        candidate.existing_story(store.db, {"story_id": None, "cluster_key": "url:dangling-cluster"})

    # A stories row matched by cluster_key whose id was later tombstoned under another cluster,
    # or matched by id whose cluster_key was later tombstoned under another id, is also refused.
    store.ingest(item(url="https://example.org/secondary-a", title="Secondary A"), DATE)
    row_a = [r for r in store.pending(5, DATE) if r["url"] == "https://example.org/secondary-a"][0]
    finish_reviewed(store, row_a, analysis(title="Secondary A"), cache_key(row_a, DEFAULTS["llm"]), DATE)
    id_a = digest(row_a["cluster_key"])[:24]
    add_alias(store.db, id_a, "url:retired-other-a")
    with pytest.raises(editorial.RetiredStory):
        candidate.existing_story(store.db, {"story_id": None, "cluster_key": row_a["cluster_key"]})

    store.ingest(item(url="https://example.org/secondary-b", title="Secondary B"), DATE)
    row_b = [r for r in store.pending(5, DATE) if r["url"] == "https://example.org/secondary-b"][0]
    finish_reviewed(store, row_b, analysis(title="Secondary B"), cache_key(row_b, DEFAULTS["llm"]), DATE)
    id_b = digest(row_b["cluster_key"])[:24]
    add_alias(store.db, "retired-other-b", row_b["cluster_key"])
    with pytest.raises(editorial.RetiredStory):
        candidate.existing_story(store.db, {"story_id": id_b, "cluster_key": "url:unrelated"})


def test_held_candidate_cannot_be_approved_after_story_retirement(context):
    cfg, store = context
    official = item(kind="feed", authority="official", url="https://example.org/official-held", title="Official post")
    store.ingest(official, DATE)
    row = store.pending(1, DATE)[0]
    checker = Reviewer(verdict("skip", criterion="news_value"), verdict("skip", criterion="news_value"))
    assert review_gate.process_item(cfg, store, row, Writer(), checker, DATE)["status"] == "held"
    before = review_gate.approval(cfg, store, row["id"])
    assert before["eligible"] is True and before["hash"]
    add_alias(store.db, digest(row["cluster_key"])[:24], row["cluster_key"])
    after_retire = review_gate.approval(cfg, store, row["id"])
    assert after_retire["eligible"] is False and "changed since the review" in after_retire["reason"]
    with pytest.raises(ValueError, match="changed since the review"):
        rejection.approve_item(cfg, store, row["id"], before["hash"], "Approve retired candidate", after(60, DATE))
    assert store.stories() == []
