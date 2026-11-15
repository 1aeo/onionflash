"""An automatic merge must retain the exact eligible pair through its transaction."""
import copy
import json

import pytest

from helpers import update_analysis, verdict
from onionflash import cli, editorial, review_gate
from helpers import seed_source_story as _publish
from helpers import analysis, make_item as item
from test_merge import EARLY, MID
from helpers import LATER, Reviewer, Writer, job, pending, run_gate as run
from test_review_request_budget import context, record


@pytest.mark.parametrize("change", ["survivor_lock", "survivor_retraction", "survivor_content", "pair_order"])
def test_newer_duplicate_merge_rechecks_pair_inside_transaction(context, monkeypatch, change):
    cfg, store = context
    stories = []
    for number, stamp, description in ((49100, EARLY, "Relay consensus stall in version 0.4.9.88."),
                                        (49101, MID, "Follow-up for #49100 and the consensus stall in 0.4.9.88.")):
        source = item(url=f"https://gitlab.torproject.org/tpo/core/tor/-/issues/{number}", kind="gitlab_issue",
                      title=description, content=description)
        draft = analysis(title=description, summary=description, why_it_matters="", confidence="reported",
                         state="developing", products=["tor"], evidence=[description])
        stories.append(_publish(store, source, draft, at=stamp))
    older, newer = stories
    cli.build(cfg, store)
    incoming = {**source, "updated_at": LATER, "public_comments": [{
        "id": "201", "author": "dev", "title": "Comment by dev", "created_at": LATER,
        "url": source["url"] + "#note_201", "body": "The stall only occurs with caching disabled.",
    }]}
    row = pending(store, incoming)
    reply = verdict("skip", criterion="new_information", update=True, same_story=older["id"])
    original_merge = editorial.merge
    saved = {}

    def changed_survivor(db, duplicate, survivor, **kwargs):
        assert kwargs["automatic"] and (duplicate, survivor) == (newer["id"], older["id"])
        assert not saved
        if change in {"survivor_lock", "survivor_retraction"}:
            with db:
                db.execute("""INSERT INTO editorial_controls
                    (story_id,revision,locked,retracted,notice_action,notice_reason,notice_at,held_updates)
                    VALUES(?,0,1,?,'lock','Concurrent editorial change',?,0)""",
                    (survivor, int(change == "survivor_retraction"), LATER))
        else:
            payload = json.loads(db.execute("SELECT payload FROM stories WHERE id=?", (survivor,)).fetchone()[0])
            if change == "pair_order":
                payload["added_at"] = "2026-11-12T12:00:00Z"
            else:
                payload.update(title="Unrelated application observation", summary="A different application reports another event.",
                               products=["arti"], sources=[{"url": "https://example.org/unrelated", "title": "Unrelated report"}])
            with db:
                db.execute("UPDATE stories SET payload=? WHERE id=?", (json.dumps(payload), survivor))
        fresh = review_gate._auto_merge_pair(store, duplicate, survivor)
        assert fresh != (duplicate, survivor)
        if change == "pair_order":
            assert fresh == (survivor, duplicate)
        saved.update(job=copy.deepcopy(job(store)), pair=fresh)
        return original_merge(db, duplicate, survivor, **kwargs)

    monkeypatch.setattr(editorial, "merge", changed_survivor)
    checker = Reviewer(reply, reply)
    result = run(cfg, store, row, Writer(update_analysis(update="The stall only occurs with caching disabled.",
                                                       evidence=["The stall only occurs with caching disabled."])), checker)
    assert result["status"] == "stale" and len(checker.calls) == 2
    assert job(store) == saved["job"] and record(store)["request_budget"]["reserved"] == 2
    assert editorial.retired(store.db, story_id=newer["id"]) is None
    assert editorial.retired(store.db, story_id=older["id"]) is None
    assert store.db.execute("SELECT COUNT(*) FROM stories").fetchone()[0] == 2
    assert tuple(store.db.execute("SELECT status,story_id FROM items WHERE id=?", (row["id"],)).fetchone()) == ("pending", newer["id"])
