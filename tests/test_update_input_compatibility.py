"""Saved description formats must not bypass update context filtering."""

import copy
import json

import pytest

from helpers import DATE, LATER, analysis, finish_reviewed, item, update_analysis
from onionflash import candidate
from onionflash.analyze import Analyzer
from onionflash.comments import analysis_context
from onionflash.config import DEFAULTS
from onionflash.store import item_hash


def saved_item(description, *, legacy, notes, updated_at):
    value = item(content=description, public_comments=notes, updated_at=updated_at)
    if legacy:
        value["source_content"] = description
        value["content"] = "Previously composed description and comment text."
    return value


def comment(ident, at, body):
    return {"id": ident, "url": f"https://example.org/news/1#note_{ident}",
            "title": "Public comment by @reporter", "author": "reporter",
            "created_at": at, "body": body}


@pytest.mark.parametrize("prior_legacy", [False, True])
@pytest.mark.parametrize("current_legacy", [False, True])
@pytest.mark.parametrize("body_changed", [False, True])
def test_update_writer_receives_only_effective_new_description_and_notes(
        store, monkeypatch, prior_legacy, current_legacy, body_changed):
    description = "The original report describes a circuit allocation defect."
    old_note = comment("1", DATE, "The original reporter is investigating the defect.")
    original = saved_item(description, legacy=prior_legacy, notes=[old_note], updated_at=DATE)
    store.ingest(original, DATE)
    finish_reviewed(store, store.pending(1, DATE)[0],
                    analysis(summary=description, evidence=[description]), "first", DATE)
    added = "The reporter has prepared a patch for the allocation defect."
    new_note = comment("2", LATER, added)
    changed = "The updated description identifies the affected allocation path."
    latest_body = changed + "\n> An old quoted claim must not be new evidence." if body_changed else description
    incoming = saved_item(latest_body, legacy=current_legacy, notes=[new_note, old_note], updated_at=LATER)
    store.ingest(incoming, LATER)
    row = store.pending(1, LATER)[0]
    original_payload = json.loads(row["payload"])
    untouched = copy.deepcopy(original_payload)
    mode, filtered = candidate.own_update_input(store.db, row, original_payload)
    assert mode == "update" and original_payload == untouched
    assert "source_content" not in filtered
    assert filtered["content"] == (changed if body_changed else "")
    assert filtered["public_comments"] == [new_note]
    captured = {}

    def complete(self, prompt, payload, schema, schema_name):
        captured.update(payload=payload, schema=schema, name=schema_name)
        return update_analysis(update=added, evidence=[added])

    monkeypatch.setattr(Analyzer, "complete", complete)
    with Analyzer(DEFAULTS) as writer:
        writer.analyze(filtered, candidate.update_target(store.db, row))
    assert captured["name"] == "onionflash_update"
    assert captured["payload"]["content"] == (changed if body_changed else "")
    assert captured["payload"]["public_comments"] == [
        {key: new_note[key] for key in ("author", "created_at", "body")}]
    choices = captured["schema"]["properties"]["evidence"]["items"]["enum"]
    assert added in choices and description not in choices
    assert not any("old quoted claim" in choice for choice in choices)


def test_legacy_reply_description_cannot_restore_quoted_history(store):
    store.ingest(item(), DATE)
    finish_reviewed(store, store.pending(1, DATE)[0], analysis(), "first", DATE)
    existing = dict(store.db.execute("SELECT * FROM stories").fetchone())
    reply = item(id="reply", kind="feed", url="https://example.org/reply", title="Re: Allocation defect",
                 content="An obsolete composed body.", source_content="A new patch was proposed.\n> Old quoted history.",
                 updated_at=LATER)
    mode, filtered = candidate.own_update_input(store.db, {"id": "reply"}, reply, existing=existing)
    assert mode == "update"
    assert filtered["content"] == "A new patch was proposed."
    assert analysis_context(filtered)[0] == "A new patch was proposed."
    assert "source_content" not in filtered
    assert reply["source_content"].endswith("Old quoted history.")


def test_description_format_does_not_change_identity_but_effective_body_does():
    description = "The original report describes a circuit allocation defect."
    modern = saved_item(description, legacy=False, notes=[], updated_at=DATE)
    legacy = saved_item(description, legacy=True, notes=[], updated_at=DATE)
    assert item_hash(legacy) == item_hash(modern)
    assert item_hash({**legacy, "content": "Different obsolete composed text."}) == item_hash(legacy)
    changed = {**legacy, "source_content": "The updated report describes a second affected allocation path."}
    assert item_hash(changed) != item_hash(legacy)


def test_legacy_description_edit_alone_is_queued_and_reaches_update_writer(store):
    original = saved_item("The original report describes a circuit allocation defect.",
                          legacy=True, notes=[], updated_at=DATE)
    store.ingest(original, DATE)
    finish_reviewed(store, store.pending(1, DATE)[0],
                    analysis(evidence=[original["source_content"]]), "first", DATE)
    changed = "The updated report identifies another affected allocation path."
    incoming = {**original, "source_content": changed, "updated_at": LATER}
    assert store.ingest(incoming, LATER)
    row = store.pending(1, LATER)[0]
    mode, filtered = candidate.own_update_input(store.db, row, json.loads(row["payload"]))
    assert mode == "update" and analysis_context(filtered) == (changed, [])
