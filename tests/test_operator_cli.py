from approval_helpers import finish_reviewed
import json
from pathlib import Path
import pytest

from onionflash import cli
from onionflash.comments import _compose
from onionflash.config import load_config
from onionflash.store import Store
from onionflash.util import item_cluster
from test_core import DATE, analysis, item


def setup_story(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('''[storage]
database = "state.sqlite3"
output_dir = "public"
[[sources]]
id = "test"
url = "https://example.org/feed.xml"
''')
    cfg = load_config(path)
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(item(), DATE)
        row = store.pending(1, DATE)[0]
        finish_reviewed(store, row, analysis(), "seed", DATE)
        story_id = store.stories()[0]["id"]
        cli.build(cfg, store)
    return path, cfg, story_id


def invoke(capsys, *args, expected=0):
    assert cli.main(list(map(str, args))) == expected
    output = capsys.readouterr()
    return json.loads(output.out) if output.out else {"error": output.err}


def test_cli_correct_build_lock_and_stale_guard(tmp_path, capsys):
    config, cfg, story_id = setup_story(tmp_path)
    current = invoke(capsys, "story", "show", "--config", config, "--story", story_id)
    patch = tmp_path / "patch.json"
    arguments = ("story", "correct", "--config", config, "--story", story_id,
                 "--expect-hash", current["hash"], "--patch", patch,
                 "--reason", "Removed an unsupported operator instruction.")
    for body in (b"\xff", b"[]", b'{"why_it_matters": NaN}'):  # refused without a change, so the hash stays current
        patch.write_bytes(body)
        invoke(capsys, *arguments, expected=2)
    patch.write_text(json.dumps({"why_it_matters": "The report says the existing keys cannot be trusted."}))
    changed = invoke(capsys, *arguments)
    assert changed["locked"] and changed["publication_pending"]
    assert changed["revision"] == 1
    stale = invoke(capsys, *arguments, expected=2)
    assert "changed" in stale["error"].lower() or "hash" in stale["error"].lower()
    invoke(capsys, "build", "--config", config)
    public = json.loads((Path(cfg["storage"]["output_dir"]) / "news" / story_id / "story.json").read_text())
    assert public["why_it_matters"] == "The report says the existing keys cannot be trusted."
    assert public["published_at"] == DATE
    assert public["editorial"]["status"] == "corrected"
    history = invoke(capsys, "story", "history", "--config", config, "--story", story_id)
    assert [revision["reason"] for revision in history["revisions"]] == ["Removed an unsupported operator instruction."]


def test_cli_retraction_is_a_permanent_noticed_page(tmp_path, capsys):
    config, cfg, story_id = setup_story(tmp_path)
    current = invoke(capsys, "story", "show", "--config", config, "--story", story_id)
    withdrawn = invoke(capsys, "story", "retract", "--config", config, "--story", story_id,
                       "--expect-hash", current["hash"], "--reason", "The report was withdrawn.")
    assert withdrawn["retracted"] and withdrawn["locked"]
    invoke(capsys, "build", "--config", config)
    article = Path(cfg["storage"]["output_dir"]) / "news" / story_id / "index.html"
    assert article.exists() and "retract" in article.read_text().lower()
    invoke(capsys, "story", "unlock", "--config", config, "--story", story_id,
           "--expect-hash", withdrawn["hash"], "--reason", "Resume automation", expected=2)


def test_operator_write_reports_busy_without_touching_story(tmp_path, capsys):
    config, cfg, story_id = setup_story(tmp_path)
    current = invoke(capsys, "story", "show", "--config", config, "--story", story_id)
    with cli.run_lock(cfg["storage"]["database"]) as locked:
        assert locked
        busy = invoke(capsys, "story", "retract", "--config", config, "--story", story_id,
                      "--expect-hash", current["hash"], "--reason", "Test lock", expected=75)
    assert busy["status"] == "already-running"
    assert invoke(capsys, "story", "show", "--config", config, "--story", story_id)["hash"] == current["hash"]


def test_rejected_cli_retry_has_no_publication_or_model_call(tmp_path, capsys):
    config, cfg, story_id = setup_story(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(item(url="https://example.org/rejected", content="Rejected source \u202e text"), DATE)
        row = store.pending(1, DATE)[0]
        for _ in range(3):
            store.defer(row["id"], "Unsupported claim", cfg["llm"], DATE, terminal=True)
    listed = invoke(capsys, "rejected", "list", "--config", config)
    assert len(listed["items"]) == 1
    assert listed["items"][0]["attempts"] == 3
    assert invoke(capsys, "rejected", "list", "--config", config, "--status", "ignored")["items"] == []
    assert cli.main(["rejected", "show", "--config", str(config), "--item", row["id"]]) == 0
    raw = capsys.readouterr().out
    assert "\\u202e" in raw and "\u202e" not in raw
    assert invoke(capsys, "rejected", "dismiss", "--config", config, "--item", row["id"], "--expect-hash",
                  row["content_hash"], "--reason", "Dismissed by mistake")["status"] == "dismissed"
    retried = invoke(capsys, "rejected", "retry", "--config", config, "--item", row["id"],
                     "--expect-hash", row["content_hash"], "--reason", "Review rule corrected")
    assert retried["status"] == "pending"
    with Store(cfg["storage"]["database"]) as store:
        assert store.pending_count() == 1
        assert len(store.stories()) == 1
        assert store.stories()[0]["id"] == story_id


def test_comments_do_not_split_identical_issue_grouping():
    original = item(content="Identical original issue description. " * 10)
    note = {"id": "gid://gitlab/Note/1", "url": original["url"] + "#note_1", "title": "Public comment by @a",
            "author": "a", "created_at": DATE, "body": "First discussion"}
    first = _compose(original, [note], DATE, source_key="k")
    second = _compose({**original, "url": "https://example.org/other-project/1"}, [{**note, "body": "Other discussion"}],
                      DATE, source_key="k")
    assert item_cluster(first) == item_cluster(second) == item_cluster(original)


def test_rejected_cli_approve_requires_flags_honors_lock_and_publishes(tmp_path, capsys):
    from approval_helpers import verdict
    from onionflash import review_gate
    from test_review_gate import LATER, Reviewer, Writer

    config, cfg, _ = setup_story(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        held_src = item(url="https://example.org/held-cli", content="Held CLI news development text. " * 4)
        store.ingest(held_src, DATE)
        row = store.pending(1, LATER)[0]
        review_gate.process_item(
            cfg,
            store,
            row,
            Writer(analysis(title="CLI approved story", evidence=["Held CLI news development text."])),
            Reviewer(verdict(), verdict("hold", criterion="news_value")),
            LATER,
        )

    shown = invoke(capsys, "rejected", "show", "--config", config, "--item", row["id"])
    approval = shown["final_review"]["approval"]
    assert approval["eligible"] is True and approval["hash"]

    # Missing required flags exit 2.
    for missing in (
        ("rejected", "approve", "--config", config, "--item", row["id"], "--reason", "Missing hash"),
        ("rejected", "approve", "--config", config, "--item", row["id"], "--approval-hash", approval["hash"]),
    ):
        with pytest.raises(SystemExit) as caught:
            cli.main(list(map(str, missing)))
        assert caught.value.code == 2
        capsys.readouterr()

    # Busy run lock returns 75 without changing state.
    with cli.run_lock(cfg["storage"]["database"]) as locked:
        assert locked
        busy = invoke(
            capsys,
            "rejected",
            "approve",
            "--config",
            config,
            "--item",
            row["id"],
            "--approval-hash",
            approval["hash"],
            "--reason",
            "Busy check",
            expected=75,
        )
    assert busy["status"] == "already-running"

    approved = invoke(
        capsys,
        "rejected",
        "approve",
        "--config",
        config,
        "--item",
        row["id"],
        "--approval-hash",
        approval["hash"],
        "--reason",
        "Approved via CLI",
    )
    assert approved["status"] == "published" and approved["publication_pending"] is True
    invoke(capsys, "build", "--config", config)
    article = Path(cfg["storage"]["output_dir"]) / "news" / approved["story_id"] / "story.json"
    assert json.loads(article.read_text())["title"] == "CLI approved story"
