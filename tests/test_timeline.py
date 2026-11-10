"""Repository snapshots preserve event identity, evidence and historical dates."""

import base64
import hashlib
import json

import pytest

from onionflash.collect import CollectionError
from onionflash.config import DEFAULTS
from onionflash.timeline import collect_timeline
from test_core import DATE, FakeClient, response, source


API = "https://gitlab.example.org/api/v4/projects/644/repository/files/README.md?ref=master"
REPOSITORY = "https://gitlab.example.org/group/timeline"
REVISION = "a" * 40
HEADER = "## Timeline\n\n|start date|end date|places|protocols|description|links|?  |\n|---|---|---|---|---|---|---|\n"


def row(start="2026-11-08", end="", places="", protocols="", description="A reported network observation", links="", unknown=""):
    return "|" + "|".join([start, end, places, protocols, description, links, unknown]) + "|\n"


def metadata(text, **changes):
    content = text.encode()
    return {
        "encoding": "base64", "size": len(content), "file_path": "README.md",
        "content_sha256": hashlib.sha256(content).hexdigest(), "last_commit_id": REVISION,
        "content": base64.b64encode(content).decode(), **changes,
    }


def stream(**changes):
    return source(**{"kind": "metrics_timeline", "url": API, "website_url": REPOSITORY, "authority": "telemetry", "max_items": 1000, **changes})


def collect(rows=None, *, text=None, record=None, settings=None, src=None, commit=None):
    record = record if record is not None else metadata(text if text is not None else HEADER + "".join(rows or [row()]))
    commit = commit if commit is not None else {"id": record.get("last_commit_id"), "committed_date": "2026-11-08T11:30:00Z"}
    client = FakeClient([response(json.dumps(record).encode(), {"etag": '"snapshot"'}), response(json.dumps(commit).encode())])
    src = src or stream()
    return collect_timeline(client, src, src["url"], {}, settings or DEFAULTS["collection"], DATE)


def test_repository_revision_citation_and_stable_event_identity():
    first = collect([row()])["items"][0]
    changed = collect(record=metadata("# Extra introduction\n" + HEADER + row(description="Corrected description", end="2026-11-08 11:00"), last_commit_id="b" * 40))["items"][0]
    assert first["source_entry_id"] == changed["source_entry_id"]
    assert first["url"] == REPOSITORY + "/-/blob/" + REVISION + "/README.md?plain=1#L5"
    assert "/-/blob/" + "b" * 40 in changed["url"] and changed["url"].endswith("#L6")
    assert first["published_at"] == "2026-11-08T00:00:00Z"
    assert first["updated_at"] == changed["updated_at"] == "2026-11-08T11:30:00Z"
    assert "End date as supplied: 2026-11-08 11:00" in changed["content"]
    assert changed["kind"] == "metrics_timeline"


def test_namespace_includes_repository_and_file_not_url_ref():
    first = collect()["items"][0]["source_entry_id"]
    # Changing the API ref does not change the data's event namespace.
    assert collect(src=stream(url=API.replace("master", "stable")))["items"][0]["source_entry_id"] == first
    assert collect(record=metadata(HEADER + row(), file_path="archive/README.md"), src=stream(url=API.replace("README.md", "archive%2FREADME.md")))["items"][0]["source_entry_id"] != first
    assert collect(src=stream(website_url="https://gitlab.example.org/other/timeline"))["items"][0]["source_entry_id"] != first


def test_scope_order_case_and_approximation_do_not_change_identity():
    first = collect([row(start="~2026-11-08", places="cn ru", protocols="OR snowflake")])["items"][0]
    second = collect([row(start="2026-11-08", places="RU CN", protocols="snowflake or")])["items"][0]
    assert first["source_entry_id"] == second["source_entry_id"]
    assert "Start date as supplied: ~2026-11-08" in first["content"]


def test_date_ranges_unknown_cause_and_old_ongoing_are_not_retimed():
    items = collect([
        row(start="2020-01-01", end="ongoing", places="cn", description="Historical blocking"),
        row(start="2020-01-02", end="2026-11-08 10:00:00", places="ru", unknown="X"),
        row(start="2026-11-09", places="by"),
    ])["items"]
    assert len(items) == 1
    assert items[0]["published_at"] == "2026-11-08T10:00:00Z"  # the recent end qualified it
    assert items[0]["updated_at"] == "2026-11-08T11:30:00Z"
    assert "Unknown cause: Yes; preserve this uncertainty" in items[0]["content"]
    assert "Event dates are not publication timestamps" in items[0]["content"]


def test_escaped_pipes_backticks_and_backslash_parity():
    description = r"Changed `a\|b` path with \\ before text and escaped \#1"
    item = collect([row(description=description)])["items"][0]
    assert "`a|b`" in item["title"]
    assert r"with \ before" in item["title"]
    assert "escaped #1" in item["title"]
    # Two backslashes encode a literal backslash followed by a real separator.
    assert collect([row(description="ends in \\\\")])["items"][0]["title"].endswith("\\")


def test_ambiguous_recent_keys_are_omitted_with_other_events_preserved():
    with pytest.raises(CollectionError, match="Ambiguous recent") as failure:
        collect([row(description="Event A"), row(description="Event B"), row(start="2026-11-07")])
    assert failure.value.catching_up
    assert len(failure.value.items) == 1
    assert failure.value.items[0]["published_at"] == "2026-11-07T00:00:00Z"


def test_old_ambiguities_do_not_block_recent_news_and_exact_duplicates_collapse():
    result = collect([row(start="2012-01-01", description="A"), row(start="2012-01-01", description="B"), row(), row()])
    assert len(result["items"]) == 1
    assert result["etag"] == '"snapshot"'


def test_recent_ended_range_cannot_hide_a_collision_with_an_old_ongoing_row():
    with pytest.raises(CollectionError, match="Ambiguous recent") as failure:
        collect([row(start="2020-01-01", end="ongoing"), row(start="2020-01-01", end="2026-11-08")])
    assert failure.value.items == []


def test_conditional_304_preserves_validated_cache_and_does_not_parse_body():
    client = FakeClient([response(b"", status=304)])
    state = {"active_url": API, "etag": '"previous"', "last_modified": "yesterday"}
    result = collect_timeline(client, stream(), API, state, DEFAULTS["collection"], DATE)
    assert result["items"] == [] and result["etag"] == '"previous"'
    assert len(client.calls) == 1
    assert client.calls[0][2]["headers"] == {"If-None-Match": '"previous"', "If-Modified-Since": "yesterday"}


def test_revision_time_updates_freshness_without_changing_event_content_or_identity():
    first = collect()["items"][0]
    later = collect(record=metadata("# New introduction\n" + HEADER + row(), last_commit_id="b" * 40), commit={"id": "b" * 40, "committed_date": DATE})["items"][0]
    assert first["source_entry_id"] == later["source_entry_id"]
    assert first["content"] == later["content"]
    assert first["published_at"] == later["published_at"]
    assert first["updated_at"] < later["updated_at"]
    assert "Repository revision time is not event time" in later["content"]


@pytest.mark.parametrize("commit", [
    {"id": "b" * 40, "committed_date": DATE},
    {"id": REVISION, "committed_date": "2026-11-08T00:00:00"},
    {"id": REVISION, "committed_date": "not a date"},
    {"id": REVISION},
])
def test_invalid_or_future_revision_metadata_fails_closed(commit):
    with pytest.raises(CollectionError, match="Invalid Metrics Timeline"):
        collect(commit=commit)


def test_commit_metadata_request_is_bound_to_configured_api_project():
    client = FakeClient([response(json.dumps(metadata(HEADER + row())).encode()), response(json.dumps({"id": REVISION, "committed_date": DATE}).encode())])
    collect_timeline(client, stream(), API, {}, DEFAULTS["collection"], DATE)
    assert client.calls[1][1] == "https://gitlab.example.org/api/v4/projects/644/repository/commits/" + REVISION
    assert "ref=" not in client.calls[1][1]


@pytest.mark.parametrize("change", [
    {"encoding": "utf8"}, {"content": "!not-base64!"},
    {"last_commit_id": "../main"}, {"last_commit_id": ""},
    {"file_path": "../private.md"}, {"file_path": "/README.md"},
    {"file_path": "a/%2e%2e/private.md"}, {"file_path": "a\\README.md"},
    {"file_path": "a//README.md"},
])
def test_invalid_snapshot_metadata_is_rejected(change):
    with pytest.raises(CollectionError, match="Invalid Metrics Timeline"):
        collect(record=metadata(HEADER + row(), **change))


@pytest.mark.parametrize("text", [
    "No table", HEADER + row() + "\n## Timeline\n",
    HEADER.replace("start date", "published date") + row(),
    HEADER.replace("|---|---|", "|--|---|", 1) + row(),
    HEADER + row(start="invalid"), HEADER + row(start="2026-02-30"),
    HEADER + row(end="2026-01-01"),
    HEADER + row(description="unescaped | pipe"), HEADER + row(description="<script>bad()</script>"),
])
def test_malformed_tables_fail_closed(text):
    with pytest.raises(CollectionError, match="Invalid Metrics Timeline"):
        collect(text=text)


@pytest.mark.parametrize("website", ["javascript:alert(1)", "https://user:secret@example.org/", "https://127.0.0.1/"])
def test_unsafe_repository_citations_are_rejected(website):
    with pytest.raises(CollectionError):
        collect(src=stream(website_url=website))


def test_bounded_context_keeps_uncertainty_before_long_description():
    result = collect([row(description="Long description " * 1000, unknown="X")], settings={**DEFAULTS["collection"], "content_chars": 1000})
    item = result["items"][0]
    assert len(item["title"]) == 500 and len(item["content"]) <= 1000
    assert "Unknown cause: Yes" in item["content"]


def test_recent_start_with_future_end_and_future_commit_clock():
    item = collect([row(start="2026-11-07", end="2026-11-20")], commit={"id": REVISION, "committed_date": "2026-11-09T00:00:00Z"})["items"][0]
    assert item["published_at"] == "2026-11-07T00:00:00Z" and item["updated_at"] == DATE


def test_unusual_historical_rows_do_not_block_recent_events():
    old = [row(start="2012-03-01", places="ru,by", protocols="obfs4/meek", unknown="x"),
           row(start="2012-04-01", end="2012-03-01", description="Reversed old range")]
    assert len(collect(old + [row()])["items"]) == 1


def test_lines_are_counted_like_gitlab():
    item = collect(text="Intro\x0cpage\n" + HEADER + row(description="One\u2028two"))["items"][0]
    assert item["url"].endswith("#L6")
