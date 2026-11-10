import json

from onionflash.store import Store
from test_core import DATE, analysis, item


def test_collected_source_snapshot_survives_later_source_edits(tmp_path):
    with Store(tmp_path / "state.db") as store:
        source = item()
        store.ingest(source, DATE)
        row = store.pending(1, DATE)[0]
        store.finish(row, analysis(), "first-analysis", DATE)
        source["content"] += " A later source correction."
        store.ingest(source, DATE)
        saved = store.db.execute("SELECT source_payload,source_item_id FROM analyses WHERE cache_key='first-analysis'").fetchone()
        assert json.loads(saved[0])["content"] == json.loads(row["payload"])["content"]
        assert saved[1] == row["id"]
