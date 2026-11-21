"""Shared pytest fixtures for configuration, SQLite stores, and wired LLM contexts."""

import pytest

from helpers import make_config
from onionflash.store import Store


@pytest.fixture
def cfg(tmp_path):
    """Return a default temporary configuration dictionary."""
    return make_config(tmp_path)


@pytest.fixture
def store(tmp_path):
    """Open and yield a temporary SQLite Store."""
    with Store(tmp_path / "state.sqlite3") as db_store:
        yield db_store


@pytest.fixture
def context(cfg):
    """Yield a paired `(cfg, store)` using temporary storage paths."""
    with Store(cfg["storage"]["database"]) as db_store:
        yield cfg, db_store


@pytest.fixture
def llm_context(context, monkeypatch):
    """Return `(cfg, store)` preconfigured with a synthetic LLM endpoint and API key."""
    configuration, _ = context
    configuration["llm"].update(
        base_url="https://model.example/v1",
        fallback_base_urls=[],
        api_key_env="REVIEW_TEST_KEY",
    )
    monkeypatch.setenv("REVIEW_TEST_KEY", "synthetic-fixture-value")
    return context
