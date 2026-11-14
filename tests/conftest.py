"""Shared pytest fixtures and re-exported test helpers."""

import pytest

from helpers import *  # noqa: F401,F403
from helpers import make_config
from onionflash.store import Store


@pytest.fixture
def cfg(tmp_path):
    return make_config(tmp_path)


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "state.sqlite3") as db_store:
        yield db_store


@pytest.fixture
def context(tmp_path):
    configuration = make_config(tmp_path)
    with Store(configuration["storage"]["database"]) as db_store:
        yield configuration, db_store
