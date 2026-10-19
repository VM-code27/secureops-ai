"""Test setup: throw-away database and data dir, no LLM, no network access needed."""
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIX = Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(ROOT))
_tmp = Path(tempfile.mkdtemp())
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp.as_posix()}/test.db"
os.environ["SECUREOPS_DATA_DIR"] = str(_tmp)
os.environ["LLM_PROVIDER"] = "offline"
os.environ["SECUREOPS_API_TOKEN"] = "test-token"


def fixture_text(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


@pytest.fixture
def fresh_db():
    from secureops import assets, db, pipeline, settings
    from secureops.intel import feeds

    db.reset()
    assets._cache.clear()
    pipeline._model.clear()
    feeds._index["value"] = None
    settings._cache["value"] = None
    yield db


@pytest.fixture
def seeded_db(fresh_db):
    """Real Zeek + Suricata fixture data pushed through the pipeline, marked as initialised."""
    from secureops import db, pipeline
    from secureops.sources import suricata, zeek

    pipeline.ingest(zeek.parse(fixture_text("zeek_conn.log"), "conn.log", sensor="fixture")["events"])
    pipeline.ingest(suricata.parse(fixture_text("suricata_eve_alerts.json"), sensor="fixture")["events"])
    db.set_meta("initialized", {"at": db.now()})
    return db
