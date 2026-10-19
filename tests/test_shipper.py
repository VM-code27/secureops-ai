"""The sensor shipper tails real log files and delivers them to the API exactly once."""
import importlib.util
import shutil
from pathlib import Path

from fastapi.testclient import TestClient

from api.main import app

FIX = Path(__file__).resolve().parent / "fixtures"
SHIPPER = Path(__file__).resolve().parent.parent / "sensor" / "shipper.py"


def load_shipper(tmp_path, monkeypatch):
    monkeypatch.setenv("API_TOKEN", "test-token")
    monkeypatch.setenv("LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("STATE_FILE", str(tmp_path / "state.json"))
    spec = importlib.util.spec_from_file_location("shipper", SHIPPER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_shipper_delivers_new_lines_once(seeded_db, tmp_path, monkeypatch):
    (tmp_path / "logs" / "zeek").mkdir(parents=True)
    (tmp_path / "logs" / "suricata").mkdir(parents=True)
    shutil.copy(FIX / "zeek_conn.json", tmp_path / "logs" / "zeek" / "conn.log")
    shutil.copy(FIX / "suricata_eve_small.json", tmp_path / "logs" / "suricata" / "eve.json")
    shipper = load_shipper(tmp_path, monkeypatch)
    with TestClient(app) as client:
        calls = []

        def post(url, params=None, data=None, headers=None, timeout=None):
            calls.append(url)
            r = client.post(url.replace(shipper.API_URL, ""), params=params, content=data, headers=headers)
            r.raise_for_status()
            return r

        monkeypatch.setattr(shipper.requests, "post", post)
        from secureops import db
        before = db.count("events")
        state = shipper.load_state()
        assert shipper.ship_once(state) == 2
        assert db.count("events") == before + 1000 + 2   # 1000 conn records + 1 alert + 1 flow
        assert shipper.ship_once(state) == 0              # nothing new -> nothing re-sent
        with open(tmp_path / "logs" / "zeek" / "conn.log", "a") as f:
            f.write((FIX / "zeek_conn.json").read_text().splitlines()[0] + "\n")
        assert shipper.ship_once(state) == 1 and db.count("events") == before + 1003
