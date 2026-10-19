"""Log shipper: tails Zeek and Suricata logs and POSTs new lines to the SecureOps API.

Environment: API_URL, API_TOKEN, SENSOR_NAME, LOG_DIR (default ./logs), STATE_FILE,
INTERVAL (seconds, default 10). Handles log rotation/truncation and retries on failure.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from urllib.parse import urlparse

import requests

API_URL = os.environ.get("API_URL", "http://localhost:8000").rstrip("/")
TOKEN = os.environ.get("API_TOKEN", "")
SENSOR = os.environ.get("SENSOR_NAME", "sensor")
LOG_DIR = Path(os.environ.get("LOG_DIR", "logs"))
STATE = Path(os.environ.get("STATE_FILE", "shipper_state.json"))
INTERVAL = float(os.environ.get("INTERVAL", "10"))
MAX_LINES = int(os.environ.get("MAX_LINES", "1000"))  # small batches keep a 512 MB API instance comfortable

# (relative path, endpoint, extra query params)
SOURCES = [("zeek/conn.log", "/ingest/zeek", {"filename": "conn.log"}),
           ("zeek/ssh.log", "/ingest/zeek", {"filename": "ssh.log"}),
           ("zeek/software.log", "/ingest/zeek", {"filename": "software.log"}),
           ("suricata/eve.json", "/ingest/suricata", {})]
KEEP_EVE = ('"event_type":"alert"', '"event_type":"flow"', '"event_type": "alert"', '"event_type": "flow"')


def load_state() -> dict:
    try:
        return json.loads(STATE.read_text())
    except (OSError, ValueError):
        return {}


def save_state(state: dict):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(state))


def read_new(path: Path, offset: int) -> tuple[list[str], int]:
    size = path.stat().st_size
    if size < offset:  # rotated or truncated
        offset = 0
    with open(path, "rb") as f:
        f.seek(offset)
        data = f.read()
    end = data.rfind(b"\n")
    if end < 0:
        return [], offset
    lines = data[:end + 1].decode("utf-8", errors="replace").splitlines()
    return lines, offset + end + 1


def ship_once(state: dict) -> int:
    sent = 0
    for rel, endpoint, params in SOURCES:
        path = LOG_DIR / rel
        if not path.exists():
            continue
        lines, new_offset = read_new(path, state.get(rel, 0))
        if rel.endswith("eve.json"):
            lines = [line for line in lines if any(k in line for k in KEEP_EVE)]
        else:
            lines = [line for line in lines if line and not line.startswith("#")] if lines and lines[0].startswith("{") \
                else lines
        for i in range(0, len(lines), MAX_LINES):
            body = "\n".join(lines[i:i + MAX_LINES])
            r = requests.post(f"{API_URL}{endpoint}", params={"sensor": SENSOR, **params}, data=body.encode(),
                              headers={"X-API-Token": TOKEN}, timeout=120)
            r.raise_for_status()
            res = r.json()
            print(f"{rel}: {min(MAX_LINES, len(lines) - i)} lines -> {res.get('events')} events, {res.get('alerts')} alerts, "
                  f"new incidents {res.get('new_incidents')}", flush=True)
            sent += 1
        state[rel] = new_offset
        save_state(state)
    return sent


LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "host.docker.internal"}


def check_url(url: str) -> None:
    """The token and your traffic metadata travel in every request: never send them in clear text."""
    u = urlparse(url)
    if u.scheme != "https" and u.hostname not in LOCAL_HOSTS and os.environ.get("ALLOW_INSECURE_HTTP") != "1":
        raise SystemExit(f"Refusing to ship logs over plain HTTP to {u.hostname}. Use an https:// API_URL.")


def main(once: bool = False):
    if not TOKEN:
        raise SystemExit("API_TOKEN is not set")
    check_url(API_URL)
    state = load_state()
    print(f"Shipping {LOG_DIR} -> {API_URL} as sensor '{SENSOR}'", flush=True)
    while True:
        try:
            ship_once(state)
        except requests.HTTPError as exc:
            code = exc.response.status_code if exc.response is not None else "?"
            msg = "API busy" if code == 503 else "API waking up or restarting" if code in (502, 504) else f"HTTP {code}"
            print(f"{msg}; will retry (nothing is lost)", flush=True)
        except requests.RequestException as exc:
            print(f"API unreachable ({exc.__class__.__name__}); retrying", flush=True)
        if once:
            return
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main(once=os.environ.get("ONCE") == "1")
