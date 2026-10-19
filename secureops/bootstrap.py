"""First-start initialisation shared by the dashboard and the API: pull live intel, download
the replay dataset and stream its first days through the pipeline.

The build runs in a background thread owned by the server process (not by a browser
session), reports progress to the database, and keeps a heartbeat. A build that was
interrupted (server restart, crash) is detected by its stale heartbeat and simply resumed:
every step is idempotent and the replay continues from its saved cursor."""
from __future__ import annotations

import threading
import traceback

import pandas as pd

from . import db
from .intel import attack, feeds, vulns
from .sources import replay

STALE_SECONDS = 180
_thread: dict = {}


def initialized() -> bool:
    return bool(db.get_meta("initialized"))


def status() -> dict:
    """{'log': [...], 'error': str|None, 'running': bool} for the progress screen."""
    st = db.get_meta("bootstrap_status", {}) or {}
    hb = st.get("heartbeat")
    alive = bool(hb) and pd.Timestamp(hb) > db.now() - pd.Timedelta(seconds=STALE_SECONDS)
    return {"log": st.get("log", []), "error": st.get("error"), "running": alive and not st.get("done")}


def _report(msg: str | None = None, **extra):
    st = db.get_meta("bootstrap_status", {}) or {}
    if msg:
        st["log"] = (st.get("log", []) + [msg])[-14:]
    st.update(heartbeat=db.now().isoformat(), **extra)
    db.set_meta("bootstrap_status", st)


def run(progress=None) -> bool:
    """Build synchronously (used by the API thread, tests and the background builder)."""
    with db.lock("bootstrap-claim", ttl=30, wait=30):  # atomic: only one process may claim the build
        if initialized() or status()["running"]:
            return False  # already built, or someone else is building and still alive
        _report(None, log=[], error=None, done=False)

    def say(m):
        _report(m)
        if progress:
            progress(m)

    try:
        say("Refreshing live threat intelligence (abuse.ch, Spamhaus)...")
        feeds.refresh()
        say("Loading the CISA Known Exploited Vulnerabilities catalogue...")
        vulns.kev_catalog()
        say("Loading the MITRE ATT&CK knowledge base...")
        attack.techniques()
        say("Downloading the UWF-ZeekData24 dataset (real Zeek logs, first run only)...")
        r = replay.bootstrap(progress=say)
        db.set_meta("initialized", {"at": db.now(), "events": r["events"], "alerts": r["alerts"],
                                    "incidents": len(r["new_incidents"])})
        _report("Ready.", done=True)
        return True
    except Exception as exc:
        _report(None, error=f"{exc.__class__.__name__}: {exc}"[:400], done=True,
                trace=traceback.format_exc()[-2000:])
        raise


def start_background() -> None:
    """Start the build in a server-side thread unless one is alive (here or in another process)."""
    t = _thread.get("t")
    if (t and t.is_alive()) or initialized() or status()["running"]:
        return

    def target():
        try:
            run()
        except Exception:
            pass  # recorded in bootstrap_status for the UI

    _thread["t"] = threading.Thread(target=target, name="secureops-bootstrap", daemon=True)
    _thread["t"].start()


def retry() -> None:
    _report(None, error=None, done=False, heartbeat=None)
    start_background()
