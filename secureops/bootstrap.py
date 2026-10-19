"""First-start initialisation shared by the dashboard and the API: pull live intel, download
the replay dataset and stream its first days through the pipeline."""
from __future__ import annotations

import pandas as pd

from . import assets, db, pipeline, settings
from .intel import attack, feeds, vulns
from .sources import replay

LOCK_MINUTES = 15


def initialized() -> bool:
    return bool(db.get_meta("initialized"))


def run(progress=None, force: bool = False) -> bool:
    say = progress or (lambda m: None)
    if not force and initialized():
        return False
    lock = db.get_meta("bootstrap_lock")
    if not force and lock and pd.Timestamp(lock) > db.now() - pd.Timedelta(minutes=LOCK_MINUTES):
        return False  # another process (API or dashboard) is already building
    db.set_meta("bootstrap_lock", db.now())
    if force:
        overrides = settings.overrides()
        db.reset()
        settings.save(overrides)
        pipeline._model.clear()
        assets._cache.clear()
    say("Refreshing live threat intelligence (abuse.ch, Spamhaus)...")
    feeds.refresh()
    say("Loading CISA Known Exploited Vulnerabilities catalogue...")
    vulns.kev_catalog()
    say("Loading MITRE ATT&CK knowledge base...")
    attack.techniques()
    say("Downloading the UWF-ZeekData24 dataset (real Zeek logs, first run only)...")
    r = replay.bootstrap(progress=say)
    db.set_meta("initialized", {"at": db.now(), "events": r["events"], "alerts": r["alerts"],
                                "incidents": len(r["new_incidents"])})
    db.set_meta("bootstrap_lock", None)
    return True
