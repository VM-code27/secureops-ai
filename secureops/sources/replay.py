"""Replay controller: streams the real UWF dataset through the pipeline as if it were live.

State (cursor = dataset time already ingested) is kept in the database, so every viewer
and the API see the same stream position.
"""
from __future__ import annotations

import pandas as pd

from .. import db, settings
from . import uwf


def state() -> dict:
    return db.get_meta("replay", {})


def _save(**kw):
    st = state()
    st.update({k: (v.isoformat() if isinstance(v, pd.Timestamp) else v) for k, v in kw.items()})
    db.set_meta("replay", st)


def advance(to: pd.Timestamp, chunk: pd.Timedelta = pd.Timedelta(hours=6), progress=None, use_llm=False) -> dict:
    """Ingest replay events from the cursor up to `to`, in chunks (under the pipeline lock, so two
    viewers streaming at once can never replay the same slice twice)."""
    with db.lock("pipeline"):
        return _advance(to, chunk, progress, use_llm)


def _advance(to, chunk, progress, use_llm) -> dict:
    ev = uwf.load()
    st = state()
    cursor = pd.Timestamp(st["cursor"]) if st.get("cursor") else ev.ts.min().floor("D")
    end = min(to, ev.ts.max() + pd.Timedelta(seconds=1))
    total = {"events": 0, "alerts": 0, "new_incidents": [], "updated_incidents": [], "rules": {}}
    from ..pipeline import ingest
    while cursor < end:
        nxt = min(cursor + chunk, end)
        batch = ev[(ev.ts >= cursor) & (ev.ts < nxt)]
        if progress and len(batch):
            progress(f"Replaying {cursor:%Y-%m-%d %H:%M} -> {nxt:%H:%M} UTC ({len(batch):,} events)")
        if len(batch):
            r = ingest(batch.copy(), use_llm=use_llm)
            total["events"] += r["events"]
            total["alerts"] += r["alerts"]
            total["new_incidents"] += r["new_incidents"]
            total["updated_incidents"] = sorted(set(total["updated_incidents"]) | set(r["updated_incidents"]))
            for k, v in r["rules"].items():
                total["rules"][k] = total["rules"].get(k, 0) + v
        cursor = nxt
        _save(cursor=cursor, start=ev.ts.min(), end=ev.ts.max(), dataset=uwf.SENSOR)
    total["cursor"] = cursor
    total["finished"] = cursor >= ev.ts.max()
    return total


def bootstrap(progress=None) -> dict:
    ev = uwf.load(progress)
    start = ev.ts.min().floor("D")
    return advance(start + pd.Timedelta(days=settings.section("replay")["history_days"]), progress=progress)


def step(minutes: int | None = None, use_llm=False, wait: int = 600) -> dict:
    with db.lock("pipeline", wait=wait):
        return _step(minutes, use_llm)


def _step(minutes: int | None, use_llm) -> dict:
    minutes = minutes or settings.section("replay")["step_minutes"]
    st = state()
    cursor = pd.Timestamp(st["cursor"]) if st.get("cursor") else uwf.load().ts.min().floor("D")
    # Skip empty stretches (the dataset has gaps between capture days) so the stream never stalls.
    ev = uwf.load()
    nxt_ev = ev.ts[ev.ts >= cursor]
    if len(nxt_ev) and nxt_ev.iloc[0] > cursor + pd.Timedelta(minutes=minutes):
        cursor = nxt_ev.iloc[0].floor("min")
        _save(cursor=cursor)
    return advance(cursor + pd.Timedelta(minutes=minutes), chunk=pd.Timedelta(minutes=minutes), use_llm=use_llm)


def summary() -> dict:
    """Replay position and dataset totals without forcing a download (safe on any page)."""
    st = state()
    if not st.get("cursor"):
        return {"active": False}
    if "total_events" not in st and (uwf._cache_dir() / "overlay.pkl").exists():
        i = uwf.info()
        _save(total_events=i["events"], attack_events=i["attack_events"], days=i["days"])
        st = state()
    start, end, cur = pd.Timestamp(st["start"]), pd.Timestamp(st["end"]), pd.Timestamp(st["cursor"])
    return {"active": True, "cursor": cur, "start": start, "end": end,
            "progress": max(0.0, min(1.0, (cur - start) / (end - start))), "finished": cur >= end,
            "total_events": st.get("total_events"), "attack_events": st.get("attack_events"), "days": st.get("days")}
