"""Streaming pipeline: ingest -> discover assets -> detect -> correlate -> prioritise ->
explain -> case. Every source (dataset replay, file upload, live sensor push) calls ingest()."""
from __future__ import annotations

from datetime import timedelta

import base64
import io

import joblib
import pandas as pd

from . import assets, assistant, db, settings
from .correlation import correlate, incident_entities, incident_title
from .detection.anomaly import AnomalyModel
from .detection.rules import detect_rules
from .scoring import score_incident

_model: dict = {}  # in-process cache; the trained model itself is stored in the database


def _save_model(m: AnomalyModel):
    buf = io.BytesIO()
    joblib.dump(m, buf, compress=3)
    db.set_meta("anomaly_model_blob", base64.b64encode(buf.getvalue()).decode())


def _load_model() -> AnomalyModel | None:
    blob = db.get_meta("anomaly_model_blob")
    return joblib.load(io.BytesIO(base64.b64decode(blob))) if blob else None


# ------------------------------------------------------------------ anomaly model lifecycle
def get_model(train: bool = True) -> AnomalyModel | None:
    if "m" in _model:
        return _model["m"]
    try:
        loaded = _load_model()
    except Exception:
        loaded = None
    if loaded is not None:
        _model["m"] = loaded
        return loaded
    if not train:
        return None
    start, end = db.time_range()
    hours = settings.section("detection")["anomaly"]["baseline_hours"]
    if start is None or end - start < pd.Timedelta(hours=hours):
        return None  # keep collecting a baseline first
    base = db.events_between(start, start + pd.Timedelta(hours=hours))
    try:
        m = AnomalyModel().fit(base)
    except ValueError:
        return None
    _save_model(m)
    db.set_meta("anomaly_model", {"trained_at": db.now(), "baseline_from": start, "baseline_to": m.trained_until,
                                  "windows": m.trained_on, "contamination": m.contamination})
    _model["m"] = m
    return m


def retrain_model() -> dict:
    _model.clear()
    db.set_meta("anomaly_model_blob", None)
    db.set_meta("anomaly_model", None)
    db.set_meta("anomaly_scored_until", None)
    return {"trained": get_model() is not None, "meta": db.get_meta("anomaly_model")}


def _max_rule_window() -> pd.Timedelta:
    d = settings.section("detection")
    return max(pd.Timedelta(d[k]["window"]) for k in ("scan", "bruteforce", "ssh_bruteforce", "lateral")) * 6


# ------------------------------------------------------------------ ingest
def ingest(events: pd.DataFrame, use_llm: bool = False, software=None) -> dict:
    """Store a batch of normalised events and run the whole pipeline on it. Replayed datasets may
    carry label_tactic / label_technique columns: they go to the separate labels table only.
    Serialised with a database lock: sensors, API workers and dashboard sessions may call it at once."""
    with db.lock("pipeline"):
        return _ingest(events, use_llm, software)


def _ingest(events: pd.DataFrame, use_llm: bool, software) -> dict:
    summary = {"events": int(len(events)), "alerts": 0, "rules": {}, "new_incidents": [], "updated_incidents": []}
    if events.empty:
        return summary
    events = events.sort_values("ts", kind="stable").reset_index(drop=True)
    start_id = db.max_id("events", "event_id") + 1
    events.insert(0, "event_id", range(start_id, start_id + len(events)))
    db.write_events(events)
    if "label_tactic" in events:
        lab = events[["event_id", "label_tactic", "label_technique"]].rename(
            columns={"label_tactic": "tactic", "label_technique": "technique"})
        db.write_labels(lab[lab.tactic.fillna("") != ""])
        events = events.drop(columns=["label_tactic", "label_technique"])
    assets.discover(events)
    if software is not None:
        assets.add_software(software)

    batch_start, batch_end = events.ts.min(), events.ts.max()
    ctx = pd.concat([db.events_between(batch_start - _max_rule_window(), batch_start), events], ignore_index=True)
    ctx = ctx.drop_duplicates("event_id").sort_values("ts", kind="stable").reset_index(drop=True)
    found = [a for a in detect_rules(ctx) if a["last_ts"] >= batch_start]

    model = get_model()
    if model is not None:
        done = db.get_meta("anomaly_scored_until")
        lo = pd.Timestamp(done) if done else db.time_range()[0].floor("h")
        hi = batch_end.floor("h")
        if hi > lo:
            win = db.events_between(lo, hi)
            found += model.detect(win, hours=set(pd.date_range(lo, hi, freq="h", inclusive="left")))
            db.set_meta("anomaly_scored_until", hi)

    alerts = pd.DataFrame(found)
    if alerts.empty:
        return summary
    alerts = alerts.drop_duplicates("alert_key")
    alerts = alerts[~alerts.alert_key.isin(db.existing_alert_keys(alerts.alert_key.tolist()))]
    if alerts.empty:
        return summary
    alerts["ts"] = pd.to_datetime(alerts.ts, utc=True)
    alerts["last_ts"] = pd.to_datetime(alerts.last_ts, utc=True)
    alerts = alerts.sort_values("ts", kind="stable").reset_index(drop=True)
    first_id = db.max_id("alerts", "alert_id") + 1
    alerts.insert(0, "alert_id", range(first_id, first_id + len(alerts)))
    alerts["dataset"] = events.dataset.iloc[0]
    summary["alerts"] = int(len(alerts))
    summary["rules"] = alerts.rule_id.value_counts().to_dict()

    gap = pd.Timedelta(minutes=settings.section("correlation")["gap_minutes"])
    open_incs = db.open_incidents_since(alerts.ts.min() - gap)
    groups, attach = correlate(alerts, open_incs)
    next_no = db.next_incident_number()
    alerts["incident_id"] = None
    for g, existing in attach.items():
        if existing:
            target, *merged = sorted(existing)
        else:
            target, merged = f"INC-{next_no:04d}", []
            next_no += 1
            summary["new_incidents"].append(target)
        alerts.loc[groups[groups == g].index, "incident_id"] = target
        for m in merged:
            moved = db.read_alerts(m)
            db.set_alert_incident(moved.alert_id.tolist(), target)
            db.update_incident(m, "pipeline", status="Resolved", resolution=f"Merged into {target}")
            db.audit(target, "merged", f"{m} merged in ({len(moved)} alerts) - linked by a shared entity", "pipeline")
        if existing:
            summary["updated_incidents"].append(target)
    db.write_alerts(alerts)
    for inc_id in summary["new_incidents"] + summary["updated_incidents"]:
        rebuild_incident(inc_id, new_alerts=int((alerts.incident_id == inc_id).sum()),
                         use_llm=use_llm and inc_id in summary["new_incidents"])
    return summary


def rebuild_incident(inc_id: str, new_alerts: int = 0, use_llm: bool = False):
    """(Re)compute an incident from all of its alerts, keeping the analyst's case fields."""
    g = db.read_alerts(inc_id)
    cur = db.get_incident(inc_id)
    ents = incident_entities(g)
    sc = score_incident(g, ents)
    ev_ids = sorted({e for es in g.evidence for e in es})
    now = db.now()
    row = dict(incident_id=inc_id, dataset=g.dataset.iloc[0], title=incident_title(g, ents), severity=sc["severity"],
               score=sc["score"], updated_at=now, first_seen=g.ts.min(), last_seen=g.last_ts.max(),
               alert_count=len(g), event_count=len(ev_ids), entities=ents, scoring=sc)
    if cur is None:
        row.update(status="New", owner="Unassigned", created_at=now, sla_due=now + timedelta(hours=sc["sla_hours"]),
                   acknowledged_at=None, resolved_at=None, resolution="", false_positive=False)
    else:
        row["sla_due"] = min(cur["sla_due"], cur["created_at"] + timedelta(hours=sc["sla_hours"]))
    ex = assistant.explain(row, g, db.events_by_ids(ev_ids), use_llm=use_llm)
    row.update(ai_summary=ex["text"], ai_mode=ex["mode"], ai_support=ex["support_rate"], ai_checks=ex["checks"])
    db.upsert_incident(row)
    if cur is None:
        db.audit(inc_id, "created", f"{len(g)} alerts correlated; {sc['severity']} ({sc['score']}); SLA due "
                                    f"{row['sla_due']:%Y-%m-%d %H:%M} UTC", "pipeline")
    elif new_alerts:
        change = f"; severity {cur['severity']} -> {sc['severity']}" if cur["severity"] != sc["severity"] else ""
        db.audit(inc_id, "updated", f"{new_alerts} new alert(s) correlated{change}", "pipeline")


def regenerate_explanation(incident_id: str, use_llm: bool = True) -> dict:
    inc = db.get_incident(incident_id)
    alerts = db.read_alerts(incident_id)
    events = db.events_by_ids([e for es in alerts.evidence for e in es])
    ex = assistant.explain(inc, alerts, events, use_llm=use_llm)
    db.upsert_incident({"incident_id": incident_id, "ai_summary": ex["text"], "ai_mode": ex["mode"],
                        "ai_support": ex["support_rate"], "ai_checks": ex["checks"]})
    db.audit(incident_id, "ai_explanation", f"mode={ex['mode']} support={ex['support_rate']:.0%} {ex['note']}".strip(),
             "assistant")
    return ex


def rescore_all() -> int:
    """Re-score every open incident (after inventory, CVE or settings changes)."""
    inc = db.list_incidents()
    ids = inc[~inc.status.isin(["Resolved", "False positive"])].incident_id.tolist()
    for i in ids:
        rebuild_incident(i)
    return len(ids)
