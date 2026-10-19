"""End-to-end pipeline: ingest -> detect -> correlate -> prioritise -> explain -> case."""
from __future__ import annotations

import json
from datetime import timedelta

import joblib
import pandas as pd

from . import assistant, db
from .config import DATA_DIR, SEED
from .correlation import correlate, incident_entities, incident_title
from .detection.anomaly import AnomalyModel, detect_all
from .scoring import score_incident
from .simulate import historical_dataset, live_scenario

MODEL_PATH = DATA_DIR / "anomaly_model.joblib"


def build_incidents(events: pd.DataFrame, alerts: pd.DataFrame, *, alert_start: int, inc_start: int,
                    dataset: str, created_at, use_llm: bool = False) -> tuple[pd.DataFrame, list[dict]]:
    """Correlate alerts into incidents, score and explain them. Pure (no DB)."""
    if alerts.empty:
        return alerts, []
    alerts = alerts.copy()
    alerts.insert(0, "alert_id", range(alert_start, alert_start + len(alerts)))
    alerts["group"] = correlate(alerts)
    alerts["dataset"] = dataset
    labeled = "campaign" in events and events.campaign.notna().any()
    camp = events.set_index("event_id").campaign if labeled else None
    groups = sorted(alerts.groupby("group"), key=lambda kv: kv[1].ts.min())
    incidents = []
    for n, (_, g) in enumerate(groups):
        inc_id = f"INC-{inc_start + n:04d}"
        alerts.loc[g.index, "incident_id"] = inc_id
        ents = incident_entities(g)
        sc = score_incident(g, ents)
        ev_ids = sorted({e for es in g.evidence for e in es})
        inc = dict(incident_id=inc_id, dataset=dataset, title=incident_title(g, ents), severity=sc["severity"],
                   score=sc["score"], status="New", owner="Unassigned", created_at=created_at,
                   first_seen=g.ts.min(), last_seen=g.last_ts.max(), sla_due=created_at + timedelta(hours=sc["sla_hours"]),
                   acknowledged_at=None, resolved_at=None, resolution="", false_positive=False,
                   alert_count=len(g), event_count=len(ev_ids), entities=ents, scoring=sc)
        if labeled:
            truth = sorted(set(camp.reindex(ev_ids).dropna()) - {""})
            inc["ground_truth"] = ",".join(truth) or "benign"
        else:
            inc["ground_truth"] = None
        ex = assistant.explain(inc, g, events[events.event_id.isin(ev_ids)], use_llm=use_llm)
        inc.update(ai_summary=ex["text"], ai_mode=ex["mode"], ai_support=ex["support_rate"],
                   ai_checks=ex["checks"])
        incidents.append(inc)
    return alerts.drop(columns="group"), incidents


def _store(alerts: pd.DataFrame, incidents: list[dict]):
    if not alerts.empty:
        db.write_alerts(alerts)
    for inc in incidents:
        row = dict(inc)
        for k in ("entities", "scoring", "ai_checks"):
            row[k] = json.dumps(row[k], default=str)
        db.insert_incident(row)
        db.audit(inc["incident_id"], "created",
                 f"{inc['alert_count']} alerts correlated; severity {inc['severity']} ({inc['score']}); "
                 f"SLA due {inc['sla_due']:%Y-%m-%d %H:%M} UTC", "pipeline")


def get_model() -> AnomalyModel:
    if MODEL_PATH.exists():
        try:
            return joblib.load(MODEL_PATH)
        except Exception:
            pass
    model = AnomalyModel().fit(db.read_events("WHERE dataset = 'historical_labeled'"))
    joblib.dump(model, MODEL_PATH)
    return model


def bootstrap(force: bool = False) -> bool:
    """Create the demo database on first run (or on reset). Returns True if it built."""
    if not force and db.get_meta("initialized"):
        return False
    db.reset()
    events = historical_dataset(SEED)
    db.write_events(events)
    model = AnomalyModel().fit(events)  # unsupervised: labels are never shown to the model
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    alerts = detect_all(events, model)
    alerts, incidents = build_incidents(events, alerts, alert_start=1, inc_start=1, dataset="historical_labeled",
                                        created_at=db.now())
    _store(alerts, incidents)
    db.set_meta("initialized", {"at": db.now(), "events": len(events), "alerts": len(alerts),
                                "incidents": len(incidents)})
    return True


def ingest_live(kind: str, use_llm: bool = True, seed: int | None = None) -> dict:
    """Live demo: new unlabelled events flow through the whole pipeline. Returns stage counts."""
    model = get_model()
    events = live_scenario(kind, start_id=db.max_id("events", "event_id") + 1, seed=seed)
    db.write_events(events)
    alerts = detect_all(events, model)
    alerts, incidents = build_incidents(events, alerts, alert_start=db.max_id("alerts", "alert_id") + 1,
                                        inc_start=db.next_incident_number(), dataset="live_unlabeled",
                                        created_at=db.now(), use_llm=use_llm)
    _store(alerts, incidents)
    return {"events": len(events), "alerts": len(alerts),
            "rules": alerts.rule_id.value_counts().to_dict() if len(alerts) else {},
            "incidents": [i["incident_id"] for i in incidents]}


def regenerate_explanation(incident_id: str, use_llm: bool = True) -> dict:
    inc = db.get_incident(incident_id)
    alerts = db.read_alerts(incident_id)
    events = db.events_by_ids([e for es in alerts.evidence for e in es])
    ex = assistant.explain(inc, alerts, events, use_llm=use_llm)
    from sqlalchemy import update
    with db.engine().begin() as c:
        c.execute(update(db.incidents).where(db.incidents.c.incident_id == incident_id).values(
            ai_summary=ex["text"], ai_mode=ex["mode"], ai_support=ex["support_rate"],
            ai_checks=json.dumps(ex["checks"], default=str)))
    db.audit(incident_id, "ai_explanation", f"mode={ex['mode']} support={ex['support_rate']:.0%} {ex['note']}".strip(),
             "assistant")
    return ex
