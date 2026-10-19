"""SecureOps AI REST API.

Run:  uvicorn api.main:app --reload     ->  http://localhost:8000/docs
"""
from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from secureops import __version__, db, pipeline
from secureops.config import ANALYSTS, ROOT
from secureops.simulate import LIVE_SCENARIOS


@asynccontextmanager
async def lifespan(_app):
    pipeline.bootstrap()  # builds the demo database on first start
    yield


app = FastAPI(title="SecureOps AI", version=__version__, lifespan=lifespan,
              description="Threat detection, incident correlation, prioritisation and evidence-cited AI investigation.")


def _public(inc: dict) -> dict:
    out = {k: v for k, v in inc.items() if k not in ("ai_checks",)}
    if out.get("dataset") == "live_unlabeled":
        out.pop("ground_truth", None)
    return json.loads(json.dumps(out, default=str))


class CaseUpdate(BaseModel):
    owner: str | None = None
    status: Literal["New", "Investigating", "Contained", "Resolved", "False positive"] | None = None
    resolution: str | None = None
    actor: str = "api"


class Ingest(BaseModel):
    scenario: Literal["multistage", "bruteforce", "spray", "iot"] = "multistage"
    use_llm: bool = True


@app.get("/health")
def health():
    return {"status": "ok", "version": __version__, "initialized": bool(db.get_meta("initialized"))}


@app.get("/incidents")
def incidents(status: str | None = None, severity: str | None = None, limit: int = 100):
    df = db.list_incidents()
    if status:
        df = df[df.status == status]
    if severity:
        df = df[df.severity == severity]
    cols = ["incident_id", "title", "severity", "score", "status", "owner", "alert_count", "first_seen", "sla_due",
            "dataset"]
    return json.loads(df[cols].head(limit).to_json(orient="records", date_format="iso"))


@app.get("/incidents/{incident_id}")
def incident(incident_id: str):
    inc = db.get_incident(incident_id)
    if not inc:
        raise HTTPException(404, "incident not found")
    return _public(inc)


@app.get("/incidents/{incident_id}/alerts")
def incident_alerts(incident_id: str):
    df = db.read_alerts(incident_id)
    return json.loads(df.to_json(orient="records", date_format="iso"))


@app.get("/incidents/{incident_id}/audit")
def incident_audit(incident_id: str):
    return json.loads(db.read_audit(incident_id).to_json(orient="records", date_format="iso"))


@app.patch("/incidents/{incident_id}")
def update(incident_id: str, body: CaseUpdate):
    if body.owner and body.owner not in ANALYSTS:
        raise HTTPException(422, f"owner must be one of {ANALYSTS}")
    try:
        inc = db.update_incident(incident_id, body.actor, owner=body.owner, status=body.status,
                                 resolution=body.resolution)
    except KeyError:
        raise HTTPException(404, "incident not found")
    return _public(inc)


@app.post("/incidents/{incident_id}/explain")
def explain(incident_id: str, use_llm: bool = True):
    if not db.get_incident(incident_id):
        raise HTTPException(404, "incident not found")
    ex = pipeline.regenerate_explanation(incident_id, use_llm=use_llm)
    return {k: ex[k] for k in ("text", "mode", "note", "support_rate", "checks")}


@app.post("/ingest/simulate")
def ingest(body: Ingest):
    """Push a fresh, unlabelled attack scenario through the full pipeline."""
    return pipeline.ingest_live(body.scenario, use_llm=body.use_llm)


@app.get("/scenarios")
def scenarios():
    return LIVE_SCENARIOS


@app.get("/metrics")
def metrics():
    p = ROOT / "reports" / "metrics.json"
    if not p.exists():
        raise HTTPException(404, "run `python -m secureops.evaluate` first")
    return json.loads(p.read_text())
