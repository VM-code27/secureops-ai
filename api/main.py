"""SecureOps AI REST API.

Run:  uvicorn api.main:app --reload     ->  http://localhost:8000/docs

Private by default: every endpoint except GET /health needs the header
`X-API-Token: $SECUREOPS_API_TOKEN` (incidents contain your network's addresses). Serve it over HTTPS only.
"""
from __future__ import annotations

import hmac
import io
import json
from contextlib import asynccontextmanager
from typing import Literal

import pandas as pd
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from secureops import __version__, assets, bootstrap, config, db, pipeline, settings
from secureops.intel import feeds
from secureops.sources import replay, suricata, zeek


@asynccontextmanager
async def lifespan(_app):
    # The API only ingests and serves data. The heavy first-start build (dataset replay) is done by
    # the dashboard, so the API fits a small free instance and both never build at once.
    db.ensure_schema()
    yield


app = FastAPI(title="SecureOps AI", version=__version__, lifespan=lifespan,
              description="Threat detection, incident correlation, prioritisation and evidence-cited AI investigation "
                          "over real Zeek / Suricata telemetry.")


def require_token(x_api_token: str = Header(default="")):
    if not config.API_TOKEN:
        raise HTTPException(403, "API disabled: set SECUREOPS_API_TOKEN on the server.")
    if not hmac.compare_digest(x_api_token.encode(), config.API_TOKEN.encode()):
        raise HTTPException(401, "Missing or wrong X-API-Token header.")


def _json(df: pd.DataFrame) -> list:
    return json.loads(df.to_json(orient="records", date_format="iso"))


def _public(inc: dict) -> dict:
    return json.loads(json.dumps({k: v for k, v in inc.items() if k != "ai_checks"}, default=str))


class CaseUpdate(BaseModel):
    owner: str | None = None
    status: Literal["New", "Investigating", "Contained", "Resolved", "False positive"] | None = None
    resolution: str | None = None
    actor: str = "api"


# ------------------------------------------------------------------ status
@app.get("/health")
def health():
    """Public liveness check - deliberately reveals nothing about your network."""
    return {"status": "ok", "version": __version__, "initialized": bootstrap.initialized()}


@app.get("/status", dependencies=[Depends(require_token)])
def status():
    return {"database": db.engine().dialect.name, "events": db.count("events"), "replay": replay.state(),
            "intel": {k: {"count": v.get("count"), "fetched_at": v.get("fetched_at")} for k, v in feeds.status().items()}}


# ------------------------------------------------------------------ incidents
@app.get("/incidents", dependencies=[Depends(require_token)])
def incidents(status: str | None = None, severity: str | None = None, limit: int = 100):
    df = db.list_incidents()
    if status:
        df = df[df.status == status]
    if severity:
        df = df[df.severity == severity]
    cols = ["incident_id", "title", "severity", "score", "status", "owner", "alert_count", "first_seen", "last_seen",
            "sla_due", "dataset"]
    return _json(df[cols].head(limit))


@app.get("/incidents/{incident_id}", dependencies=[Depends(require_token)])
def incident(incident_id: str):
    inc = db.get_incident(incident_id)
    if not inc:
        raise HTTPException(404, "incident not found")
    return _public(inc)


@app.get("/incidents/{incident_id}/alerts", dependencies=[Depends(require_token)])
def incident_alerts(incident_id: str):
    return _json(db.read_alerts(incident_id))


@app.get("/incidents/{incident_id}/audit", dependencies=[Depends(require_token)])
def incident_audit(incident_id: str):
    return _json(db.read_audit(incident_id))


@app.patch("/incidents/{incident_id}", dependencies=[Depends(require_token)])
def update(incident_id: str, body: CaseUpdate):
    if body.owner and body.owner not in settings.team():
        raise HTTPException(422, f"owner must be one of {settings.team()} (add analysts in Settings)")
    try:
        return _public(db.update_incident(incident_id, body.actor, owner=body.owner, status=body.status,
                                          resolution=body.resolution))
    except KeyError:
        raise HTTPException(404, "incident not found")


@app.post("/incidents/{incident_id}/explain", dependencies=[Depends(require_token)])
def explain(incident_id: str, use_llm: bool = True):
    if not db.get_incident(incident_id):
        raise HTTPException(404, "incident not found")
    ex = pipeline.regenerate_explanation(incident_id, use_llm=use_llm)
    return {k: ex[k] for k in ("text", "mode", "note", "support_rate", "checks")}


# ------------------------------------------------------------------ ingest (sensors)
async def _ingest(events, software=None) -> dict:
    """Run the pipeline in a worker thread (never block the event loop, so /health stays up). If the
    pipeline is busy (e.g. the dashboard is replaying), answer 503 quickly; sensors retry later and
    lose nothing, because the shipper only advances after a successful upload."""
    try:
        return await run_in_threadpool(pipeline.ingest, events, software=software, wait=20)
    except TimeoutError:
        raise HTTPException(503, "Pipeline busy - retry shortly.", headers={"Retry-After": "15"})
@app.post("/ingest/zeek", dependencies=[Depends(require_token)])
async def ingest_zeek(request: Request, sensor: str = "sensor", filename: str = ""):
    """Body: raw Zeek log text (TSV with #fields header, or JSON lines) - conn, ssh or software."""
    body = (await request.body()).decode("utf-8", errors="replace")
    parsed = await run_in_threadpool(zeek.parse, body, filename, sensor=sensor)
    res = await _ingest(parsed["events"], software=parsed["software"])
    return {"log": parsed["path"], "rows": parsed["rows"], **res}


@app.post("/ingest/suricata", dependencies=[Depends(require_token)])
async def ingest_suricata(request: Request, sensor: str = "sensor"):
    """Body: Suricata eve.json lines (alert and flow events are used)."""
    body = (await request.body()).decode("utf-8", errors="replace")
    parsed = await run_in_threadpool(suricata.parse, body, sensor=sensor)
    res = await _ingest(parsed["events"])
    return {"alerts_in_file": parsed["alerts"], "flows_in_file": parsed["flows"], **res}


# ------------------------------------------------------------------ replay / intel / assets
@app.get("/replay", dependencies=[Depends(require_token)])
def replay_state():
    return replay.state()


@app.post("/replay/step", dependencies=[Depends(require_token)])
def replay_step(minutes: int | None = None):
    return json.loads(json.dumps(replay.step(minutes), default=str))


@app.get("/intel/status", dependencies=[Depends(require_token)])
def intel_status():
    return {"feeds": feeds.status(), "kev": db.get_meta("kev_status"), "indicators": len(feeds.index())}


@app.post("/intel/refresh", dependencies=[Depends(require_token)])
def intel_refresh():
    return feeds.refresh(force=True)


@app.get("/assets", dependencies=[Depends(require_token)])
def list_assets(limit: int = 500):
    return _json(db.read_assets().sort_values("criticality", ascending=False).head(limit))


@app.post("/assets/inventory", dependencies=[Depends(require_token)])
async def upload_inventory(request: Request):
    """Body: CSV with columns ip, hostname, criticality, owner, cpe, notes."""
    n = assets.apply_inventory(pd.read_csv(io.BytesIO(await request.body())))
    return {"assets_updated": n, "incidents_rescored": pipeline.rescore_all()}


@app.post("/assets/cves", dependencies=[Depends(require_token)])
def lookup_cves():
    return {"cves_linked": assets.lookup_cves(), "incidents_rescored": pipeline.rescore_all()}


@app.get("/settings", dependencies=[Depends(require_token)])
def get_settings():
    return settings.get()


@app.get("/metrics", dependencies=[Depends(require_token)])
def metrics():
    p = config.ROOT / "reports" / "metrics.json"
    if not p.exists():
        raise HTTPException(404, "run `python -m secureops.evaluate` first")
    return json.loads(p.read_text())
