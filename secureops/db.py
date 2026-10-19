"""Persistence: SQLite by default, any PostgreSQL (e.g. free Neon/Supabase) via DATABASE_URL."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from functools import lru_cache

import pandas as pd
from sqlalchemy import (Boolean, Column, DateTime, Float, Integer, MetaData, String, Table, Text, create_engine, text,
                        insert, select, update)

from . import config

metadata = MetaData()

incidents = Table(
    "incidents", metadata,
    Column("incident_id", String(16), primary_key=True),
    Column("dataset", String(32)),
    Column("title", Text),
    Column("severity", String(16)),
    Column("score", Float),
    Column("status", String(24)),
    Column("owner", String(64)),
    Column("created_at", DateTime(timezone=True)),
    Column("first_seen", DateTime(timezone=True)),
    Column("last_seen", DateTime(timezone=True)),
    Column("sla_due", DateTime(timezone=True)),
    Column("acknowledged_at", DateTime(timezone=True), nullable=True),
    Column("resolved_at", DateTime(timezone=True), nullable=True),
    Column("resolution", Text, default=""),
    Column("false_positive", Boolean, default=False),
    Column("alert_count", Integer),
    Column("event_count", Integer),
    Column("entities", Text),
    Column("scoring", Text),
    Column("ai_summary", Text),
    Column("ai_mode", String(64)),
    Column("ai_support", Float),
    Column("ai_checks", Text),
    Column("ground_truth", Text, nullable=True),
)

audit_log = Table(
    "audit_log", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("ts", DateTime(timezone=True)),
    Column("actor", String(64)),
    Column("incident_id", String(16)),
    Column("action", String(64)),
    Column("detail", Text),
)

meta = Table("meta", metadata, Column("key", String(64), primary_key=True), Column("value", Text))

STATUSES = ["New", "Investigating", "Contained", "Resolved", "False positive"]


@lru_cache(maxsize=1)
def engine():
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    return create_engine(config.DATABASE_URL, pool_pre_ping=True)


def now() -> datetime:
    return datetime.now(timezone.utc)


def reset():
    eng = engine()
    with eng.begin() as c:
        for t in ("events", "alerts"):
            c.exec_driver_sql(f"DROP TABLE IF EXISTS {t}")
    metadata.drop_all(eng)
    metadata.create_all(eng)


def ensure_schema():
    metadata.create_all(engine())


def get_meta(key: str, default=None):
    ensure_schema()
    with engine().connect() as c:
        row = c.execute(select(meta.c.value).where(meta.c.key == key)).first()
    return json.loads(row[0]) if row else default


def set_meta(key: str, value):
    with engine().begin() as c:
        c.execute(meta.delete().where(meta.c.key == key))
        c.execute(insert(meta).values(key=key, value=json.dumps(value, default=str)))


# ------------------------------------------------------------------ events/alerts
def _to_sql(df: pd.DataFrame, table: str):
    multi = engine().dialect.name == "postgresql"  # SQLite caps bind variables; executemany is fast there
    df.to_sql(table, engine(), if_exists="append", index=False, chunksize=1000 if multi else 10000,
              method="multi" if multi else None)


def write_events(df: pd.DataFrame):
    _to_sql(df, "events")


def write_alerts(df: pd.DataFrame):
    out = df.copy()
    out["targets"] = out.targets.map(json.dumps)
    out["evidence"] = out.evidence.map(json.dumps)
    _to_sql(out, "alerts")


def _fix_ts(df: pd.DataFrame, cols) -> pd.DataFrame:
    for c in cols:
        if c in df:
            df[c] = pd.to_datetime(df[c], utc=True, format="mixed")
    return df


def read_events(where: str = "", params: dict | None = None) -> pd.DataFrame:
    df = pd.read_sql_query(f"SELECT * FROM events {where}", engine(), params=params)
    return _fix_ts(df, ["ts"])


def events_by_ids(ids: list[int]) -> pd.DataFrame:
    if not ids:
        return read_events("WHERE 1=0")
    ids = sorted(set(int(i) for i in ids))
    return read_events(f"WHERE event_id IN ({','.join(map(str, ids))})")


def read_alerts(incident_id: str | None = None) -> pd.DataFrame:
    if incident_id:
        df = pd.read_sql_query(text("SELECT * FROM alerts WHERE incident_id = :i"), engine(), params={"i": incident_id})
    else:
        df = pd.read_sql_query("SELECT * FROM alerts", engine())
    df["targets"] = df.targets.map(json.loads)
    df["evidence"] = df.evidence.map(json.loads)
    return _fix_ts(df, ["ts", "last_ts"])


def max_id(table: str, col: str) -> int:
    try:
        with engine().connect() as c:
            return int(c.exec_driver_sql(f"SELECT COALESCE(MAX({col}), 0) FROM {table}").scalar())
    except Exception:
        return 0


def count(table: str, where: str = "") -> int:
    with engine().connect() as c:
        return int(c.exec_driver_sql(f"SELECT COUNT(*) FROM {table} {where}").scalar())


# ------------------------------------------------------------------ incidents
def insert_incident(row: dict):
    with engine().begin() as c:
        c.execute(insert(incidents).values(**row))


def next_incident_number() -> int:
    with engine().connect() as c:
        ids = [r[0] for r in c.execute(select(incidents.c.incident_id))]
    return max([int(i.split("-")[1]) for i in ids], default=0) + 1


def list_incidents() -> pd.DataFrame:
    ensure_schema()
    df = pd.read_sql_table("incidents", engine())
    df = _fix_ts(df, ["created_at", "first_seen", "last_seen", "sla_due", "acknowledged_at", "resolved_at"])
    return df.sort_values(["score"], ascending=False)


def get_incident(incident_id: str) -> dict | None:
    with engine().connect() as c:
        row = c.execute(select(incidents).where(incidents.c.incident_id == incident_id)).mappings().first()
    if not row:
        return None
    d = dict(row)
    for k in ("entities", "scoring", "ai_checks"):
        d[k] = json.loads(d[k]) if d[k] else {}
    for k in ("created_at", "first_seen", "last_seen", "sla_due", "acknowledged_at", "resolved_at"):
        if d[k] is not None:
            d[k] = pd.Timestamp(d[k]).tz_localize("UTC") if pd.Timestamp(d[k]).tzinfo is None else pd.Timestamp(d[k])
    return d


def audit(incident_id: str, action: str, detail: str, actor: str = "system"):
    with engine().begin() as c:
        c.execute(insert(audit_log).values(ts=now(), actor=actor, incident_id=incident_id, action=action, detail=detail))


def read_audit(incident_id: str | None = None) -> pd.DataFrame:
    q = select(audit_log).order_by(audit_log.c.id.desc())
    if incident_id:
        q = q.where(audit_log.c.incident_id == incident_id)
    with engine().connect() as c:
        df = pd.DataFrame(c.execute(q).mappings().all())
    return _fix_ts(df, ["ts"]) if not df.empty else pd.DataFrame(columns=["id", "ts", "actor", "incident_id", "action", "detail"])


def update_incident(incident_id: str, actor: str, **changes):
    """Case-management update with an audit entry for every changed field."""
    cur = get_incident(incident_id)
    if cur is None:
        raise KeyError(incident_id)
    changes = {k: v for k, v in changes.items() if v is not None and cur.get(k) != v}
    if not changes:
        return cur
    ts = now()
    if "owner" in changes and changes["owner"] != "Unassigned" and cur["acknowledged_at"] is None:
        changes["acknowledged_at"] = ts
    if changes.get("status") in ("Resolved", "False positive") and cur["resolved_at"] is None:
        changes["resolved_at"] = ts
        changes["false_positive"] = changes["status"] == "False positive"
        if cur["acknowledged_at"] is None:
            changes["acknowledged_at"] = ts
    if changes.get("status") in ("New", "Investigating", "Contained"):
        changes["resolved_at"] = None
        changes["false_positive"] = False
    with engine().begin() as c:
        c.execute(update(incidents).where(incidents.c.incident_id == incident_id).values(**changes))
    for k, v in changes.items():
        if k in ("owner", "status", "resolution"):
            audit(incident_id, f"set_{k}", f"{cur.get(k)!s} -> {v!s}", actor)
    return get_incident(incident_id)
