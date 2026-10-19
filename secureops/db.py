"""Persistence: SQLite by default, any PostgreSQL (e.g. free Neon) via DATABASE_URL."""
from __future__ import annotations

import json
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import lru_cache

import pandas as pd
from sqlalchemy import (BigInteger, Boolean, Column, DateTime, Float, Index, Integer, MetaData, String, Table, Text,
                        create_engine, delete, insert, select, text, update)

from . import config

metadata = MetaData()

events = Table(
    "events", metadata,
    Column("event_id", BigInteger, primary_key=True),
    Column("ts", DateTime(timezone=True), index=True),
    Column("source", String(24)),      # zeek_conn | zeek_ssh | suricata_alert | suricata_flow
    Column("sensor", String(64)),      # replay:uwf-zeekdata24 | upload | <sensor name>
    Column("dataset", String(16)),     # replay | live
    Column("uid", String(64)),
    Column("src_ip", String(64), index=True),
    Column("src_port", Integer),
    Column("dst_ip", String(64), index=True),
    Column("dst_port", Integer),
    Column("proto", String(16)),
    Column("service", String(64)),
    Column("conn_state", String(16)),
    Column("duration", Float),
    Column("bytes_out", BigInteger),
    Column("bytes_in", BigInteger),
    Column("pkts_out", BigInteger),
    Column("pkts_in", BigInteger),
    Column("outcome", String(16)),     # ssh auth: success | failure
    Column("auth_attempts", Integer),
    Column("signature", Text),
    Column("signature_id", BigInteger),
    Column("sig_severity", Integer),
    Column("category", Text),
)

# Ground-truth labels for replayed datasets. Kept in a separate table that the detection
# code never reads - only evaluate.py and the "lab label" panel use it.
labels = Table(
    "labels", metadata,
    Column("event_id", BigInteger, primary_key=True),
    Column("tactic", String(128)),
    Column("technique", String(128)),
)

alerts = Table(
    "alerts", metadata,
    Column("alert_id", BigInteger, primary_key=True),
    Column("alert_key", String(256), unique=True),
    Column("incident_id", String(16), index=True),
    Column("rule_id", String(32)),
    Column("rule_name", String(128)),
    Column("tactic", String(64)),
    Column("technique", String(64)),
    Column("ts", DateTime(timezone=True)),
    Column("last_ts", DateTime(timezone=True)),
    Column("src_ip", String(64)),
    Column("dst_ip", String(64)),
    Column("targets", Text),
    Column("user", String(128)),
    Column("confidence", Float),
    Column("description", Text),
    Column("evidence", Text),
    Column("cve", String(32)),
    Column("dataset", String(16)),
)

incidents = Table(
    "incidents", metadata,
    Column("incident_id", String(16), primary_key=True),
    Column("dataset", String(16)),
    Column("title", Text),
    Column("severity", String(16)),
    Column("score", Float),
    Column("status", String(24)),
    Column("owner", String(64)),
    Column("created_at", DateTime(timezone=True)),
    Column("updated_at", DateTime(timezone=True)),
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

assets = Table(
    "assets", metadata,
    Column("ip", String(64), primary_key=True),
    Column("hostname", String(128), default=""),
    Column("role", Text, default=""),
    Column("criticality", Integer, default=1),
    Column("criticality_source", String(16), default="inferred"),  # inferred | inventory
    Column("owner", String(128), default=""),
    Column("cpes", Text, default="[]"),
    Column("cves", Text, default="[]"),
    Column("software", Text, default="[]"),     # observed (Zeek software.log)
    Column("services", Text, default="[]"),     # services this host answered
    Column("fan_in", Integer, default=0),
    Column("fan_out", Integer, default=0),
    Column("is_hub", Boolean, default=False),
    Column("first_seen", DateTime(timezone=True)),
    Column("last_seen", DateTime(timezone=True)),
    Column("notes", Text, default=""),
)

intel = Table(
    "intel", metadata,
    Column("indicator", String(64), primary_key=True),
    Column("kind", String(8)),          # ip | cidr
    Column("source", String(32)),
    Column("context", Text),
    Column("fetched_at", DateTime(timezone=True)),
)

vulns = Table(
    "vulns", metadata,
    Column("cve_id", String(32), primary_key=True),
    Column("cvss", Float),
    Column("severity", String(16)),
    Column("description", Text),
    Column("published", String(32)),
    Column("kev", Boolean, default=False),
    Column("kev_date", String(16)),
    Column("ransomware", String(16)),
    Column("epss", Float),
    Column("epss_percentile", Float),
    Column("fetched_at", DateTime(timezone=True)),
)

meta = Table("meta", metadata, Column("key", String(64), primary_key=True), Column("value", Text))

# Cross-process mutex (dashboard sessions, API workers and sensors all write to one database).
locks = Table("locks", metadata, Column("name", String(32), primary_key=True), Column("holder", String(64)),
              Column("until", DateTime(timezone=True)))
Index("ix_alerts_rule_ts", alerts.c.rule_id, alerts.c.ts)

STATUSES = ["New", "Investigating", "Contained", "Resolved", "False positive"]
EVENT_COLUMNS = [c.name for c in events.columns]


_override: dict = {}


@lru_cache(maxsize=4)
def _engine(url: str):
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    return create_engine(url, pool_pre_ping=True)


def engine():
    return _engine(_override.get("url", config.DATABASE_URL))


def use_database(url: str | None):
    """Point this process at another database (used by the evaluation harness)."""
    if url:
        _override["url"] = url
    else:
        _override.pop("url", None)


def py(ts):
    """Timestamp -> python datetime (microsecond precision, as databases store it)."""
    return None if ts is None else pd.Timestamp(ts).floor("us").to_pydatetime()


def now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_schema():
    metadata.create_all(engine())


def reset():
    metadata.drop_all(engine())
    metadata.create_all(engine())


_held = threading.local()


@contextmanager
def lock(name: str = "pipeline", ttl: int = 300, wait: int = 600):
    """Database-backed lock so only one writer runs the pipeline at a time, across processes.
    Re-entrant within a thread; expires after `ttl` seconds if its holder dies."""
    held = getattr(_held, "names", None)
    if held is None:
        held = _held.names = set()
    if name in held:
        yield
        return
    ensure_schema()
    me = uuid.uuid4().hex
    with engine().begin() as c:
        if not c.execute(select(locks.c.name).where(locks.c.name == name)).first():
            try:
                c.execute(insert(locks).values(name=name, holder=None, until=now()))
            except Exception:
                pass
    deadline = time.monotonic() + wait
    while True:
        t = now()
        with engine().begin() as c:
            got = c.execute(update(locks).where(locks.c.name == name,
                                                (locks.c.holder.is_(None)) | (locks.c.until < t))
                            .values(holder=me, until=t + timedelta(seconds=ttl))).rowcount
        if got == 1:
            break
        if time.monotonic() > deadline:
            raise TimeoutError(f"could not acquire the {name} lock")
        time.sleep(0.2)
    held.add(name)
    try:
        yield
    finally:
        held.discard(name)
        with engine().begin() as c:
            c.execute(update(locks).where(locks.c.name == name, locks.c.holder == me).values(holder=None))


def get_meta(key: str, default=None):
    ensure_schema()
    with engine().connect() as c:
        row = c.execute(select(meta.c.value).where(meta.c.key == key)).first()
    return json.loads(row[0]) if row else default


def set_meta(key: str, value):
    ensure_schema()
    with engine().begin() as c:
        c.execute(delete(meta).where(meta.c.key == key))
        c.execute(insert(meta).values(key=key, value=json.dumps(value, default=str)))


def _to_sql(df: pd.DataFrame, table: str):
    if df.empty:
        return
    multi = engine().dialect.name == "postgresql"  # SQLite caps bind variables; executemany is fast there
    df.to_sql(table, engine(), if_exists="append", index=False, chunksize=1000 if multi else 10000,
              method="multi" if multi else None)


def _fix_ts(df: pd.DataFrame, cols) -> pd.DataFrame:
    for c in cols:
        if c in df:
            df[c] = pd.to_datetime(df[c], utc=True, format="mixed")
    return df


def _ts(v):
    if v is None:
        return None
    t = pd.Timestamp(v)
    return t.tz_localize("UTC") if t.tzinfo is None else t


def count(table: str, where: str = "") -> int:
    with engine().connect() as c:
        return int(c.exec_driver_sql(f"SELECT COUNT(*) FROM {table} {where}").scalar())


def max_id(table: str, col: str) -> int:
    with engine().connect() as c:
        return int(c.exec_driver_sql(f"SELECT COALESCE(MAX({col}), 0) FROM {table}").scalar())


# ------------------------------------------------------------------ events / labels
def write_events(df: pd.DataFrame):
    _to_sql(df[EVENT_COLUMNS], "events")


def write_labels(df: pd.DataFrame):
    _to_sql(df[["event_id", "tactic", "technique"]], "labels")


def read_events(where: str = "", params: dict | None = None) -> pd.DataFrame:
    df = pd.read_sql_query(text(f"SELECT * FROM events {where}"), engine(), params=params or {})
    return _fix_ts(df, ["ts"])


def read_events_sql(sql: str, params: dict | None = None) -> pd.DataFrame:
    """Aggregate / custom queries over events (SQL portable between SQLite and PostgreSQL)."""
    return pd.read_sql_query(text(sql), engine(), params=params or {})


def events_between(start, end) -> pd.DataFrame:
    return read_events("WHERE ts >= :a AND ts < :b ORDER BY ts", {"a": py(start), "b": py(end)})


def events_by_ids(ids) -> pd.DataFrame:
    ids = sorted({int(i) for i in ids})
    if not ids:
        return read_events("WHERE 1=0")
    frames = [read_events(f"WHERE event_id IN ({','.join(map(str, ids[i:i + 900]))})") for i in range(0, len(ids), 900)]
    return pd.concat(frames, ignore_index=True)


def read_labels() -> pd.DataFrame:
    return pd.read_sql_table("labels", engine())


def time_range(where: str = "") -> tuple:
    with engine().connect() as c:
        lo, hi = c.exec_driver_sql(f"SELECT MIN(ts), MAX(ts) FROM events {where}").first()
    return _ts(lo), _ts(hi)


# ------------------------------------------------------------------ alerts
def write_alerts(df: pd.DataFrame):
    out = df.copy()
    out["targets"] = out.targets.map(json.dumps)
    out["evidence"] = out.evidence.map(json.dumps)
    _to_sql(out[[c.name for c in alerts.columns]], "alerts")


def existing_alert_keys(keys: list[str]) -> set[str]:
    found = set()
    with engine().connect() as c:
        for i in range(0, len(keys), 500):
            found |= {r[0] for r in c.execute(select(alerts.c.alert_key).where(alerts.c.alert_key.in_(keys[i:i + 500])))}
    return found


def _decode_alerts(df: pd.DataFrame) -> pd.DataFrame:
    df["targets"] = df.targets.map(json.loads)
    df["evidence"] = df.evidence.map(json.loads)
    return _fix_ts(df, ["ts", "last_ts"])


def read_alerts(incident_ids: list[str] | str | None = None) -> pd.DataFrame:
    q = select(alerts)
    if incident_ids is not None:
        ids = [incident_ids] if isinstance(incident_ids, str) else list(incident_ids)
        q = q.where(alerts.c.incident_id.in_(ids or [""]))
    with engine().connect() as c:
        df = pd.DataFrame(c.execute(q).mappings().all(), columns=[col.name for col in alerts.columns])
    return _decode_alerts(df)


def set_alert_incident(alert_ids: list[int], incident_id: str):
    with engine().begin() as c:
        for i in range(0, len(alert_ids), 500):
            c.execute(update(alerts).where(alerts.c.alert_id.in_(alert_ids[i:i + 500])).values(incident_id=incident_id))


# ------------------------------------------------------------------ incidents
JSON_COLS = ("entities", "scoring", "ai_checks")
TS_COLS = ("created_at", "updated_at", "first_seen", "last_seen", "sla_due", "acknowledged_at", "resolved_at")


def _enc(row: dict) -> dict:
    out = {}
    for k, v in row.items():
        if k in JSON_COLS:
            v = json.dumps(v, default=str)
        elif isinstance(v, pd.Timestamp):
            v = py(v)
        out[k] = v
    return out


def upsert_incident(row: dict):
    with engine().begin() as c:
        exists = c.execute(select(incidents.c.incident_id).where(incidents.c.incident_id == row["incident_id"])).first()
        if exists:
            c.execute(update(incidents).where(incidents.c.incident_id == row["incident_id"]).values(**_enc(row)))
        else:
            c.execute(insert(incidents).values(**_enc(row)))


def next_incident_number() -> int:
    with engine().connect() as c:
        ids = [r[0] for r in c.execute(select(incidents.c.incident_id))]
    return max([int(i.split("-")[1]) for i in ids], default=0) + 1


def list_incidents() -> pd.DataFrame:
    ensure_schema()
    with engine().connect() as c:
        df = pd.DataFrame(c.execute(select(incidents)).mappings().all(), columns=[col.name for col in incidents.columns])
    df = _fix_ts(df, TS_COLS)
    return df.sort_values("score", ascending=False)


def _decode_incident(d) -> dict:
    d = dict(d)
    for k in JSON_COLS:
        d[k] = json.loads(d[k]) if d[k] else {}
    for k in TS_COLS:
        d[k] = _ts(d[k])
    return d


def get_incident(incident_id: str) -> dict | None:
    with engine().connect() as c:
        row = c.execute(select(incidents).where(incidents.c.incident_id == incident_id)).mappings().first()
    return _decode_incident(row) if row else None


def open_incidents_since(since) -> list[dict]:
    q = select(incidents).where(incidents.c.status.notin_(["Resolved", "False positive"]),
                                incidents.c.last_seen >= py(since))
    with engine().connect() as c:
        return [_decode_incident(r) for r in c.execute(q).mappings().all()]


def audit(incident_id: str, action: str, detail: str, actor: str = "system"):
    with engine().begin() as c:
        c.execute(insert(audit_log).values(ts=now(), actor=actor, incident_id=incident_id, action=action, detail=detail))


def read_audit(incident_id: str | None = None) -> pd.DataFrame:
    q = select(audit_log).order_by(audit_log.c.id.desc())
    if incident_id:
        q = q.where(audit_log.c.incident_id == incident_id)
    with engine().connect() as c:
        df = pd.DataFrame(c.execute(q).mappings().all(), columns=[col.name for col in audit_log.columns])
    return _fix_ts(df, ["ts"])


def update_incident(incident_id: str, actor: str, **changes):
    """Case-management update with an audit entry for every changed field."""
    cur = get_incident(incident_id)
    if cur is None:
        raise KeyError(incident_id)
    changes = {k: v for k, v in changes.items() if v is not None and cur.get(k) != v}
    if not changes:
        return cur
    ts = now()
    if changes.get("owner", "Unassigned") != "Unassigned" and cur["acknowledged_at"] is None:
        changes["acknowledged_at"] = ts
    if changes.get("status") in ("Resolved", "False positive"):
        changes["resolved_at"] = cur["resolved_at"] or ts
        changes["false_positive"] = changes["status"] == "False positive"
        changes.setdefault("acknowledged_at", cur["acknowledged_at"] or ts)
    elif changes.get("status") in ("New", "Investigating", "Contained"):
        changes["resolved_at"] = None
        changes["false_positive"] = False
    changes["updated_at"] = ts
    with engine().begin() as c:
        c.execute(update(incidents).where(incidents.c.incident_id == incident_id).values(**_enc(changes)))
    for k, v in changes.items():
        if k in ("owner", "status", "resolution"):
            audit(incident_id, f"set_{k}", f"{cur.get(k)!s} -> {v!s}", actor)
    return get_incident(incident_id)


# ------------------------------------------------------------------ assets / intel / vulns
ASSET_JSON = ("cpes", "cves", "software", "services")


def read_assets() -> pd.DataFrame:
    ensure_schema()
    with engine().connect() as c:
        df = pd.DataFrame(c.execute(select(assets)).mappings().all(), columns=[col.name for col in assets.columns])
    for k in ASSET_JSON:
        df[k] = df[k].map(lambda v: json.loads(v) if v else [])
    return _fix_ts(df, ["first_seen", "last_seen"])


def upsert_assets(rows: list[dict]):
    if not rows:
        return
    enc = [_enc({k: (json.dumps(v) if k in ASSET_JSON else v) for k, v in r.items()}) for r in rows]
    with engine().begin() as c:
        ips = [r["ip"] for r in enc]
        have = set()
        for i in range(0, len(ips), 500):
            have |= {x[0] for x in c.execute(select(assets.c.ip).where(assets.c.ip.in_(ips[i:i + 500])))}
        for r in enc:
            if r["ip"] in have:
                c.execute(update(assets).where(assets.c.ip == r["ip"]).values(**{k: v for k, v in r.items() if k != "ip"}))
            else:
                c.execute(insert(assets).values(**r))


def replace_intel(source: str, df: pd.DataFrame):
    with engine().begin() as c:
        c.execute(delete(intel).where(intel.c.source == source))
    if not df.empty:
        existing = set(read_intel().indicator)
        _to_sql(df.drop_duplicates("indicator")[lambda d: ~d.indicator.isin(existing)], "intel")


def read_intel() -> pd.DataFrame:
    ensure_schema()
    with engine().connect() as c:
        df = pd.DataFrame(c.execute(select(intel)).mappings().all(), columns=[col.name for col in intel.columns])
    return _fix_ts(df, ["fetched_at"])


def read_vulns(cve_ids=None) -> pd.DataFrame:
    ensure_schema()
    q = select(vulns)
    if cve_ids is not None:
        q = q.where(vulns.c.cve_id.in_(list(cve_ids) or [""]))
    with engine().connect() as c:
        return pd.DataFrame(c.execute(q).mappings().all(), columns=[col.name for col in vulns.columns])


def upsert_vulns(rows: list[dict]):
    with engine().begin() as c:
        for r in rows:
            c.execute(delete(vulns).where(vulns.c.cve_id == r["cve_id"]))
            c.execute(insert(vulns).values(**_enc(r)))
