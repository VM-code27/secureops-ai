"""Suricata eve.json parser: `alert` events become IDS alert events and `flow` events
become connection records, so detection also works on a Suricata-only sensor."""
from __future__ import annotations

import gzip
import json

import pandas as pd

from . import normalise

FLOW_STATE = {"new": "S0", "established": "SF", "closed": "SF", "bypassed": "SF"}


def parse(text: str, sensor: str = "upload", dataset: str = "live") -> dict:
    alerts, flows = [], []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        e = json.loads(line)
        flow = e.get("flow") or {}
        base = dict(ts=e.get("timestamp"), src_ip=e.get("src_ip"), src_port=e.get("src_port"), dst_ip=e.get("dest_ip"),
                    dst_port=e.get("dest_port"), proto=str(e.get("proto", "")).lower(), service=e.get("app_proto"),
                    uid=str(e.get("flow_id", "")), bytes_out=flow.get("bytes_toserver"),
                    bytes_in=flow.get("bytes_toclient"), pkts_out=flow.get("pkts_toserver"),
                    pkts_in=flow.get("pkts_toclient"))
        if e.get("event_type") == "alert":
            a = e.get("alert") or {}
            alerts.append({**base, "signature": a.get("signature"), "signature_id": a.get("signature_id"),
                           "sig_severity": a.get("severity"), "category": a.get("category")})
        elif e.get("event_type") == "flow":
            start = pd.to_datetime(flow.get("start"), utc=True)
            end = pd.to_datetime(flow.get("end"), utc=True)
            flows.append({**base, "conn_state": FLOW_STATE.get(flow.get("state", ""), "OTH"),
                          "duration": (end - start).total_seconds() if pd.notna(start) and pd.notna(end) else 0})
    frames = [normalise(pd.DataFrame(rows), src, sensor, dataset)
              for rows, src in ((alerts, "suricata_alert"), (flows, "suricata_flow")) if rows]
    ev = pd.concat(frames, ignore_index=True).sort_values("ts", kind="stable").reset_index(drop=True) if frames \
        else normalise(pd.DataFrame(columns=["ts"]), "suricata_alert", sensor, dataset)
    return {"events": ev, "alerts": len(alerts), "flows": len(flows)}


def parse_bytes(raw: bytes, filename: str = "", **kw) -> dict:
    if filename.endswith(".gz"):
        raw = gzip.decompress(raw)
    return parse(raw.decode("utf-8", errors="replace"), **kw)
