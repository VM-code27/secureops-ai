"""Log sources. Every source produces events in one normalised schema (db.EVENT_COLUMNS)."""
from __future__ import annotations

import pandas as pd

from ..db import EVENT_COLUMNS

INT_COLS = ["src_port", "dst_port", "bytes_out", "bytes_in", "pkts_out", "pkts_in", "auth_attempts", "signature_id",
            "sig_severity"]
STR_COLS = ["source", "sensor", "dataset", "uid", "src_ip", "dst_ip", "proto", "service", "conn_state", "outcome",
            "signature", "category"]


def normalise(df: pd.DataFrame, source: str, sensor: str, dataset: str) -> pd.DataFrame:
    """Coerce any parsed log frame into the event schema (event_id is assigned at ingest)."""
    out = pd.DataFrame(index=df.index)
    for c in EVENT_COLUMNS:
        if c != "event_id":
            out[c] = df[c] if c in df else None
    out["source"], out["sensor"], out["dataset"] = source, sensor, dataset
    out["ts"] = pd.to_datetime(out.ts, utc=True, format="mixed")
    for c in INT_COLS:
        out[c] = pd.to_numeric(out[c], errors="coerce").fillna(0).astype("int64")
    out["duration"] = pd.to_numeric(out.duration, errors="coerce").fillna(0.0).astype(float)
    for c in STR_COLS:
        out[c] = out[c].where(out[c].notna(), "").astype(str).replace({"-": "", "nan": "", "None": "", "(empty)": ""})
    return out.dropna(subset=["ts"]).sort_values("ts", kind="stable").reset_index(drop=True)
