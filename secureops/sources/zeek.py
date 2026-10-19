"""Zeek log parser: default TSV format (with a #fields header) or JSON lines.
Supports conn.log, ssh.log and software.log (software feeds the asset inventory)."""
from __future__ import annotations

import gzip
import json

import pandas as pd

from . import normalise

CONN_MAP = {"id.orig_h": "src_ip", "id.orig_p": "src_port", "id.resp_h": "dst_ip", "id.resp_p": "dst_port",
            "orig_bytes": "bytes_out", "resp_bytes": "bytes_in", "orig_pkts": "pkts_out", "resp_pkts": "pkts_in"}


def _read_tsv(text: str) -> tuple[str, pd.DataFrame]:
    path, fields, unset, empty = "", [], "-", "(empty)"
    rows = []
    for line in text.splitlines():
        if line.startswith("#"):
            key, _, val = line[1:].partition("\t")
            if key == "fields":
                fields = val.split("\t")
            elif key == "path":
                path = val
            elif key == "unset_field":
                unset = val
            elif key == "empty_field":
                empty = val
            continue
        if line.strip():
            rows.append(line.split("\t"))
    df = pd.DataFrame(rows, columns=fields) if rows else pd.DataFrame(columns=fields)
    df = df.replace({unset: None, empty: None})
    if "ts" in df and len(df):
        df["ts"] = pd.to_datetime(pd.to_numeric(df.ts), unit="s", utc=True)
    return path, df


def _read_json(text: str) -> tuple[str, pd.DataFrame]:
    recs = [json.loads(line) for line in text.splitlines() if line.strip().startswith("{")]
    df = pd.DataFrame(recs)
    path = str(df["_path"].iloc[0]) if "_path" in df and len(df) else ""
    if "ts" in df and len(df):
        df["ts"] = pd.to_datetime(df.ts, unit="s", utc=True) if pd.api.types.is_numeric_dtype(df.ts) \
            else pd.to_datetime(df.ts, utc=True, format="mixed")
    return path, df


def _guess_path(df: pd.DataFrame, filename: str) -> str:
    name = filename.lower().rsplit("/", 1)[-1]
    for p in ("conn", "ssh", "software"):
        if name.startswith(p + ".") or name.startswith(p + "_") or name.startswith(p + "-"):
            return p
    cols = set(df.columns)
    if "conn_state" in cols:
        return "conn"
    if "auth_success" in cols:
        return "ssh"
    if "software_type" in cols:
        return "software"
    return ""


def parse(text: str, filename: str = "", sensor: str = "upload", dataset: str = "live") -> dict:
    """Returns {"events": normalised DataFrame, "software": DataFrame, "path": str, "rows": int}."""
    first = next((line for line in text.splitlines() if line.strip()), "")
    path, df = _read_tsv(text) if first.startswith("#") else _read_json(text)
    path = path or _guess_path(df, filename)
    out = {"events": normalise(pd.DataFrame(columns=["ts"]), "zeek_conn", sensor, dataset),
           "software": pd.DataFrame(columns=["host", "name", "version", "type"]), "path": path, "rows": len(df)}
    if df.empty:
        return out
    if path == "conn":
        out["events"] = normalise(df.rename(columns=CONN_MAP), "zeek_conn", sensor, dataset)
    elif path == "ssh":
        d = df.rename(columns=CONN_MAP)
        if "auth_success" in d:
            d["outcome"] = d.auth_success.map(
                lambda v: "" if v is None else ("success" if str(v).lower() in ("t", "true") else "failure"))
        d["service"], d["proto"] = "ssh", "tcp"
        out["events"] = normalise(d, "zeek_ssh", sensor, dataset)
    elif path == "software":
        version = df["unparsed_version"] if "unparsed_version" in df else df.get("version.major")
        out["software"] = pd.DataFrame({"host": df.get("host"), "name": df.get("name"), "version": version,
                                        "type": df.get("software_type")}).dropna(subset=["host", "name"])
    return out


def parse_bytes(raw: bytes, filename: str, **kw) -> dict:
    if filename.endswith(".gz"):
        raw, filename = gzip.decompress(raw), filename[:-3]
    return parse(raw.decode("utf-8", errors="replace"), filename, **kw)
