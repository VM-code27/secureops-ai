"""UWF-ZeekData24 - real Zeek conn logs labelled with MITRE ATT&CK (University of West
Florida, CC BY 4.0, https://datasets.uwf.edu).

Files are discovered from the dataset's directory index (nothing about the file list is
hard-coded), downloaded once and cached.

Time overlay: UWF recorded the benign capture (Oct-Nov 2024) and the attack captures
(Feb-Mar 2024) in different weeks. Replaying them as-is would put attacks on days with
no normal traffic, which makes detection trivially easy. So each attack day is overlaid
with one benign day (cycled in order), shifting only the date and keeping each capture's
real time-of-day and inter-arrival timing. This is documented in the evaluation report.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

import pandas as pd
import requests

from .. import config, settings
from . import normalise

SENSOR = "replay:uwf-zeekdata24"
COLMAP = {"src_ip_zeek": "src_ip", "src_port_zeek": "src_port", "dest_ip_zeek": "dst_ip", "dest_port_zeek": "dst_port",
          "orig_bytes": "bytes_out", "resp_bytes": "bytes_in", "orig_pkts": "pkts_out", "resp_pkts": "pkts_in"}
NO_LABEL = {"none", "duplicate", "", "nan"}


def _cache_dir():
    d = config.CACHE_DIR / "uwf"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _links(url: str) -> list[str]:
    html = requests.get(url, timeout=60).text
    return [h for h in re.findall(r'href="([^"]+)"', html) if not h.startswith(("?", "/", "..", "http"))]


def download(progress=None) -> list:
    """Discover and download every CSV part file under replay.source_url. Returns local paths."""
    base = settings.section("replay")["source_url"]
    paths = []
    for sub in [h for h in _links(base) if h.endswith("/")]:
        for f in [h for h in _links(urljoin(base, sub)) if h.endswith(".csv")]:
            local = _cache_dir() / f"{sub.strip('/')}.csv"
            if not local.exists() or local.stat().st_size == 0:
                if progress:
                    progress(f"Downloading {sub}{f}")
                r = requests.get(urljoin(urljoin(base, sub), f), timeout=300)
                r.raise_for_status()
                local.write_bytes(r.content)
            paths.append(local)
    return paths


def _labels(series: pd.Series) -> str:
    vals = sorted({str(v) for v in series if str(v).lower() not in NO_LABEL})
    return ",".join(vals)


_mem: dict = {}


def load(progress=None) -> pd.DataFrame:
    """Return the full overlaid replay timeline: normalised events + label_tactic/label_technique."""
    if "df" in _mem:
        return _mem["df"]
    cached = _cache_dir() / "overlay.pkl"
    if cached.exists():
        _mem["df"] = pd.read_pickle(cached)
        return _mem["df"]
    raw = pd.concat([pd.read_csv(p, low_memory=False) for p in download(progress)], ignore_index=True)
    # The same connection can appear in several tactic files: keep one row, union its labels.
    lab = raw.groupby("uid").agg(label_tactic=("label_tactic", _labels), label_technique=("label_technique", _labels))
    raw = raw.drop_duplicates("uid").set_index("uid").join(lab, rsuffix="_u").reset_index()
    raw["label_tactic"], raw["label_technique"] = raw.pop("label_tactic_u"), raw.pop("label_technique_u")
    raw["ts"] = pd.to_datetime(raw["ts"], unit="s", utc=True)
    is_attack = raw.label_tactic != ""

    attack_days = sorted(raw.loc[is_attack, "ts"].dt.normalize().unique())
    benign = raw[~is_attack]
    benign_days = sorted(benign.ts.dt.normalize().unique())
    parts = [raw[is_attack]]
    for i, day in enumerate(attack_days):
        src_day = benign_days[i % len(benign_days)]
        chunk = benign[benign.ts.dt.normalize() == src_day].copy()
        chunk["ts"] = chunk.ts + (day - src_day)
        chunk["uid"] = chunk.uid + f"-d{i}"
        parts.append(chunk)
    df = pd.concat(parts, ignore_index=True).rename(columns=COLMAP)
    ev = normalise(df, "zeek_conn", SENSOR, "replay")
    # normalise() re-sorts rows, so re-attach the labels by connection uid.
    ev = ev.join(df.set_index("uid")[["label_tactic", "label_technique"]], on="uid")
    ev.to_pickle(cached)
    _mem["df"] = ev
    return ev


def info() -> dict:
    ev = load()
    days = ev.ts.dt.normalize().unique()
    return {"events": len(ev), "attack_events": int((ev.label_tactic != "").sum()), "days": len(days),
            "start": ev.ts.min(), "end": ev.ts.max(),
            "tactics": ev.loc[ev.label_tactic != "", "label_tactic"].str.split(",").explode().value_counts().to_dict()}
