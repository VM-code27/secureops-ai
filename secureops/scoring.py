"""Incident prioritisation: threat confidence x asset importance x vulnerability exposure.

score = 100 * (0.45 * threat + 0.25 * asset + 0.20 * exposure + 0.10 * spread)

* threat   - noisy-OR of the strongest alert per rule, +0.1 if 3+ kill-chain stages.
* asset    - highest business criticality (1-5) among affected internal assets.
* exposure - 1.0 if an exploit signature names a CVE the target really has
             ("confirmed exploitable"), else 0.6 x the worst CVSS on affected assets.
* spread   - number of affected internal assets, log-scaled.
"""
from __future__ import annotations

import math

import pandas as pd

from .assets import asset_index
from .config import SLA_HOURS
from .nvd import load_cves

WEIGHTS = {"threat": 0.45, "asset": 0.25, "exposure": 0.20, "spread": 0.10}


def band(score: float) -> str:
    return "Critical" if score >= 80 else "High" if score >= 60 else "Medium" if score >= 40 else "Low"


def score_incident(group: pd.DataFrame, entities: dict) -> dict:
    idx = asset_index()
    cves = load_cves()
    per_rule = group.groupby("rule_id").confidence.max()
    threat = 1.0
    for c in per_rule:
        threat *= 1 - c
    threat = 1 - threat
    stages = set(group.tactic) - {"Anomaly"}
    if len(stages) >= 3:
        threat = min(1.0, threat + 0.1)

    assets = [idx[ip] for ip in entities["internal"]]
    crit = max([a["criticality"] for a in assets], default=1)
    asset = crit / 5

    exploited = []
    for _, a in group[group.cve != ""].iterrows():
        tgt = idx.get(a.dst_ip)
        if tgt and a.cve in tgt["cves"]:
            exploited.append((tgt["hostname"], a.cve))
    exposed = sorted({(a["hostname"], c) for a in assets for c in a["cves"]})
    worst = max([cves.get(c, {}).get("cvss") or 0 for _, c in exposed], default=0)
    exposure = 1.0 if exploited else 0.6 * worst / 10

    spread = min(1.0, math.log2(1 + len(assets)) / math.log2(26))
    parts = {"threat": threat, "asset": asset, "exposure": exposure, "spread": spread}
    score = round(100 * sum(WEIGHTS[k] * v for k, v in parts.items()), 1)
    return {
        "score": score,
        "severity": band(score),
        "sla_hours": SLA_HOURS[band(score)],
        "breakdown": {k: round(v, 3) for k, v in parts.items()},
        "max_criticality": crit,
        "exploited_cves": sorted(set(exploited)),
        "exposed_cves": exposed,
        "stages": sorted(stages),
    }
