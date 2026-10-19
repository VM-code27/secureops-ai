"""Incident prioritisation: threat confidence x asset importance x vulnerability exposure.

score = 100 * (w_threat * threat + w_asset * asset + w_exposure * exposure + w_spread * spread)
(weights, severity bands and SLA hours come from settings)

* threat   - noisy-OR of the strongest alert per rule, +0.1 if 3+ ATT&CK tactics.
* asset    - highest criticality (1-5) of affected internal assets (inventory or inferred).
* exposure - 1.0 if an IDS signature names a CVE the target is known to have ("confirmed
             exploitable"); otherwise the worst CVE on affected assets, CVSS/10 weighted by
             live exploitation evidence (CISA KEV = 1.0, else 0.5 + 0.5 x EPSS).
* spread   - number of affected internal assets, log-scaled.
"""
from __future__ import annotations

import math

import pandas as pd

from . import settings
from .assets import index as asset_index
from .intel import vulns


def band(score: float) -> str:
    b = settings.section("scoring")["bands"]
    return "Critical" if score >= b["Critical"] else "High" if score >= b["High"] else "Medium" if score >= b["Medium"] else "Low"


def score_incident(group: pd.DataFrame, entities: dict) -> dict:
    idx = asset_index()
    weights = settings.section("scoring")["weights"]
    threat = 1.0
    for c in group.groupby("rule_id").confidence.max():
        threat *= 1 - c
    threat = 1 - threat
    stages = set(group.tactic) - {"Anomaly"}
    if len(stages) >= 3:
        threat = min(1.0, threat + 0.1)

    assets = [idx[ip] for ip in entities["internal"] if ip in idx]
    crit = max([a["criticality"] or 1 for a in assets], default=1)

    exploited = []
    for _, a in group[group.cve != ""].iterrows():
        tgt = idx.get(a.dst_ip)
        if tgt and a.cve in (tgt.get("cves") or []):
            exploited.append((label(a.dst_ip), a.cve))
    cves = sorted({c for a in assets for c in (a.get("cves") or [])})
    worst, cve_rows = vulns.exposure(cves) if cves else (0.0, [])
    exposure = 1.0 if exploited else worst

    spread = min(1.0, math.log2(1 + len(assets)) / math.log2(26))
    parts = {"threat": threat, "asset": crit / 5, "exposure": exposure, "spread": spread}
    score = round(100 * sum(weights[k] * v for k, v in parts.items()), 1)
    sev = band(score)
    return {"score": score, "severity": sev, "sla_hours": settings.section("sla_hours")[sev],
            "breakdown": {k: round(v, 3) for k, v in parts.items()}, "weights": weights, "max_criticality": crit,
            "exploited_cves": sorted(set(exploited)), "top_cves": cve_rows[:5], "stages": sorted(stages)}


def label(ip: str) -> str:
    from .assets import label as _label
    return _label(ip)
