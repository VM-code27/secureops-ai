"""Incident correlation - turns hundreds of alerts into a few cases.

Two alerts belong to the same incident when they share an entity (an IP that is
not shared infrastructure) and occur within CORRELATION_GAP_MINUTES of each
other. Chains are followed transitively with union-find, so
scan -> exploit -> C2 -> lateral movement -> exfiltration becomes ONE incident.
"""
from __future__ import annotations

import pandas as pd

from .assets import asset_index, is_internal
from .config import CORRELATION_GAP_MINUTES

KILL_CHAIN = ["Reconnaissance", "Initial Access", "Credential Access", "Discovery", "Command and Control",
              "Lateral Movement", "Exfiltration", "Anomaly"]


def alert_entities(a) -> set[str]:
    idx = asset_index()
    ents = set()
    for ip in [a["src_ip"], a["dst_ip"]]:
        if not ip:
            continue
        if ip in idx and idx[ip]["is_hub"]:
            continue  # DNS, DC, VPN... everything touches these
        ents.add(ip)
    return ents


class _UF:
    def __init__(self, n):
        self.p = list(range(n))

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        self.p[self.find(a)] = self.find(b)


def correlate(alerts: pd.DataFrame) -> pd.Series:
    """Return a group label per alert (same label = same incident)."""
    if alerts.empty:
        return pd.Series(dtype=int)
    gap = pd.Timedelta(minutes=CORRELATION_GAP_MINUTES)
    order = alerts.sort_values("ts").index
    uf = _UF(len(alerts))
    pos = {ix: i for i, ix in enumerate(alerts.index)}
    last: dict[str, tuple] = {}  # entity -> (alert position, last_ts)
    for ix in order:
        a = alerts.loc[ix]
        i = pos[ix]
        for e in alert_entities(a):
            if e in last and a.ts - last[e][1] <= gap:
                uf.union(i, last[e][0])
            prev_ts = last[e][1] if e in last else a.last_ts
            last[e] = (i, max(a.last_ts, prev_ts))
    roots = [uf.find(pos[ix]) for ix in alerts.index]
    remap = {r: n for n, r in enumerate(dict.fromkeys(roots))}
    return pd.Series([remap[r] for r in roots], index=alerts.index)


def incident_entities(group: pd.DataFrame) -> dict:
    idx = asset_index()
    ips = set(group.src_ip) | set(group.dst_ip) | {t for ts in group.targets for t in ts}
    ips.discard("")
    internal = sorted(ip for ip in ips if is_internal(ip) and ip in idx)
    external = sorted(ip for ip in ips if not is_internal(ip))
    return {"internal": internal, "external": external, "users": sorted(set(group.user) - {""})}


def incident_title(group: pd.DataFrame, entities: dict) -> str:
    idx = asset_index()
    tactics = [t for t in KILL_CHAIN if t in set(group.tactic)]
    # Name the incident after the internal asset that appears most often.
    counts = pd.concat([group.src_ip, group.dst_ip]).value_counts()
    focus = next((ip for ip in counts.index if ip in idx and not idx[ip]["is_hub"]), None) or \
        next((ip for ip in counts.index if ip in idx), None)
    where = idx[focus]["hostname"] if focus else (entities["external"][0] if entities["external"] else "unknown")
    if len(set(tactics) - {"Anomaly"}) >= 3:
        kind = "Multi-stage attack"
    else:
        kind = group.rule_name.value_counts().index[0]
    return f"{kind} - {where} ({' > '.join(tactics)})"
