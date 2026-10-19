"""Incident correlation - turns hundreds of alerts into a few cases, continuously.

Two alerts belong together when they share an entity (an IP that is not shared
infrastructure and not allow-listed) and occur within correlation.gap_minutes of each
other. Chains are followed transitively with union-find. New alerts can join an open
incident; if one alert links two open incidents, they are merged.
"""
from __future__ import annotations

import pandas as pd

from . import settings
from .assets import home_nets, index as asset_index, label

KILL_CHAIN = ["Reconnaissance", "Initial Access", "Credential Access", "Discovery", "Persistence", "Privilege Escalation",
              "Defense Evasion", "Command and Control", "Lateral Movement", "Exfiltration", "Anomaly"]


def alert_entities(a) -> set[str]:
    idx = asset_index()
    allow = set(settings.section("network")["allowlist_sources"])
    return {ip for ip in (a["src_ip"], a["dst_ip"]) if ip and ip not in allow and not idx.get(ip, {}).get("is_hub")}


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


def correlate(new_alerts: pd.DataFrame, open_incidents: list[dict]) -> tuple[pd.Series, dict]:
    """Assign each new alert a group. Returns (group per alert, {group: [existing incident ids]}).
    Groups that touch existing incidents should be attached to them (several = merge)."""
    gap = pd.Timedelta(minutes=settings.section("correlation")["gap_minutes"])
    n_inc = len(open_incidents)
    uf = _UF(n_inc + len(new_alerts))
    last: dict[str, tuple[int, pd.Timestamp]] = {}
    for i, inc in enumerate(open_incidents):
        for e in inc["entities"].get("links", []):
            if e not in last or inc["last_seen"] > last[e][1]:
                last[e] = (i, inc["last_seen"])
    pos = {ix: n_inc + k for k, ix in enumerate(new_alerts.index)}
    for ix in new_alerts.sort_values("ts").index:
        a = new_alerts.loc[ix]
        i = pos[ix]
        for e in alert_entities(a):
            if e in last and a.ts - last[e][1] <= gap:
                uf.union(i, last[e][0])
            last[e] = (i, max(a.last_ts, last[e][1]) if e in last else a.last_ts)
    groups = pd.Series({ix: uf.find(pos[ix]) for ix in new_alerts.index}, dtype="int64")
    attach: dict[int, list[str]] = {}
    for i, inc in enumerate(open_incidents):
        attach.setdefault(uf.find(i), []).append(inc["incident_id"])
    return groups, {g: attach.get(g, []) for g in groups.unique()}


def incident_entities(group: pd.DataFrame) -> dict:
    home = home_nets()
    ips = set(group.src_ip) | set(group.dst_ip) | {t for ts in group.targets for t in ts}
    ips.discard("")
    links = set()
    for _, a in group.iterrows():
        links |= alert_entities(a)
    return {"internal": sorted(ip for ip in ips if ip in home), "external": sorted(ip for ip in ips if ip not in home),
            "users": sorted(set(group.user) - {""}), "links": sorted(links)}


def incident_title(group: pd.DataFrame, entities: dict) -> str:
    idx = asset_index()
    tactics = [t for t in KILL_CHAIN if t in set(group.tactic)]
    counts = pd.concat([group.src_ip, group.dst_ip]).value_counts()
    counts = counts[counts.index != ""]
    focus = next((ip for ip in counts.index if ip in entities["internal"] and not idx.get(ip, {}).get("is_hub")), None) \
        or (counts.index[0] if len(counts) else "unknown")
    real = set(tactics) - {"Anomaly"}
    kind = "Multi-stage attack" if len(real) >= 3 else group.rule_name.value_counts().index[0]
    return f"{kind} - {label(focus)} ({' > '.join(tactics)})"
