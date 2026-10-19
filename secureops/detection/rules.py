"""Signature / threshold detection rules mapped to MITRE ATT&CK.

Like a real SIEM, rules fire per event or per minute while a condition holds, so a
single attack produces many duplicate alerts. Correlation (correlation.py) is what
turns them back into a handful of incidents.
"""
from __future__ import annotations

import re

import numpy as np
import pandas as pd

from ..assets import is_internal
from ..config import ALLOWLIST_SOURCES, THRESHOLDS
from ..simulate import THREAT_INTEL

LATERAL_PORTS = {445, 3389, 5985, 135, 22}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def _alert(rule_id, rule_name, tactic, technique, rows: pd.DataFrame, confidence, description,
           src_ip="", dst_ip="", targets=None, user="", cve=""):
    return dict(rule_id=rule_id, rule_name=rule_name, tactic=tactic, technique=technique,
                ts=rows.ts.min(), last_ts=rows.ts.max(), src_ip=src_ip, dst_ip=dst_ip,
                targets=sorted(targets or []), user=user, confidence=float(confidence),
                description=description, evidence=[int(x) for x in rows.event_id.tolist()[:60]], cve=cve)


def _sliding(df: pd.DataFrame, key_cols: list[str], value_col: str, window: str, threshold: int):
    """Yield (key, rows) for every minute in which the trailing `window` holds at least
    `threshold` distinct values of `value_col` for a key. Two-pointer scan per group."""
    win = np.timedelta64(pd.Timedelta(window))
    for key, g in df.groupby(key_cols, sort=False):
        if g[value_col].nunique() < threshold:
            continue
        g = g.sort_values("ts")
        ts = g.ts.values
        vals = g[value_col].tolist()
        counts: dict = {}
        left = 0
        buckets: dict = {}
        for right in range(len(g)):
            counts[vals[right]] = counts.get(vals[right], 0) + 1
            while ts[right] - ts[left] > win:
                counts[vals[left]] -= 1
                if not counts[vals[left]]:
                    del counts[vals[left]]
                left += 1
            if len(counts) >= threshold:
                buckets[ts[right].astype("datetime64[m]")] = (left, right)
        for left, right in buckets.values():
            yield key, g.iloc[left:right + 1]


def detect_rules(events: pd.DataFrame) -> list[dict]:
    ev = events[~events.src_ip.isin(ALLOWLIST_SOURCES)]
    alerts: list[dict] = []
    conn = ev[ev.source == "zeek_conn"]
    auth = ev[ev.source == "auth"]
    fails = auth[auth.outcome == "failure"]

    # 1. Threat-intel indicator match (per event).
    ioc = ev[ev.dst_ip.isin(THREAT_INTEL.keys()) | ev.src_ip.isin(THREAT_INTEL.keys())]
    for _, r in ioc.iterrows():
        outbound = r.dst_ip in THREAT_INTEL
        ind = r.dst_ip if outbound else r.src_ip
        alerts.append(_alert(
            "R-IOC", "Threat-intel indicator match",
            "Command and Control" if outbound else "Reconnaissance",
            "T1071.001 Web Protocols" if outbound else "T1595 Active Scanning",
            r.to_frame().T, 0.9,
            f"{'Outbound' if outbound else 'Inbound'} {r.source} event {r.src_ip} -> {r.dst_ip}:{r.dst_port} "
            f"matches indicator {ind}: {THREAT_INTEL[ind]}.",
            src_ip=r.src_ip, dst_ip=r.dst_ip))

    # 2. IDS signatures (per event).
    for _, r in ev[(ev.source == "suricata") & (ev.sig_severity > 0)].iterrows():
        m = CVE_RE.search(r.signature)
        alerts.append(_alert(
            "R-IDS", "IDS exploit signature", "Initial Access", "T1190 Exploit Public-Facing Application",
            r.to_frame().T, 0.8 if r.sig_severity == 1 else 0.5,
            f"Suricata signature '{r.signature}' fired for {r.src_ip} -> {r.dst_ip}:{r.dst_port}.",
            src_ip=r.src_ip, dst_ip=r.dst_ip, cve=m.group(0) if m else ""))

    # 3. Brute force: many failures from one source to one target.
    thr = THRESHOLDS["brute_force_failures_5m"]
    for (src, dst), rows in _sliding(fails, ["src_ip", "dst_ip"], "event_id", "5min", thr):
        alerts.append(_alert(
            "R-BRUTE", "Brute-force authentication", "Credential Access", "T1110.001 Password Guessing",
            rows, 0.6, f"{len(rows)} failed {rows.service.iloc[0]} logins from {src} to {dst} within 5 minutes "
                       f"(threshold {thr}); users tried: {', '.join(sorted(rows.user.unique())[:6])}.",
            src_ip=src, dst_ip=dst))

    # 4. Success after brute force.
    if len(fails):
        fail_ts = {k: g.ts.sort_values().values for k, g in fails.groupby(["src_ip", "dst_ip"])}
        for _, r in auth[auth.outcome == "success"].iterrows():
            arr = fail_ts.get((r.src_ip, r.dst_ip))
            if arr is None:
                continue
            t = np.datetime64(r.ts.tz_convert(None))
            n = np.searchsorted(arr, t) - np.searchsorted(arr, t - np.timedelta64(30, "m"))
            if n >= thr:
                prior = fails[(fails.src_ip == r.src_ip) & (fails.dst_ip == r.dst_ip) & (fails.ts <= r.ts)
                              & (fails.ts >= r.ts - pd.Timedelta("30min"))].tail(20)
                alerts.append(_alert(
                    "R-BRUTE-OK", "Successful login after brute force", "Initial Access", "T1078 Valid Accounts",
                    pd.concat([prior, r.to_frame().T]), 0.85,
                    f"Account '{r.user}' logged in to {r.dst_ip} via {r.service} from {r.src_ip} "
                    f"after {n} failed attempts in the previous 30 minutes.",
                    src_ip=r.src_ip, dst_ip=r.dst_ip, user=r.user))

    # 5. Password spray: one source, many different accounts.
    thr_s = THRESHOLDS["spray_distinct_users_10m"]
    for src, rows in _sliding(fails, ["src_ip"], "user", "10min", thr_s):
        src = src[0] if isinstance(src, tuple) else src
        alerts.append(_alert(
            "R-SPRAY", "Password spray", "Credential Access", "T1110.003 Password Spraying",
            rows, 0.7, f"{rows.user.nunique()} different accounts failed to log in from {src} within 10 minutes "
                       f"(threshold {thr_s}).", src_ip=src, dst_ip=rows.dst_ip.mode().iloc[0]))

    # 6. Port scan.
    thr_p = THRESHOLDS["scan_distinct_ports_1m"]
    for src, rows in _sliding(conn, ["src_ip"], "dst_port", "1min", thr_p):
        src = src[0] if isinstance(src, tuple) else src
        internal = is_internal(src)
        dsts = rows.dst_ip.unique()
        alerts.append(_alert(
            "R-SCAN", "Port scan", "Discovery" if internal else "Reconnaissance",
            "T1046 Network Service Discovery" if internal else "T1595.001 Scanning IP Blocks",
            rows, 0.5, f"{src} probed {rows.dst_port.nunique()} distinct ports on {len(dsts)} host(s) within one minute; "
                       f"{(rows.conn_state == 'REJ').mean():.0%} of connections were rejected.",
            src_ip=src, dst_ip=dsts[0] if len(dsts) == 1 else "", targets=list(dsts)))

    # 7. Lateral movement: internal host fans out over admin protocols.
    lat = conn[conn.dst_port.isin(LATERAL_PORTS) & conn.src_ip.map(is_internal).astype(bool) & conn.dst_ip.map(is_internal).astype(bool)]
    thr_l = THRESHOLDS["lateral_distinct_hosts_10m"]
    for src, rows in _sliding(lat, ["src_ip"], "dst_ip", "10min", thr_l):
        src = src[0] if isinstance(src, tuple) else src
        alerts.append(_alert(
            "R-LATERAL", "Lateral movement fan-out", "Lateral Movement", "T1021.002 SMB/Windows Admin Shares",
            rows, 0.75, f"{src} opened admin-protocol sessions (ports {', '.join(str(int(x)) for x in sorted(rows.dst_port.unique()))}) to "
                        f"{rows.dst_ip.nunique()} internal hosts within 10 minutes (threshold {thr_l}).",
            src_ip=src, targets=list(rows.dst_ip.unique())))

    # 8. Large outbound transfer.
    big = conn[(conn.bytes_out >= THRESHOLDS["exfil_bytes_per_conn"]) & conn.src_ip.map(is_internal).astype(bool)
               & ~conn.dst_ip.map(is_internal).astype(bool)]
    for _, r in big.iterrows():
        to_ioc = r.dst_ip in THREAT_INTEL
        alerts.append(_alert(
            "R-EXFIL", "Large outbound data transfer", "Exfiltration",
            "T1041 Exfiltration Over C2 Channel" if to_ioc else "T1048 Exfiltration Over Alternative Protocol",
            r.to_frame().T, 0.9 if to_ioc else 0.6,
            f"{r.src_ip} sent {r.bytes_out / 1024**2:,.0f} MB to external host {r.dst_ip}:{r.dst_port} in one "
            f"connection ({'a known C2 indicator' if to_ioc else 'not on any threat-intel list'}).",
            src_ip=r.src_ip, dst_ip=r.dst_ip))
    return alerts
