"""Detection rules over normalised network events, mapped to MITRE ATT&CK.

Thresholds come from settings (config.yaml / Settings page); names, tactics, techniques
and confidences come from rules.yaml. Rules fire once per key per minute while a
condition holds, so one attack produces many alerts - correlation turns them back
into incidents. Every alert carries the IDs of the events that triggered it.
"""
from __future__ import annotations

import re

import numpy as np
import pandas as pd

from .. import settings
from ..assets import home_nets
from ..intel import feeds

CONN_SOURCES = ["zeek_conn", "suricata_flow"]
FAILED = {"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR", "OTH"}
CVE_RE = re.compile(r"CVE[-_ ](\d{4})[-_ ](\d{4,7})", re.I)


def _alert(rule_id: str, rows: pd.DataFrame, key: str, description: str, src_ip="", dst_ip="", targets=None,
           user="", cve="", confidence=None) -> dict:
    meta = settings.rules()[rule_id]
    last = pd.Timestamp(rows.ts.max())
    return dict(alert_key=f"{rule_id}|{key}|{last.floor('min').isoformat()}", rule_id=rule_id, rule_name=meta["name"],
                tactic=meta["tactic"], technique=meta["technique"], ts=pd.Timestamp(rows.ts.min()), last_ts=last,
                src_ip=src_ip, dst_ip=dst_ip, targets=sorted(targets or [])[:50], user=user,
                confidence=float(confidence if confidence is not None else meta["confidence"]),
                description=description, evidence=[int(x) for x in rows.event_id.tolist()[-60:]], cve=cve)


def _sliding(df: pd.DataFrame, key_cols: list[str], value_col: str, window: str, threshold: int):
    """Yield (key, rows) once per minute in which the trailing window holds at least
    `threshold` distinct values of value_col for a key (two-pointer scan per group)."""
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
            yield (key if isinstance(key, tuple) else (key,)), g.iloc[left:right + 1]


def _in(series: pd.Series, home) -> pd.Series:
    return series.map(lambda x: x in home).astype(bool)


def detect_rules(events: pd.DataFrame) -> list[dict]:
    det = settings.section("detection")
    allow = set(settings.section("network")["allowlist_sources"])
    home = home_nets(events)
    ev = events[~events.src_ip.isin(allow)]
    conn = ev[ev.source.isin(CONN_SOURCES)]
    out: list[dict] = []

    # Port scan (many ports on few hosts) and host sweep (many hosts).
    sc = det["scan"]
    for (src,), rows in _sliding(conn, ["src_ip"], "dst_port", sc["window"], sc["distinct_ports"]):
        dsts = rows.dst_ip.unique()
        out.append(_alert("R-SCAN", rows, f"ports|{src}",
                          f"{src} probed {rows.dst_port.nunique()} distinct ports on {len(dsts)} host(s) within "
                          f"{sc['window']}; {rows.conn_state.isin(FAILED).mean():.0%} of attempts got no normal reply.",
                          src_ip=src, dst_ip=dsts[0] if len(dsts) == 1 else "", targets=list(dsts)))
    for (src,), rows in _sliding(conn, ["src_ip"], "dst_ip", sc["window"], sc["distinct_hosts"]):
        out.append(_alert("R-SCAN", rows, f"hosts|{src}",
                          f"{src} contacted {rows.dst_ip.nunique()} distinct hosts within {sc['window']} "
                          f"(ports {', '.join(map(str, sorted(rows.dst_port.unique())[:8]))}); "
                          f"{rows.conn_state.isin(FAILED).mean():.0%} of attempts got no normal reply.",
                          src_ip=src, targets=list(rows.dst_ip.unique())))

    # Brute force from connection logs: many TCP sessions to the same service.
    bf = det["bruteforce"]
    tcp = conn[(conn.proto == "tcp") & ~conn.service.isin(bf["ignore_services"])]
    for (src, dst, port), rows in _sliding(tcp, ["src_ip", "dst_ip", "dst_port"], "event_id", bf["window"], bf["attempts"]):
        out.append(_alert("R-BRUTE", rows, f"{src}|{dst}|{port}",
                          f"{len(rows)} connections from {src} to {dst}:{port} ({rows.service.iloc[-1] or 'unidentified service'}) "
                          f"within {bf['window']} (threshold {bf['attempts']}); median {rows.bytes_out.median():.0f} bytes "
                          f"sent per attempt.", src_ip=src, dst_ip=dst))

    # SSH authentication (Zeek ssh.log).
    ssh = ev[ev.source == "zeek_ssh"]
    sb = det["ssh_bruteforce"]
    fails = ssh[ssh.outcome == "failure"]
    for (src, dst), rows in _sliding(fails, ["src_ip", "dst_ip"], "event_id", sb["window"], sb["failures"]):
        out.append(_alert("R-SSH-BRUTE", rows, f"{src}|{dst}",
                          f"{len(rows)} failed SSH logins from {src} to {dst} within {sb['window']} "
                          f"(threshold {sb['failures']}).", src_ip=src, dst_ip=dst))
    if len(fails):
        win = pd.Timedelta(sb["window"]) * 6
        for _, r in ssh[ssh.outcome == "success"].iterrows():
            prior = fails[(fails.src_ip == r.src_ip) & (fails.dst_ip == r.dst_ip) & (fails.ts <= r.ts) & (fails.ts >= r.ts - win)]
            if len(prior) >= sb["failures"]:
                out.append(_alert("R-SSH-OK", pd.concat([prior.tail(20), r.to_frame().T]), f"{r.src_ip}|{r.dst_ip}",
                                  f"SSH login to {r.dst_ip} from {r.src_ip} succeeded after {len(prior)} failures in the "
                                  f"previous {win}.", src_ip=r.src_ip, dst_ip=r.dst_ip))

    # Lateral movement: an internal host fans out over admin protocols.
    lt = det["lateral"]
    lat = conn[conn.dst_port.isin(lt["ports"])]
    lat = lat[_in(lat.src_ip, home) & _in(lat.dst_ip, home)]
    for (src,), rows in _sliding(lat, ["src_ip"], "dst_ip", lt["window"], lt["distinct_hosts"]):
        out.append(_alert("R-LATERAL", rows, src,
                          f"{src} opened admin-protocol sessions (ports {', '.join(map(str, sorted(rows.dst_port.unique())))}) "
                          f"to {rows.dst_ip.nunique()} internal hosts within {lt['window']} (threshold {lt['distinct_hosts']}).",
                          src_ip=src, targets=list(rows.dst_ip.unique())))

    # Large outbound transfer from inside to outside.
    big = conn[conn.bytes_out >= det["exfil"]["bytes_per_conn"]]
    big = big[_in(big.src_ip, home) & ~_in(big.dst_ip, home)]
    for _, r in big.iterrows():
        out.append(_alert("R-EXFIL", r.to_frame().T, f"{r.src_ip}|{r.dst_ip}",
                          f"{r.src_ip} sent {r.bytes_out / 1024**2:,.0f} MB to external host {r.dst_ip}:{r.dst_port} in one "
                          f"connection.", src_ip=r.src_ip, dst_ip=r.dst_ip))

    # Live threat-intel match (either direction), one alert per pair per minute.
    ix = feeds.index()
    if len(ix):
        hits = {ip: ix.lookup(ip) for ip in set(ev.src_ip) | set(ev.dst_ip) if ip not in home}
        hits = {k: v for k, v in hits.items() if v}
        if hits:
            m = ev[ev.src_ip.isin(hits.keys()) | ev.dst_ip.isin(hits.keys())]
            for (src, dst), rows in m.groupby(["src_ip", "dst_ip"]):
                ind_ip = dst if dst in hits else src
                indicator, ctx = hits[ind_ip]
                for _, minute in rows.groupby(rows.ts.dt.floor("min")):
                    out.append(_alert("R-IOC", minute, f"{src}|{dst}",
                                      f"{len(minute)} {'outbound' if ind_ip == dst else 'inbound'} event(s) {src} -> {dst} "
                                      f"match live threat-intel indicator {indicator}: {ctx}.", src_ip=src, dst_ip=dst))

    # Suricata IDS alerts.
    base = settings.rules()["R-IDS"]["confidence"]
    for _, r in ev[ev.source == "suricata_alert"].iterrows():
        m = CVE_RE.search(r.signature or "")
        conf = min(0.95, max(0.2, base + {1: 0.2, 2: 0.0, 3: -0.2}.get(int(r.sig_severity), 0)))
        out.append(_alert("R-IDS", r.to_frame().T, f"{r.src_ip}|{r.dst_ip}|{r.signature_id}",
                          f"Suricata signature '{r.signature}' (sid {r.signature_id}, severity {r.sig_severity}, "
                          f"{r.category or 'uncategorised'}) fired for {r.src_ip} -> {r.dst_ip}:{r.dst_port}.",
                          src_ip=r.src_ip, dst_ip=r.dst_ip, cve=f"CVE-{m.group(1)}-{m.group(2)}" if m else "",
                          confidence=conf))
    return out
