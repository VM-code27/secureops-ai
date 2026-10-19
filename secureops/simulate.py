"""Controlled-lab log generator.

Produces normalised Zeek-style connection logs, Suricata-style IDS alerts and
authentication logs for the 500-device network in `assets.py`.

* `historical_dataset(seed)`  - 48 h of LABELLED traffic: benign baseline, realistic
  false-positive sources, and 7 attack campaigns (two of them deliberately hard).
* `live_scenario(kind, ...)`  - fresh, UNLABELLED events stamped "now" for the demo.

All external addresses come from the RFC 5737 documentation ranges, so no real
third-party IP is ever named as an attacker.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd

from .assets import build_assets

T0 = datetime(2026, 10, 5, tzinfo=timezone.utc)
HOURS = 48

COLUMNS = ["ts", "source", "src_ip", "dst_ip", "dst_port", "proto", "service", "conn_state",
           "bytes_out", "bytes_in", "duration", "user", "outcome", "signature", "sig_severity",
           "label", "campaign"]

THREAT_INTEL = {  # indicator -> context (simulated threat-intel feed)
    "203.0.113.99": "Known C2 server (simulated feed: botnet controller)",
    "203.0.113.45": "Known SSH brute-force source (simulated feed)",
    "203.0.113.7": "Known phishing host (simulated feed)",
    "198.51.100.9": "Known malware distribution (simulated feed)",
}

ATTACKER_IPS = {"203.0.113.66", "203.0.113.99", "203.0.113.45", "198.51.100.77", "192.0.2.150",
                "203.0.113.200", "203.0.113.12", "198.51.100.180", "198.51.100.200", "198.51.100.33"}
ATTACKER_IPS |= set(THREAT_INTEL)

CAMPAIGNS = {
    "C1": "Multi-stage intrusion (scan > exploit > C2 > lateral > exfil)",
    "C2": "SSH brute force leading to account compromise",
    "C3": "VPN password spray",
    "C4": "IoT camera exploitation and botnet C2",
    "C5": "Low-and-slow port scan (hard)",
    "C6": "Slow data exfiltration over HTTPS (hard)",
    "C7": "Valid-account misuse with stolen credentials (hard)",
}


def _external_pool() -> list[str]:
    pool = [f"{p}.{i}" for p in ("198.51.100", "192.0.2", "203.0.113") for i in range(1, 255)]
    return [ip for ip in pool if ip not in ATTACKER_IPS]


def _ev(ts, source="zeek_conn", src_ip="", dst_ip="", dst_port=0, proto="tcp", service="",
        conn_state="SF", bytes_out=0, bytes_in=0, duration=0.0, user="", outcome="",
        signature="", sig_severity=0, label="benign", campaign=""):
    return dict(ts=ts, source=source, src_ip=src_ip, dst_ip=dst_ip, dst_port=int(dst_port), proto=proto,
                service=service, conn_state=conn_state, bytes_out=int(bytes_out), bytes_in=int(bytes_in),
                duration=float(duration), user=user, outcome=outcome, signature=signature,
                sig_severity=int(sig_severity), label=label, campaign=campaign)


# --------------------------------------------------------------------------- benign
def _benign(rng: np.random.Generator, t0: datetime, hours: int) -> list[dict]:
    assets = build_assets()
    ws = assets[assets.type == "workstation"]
    iot = assets[assets.type == "iot"]
    ext = _external_pool()
    internal_services = [("10.10.1.21", 445, "smb"), ("10.10.1.15", 443, "https"), ("10.10.1.16", 443, "https"),
                         ("10.10.1.43", 443, "https"), ("10.10.1.11", 443, "https")]
    ev = []
    for h in range(hours):
        base = t0 + timedelta(hours=h)
        hod = base.hour
        business = 8 <= hod < 18
        n = rng.poisson(800 if business else 60)
        srcs = ws.sample(n=n, replace=True, random_state=int(rng.integers(1 << 31)))
        offs = rng.uniform(0, 3600, n)
        kind = rng.random(n)
        for (_, a), off, k in zip(srcs.iterrows(), offs, kind):
            ts = base + timedelta(seconds=float(off))
            if k < 0.60:
                port = 443 if rng.random() < 0.9 else 80
                ev.append(_ev(ts, src_ip=a.ip, dst_ip=ext[rng.integers(len(ext))], dst_port=port,
                              service="https" if port == 443 else "http",
                              bytes_out=rng.lognormal(7.6, 1.0), bytes_in=rng.lognormal(10.6, 1.2),
                              duration=rng.exponential(2)))
            elif k < 0.85:
                ip, port, svc = internal_services[rng.integers(len(internal_services))]
                ev.append(_ev(ts, src_ip=a.ip, dst_ip=ip, dst_port=port, service=svc,
                              bytes_out=rng.lognormal(8, 1.0), bytes_in=rng.lognormal(10, 1.2),
                              duration=rng.exponential(3)))
            else:
                ev.append(_ev(ts, src_ip=a.ip, dst_ip="10.10.1.2", dst_port=53, proto="udp", service="dns",
                              bytes_out=rng.integers(40, 90), bytes_in=rng.integers(80, 300), duration=0.01))
        # Public web servers receive client traffic.
        for _ in range(rng.poisson(35 if business else 10)):
            ev.append(_ev(base + timedelta(seconds=float(rng.uniform(0, 3600))), src_ip=ext[rng.integers(len(ext))],
                          dst_ip=["10.10.1.10", "10.10.1.11"][rng.integers(2)], dst_port=443, service="https",
                          bytes_out=rng.lognormal(7, 0.8), bytes_in=rng.lognormal(10, 1)))
        # App server polls the database every 5 minutes.
        for m in range(0, 60, 5):
            ev.append(_ev(base + timedelta(minutes=m, seconds=float(rng.uniform(0, 5))), src_ip="10.10.1.12",
                          dst_ip="10.10.1.30", dst_port=5432, service="postgresql",
                          bytes_out=rng.integers(500, 3000), bytes_in=rng.integers(2000, 50000)))
        # IoT heartbeats every 30 minutes.
        for half in (0, 1800):
            for ip in iot.ip:
                ev.append(_ev(base + timedelta(seconds=half + float(rng.uniform(0, 120))), src_ip=ip,
                              dst_ip="10.10.1.40", dst_port=8883, service="mqtt",
                              bytes_out=rng.integers(200, 600), bytes_in=rng.integers(100, 300)))
        # Nightly backup: internal pull, then a large offsite upload (a classic false positive).
        if hod == 1:
            ev.append(_ev(base + timedelta(minutes=2), src_ip="10.10.1.20", dst_ip="10.10.1.21", dst_port=445,
                          service="smb", bytes_out=5e5, bytes_in=rng.uniform(1.2e9, 1.6e9), duration=900))
            ev.append(_ev(base + timedelta(minutes=20), src_ip="10.10.1.20", dst_ip="198.51.100.200", dst_port=443,
                          service="https", bytes_out=rng.uniform(1.4e9, 2.0e9), bytes_in=2e6, duration=1500))
        # Morning logons against the domain controller.
        if hod == 8:
            for _, a in ws.iterrows():
                ts = base + timedelta(seconds=float(rng.uniform(0, 3600)))
                for f in range(rng.choice([0, 0, 0, 0, 0, 0, 0, 0, 1, 2])):
                    ev.append(_ev(ts - timedelta(seconds=20 * (f + 1)), source="auth", src_ip=a.ip, dst_ip="10.10.1.3",
                                  dst_port=88, service="kerberos", user=a.user, outcome="failure"))
                ev.append(_ev(ts, source="auth", src_ip=a.ip, dst_ip="10.10.1.3", dst_port=88,
                              service="kerberos", user=a.user, outcome="success"))
            # Remote staff connect to the VPN.
            for i in range(60):
                ev.append(_ev(base + timedelta(seconds=float(rng.uniform(0, 3600))), source="auth",
                              src_ip=ext[rng.integers(len(ext))], dst_ip="10.10.1.5", dst_port=443,
                              service="vpn", user=f"user{rng.integers(1, 381):04d}", outcome="success"))
        # Admins use SSH from the jump host.
        if business and rng.random() < 0.3:
            ev.append(_ev(base + timedelta(minutes=float(rng.uniform(0, 60))), source="auth", src_ip="10.10.1.43",
                          dst_ip="10.10.1.30", dst_port=22, service="ssh", user="dbadmin", outcome="success"))
    return ev


def _benign_noise_makers(t0: datetime) -> list[dict]:
    """Benign activity that LOOKS malicious - the realistic false-positive sources."""
    ev = []
    # A user fat-fingers their password 12 times in 3 minutes, then gets it right.
    t = t0 + timedelta(hours=33, minutes=5)
    for i in range(12):
        ev.append(_ev(t + timedelta(seconds=15 * i), source="auth", src_ip="10.10.2.42", dst_ip="10.10.1.3",
                      dst_port=88, service="kerberos", user="user0042", outcome="failure"))
    ev.append(_ev(t + timedelta(seconds=200), source="auth", src_ip="10.10.2.42", dst_ip="10.10.1.3",
                  dst_port=88, service="kerberos", user="user0042", outcome="success"))
    # Authorised weekly vulnerability scan (allow-listed in config.ALLOWLIST_SOURCES).
    t = t0 + timedelta(hours=27)
    rng = np.random.default_rng(7)
    for i in range(1500):
        port = int(rng.integers(1, 1025))
        ev.append(_ev(t + timedelta(seconds=i * 0.4), src_ip="10.10.1.250", dst_ip=f"10.10.1.{rng.integers(1, 44)}",
                      dst_port=port, conn_state="REJ" if port not in (22, 80, 443, 445) else "SF",
                      bytes_out=60, bytes_in=40))
    return ev


# ------------------------------------------------------------------------- attacks
def _c1_multistage(rng, t, attacker="203.0.113.66", target="10.10.1.10", c2="203.0.113.99",
                   label=CAMPAIGNS["C1"], camp="C1", beacon_minutes=180, beacon_every=60.0):
    ev = []
    ports = rng.choice(np.arange(1, 1025), size=200, replace=False)
    for i, p in enumerate(ports):
        ev.append(_ev(t + timedelta(seconds=i * 0.45), src_ip=attacker, dst_ip=target, dst_port=p,
                      conn_state="SF" if p in (80, 443) else "REJ", bytes_out=60, bytes_in=40, label=label, campaign=camp))
    t2 = t + timedelta(minutes=5)
    for i in range(8):
        ev.append(_ev(t2 + timedelta(seconds=20 * i), source="suricata", src_ip=attacker, dst_ip=target, dst_port=80,
                      service="http", signature="ET EXPLOIT Apache HTTP Server 2.4.49 Path Traversal (CVE-2021-41773)",
                      sig_severity=1, label=label, campaign=camp))
    t3 = t + timedelta(minutes=10)
    n_beacons = int(beacon_minutes * 60 / beacon_every)
    for i in range(n_beacons):
        ev.append(_ev(t3 + timedelta(seconds=i * beacon_every + float(rng.normal(0, beacon_every / 12))), src_ip=target,
                      dst_ip=c2, dst_port=443, service="https", bytes_out=rng.integers(300, 600),
                      bytes_in=rng.integers(200, 400), duration=0.3, label=label, campaign=camp))
    t4 = t3 + timedelta(seconds=n_beacons * beacon_every * 0.45)
    victims = [f"10.10.2.{i}" for i in rng.choice(np.arange(1, 255), 20, replace=False)] + \
              ["10.10.1.21", "10.10.1.30", "10.10.1.31", "10.10.1.15", "10.10.1.12"]
    for i, v in enumerate(victims):
        ev.append(_ev(t4 + timedelta(seconds=i * 9), src_ip=target, dst_ip=v, dst_port=445, service="smb",
                      conn_state="SF" if i % 3 else "S0", bytes_out=rng.integers(2000, 9000),
                      bytes_in=rng.integers(1000, 5000), label=label, campaign=camp))
    t5 = t3 + timedelta(seconds=n_beacons * beacon_every * 0.9)
    ev.append(_ev(t5, src_ip=target, dst_ip=c2, dst_port=443, service="https", bytes_out=rng.uniform(7e8, 9e8),
                  bytes_in=3e5, duration=600, label=label, campaign=camp))
    return ev


def _c2_bruteforce(rng, t, attacker="203.0.113.45", target="10.10.1.30", label=CAMPAIGNS["C2"], camp="C2", n=80):
    ev = []
    users = ["root", "admin", "oracle", "postgres", "ubuntu"]
    for i in range(n):
        ev.append(_ev(t + timedelta(seconds=i * 6), source="auth", src_ip=attacker, dst_ip=target, dst_port=22,
                      service="ssh", user=users[rng.integers(len(users))], outcome="failure", label=label, campaign=camp))
    ts = t + timedelta(seconds=n * 6 + 10)
    ev.append(_ev(ts, source="auth", src_ip=attacker, dst_ip=target, dst_port=22, service="ssh", user="oracle",
                  outcome="success", label=label, campaign=camp))
    ev.append(_ev(ts + timedelta(seconds=5), src_ip=attacker, dst_ip=target, dst_port=22, service="ssh",
                  bytes_out=rng.integers(20000, 60000), bytes_in=rng.integers(1e5, 5e5), duration=420,
                  label=label, campaign=camp))
    return ev


def _c3_spray(rng, t, attacker="198.51.100.77", target="10.10.1.5", label=CAMPAIGNS["C3"], camp="C3", n=40):
    users = rng.choice(np.arange(1, 381), n, replace=False)
    return [_ev(t + timedelta(seconds=30 * i), source="auth", src_ip=attacker, dst_ip=target, dst_port=443,
                service="vpn", user=f"user{u:04d}", outcome="failure", label=label, campaign=camp)
            for i, u in enumerate(users)]


def _c4_iot(rng, t, attacker="192.0.2.150", cam="10.10.4.17", c2="203.0.113.200", label=CAMPAIGNS["C4"],
            camp="C4", minutes=115, every=120):
    ev = [_ev(t + timedelta(seconds=10 * i), source="suricata", src_ip=attacker, dst_ip=cam, dst_port=80,
              service="http", signature="ET EXPLOIT Hikvision IP Camera Command Injection (CVE-2021-36260)",
              sig_severity=1, label=label, campaign=camp) for i in range(3)]
    for i in range(int(minutes * 60 / every)):
        ev.append(_ev(t + timedelta(minutes=5, seconds=i * every + float(rng.uniform(-5, 5))), src_ip=cam, dst_ip=c2,
                      dst_port=6667, service="irc", bytes_out=rng.integers(100, 400), bytes_in=rng.integers(50, 900),
                      duration=1.2, label=label, campaign=camp))
    return ev


def _c5_slow_scan(rng, t, attacker="203.0.113.12"):
    ev = []
    for i in range(360):
        ev.append(_ev(t + timedelta(seconds=i * 240 + float(rng.uniform(-60, 60))), src_ip=attacker,
                      dst_ip=f"10.10.1.{rng.integers(1, 44)}", dst_port=int(rng.integers(1, 65536)), conn_state="REJ",
                      bytes_out=60, bytes_in=40, label=CAMPAIGNS["C5"], campaign="C5"))
    return ev


def _c6_slow_exfil(rng, t0, src="10.10.2.44", dst="198.51.100.180"):
    ev = []
    for day in (0, 1):
        for h in range(9, 17):
            ev.append(_ev(t0 + timedelta(days=day, hours=h, minutes=float(rng.uniform(0, 50))), src_ip=src, dst_ip=dst,
                          dst_port=443, service="https", bytes_out=rng.uniform(3e6, 5e6), bytes_in=rng.uniform(5e3, 2e4),
                          duration=rng.uniform(20, 60), label=CAMPAIGNS["C6"], campaign="C6"))
    return ev


def _c7_valid_account(rng, t, attacker="198.51.100.33"):
    label, camp = CAMPAIGNS["C7"], "C7"
    ev = [_ev(t, source="auth", src_ip=attacker, dst_ip="10.10.1.5", dst_port=443, service="vpn", user="user0117",
              outcome="success", label=label, campaign=camp)]
    for i in range(5):
        ev.append(_ev(t + timedelta(minutes=3 + i * 7), src_ip=attacker, dst_ip="10.10.1.21", dst_port=445,
                      service="smb", bytes_out=rng.integers(2000, 8000), bytes_in=rng.uniform(2e6, 6e6),
                      duration=30, label=label, campaign=camp))
    return ev


def _finalise(rows: list[dict], dataset: str, start_id: int = 1) -> pd.DataFrame:
    df = pd.DataFrame(rows, columns=COLUMNS)
    df["ts"] = pd.to_datetime(df["ts"], utc=True)
    df = df.sort_values("ts", kind="stable").reset_index(drop=True)
    df.insert(0, "event_id", np.arange(start_id, start_id + len(df)))
    df["dataset"] = dataset
    return df


def historical_dataset(seed: int = 42, dataset: str = "historical_labeled") -> pd.DataFrame:
    """48 hours of labelled lab traffic. Different seeds give different-but-similar data
    (used to keep a held-out test set separate from the data thresholds were tuned on)."""
    rng = np.random.default_rng(seed)
    jitter = lambda: timedelta(minutes=float(rng.uniform(-90, 90)))  # noqa: E731
    rows = _benign(rng, T0, HOURS) + _benign_noise_makers(T0)
    rows += _c1_multistage(rng, T0 + timedelta(hours=14) + jitter())
    rows += _c2_bruteforce(rng, T0 + timedelta(hours=22) + jitter())
    rows += _c3_spray(rng, T0 + timedelta(hours=33, minutes=30) + jitter())
    rows += _c4_iot(rng, T0 + timedelta(hours=27) + jitter())
    rows += _c5_slow_scan(rng, T0 + timedelta(hours=6) + jitter())
    rows += _c6_slow_exfil(rng, T0)
    rows += _c7_valid_account(rng, T0 + timedelta(hours=34, minutes=10) + jitter())
    return _finalise(rows, dataset)


# ---------------------------------------------------------------------------- live
LIVE_SCENARIOS = {
    "Multi-stage intrusion on a web server": "multistage",
    "SSH brute force against a database": "bruteforce",
    "VPN password spray": "spray",
    "IoT camera hijack": "iot",
}


def live_scenario(kind: str, start_id: int, now: datetime | None = None, seed: int | None = None) -> pd.DataFrame:
    """Fresh UNLABELLED events for the live demo (labels are stripped before storage)."""
    rng = np.random.default_rng(seed)
    now = now or datetime.now(timezone.utc)
    t = now - timedelta(minutes=12)
    a = f"203.0.113.{rng.integers(120, 199)}"
    if kind == "multistage":
        rows = _c1_multistage(rng, t, attacker=a, target="10.10.1.10", c2="203.0.113.99", beacon_minutes=6, beacon_every=10)
    elif kind == "bruteforce":
        rows = _c2_bruteforce(rng, t, attacker=a, target="10.10.1.30", n=60)
    elif kind == "spray":
        rows = _c3_spray(rng, t, attacker=a, n=25)
    elif kind == "iot":
        rows = _c4_iot(rng, t, attacker=a, cam="10.10.4.17", c2=f"198.51.100.{rng.integers(120, 199)}", minutes=8, every=20)
    else:
        raise ValueError(f"unknown scenario {kind}")
    ws = build_assets().query("type == 'workstation'").ip.tolist()
    ext = _external_pool()
    for _ in range(60):  # a little benign background traffic in the same window
        rows.append(_ev(t + timedelta(seconds=float(rng.uniform(0, 720))), src_ip=ws[rng.integers(len(ws))],
                        dst_ip=ext[rng.integers(len(ext))], dst_port=443, service="https",
                        bytes_out=rng.lognormal(7.6, 1), bytes_in=rng.lognormal(10.6, 1.2)))
    df = _finalise(rows, "live_unlabeled", start_id)
    df["label"] = None
    df["campaign"] = None
    return df
