"""Simulated enterprise asset inventory: 500 devices (servers, workstations, IoT).

Each asset carries a business criticality (1-5), installed software and the CVEs
that software is exposed to (CVE details come from the NVD cache).
"""
from __future__ import annotations

import ipaddress
from functools import lru_cache

import numpy as np
import pandas as pd

from .nvd import TRACKED_CVES, load_cves

# ip, hostname, role, criticality, software, is_hub (shared infrastructure that
# every host talks to - never used to link unrelated alerts together)
SERVERS = [
    ("10.10.1.1", "core-rtr-01", "Core router", 5, ["Cisco IOS XE 17.9"], True),
    ("10.10.1.2", "dns-01", "DNS resolver", 4, ["BIND 9.18"], True),
    ("10.10.1.3", "dc-01", "Domain controller", 5, ["Windows Server 2022"], True),
    ("10.10.1.4", "fw-01", "Perimeter firewall", 5, ["Palo Alto PAN-OS 11.1"], True),
    ("10.10.1.5", "vpn-gw-01", "VPN gateway", 5, ["OpenVPN Access Server 2.12"], True),
    ("10.10.1.10", "web-srv-01", "Public web server", 4, ["Apache HTTP Server 2.4.49"], False),
    ("10.10.1.11", "web-srv-02", "Public web server", 4, ["Apache HTTP Server 2.4.62"], False),
    ("10.10.1.12", "app-srv-01", "Customer portal backend", 4, ["Apache Log4j 2.14.1"], False),
    ("10.10.1.15", "mail-01", "Mail server", 4, ["Microsoft Exchange 2019 CU9"], False),
    ("10.10.1.16", "wiki-01", "Internal wiki", 3, ["Atlassian Confluence 8.0.0"], False),
    ("10.10.1.20", "backup-01", "Backup server", 4, ["Veeam 12"], False),
    ("10.10.1.21", "file-01", "File server", 4, ["Windows SMBv1"], False),
    ("10.10.1.22", "mft-01", "Managed file transfer", 4, ["Progress MOVEit Transfer 2023.0"], False),
    ("10.10.1.30", "db-srv-01", "Customer database", 5, ["PostgreSQL 15", "OpenSSH 8.5p1"], False),
    ("10.10.1.31", "db-srv-02", "Analytics database", 4, ["PostgreSQL 16", "OpenSSH 9.8p1"], False),
    ("10.10.1.40", "mqtt-01", "IoT message broker", 3, ["Mosquitto 2.0"], True),
    ("10.10.1.41", "ci-01", "CI server", 3, ["Jenkins 2.462"], False),
    ("10.10.1.42", "monitor-01", "Monitoring", 3, ["Zabbix 7.0"], False),
    ("10.10.1.43", "hr-app-01", "HR application", 4, ["Workday connector"], False),
    ("10.10.1.250", "vuln-scanner-01", "Authorised vulnerability scanner", 2, ["Nessus 10"], False),
]

DEPARTMENTS = ["Finance", "Engineering", "HR", "Sales", "Operations", "Legal"]
IOT_TYPES = [("camera", 40, 2), ("printer", 20, 1), ("badge-reader", 20, 3), ("hvac-sensor", 20, 1)]
VULNERABLE_CAMERAS = {17, 3, 8, 21, 26, 30, 33, 36}  # 10.10.4.x running old Hikvision firmware


def _cves_for(software: list[str]) -> list[str]:
    return [c for s in software for c in TRACKED_CVES.get(s, [])]


@lru_cache(maxsize=1)
def build_assets(seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    for ip, host, role, crit, sw, hub in SERVERS:
        rows.append(dict(ip=ip, hostname=host, type="server", role=role, department="IT",
                         criticality=crit, software=sw, is_hub=hub))
    ws_ips = [f"10.10.2.{i}" for i in range(1, 255)] + [f"10.10.3.{i}" for i in range(1, 127)]
    for n, ip in enumerate(ws_ips, start=1):
        dept = DEPARTMENTS[rng.integers(len(DEPARTMENTS))]
        chrome = "Google Chrome 116" if rng.random() < 0.3 else "Google Chrome 129"
        rows.append(dict(ip=ip, hostname=f"ws-{n:04d}", type="workstation", role=f"{dept} workstation",
                         department=dept, criticality=3 if dept in ("Finance", "Legal", "HR") else 2,
                         software=["Windows 11 23H2", chrome], is_hub=False, user=f"user{n:04d}"))
    octet = 1
    for kind, count, crit in IOT_TYPES:
        for _ in range(count):
            sw = [f"{kind} firmware"]
            if kind == "camera":
                sw = ["Hikvision IP Camera firmware 5.5" if octet in VULNERABLE_CAMERAS else "Hikvision IP Camera firmware 5.7"]
            rows.append(dict(ip=f"10.10.4.{octet}", hostname=f"{kind}-{octet:03d}", type="iot", role=kind,
                             department="Facilities", criticality=crit, software=sw, is_hub=False))
            octet += 1
    df = pd.DataFrame(rows)
    df["user"] = df.get("user").fillna("")
    df["cves"] = df["software"].apply(_cves_for)
    cvss = load_cves()
    df["max_cvss"] = df["cves"].apply(lambda cs: max([cvss.get(c, {}).get("cvss") or 0 for c in cs], default=0.0))
    df["asset_id"] = "AST-" + df["hostname"]
    return df


@lru_cache(maxsize=1)
def asset_index() -> dict:
    return {r["ip"]: r for r in build_assets().to_dict("records")}


def is_internal(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network("10.0.0.0/8")
    except ValueError:
        return False
