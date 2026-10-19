"""Live threat-intelligence feeds (free, no key):

* abuse.ch Feodo Tracker  - botnet C2 server IPs
* Spamhaus DROP            - hijacked / criminal netblocks (CIDR)
* abuse.ch URLhaus         - malware-distribution URLs (IP-literal hosts are used)

Feeds are refreshed when older than intel.refresh_hours and stored in the `intel` table.
"""
from __future__ import annotations

import bisect
import csv
import io
import ipaddress
import json
from urllib.parse import urlparse

import pandas as pd
import requests

from .. import db, settings

_index: dict = {"built_at": None, "value": None}


def _feodo(url: str) -> pd.DataFrame:
    rows = requests.get(url, timeout=60).json()
    return pd.DataFrame([{"indicator": r["ip_address"], "kind": "ip",
                          "context": f"Feodo Tracker: {r.get('malware')} C2 (port {r.get('port')}, status {r.get('status')}, "
                                     f"last online {r.get('last_online')})"} for r in rows])


def _spamhaus(url: str) -> pd.DataFrame:
    out = []
    for line in requests.get(url, timeout=60).text.splitlines():
        rec = json.loads(line) if line.strip().startswith("{") else {}
        if "cidr" in rec:
            out.append({"indicator": rec["cidr"], "kind": "cidr",
                        "context": f"Spamhaus DROP {rec.get('sblid', '')} ({rec.get('rir', '')}): do not route or peer"})
    return pd.DataFrame(out)


def _urlhaus(url: str) -> pd.DataFrame:
    text = requests.get(url, timeout=120).text
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    out = []
    for row in csv.reader(lines):
        if len(row) < 6:
            continue
        host = urlparse(row[2]).hostname or ""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            continue  # domain hosts need DNS logs to match; conn logs only carry IPs
        out.append({"indicator": host, "kind": "ip", "context": f"URLhaus: {row[5]} URL {row[2]} ({row[3]}, added {row[1]})"})
    return pd.DataFrame(out)


FETCHERS = {"feodo": _feodo, "spamhaus_drop": _spamhaus, "urlhaus": _urlhaus}


def status() -> dict:
    return db.get_meta("intel_status", {})


def refresh(force: bool = False) -> dict:
    feeds = settings.section("intel")["feeds"]
    ttl = pd.Timedelta(hours=settings.section("intel")["refresh_hours"])
    st = status()
    for name, fn in FETCHERS.items():
        url = feeds.get(name)
        if not url:
            continue
        last = st.get(name, {}).get("fetched_at")
        if not force and last and pd.Timestamp(last) > db.now() - ttl and not st[name].get("error"):
            continue
        try:
            df = fn(url)
            df["source"], df["fetched_at"] = name, db.now()
            db.replace_intel(name, df)
            st[name] = {"fetched_at": db.now().isoformat(), "count": int(len(df)), "url": url, "error": ""}
        except Exception as exc:  # keep the previous copy if a feed is down
            st[name] = {**st.get(name, {}), "error": f"{exc.__class__.__name__}: {exc}"[:200], "url": url}
    db.set_meta("intel_status", st)
    _index["value"] = None
    return st


class IntelIndex:
    """Fast membership test for single IPs and CIDR blocks."""

    def __init__(self, df: pd.DataFrame):
        self.ips = dict(zip(df[df.kind == "ip"].indicator, df[df.kind == "ip"].context))
        nets = []
        for ind, ctx in zip(df[df.kind == "cidr"].indicator, df[df.kind == "cidr"].context):
            try:
                n = ipaddress.ip_network(ind, strict=False)
                if n.version == 4:
                    nets.append((int(n.network_address), int(n.broadcast_address), ind, ctx))
            except ValueError:
                pass
        nets.sort()
        self.starts = [n[0] for n in nets]
        self.nets = nets

    def __len__(self):
        return len(self.ips) + len(self.nets)

    def lookup(self, ip: str) -> tuple[str, str] | None:
        if not ip:
            return None
        if ip in self.ips:
            return ip, self.ips[ip]
        try:
            v = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return None
        i = bisect.bisect_right(self.starts, v) - 1
        if i >= 0 and self.nets[i][0] <= v <= self.nets[i][1]:
            return self.nets[i][2], self.nets[i][3]
        return None


def index() -> IntelIndex:
    if _index["value"] is None:
        _index["value"] = IntelIndex(db.read_intel())
    return _index["value"]


def load_text_table(text: str) -> pd.DataFrame:  # helper for tests
    return pd.read_csv(io.StringIO(text))
