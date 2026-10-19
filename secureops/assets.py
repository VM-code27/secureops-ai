"""Asset inventory: discovered automatically from traffic, enriched by an optional CSV.

Discovery (per ingested batch):
  * internal hosts = IPs inside the home networks (configured, or inferred - see HomeNets)
  * services       = what a host answered (Zeek service name, else proto/port)
  * fan-in/out     = distinct peers; a host most others talk to is a shared "hub"
  * criticality    = 1 + 1 if it serves anything + up to 2 for popularity (log10 fan-in)
                     + 1 if hub, capped at 5 - unless the inventory CSV sets it.
Inventory CSV columns: ip (required), hostname, criticality (1-5), owner, cpe (';'-separated
CPE 2.3 strings used for live NVD CVE lookup), notes.
"""
from __future__ import annotations

import ipaddress
import math

import pandas as pd

from . import db, settings

PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10")]
ANSWERED = {"SF", "S1", "S2", "S3", "RSTO", "RSTR", "SH", "SHR"}
_cache: dict = {}


# ------------------------------------------------------------------ home networks
class HomeNets:
    def __init__(self, nets):
        self.nets = [ipaddress.ip_network(n, strict=False) for n in nets]
        self._memo: dict = {}

    def __contains__(self, ip: str) -> bool:
        if ip not in self._memo:
            try:
                a = ipaddress.ip_address(ip)
                self._memo[ip] = any(a in n for n in self.nets if n.version == a.version)
            except ValueError:
                self._memo[ip] = False
        return self._memo[ip]

    def __repr__(self):
        return ", ".join(map(str, self.nets))


def infer_home_nets(events: pd.DataFrame) -> list[str]:
    """RFC 1918 + any public /16 holding >= 30% of observed hosts that both sends and receives."""
    nets = [str(n) for n in PRIVATE]
    srcs, dsts = set(events.src_ip), set(events.dst_ip)
    ips = [ip for ip in srcs | dsts if ip and ":" not in ip]
    if not ips:
        return nets
    by16 = pd.Series([".".join(ip.split(".")[:2]) for ip in ips]).value_counts()
    for prefix, n in by16.items():
        net = ipaddress.ip_network(f"{prefix}.0.0/16")
        if n / len(ips) >= 0.3 and not any(net.subnet_of(p) for p in PRIVATE if p.version == 4) \
                and any(ip.startswith(prefix + ".") for ip in srcs) and any(ip.startswith(prefix + ".") for ip in dsts):
            nets.append(str(net))
    return nets


def home_nets(events: pd.DataFrame | None = None) -> HomeNets:
    conf = settings.section("network")["home_networks"]
    if conf != "auto":
        return HomeNets(conf)
    stored = db.get_meta("home_networks_inferred")
    if events is not None and len(events):
        inferred = infer_home_nets(events)
        if stored:
            inferred = sorted(set(stored) | set(inferred))
        if inferred != stored:
            db.set_meta("home_networks_inferred", inferred)
        stored = inferred
    return HomeNets(stored or [str(n) for n in PRIVATE])


# ------------------------------------------------------------------ discovery
def discover(events: pd.DataFrame) -> int:
    """Update the asset table from a batch of events. Returns number of assets touched."""
    conn = events[events.source.isin(["zeek_conn", "suricata_flow", "zeek_ssh"])]
    if conn.empty:
        return 0
    home = home_nets(conn)
    internal = sorted({ip for ip in set(conn.src_ip) | set(conn.dst_ip) if ip and ip in home})
    if not internal:
        return 0
    cur = db.read_assets().set_index("ip")
    answered = conn[conn.conn_state.isin(ANSWERED) | (conn.source == "zeek_ssh")]
    svc_name = answered.service.where(answered.service != "", answered.proto + "/" + answered.dst_port.astype(str))
    services = answered.assign(svc=svc_name).groupby("dst_ip").svc.agg(lambda s: s.value_counts().index[:8].tolist())
    fan_in = conn.groupby("dst_ip").src_ip.nunique()
    fan_out = conn.groupby("src_ip").dst_ip.nunique()
    first = pd.concat([conn[["src_ip", "ts"]].rename(columns={"src_ip": "ip"}),
                       conn[["dst_ip", "ts"]].rename(columns={"dst_ip": "ip"})]).groupby("ip").ts.agg(["min", "max"])
    active = max(len(set(internal) | set(cur.index)), 1)
    hub_share = settings.section("network")["hub_fan_in_share"]
    rows = []
    for ip in internal:
        old = cur.loc[ip].to_dict() if ip in cur.index else {}
        svcs = list(dict.fromkeys((old.get("services") or []) + services.get(ip, [])))[:10]
        fi = max(int(fan_in.get(ip, 0)), int(old.get("fan_in") or 0))
        fo = max(int(fan_out.get(ip, 0)), int(old.get("fan_out") or 0))
        hub = fi >= max(3, hub_share * active)
        row = {"ip": ip, "services": svcs, "fan_in": fi, "fan_out": fo, "is_hub": bool(hub),
               "first_seen": min(x for x in [old.get("first_seen"), first.loc[ip, "min"]] if x is not None and pd.notna(x)),
               "last_seen": max(x for x in [old.get("last_seen"), first.loc[ip, "max"]] if x is not None and pd.notna(x)),
               "role": ("Server: " + ", ".join(svcs[:3])) if svcs else "Client"}
        if old.get("criticality_source") != "inventory":
            crit = 1 + (1 if svcs else 0) + min(2, round(math.log10(1 + fi))) + (1 if hub else 0)
            row.update(criticality=int(min(5, crit)), criticality_source="inferred")
        if not old:
            row.update(hostname="", owner="", cpes=[], cves=[], software=[], notes="")
        rows.append(row)
    db.upsert_assets(rows)
    _cache.clear()
    return len(rows)


def add_software(sw: pd.DataFrame):
    if sw.empty:
        return
    cur = db.read_assets().set_index("ip")
    rows = []
    for host, g in sw.groupby("host"):
        if host not in cur.index:
            continue
        seen = [f"{n} {v}".strip() for n, v in zip(g.name, g.version.fillna(""))]
        rows.append({"ip": host, "software": sorted(set(cur.loc[host, "software"]) | set(seen))[:30]})
    db.upsert_assets(rows)
    _cache.clear()


def apply_inventory(df: pd.DataFrame) -> int:
    """Merge an inventory CSV. Inventory values override inferred ones."""
    df = df.rename(columns=str.lower)
    if "ip" not in df:
        raise ValueError("inventory CSV needs an 'ip' column")
    rows = []
    for r in df.fillna("").to_dict("records"):
        ip = str(r["ip"]).strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        row = {"ip": ip}
        if r.get("hostname"):
            row["hostname"] = str(r["hostname"])
        if str(r.get("criticality", "")).strip():
            row["criticality"] = int(min(5, max(1, int(float(r["criticality"])))))
            row["criticality_source"] = "inventory"
        if r.get("owner"):
            row["owner"] = str(r["owner"])
        if r.get("cpe"):
            row["cpes"] = [c.strip() for c in str(r["cpe"]).split(";") if c.strip().startswith("cpe:2.3:")]
        if r.get("notes"):
            row["notes"] = str(r["notes"])
        rows.append(row)
    existing = set(db.read_assets().ip)
    for row in rows:
        if row["ip"] not in existing:
            row.setdefault("hostname", "")
            row.setdefault("criticality", 1)
            row.setdefault("criticality_source", "inventory")
            row.update(role="Inventory only (not yet seen)", services=[], software=[], cves=[], fan_in=0, fan_out=0,
                       is_hub=False, owner=row.get("owner", ""), notes=row.get("notes", ""), cpes=row.get("cpes", []))
    db.upsert_assets(rows)
    _cache.clear()
    return len(rows)


def lookup_cves(progress=None) -> int:
    """Live NVD lookup of CVEs for every asset CPE (plus KEV + EPSS)."""
    from .intel import vulns
    a = db.read_assets()
    with_cpe = a[a.cpes.map(len) > 0]
    found = vulns.enrich_cpes([c for cs in with_cpe.cpes for c in cs]) if len(with_cpe) else {}
    rows = [{"ip": r.ip, "cves": sorted({c for cpe in r.cpes for c in found.get(cpe, [])})} for r in with_cpe.itertuples()]
    db.upsert_assets(rows)
    _cache.clear()
    return sum(len(r["cves"]) for r in rows)


def index() -> dict:
    if "idx" not in _cache:
        a = db.read_assets()
        _cache["idx"] = {r["ip"]: r for r in a.to_dict("records")}
    return _cache["idx"]


def label(ip: str) -> str:
    a = index().get(ip)
    if not a:
        return ip
    return f"{a['hostname']} ({ip})" if a.get("hostname") else ip
