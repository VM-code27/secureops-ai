"""Live vulnerability intelligence (free):

* NVD API 2.0     - CVE details and CPE -> CVE matching for your asset inventory
* CISA KEV        - CVEs known to be exploited in the wild
* FIRST EPSS      - probability a CVE will be exploited in the next 30 days
"""
from __future__ import annotations

import json
import time

import pandas as pd
import requests

from .. import config, db, settings

KEV_CACHE = "kev.json"


def _nvd_get(params: dict) -> dict:
    url = settings.section("intel")["feeds"]["nvd"]
    headers = {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}
    delay = 0.7 if config.NVD_API_KEY else 6.5  # NVD public rate limit is 5 requests / 30 s
    for attempt in range(3):
        try:
            r = requests.get(url, params=params, headers=headers, timeout=60)
            if r.status_code in (403, 429, 503):
                raise requests.HTTPError(f"NVD {r.status_code}")
            r.raise_for_status()
            time.sleep(delay)
            return r.json()
        except requests.RequestException:
            time.sleep(delay * (attempt + 2))
    raise RuntimeError(f"NVD request failed: {params}")


def _parse_cve(item: dict) -> dict:
    cve = item["cve"]
    desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
    score = severity = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        m = cve.get("metrics", {}).get(key)
        if m:
            score = m[0]["cvssData"].get("baseScore")
            severity = m[0]["cvssData"].get("baseSeverity") or m[0].get("baseSeverity")
            break
    return {"cve_id": cve["id"], "cvss": score, "severity": severity, "description": desc[:1500],
            "published": cve.get("published", "")[:10]}


def kev_catalog(force: bool = False) -> dict:
    path = config.CACHE_DIR / KEV_CACHE
    ttl = settings.section("intel")["refresh_hours"] * 3600
    if force or not path.exists() or time.time() - path.stat().st_mtime > ttl:
        try:
            r = requests.get(settings.section("intel")["feeds"]["cisa_kev"], timeout=120)
            r.raise_for_status()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(r.text, encoding="utf-8")
        except requests.RequestException:
            if not path.exists():
                return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    db.set_meta("kev_status", {"version": data.get("catalogVersion"), "count": data.get("count"),
                               "fetched_at": pd.Timestamp(path.stat().st_mtime, unit="s", tz="UTC").isoformat()})
    return {v["cveID"]: v for v in data.get("vulnerabilities", [])}


def epss(cve_ids: list[str]) -> dict:
    out = {}
    url = settings.section("intel")["feeds"]["epss"]
    for i in range(0, len(cve_ids), 100):
        r = requests.get(url, params={"cve": ",".join(cve_ids[i:i + 100])}, timeout=60)
        if r.ok:
            out.update({d["cve"]: (float(d["epss"]), float(d["percentile"])) for d in r.json().get("data", [])})
    return out


def enrich(cve_ids, force: bool = False) -> pd.DataFrame:
    """Make sure every CVE has NVD details + KEV + EPSS in the vulns table."""
    cve_ids = sorted({c for c in cve_ids if c})
    have = db.read_vulns(cve_ids)
    todo = cve_ids if force else [c for c in cve_ids if c not in set(have.cve_id)]
    if todo:
        kev = kev_catalog()
        scores = epss(todo)
        rows = []
        for cid in todo:
            try:
                items = _nvd_get({"cveId": cid}).get("vulnerabilities", [])
                rec = _parse_cve(items[0]) if items else {"cve_id": cid, "cvss": None, "severity": None,
                                                         "description": "Not found in NVD", "published": ""}
            except RuntimeError:
                continue
            k = kev.get(cid)
            e = scores.get(cid, (None, None))
            rows.append({**rec, "kev": bool(k), "kev_date": k["dateAdded"] if k else "",
                         "ransomware": k.get("knownRansomwareCampaignUse", "") if k else "",
                         "epss": e[0], "epss_percentile": e[1], "fetched_at": db.now()})
        db.upsert_vulns(rows)
    return db.read_vulns(cve_ids)


def cves_for_cpe(cpe: str, limit: int = 200) -> list[dict]:
    """CVEs affecting a CPE 2.3 string, e.g. cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"""
    data = _nvd_get({"virtualMatchString": cpe, "resultsPerPage": limit})
    return [_parse_cve(v) for v in data.get("vulnerabilities", [])]


def enrich_cpes(cpes: list[str]) -> dict[str, list[str]]:
    """Look up CVEs for each CPE, store details (with KEV + EPSS). Returns {cpe: [cve ids]}."""
    out = {}
    kev = kev_catalog()
    for cpe in sorted(set(cpes)):
        recs = cves_for_cpe(cpe)
        scores = epss([r["cve_id"] for r in recs])
        rows = []
        for rec in recs:
            k = kev.get(rec["cve_id"])
            e = scores.get(rec["cve_id"], (None, None))
            rows.append({**rec, "kev": bool(k), "kev_date": k["dateAdded"] if k else "",
                         "ransomware": k.get("knownRansomwareCampaignUse", "") if k else "",
                         "epss": e[0], "epss_percentile": e[1], "fetched_at": db.now()})
        db.upsert_vulns(rows)
        out[cpe] = [r["cve_id"] for r in recs]
    return out


def exposure(cve_ids) -> tuple[float, list[dict]]:
    """Exposure in [0,1] for a set of CVEs: CVSS/10 weighted by real-world exploitation
    evidence (KEV listed = 1.0, otherwise 0.5 + 0.5 x EPSS)."""
    v = db.read_vulns(list(cve_ids))
    best, rows = 0.0, []
    for r in v.itertuples():
        if r.cvss is None or pd.isna(r.cvss):
            continue
        likelihood = 1.0 if r.kev else 0.5 + 0.5 * (r.epss or 0)
        val = r.cvss / 10 * likelihood
        rows.append({"cve": r.cve_id, "cvss": r.cvss, "kev": bool(r.kev), "epss": r.epss, "exposure": round(val, 3)})
        best = max(best, val)
    return best, sorted(rows, key=lambda x: -x["exposure"])
