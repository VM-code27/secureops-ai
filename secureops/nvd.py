"""NVD (National Vulnerability Database) client with an offline cache.

The cache in data/nvd_cache.json was built from the live NVD API 2.0 by
`python scripts/refresh_nvd.py`. The app reads the cache so it works offline
and never hits NVD rate limits on a free host.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_PATH = Path(__file__).resolve().parent.parent / "data" / "nvd_cache.json"

# Software that appears in the simulated asset inventory -> CVEs it is exposed to.
TRACKED_CVES = {
    "Apache HTTP Server 2.4.49": ["CVE-2021-41773", "CVE-2021-42013"],
    "Apache Log4j 2.14.1": ["CVE-2021-44228"],
    "OpenSSH 8.5p1": ["CVE-2024-6387"],
    "Windows SMBv1": ["CVE-2017-0144"],
    "Microsoft Exchange 2019 CU9": ["CVE-2021-34473"],
    "Atlassian Confluence 8.0.0": ["CVE-2023-22515"],
    "Cisco IOS XE 17.9": ["CVE-2023-20198"],
    "Hikvision IP Camera firmware 5.5": ["CVE-2021-36260"],
    "Progress MOVEit Transfer 2023.0": ["CVE-2023-34362"],
    "Palo Alto PAN-OS 11.1": ["CVE-2024-3400"],
    "Google Chrome 116": ["CVE-2023-4863"],
}


def _parse(item: dict) -> dict:
    cve = item["cve"]
    desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
    score, severity, vector = None, None, None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0]["cvssData"]
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or metrics[key][0].get("baseSeverity")
            vector = data.get("vectorString")
            break
    return {
        "id": cve["id"],
        "published": cve.get("published"),
        "description": desc,
        "cvss": score,
        "severity": severity,
        "vector": vector,
        "kev": bool(cve.get("cisaExploitAdd")),
        "source": "NVD API 2.0",
    }


def fetch_cve(cve_id: str, api_key: str | None = None) -> dict:
    headers = {"apiKey": api_key} if api_key else {}
    r = requests.get(NVD_URL, params={"cveId": cve_id}, headers=headers, timeout=30)
    r.raise_for_status()
    vulns = r.json().get("vulnerabilities", [])
    if not vulns:
        raise ValueError(f"{cve_id} not found in NVD")
    return _parse(vulns[0])


def refresh_cache(api_key: str | None = None, force: bool = False) -> dict:
    api_key = api_key or os.getenv("NVD_API_KEY")
    delay = 1 if api_key else 6.5  # NVD public rate limit: 5 requests / 30 s
    out = {} if force else load_cves()
    ids = sorted({c for cves in TRACKED_CVES.values() for c in cves} - set(out))
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    for cve_id in ids:
        for attempt in range(3):
            try:
                out[cve_id] = fetch_cve(cve_id, api_key)
                break
            except requests.RequestException as exc:
                print(f"{cve_id}: attempt {attempt + 1} failed ({exc.__class__.__name__})")
                time.sleep(delay * (attempt + 1))
        else:
            continue
        print(f"fetched {cve_id}: CVSS {out[cve_id]['cvss']}")
        CACHE_PATH.write_text(json.dumps(out, indent=2))
        time.sleep(delay)
    return out


def load_cves() -> dict:
    if CACHE_PATH.exists():
        return json.loads(CACHE_PATH.read_text())
    return {}
