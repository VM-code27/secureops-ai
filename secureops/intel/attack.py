"""MITRE ATT&CK knowledge base, downloaded live from MITRE's official STIX repository and
streamed (ijson) into a compact technique index used by the AI assistant's retrieval."""
from __future__ import annotations

import json

import ijson
import requests

from .. import config, settings

CACHE = "attack_techniques.json"
_mem: dict = {}


def _build() -> dict:
    url = settings.section("intel")["feeds"]["mitre_attack"]
    raw = config.CACHE_DIR / "enterprise-attack.json"
    raw.parent.mkdir(parents=True, exist_ok=True)
    with requests.get(url, stream=True, timeout=300) as r:
        r.raise_for_status()
        with open(raw, "wb") as f:
            for chunk in r.iter_content(1 << 20):
                f.write(chunk)
    out = {}
    with open(raw, "rb") as f:
        for obj in ijson.items(f, "objects.item"):
            if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            ext = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
            if not ext:
                continue
            out[ext["external_id"]] = {
                "id": ext["external_id"], "name": obj.get("name", ""), "url": ext.get("url", ""),
                "tactics": [p["phase_name"].replace("-", " ").title() for p in obj.get("kill_chain_phases", [])],
                "description": obj.get("description", "")[:1500],
                "detection": (obj.get("x_mitre_detection") or "")[:800],
            }
    raw.unlink(missing_ok=True)
    (config.CACHE_DIR / CACHE).write_text(json.dumps(out), encoding="utf-8")
    return out


def techniques(build_if_missing: bool = True) -> dict:
    if "kb" not in _mem:
        path = config.CACHE_DIR / CACHE
        if path.exists():
            _mem["kb"] = json.loads(path.read_text(encoding="utf-8"))
        elif build_if_missing:
            try:
                _mem["kb"] = _build()
            except Exception:
                return {}
        else:
            return {}
    return _mem["kb"]


def lookup(technique_id: str) -> dict | None:
    kb = techniques(build_if_missing=False)  # the download happens once, at bootstrap
    return kb.get(technique_id) or kb.get(technique_id.split(".")[0])
