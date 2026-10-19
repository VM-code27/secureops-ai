"""Runtime settings = config.yaml defaults deep-merged with overrides saved from the
Settings page (stored in the database, so every process and restart sees them)."""
from __future__ import annotations

import copy
import os
import time
from functools import lru_cache

import pandas as pd
import yaml

from . import config

_cache: dict = {"at": 0.0, "value": None}
TTL_SECONDS = 10


@lru_cache(maxsize=1)
def defaults() -> dict:
    return yaml.safe_load(config.CONFIG_FILE.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def rules() -> dict:
    return yaml.safe_load(config.RULES_FILE.read_text(encoding="utf-8"))


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def get() -> dict:
    if _cache["value"] is None or time.time() - _cache["at"] > TTL_SECONDS:
        from . import db
        merged = _merge(defaults(), db.get_meta("settings_override", {}))
        # Environment variables (deployment secrets) win for the AI provider settings.
        for key, env in (("provider", "LLM_PROVIDER"), ("groq_model", "GROQ_MODEL"), ("ollama_model", "OLLAMA_MODEL")):
            if os.getenv(env):
                merged["ai"][key] = os.getenv(env)
        _cache.update(at=time.time(), value=merged)
    return _cache["value"]


def overrides() -> dict:
    from . import db
    return db.get_meta("settings_override", {})


def save(override: dict):
    from . import db
    db.set_meta("settings_override", override)
    _cache["value"] = None


def section(name: str) -> dict:
    return get()[name]


def window(spec: str) -> pd.Timedelta:
    return pd.Timedelta(spec)


def team() -> list[str]:
    return ["Unassigned"] + [t for t in get().get("team", []) if t and t != "Unassigned"]
