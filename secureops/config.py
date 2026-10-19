"""Paths and secrets (environment variables). Tunable behaviour lives in config.yaml /
the Settings page - see settings.py."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("SECUREOPS_DATA_DIR", ROOT / "data"))
CACHE_DIR = DATA_DIR / "cache"
PLAYBOOK_DIR = ROOT / "playbooks"
CONFIG_FILE = ROOT / "config.yaml"
RULES_FILE = ROOT / "rules.yaml"

DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{(DATA_DIR / 'secureops.db').as_posix()}")
if DATABASE_URL.startswith("postgres://"):  # Neon / Supabase style URLs
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Secrets - never stored in files or the database.
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
OLLAMA_URL = os.getenv("OLLAMA_URL", "")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
API_TOKEN = os.getenv("SECUREOPS_API_TOKEN", "")  # required for every API call that changes data (sensors, cases)
