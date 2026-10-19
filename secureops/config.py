"""Central configuration. Everything can be overridden with environment variables."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
PLAYBOOK_DIR = ROOT / "playbooks"

DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{(DATA_DIR / 'secureops.db').as_posix()}")
# Neon / Supabase give "postgres://" URLs; SQLAlchemy wants "postgresql://".
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

SEED = int(os.getenv("SECUREOPS_SEED", "42"))

# Detection thresholds (tune here, then re-run `python -m secureops.evaluate`).
THRESHOLDS = {
    "brute_force_failures_5m": 10,
    "spray_distinct_users_10m": 8,
    "scan_distinct_ports_1m": 15,
    "lateral_distinct_hosts_10m": 10,
    "exfil_bytes_per_conn": 100 * 1024**2,
    "anomaly_contamination": 0.004,
}

# Tuning: sources that are authorised to behave "badly" (e.g. the vulnerability scanner).
ALLOWLIST_SOURCES = {"10.10.1.250"}

# Correlation: alerts sharing an entity within this gap are merged into one incident.
CORRELATION_GAP_MINUTES = 120

# SLA (hours to resolve) per severity band.
SLA_HOURS = {"Critical": 1, "High": 4, "Medium": 24, "Low": 72}

ANALYSTS = ["Unassigned", "Vimala (Tier 2)", "Alex (Tier 1)", "Sam (Tier 1)", "Priya (Tier 3 / IR lead)"]

# AI assistant provider: "auto" picks Groq if GROQ_API_KEY is set, then Ollama if
# OLLAMA_URL is set, otherwise the offline evidence-template engine.
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "auto")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
OLLAMA_URL = os.getenv("OLLAMA_URL", "")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
