import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
# Tests use their own throwaway SQLite database and never call an LLM.
os.environ.setdefault("DATABASE_URL", f"sqlite:///{Path(tempfile.mkdtemp()).as_posix()}/test.db")
os.environ["LLM_PROVIDER"] = "offline"
