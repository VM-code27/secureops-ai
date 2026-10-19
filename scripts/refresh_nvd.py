"""Refresh data/nvd_cache.json from the live NVD API (set NVD_API_KEY to go faster)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from secureops.nvd import refresh_cache  # noqa: E402

if __name__ == "__main__":
    refresh_cache()
