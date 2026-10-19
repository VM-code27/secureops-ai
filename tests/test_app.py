"""Headless smoke test of every dashboard page (Streamlit AppTest)."""
from pathlib import Path

from streamlit.testing.v1 import AppTest

APP = Path(__file__).resolve().parent.parent / "streamlit_app.py"

PAGES = ["Overview", "Incident queue", "Investigate", "Live attack demo", "Evaluation", "About"]


def _run(page, **state):
    at = AppTest.from_file(str(APP), default_timeout=120)
    at.session_state["page"] = page
    for k, v in state.items():
        at.session_state[k] = v
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    return at


def test_all_pages_render():
    for p in PAGES:
        _run(p)


def test_live_demo_and_case_flow():
    at = _run("Live attack demo")
    at.button[[b.label for b in at.button].index("Inject & run pipeline")].click().run()
    assert not at.exception, [e.value for e in at.exception]
    assert any("Prioritise" in m.value for m in at.markdown)
