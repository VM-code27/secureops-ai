"""Headless smoke test of every dashboard page (Streamlit AppTest) on real fixture data."""
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

APP = Path(__file__).resolve().parent.parent / "streamlit_app.py"
PAGES = ["Live", "Overview", "Investigate"]


@pytest.mark.parametrize("page", PAGES)
def test_page_renders(seeded_db, page):
    at = AppTest.from_file(str(APP), default_timeout=120)
    at.session_state["page"] = page
    at.run()
    assert not at.exception, [e.value for e in at.exception]


def test_case_update_from_dashboard(seeded_db):
    from secureops import db, settings
    settings.save({"team": ["Priya"]})
    inc_id = db.list_incidents().iloc[0].incident_id
    at = AppTest.from_file(str(APP), default_timeout=120)
    at.session_state["page"] = "Investigate"
    at.session_state["focus"] = inc_id
    at.run()
    owner = next(s for s in at.selectbox if s.label == "Owner")
    owner.set_value("Priya")
    next(b for b in at.button if b.label == "Save case").click()
    at.run()
    assert not at.exception
    assert db.get_incident(inc_id)["owner"] == "Priya"


def test_chat_answers_with_citations(seeded_db):
    from secureops import chat, db
    inc_id = db.list_incidents().iloc[0].incident_id
    r = chat.answer(f"explain {inc_id}")
    assert r["focus"] == inc_id and r["support_rate"] == 1.0 and inc_id in r["text"]
    r = chat.answer("what is happening right now?")
    assert r["support_rate"] == 1.0 and any(s["id"] == "STAT-1" for s in r["sources"])
