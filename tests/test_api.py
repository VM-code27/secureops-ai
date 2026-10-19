"""API: public reads, token-protected writes, sensor ingest of real logs."""
from conftest import fixture_text
from fastapi.testclient import TestClient

from api.main import app

H = {"X-API-Token": "test-token"}


def test_api_flow(seeded_db):
    from secureops import settings
    settings.save({"team": ["Sam"]})
    with TestClient(app) as c:
        health = c.get("/health").json()
        assert health["initialized"] and set(health) == {"status", "version", "initialized"}  # reveals nothing else
        assert c.get("/incidents").status_code == 401  # reads are private too
        assert c.get("/assets").status_code == 401
        r = c.post("/ingest/zeek?sensor=t&filename=ssh.log", content=fixture_text("zeek_ssh.log"))
        assert r.status_code == 401
        r = c.post("/ingest/zeek?sensor=t&filename=ssh.log", content=fixture_text("zeek_ssh.log"), headers=H)
        assert r.status_code == 200 and r.json()["log"] == "ssh" and r.json()["events"] == 22
        r = c.post("/ingest/suricata?sensor=t", content=fixture_text("suricata_eve_small.json"), headers=H)
        assert r.json()["alerts_in_file"] == 1
        incs = c.get("/incidents", headers=H).json()
        assert incs and incs[0]["score"] >= incs[-1]["score"]
        iid = incs[0]["incident_id"]
        assert c.get(f"/incidents/{iid}", headers=H).json()["ai_summary"]
        assert c.patch(f"/incidents/{iid}", json={"owner": "Sam"}).status_code == 401
        assert c.patch(f"/incidents/{iid}", json={"owner": "Mallory"}, headers=H).status_code == 422
        r = c.patch(f"/incidents/{iid}", json={"owner": "Sam", "status": "Investigating"}, headers=H)
        assert r.status_code == 200 and r.json()["owner"] == "Sam"
        assert {a["action"] for a in c.get(f"/incidents/{iid}/audit", headers=H).json()} >= {"created", "set_owner", "set_status"}
        assert c.get("/assets", headers=H).json()
        csv = "ip,hostname,criticality,owner,cpe\n10.47.3.155,rdp-gw,5,IT,\n"
        r = c.post("/assets/inventory", content=csv, headers=H)
        assert r.json()["assets_updated"] == 1
        assert [a for a in c.get("/assets", headers=H).json() if a["ip"] == "10.47.3.155"][0]["criticality_source"] == "inventory"
