from fastapi.testclient import TestClient

from api.main import app


def test_api_flow():
    with TestClient(app) as c:
        assert c.get("/health").json()["status"] == "ok"
        incs = c.get("/incidents").json()
        assert incs and incs[0]["score"] >= incs[-1]["score"]
        iid = incs[0]["incident_id"]
        assert c.get(f"/incidents/{iid}").json()["ai_summary"]
        assert c.get(f"/incidents/{iid}/alerts").json()
        r = c.patch(f"/incidents/{iid}", json={"owner": "Sam (Tier 1)", "status": "Investigating"})
        assert r.status_code == 200 and r.json()["owner"] == "Sam (Tier 1)"
        assert c.patch(f"/incidents/{iid}", json={"owner": "Mallory"}).status_code == 422
        live = c.post("/ingest/simulate", json={"scenario": "bruteforce"}).json()
        assert live["alerts"] > 0 and live["incidents"]
        new = c.get(f"/incidents/{live['incidents'][0]}").json()
        assert "ground_truth" not in new  # live data is unlabelled
        assert c.post(f"/incidents/{iid}/explain").json()["support_rate"] > 0.9
