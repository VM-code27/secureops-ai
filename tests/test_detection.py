"""Rule logic, threat-intel matching, correlation and scoring."""
from datetime import datetime, timedelta, timezone

import pandas as pd
from conftest import fixture_text

from secureops import assistant, db, pipeline, settings
from secureops.detection.rules import detect_rules
from secureops.intel.feeds import IntelIndex
from secureops.sources import normalise, suricata

T0 = datetime(2026, 1, 5, 10, tzinfo=timezone.utc)


def conns(rows):
    df = normalise(pd.DataFrame(rows), "zeek_conn", "unit", "live")
    df.insert(0, "event_id", range(1, len(df) + 1))
    return df


def test_bruteforce_threshold_from_settings(fresh_db):
    rows = [dict(ts=T0 + timedelta(seconds=10 * i), src_ip="10.0.0.5", dst_ip="10.0.0.9", dst_port=4848, proto="tcp",
                 conn_state="SF", bytes_out=600) for i in range(12)]
    assert {a["rule_id"] for a in detect_rules(conns(rows))} == {"R-BRUTE"}
    settings.save({"detection": {"bruteforce": {"attempts": 50}}})
    assert detect_rules(conns(rows)) == []


def test_dns_chatter_is_not_bruteforce(fresh_db):
    rows = [dict(ts=T0 + timedelta(seconds=i), src_ip="10.0.0.5", dst_ip="10.0.0.53", dst_port=53, proto="udp",
                 service="dns") for i in range(200)]
    assert detect_rules(conns(rows)) == []


def test_port_scan_and_lateral(fresh_db):
    scan = [dict(ts=T0 + timedelta(seconds=i), src_ip="10.0.0.66", dst_ip="10.0.0.10", dst_port=1000 + i, proto="tcp",
                 conn_state="REJ") for i in range(40)]
    lat = [dict(ts=T0 + timedelta(seconds=5 * i), src_ip="10.0.0.70", dst_ip=f"10.0.1.{i}", dst_port=445, proto="tcp",
                conn_state="SF") for i in range(15)]
    rules = [a["rule_id"] for a in detect_rules(conns(scan + lat))]
    assert "R-SCAN" in rules and "R-LATERAL" in rules


def test_exfil_needs_external_destination(fresh_db):
    big = dict(ts=T0, src_ip="10.0.0.5", dst_port=443, proto="tcp", conn_state="SF", bytes_out=500 * 1024**2)
    assert [a["rule_id"] for a in detect_rules(conns([{**big, "dst_ip": "203.0.113.9"}]))] == ["R-EXFIL"]
    assert detect_rules(conns([{**big, "dst_ip": "10.0.0.6"}])) == []


def test_intel_index_ip_and_cidr():
    ix = IntelIndex(pd.DataFrame([{"indicator": "198.51.100.7", "kind": "ip", "context": "c2"},
                                  {"indicator": "203.0.113.0/24", "kind": "cidr", "context": "drop"}]))
    assert ix.lookup("198.51.100.7")[1] == "c2"
    assert ix.lookup("203.0.113.200")[0] == "203.0.113.0/24"
    assert ix.lookup("192.0.2.1") is None


def test_threat_intel_match_raises_alert(fresh_db):
    db.replace_intel("unit", pd.DataFrame([{"indicator": "203.0.113.0/24", "kind": "cidr", "context": "Spamhaus DROP test",
                                            "source": "unit", "fetched_at": db.now()}]))
    ev = conns([dict(ts=T0, src_ip="10.0.0.5", dst_ip="203.0.113.50", dst_port=443, proto="tcp", conn_state="SF")])
    alerts = detect_rules(ev)
    assert [a["rule_id"] for a in alerts] == ["R-IOC"] and "Spamhaus DROP test" in alerts[0]["description"]


def test_suricata_alerts_flow_to_incidents_with_cited_explanations(fresh_db):
    r = pipeline.ingest(suricata.parse(fixture_text("suricata_eve_alerts.json"), sensor="unit")["events"])
    assert 0 < r["alerts"] <= 21 and r["new_incidents"]  # same signature+pair within a minute is deduplicated
    inc = db.get_incident(r["new_incidents"][0])
    assert inc["ai_support"] == 1.0 and "[ALR-" in inc["ai_summary"]


def test_streaming_alerts_join_open_incident(fresh_db):
    rows = lambda start: [dict(ts=start + timedelta(seconds=10 * i), src_ip="10.0.0.5", dst_ip="10.0.0.9",  # noqa: E731
                               dst_port=4848, proto="tcp", conn_state="SF") for i in range(12)]
    first = pipeline.ingest(normalise(pd.DataFrame(rows(T0)), "zeek_conn", "unit", "live"))
    second = pipeline.ingest(normalise(pd.DataFrame(rows(T0 + timedelta(minutes=30))), "zeek_conn", "unit", "live"))
    assert len(first["new_incidents"]) == 1 and second["new_incidents"] == []
    assert second["updated_incidents"] == first["new_incidents"]
    assert db.get_incident(first["new_incidents"][0])["alert_count"] == first["alerts"] + second["alerts"]


def test_verifier_flags_uncited_and_invented_ids():
    ctx = [{"id": "EVT-1"}, {"id": "ALR-2"}, {"id": "AST-10.0.0.5"}]
    v = assistant.verify("The host 10.0.0.5 beaconed out [EVT-1, AST-10.0.0.5]. It was compromised by magic. "
                         "The attacker used account bob [EVT-999].", ctx)
    assert [c["supported"] for c in v["checks"]] == [True, False, False]
