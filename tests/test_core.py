from datetime import timedelta

import pandas as pd

from secureops import assistant, db, pipeline
from secureops.detection.rules import detect_rules
from secureops.simulate import T0, _c1_multistage, _c2_bruteforce, _c3_spray, _ev, _finalise

import numpy as np


def _events(rows):
    return _finalise(rows, "test")


def test_bruteforce_then_success_detected():
    ev = _events(_c2_bruteforce(np.random.default_rng(0), T0))
    rules = {a["rule_id"] for a in detect_rules(ev)}
    assert {"R-BRUTE", "R-BRUTE-OK", "R-IOC"} <= rules


def test_few_failures_do_not_alert():
    rows = [_ev(T0 + timedelta(seconds=i * 10), source="auth", src_ip="10.10.2.9", dst_ip="10.10.1.3",
                dst_port=88, user="user0009", outcome="failure") for i in range(3)]
    assert detect_rules(_events(rows)) == []


def test_spray_and_multistage_rules():
    rng = np.random.default_rng(1)
    assert "R-SPRAY" in {a["rule_id"] for a in detect_rules(_events(_c3_spray(rng, T0)))}
    rules = {a["rule_id"] for a in detect_rules(_events(_c1_multistage(rng, T0)))}
    assert {"R-SCAN", "R-IDS", "R-IOC", "R-LATERAL", "R-EXFIL"} <= rules


def test_allowlisted_scanner_is_ignored():
    rows = [_ev(T0 + timedelta(seconds=i), src_ip="10.10.1.250", dst_ip="10.10.1.10", dst_port=i + 1,
                conn_state="REJ") for i in range(50)]
    assert detect_rules(_events(rows)) == []


def test_multistage_correlates_into_one_critical_incident():
    from secureops.detection.anomaly import AnomalyModel, detect_all
    from secureops.simulate import historical_dataset

    hist = historical_dataset(3)
    model = AnomalyModel().fit(hist)
    ev = _events(_c1_multistage(np.random.default_rng(2), T0))
    alerts = detect_all(ev, model)
    alerts, incs = pipeline.build_incidents(ev, alerts, alert_start=1, inc_start=1, dataset="t",
                                            created_at=pd.Timestamp.now(tz="UTC"))
    assert len(alerts) > 50 and len(incs) == 1
    inc = incs[0]
    assert inc["severity"] == "Critical"
    assert ("web-srv-01", "CVE-2021-41773") in inc["scoring"]["exploited_cves"]
    assert inc["ai_support"] == 1.0


def test_verifier_flags_uncited_and_invented_ids():
    ctx = [{"id": "EVT-1"}, {"id": "ALR-2"}]
    v = assistant.verify("The host beaconed to a C2 server [EVT-1]. It was also compromised by magic. "
                         "The attacker used account bob [EVT-999].", ctx)
    assert [c["supported"] for c in v["checks"]] == [True, False, False]
    assert v["support_rate"] == round(1 / 3, 3)


def test_case_workflow_and_audit():
    pipeline.bootstrap(force=True)
    inc_id = db.list_incidents().iloc[0].incident_id
    db.update_incident(inc_id, "tester", owner="Alex (Tier 1)")
    inc = db.update_incident(inc_id, "tester", status="False positive", resolution="sanctioned backup")
    assert inc["acknowledged_at"] is not None and inc["resolved_at"] is not None and inc["false_positive"]
    actions = set(db.read_audit(inc_id).action)
    assert {"created", "set_owner", "set_status", "set_resolution"} <= actions
