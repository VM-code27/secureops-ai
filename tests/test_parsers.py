"""Parsers against real Zeek (TSV + JSON) and Suricata eve.json samples."""
from conftest import fixture_text

from secureops.sources import suricata, zeek


def test_zeek_conn_tsv_and_json_agree():
    tsv = zeek.parse(fixture_text("zeek_conn.log"), "conn.log")
    js = zeek.parse(fixture_text("zeek_conn.json"), "conn.json")
    assert tsv["path"] == js["path"] == "conn"
    assert len(tsv["events"]) == 2000 and len(js["events"]) == 1000
    first_tsv = tsv["events"].set_index("uid").loc["CMwJl820SlYyy434c8"]
    first_js = js["events"].set_index("uid").loc["CMwJl820SlYyy434c8"]
    for col in ("src_ip", "dst_ip", "dst_port", "bytes_out", "bytes_in", "conn_state"):
        assert first_tsv[col] == first_js[col]
    assert first_tsv.dst_port == 3389 and first_tsv.conn_state == "RSTR"


def test_zeek_ssh_outcomes():
    ev = zeek.parse(fixture_text("zeek_ssh.log"), "ssh.log")["events"]
    assert set(ev.outcome) <= {"success", "failure", ""}
    assert (ev.outcome == "failure").sum() >= 1 and (ev.outcome == "success").sum() >= 1
    assert (ev.source == "zeek_ssh").all()


def test_zeek_software_feeds_assets():
    sw = zeek.parse(fixture_text("zeek_software.log"), "software.log")["software"]
    assert len(sw) > 100 and {"host", "name", "version"} <= set(sw.columns)


def test_suricata_alerts_and_flows():
    r = suricata.parse(fixture_text("suricata_eve_small.json"))
    assert r["alerts"] == 1 and r["flows"] == 1
    a = suricata.parse(fixture_text("suricata_eve_alerts.json"))
    ev = a["events"]
    assert a["alerts"] == 21 and (ev.source == "suricata_alert").all()
    assert ev.signature.str.len().gt(0).all() and ev.sig_severity.isin([1, 2, 3]).all()
