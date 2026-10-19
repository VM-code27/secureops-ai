"""Measured evaluation on LABELLED lab data.

Thresholds were tuned on the development set (seed 42). The headline numbers are
reported on a HELD-OUT test set (different seed: different benign traffic, attack
timing and jitter) that was never used for tuning, using the model trained on the
development set only.

Unit of detection: one source IP in one clock hour (a "window"). A window is truly
malicious if it contains any attack event; it is predicted malicious if any alert
cites an event from it as evidence.

Run:  python -m secureops.evaluate
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pandas as pd

from .config import ROOT, SEED
from .detection.anomaly import AnomalyModel, detect_all
from .pipeline import build_incidents
from .simulate import CAMPAIGNS, historical_dataset

REPORT_DIR = ROOT / "reports"
TEST_SEED = 1337

WHY_MISSED = {
    "C5": "one probe every ~4 minutes stays far below the per-minute scan threshold",
    "C6": "~4 MB per hour over HTTPS to an unlisted host looks like normal web uploads",
    "C7": "a single successful VPN login with valid credentials followed by normal-looking file access "
          "matches no rule and is not statistically unusual",
}


def _prf(tp, fp, fn, tn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"precision": round(p, 3), "recall": round(r, 3), "f1": round(f1, 3), "false_positive_rate": round(fpr, 4),
            "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn)}


def evaluate_run(events: pd.DataFrame, alerts: pd.DataFrame, incidents: list[dict]) -> dict:
    ev = events.set_index("event_id")
    mal = events.campaign != ""
    win = list(zip(events.src_ip, events.ts.dt.floor("h")))
    events = events.assign(win=win)
    truth = set(events.loc[mal, "win"])
    universe = set(win)
    ev_win = events.set_index("event_id").win

    def windows_of(alert_rows):
        ids = {e for es in alert_rows.evidence for e in es}
        return set(ev_win.reindex(list(ids)).dropna())

    def window_metrics(alert_rows):
        pred = windows_of(alert_rows) if len(alert_rows) else set()
        tp = len(pred & truth)
        fp = len(pred - truth)
        fn = len(truth - pred)
        return _prf(tp, fp, fn, len(universe) - tp - fp - fn)

    alerts = alerts.assign(malicious=alerts.evidence.map(lambda es: bool((ev.loc[es, "campaign"] != "").any())))
    rules_only = alerts[alerts.rule_id != "ML-ANOMALY"]
    ml_only = alerts[alerts.rule_id == "ML-ANOMALY"]

    per_campaign = []
    for cid, name in CAMPAIGNS.items():
        c_ids = set(events.loc[events.campaign == cid, "event_id"])
        hits = alerts[alerts.evidence.map(lambda es: bool(c_ids & set(es)))]
        incs = sorted({i for i in hits.incident_id})
        top = max([i for i in incidents if i["incident_id"] in incs], key=lambda i: i["score"], default=None)
        per_campaign.append({
            "campaign": cid, "name": name, "events": len(c_ids), "detected": bool(len(hits)),
            "detected_by": sorted(hits.rule_id.unique()), "alerts": int(len(hits)), "incidents": len(incs),
            "top_severity": top["severity"] if top else None, "top_score": top["score"] if top else None,
            "why_missed": None if len(hits) else WHY_MISSED.get(cid, "not detected"),
        })

    tp_inc = [i for i in incidents if i["ground_truth"] != "benign"]
    fp_inc = [i for i in incidents if i["ground_truth"] == "benign"]
    ranked = sorted(incidents, key=lambda i: -i["score"])
    k = len(tp_inc)
    precision_at_k = sum(i["ground_truth"] != "benign" for i in ranked[:k]) / k if k else 0.0
    mixed = [i for i in tp_inc if "," in i["ground_truth"]]

    per_rule = (alerts.groupby("rule_id").agg(alerts=("alert_id", "size"), true_alerts=("malicious", "sum"))
                .assign(precision=lambda d: (d.true_alerts / d.alerts).round(3)).reset_index().to_dict("records"))
    fp_sources = (pd.Series([i["title"].split(" - ")[0] for i in fp_inc]).value_counts().to_dict())

    return {
        "data": {"events": int(len(events)), "attack_events": int(mal.sum()), "windows": len(universe),
                 "malicious_windows": len(truth)},
        "detection_combined": window_metrics(alerts),
        "detection_rules_only": window_metrics(rules_only),
        "detection_anomaly_only": window_metrics(ml_only),
        "alert_precision": round(float(alerts.malicious.mean()), 3) if len(alerts) else 0.0,
        "campaign_recall": round(sum(c["detected"] for c in per_campaign) / len(per_campaign), 3),
        "per_campaign": per_campaign,
        "per_rule": per_rule,
        "correlation": {
            "alerts": int(len(alerts)), "incidents": len(incidents),
            "alert_reduction": round(1 - len(incidents) / len(alerts), 3) if len(alerts) else 0.0,
            "true_incidents": len(tp_inc), "false_positive_incidents": len(fp_inc),
            "true_attack_alerts": int(alerts.malicious.sum()),
            "true_attack_alerts_per_incident": round(alerts.malicious.sum() / len(tp_inc), 1) if tp_inc else 0,
            "incidents_mixing_campaigns": len(mixed),
            "false_positive_sources": fp_sources,
        },
        "prioritisation": {
            "precision_at_k": round(precision_at_k, 3), "k": k,
            "mean_score_true": round(sum(i["score"] for i in tp_inc) / len(tp_inc), 1) if tp_inc else None,
            "mean_score_false": round(sum(i["score"] for i in fp_inc) / len(fp_inc), 1) if fp_inc else None,
            "top5": [{"id": i["incident_id"], "score": i["score"], "truth": i["ground_truth"],
                      "title": i["title"]} for i in ranked[:5]],
        },
        "triage_queue": {"before_alerts": int(len(alerts)), "after_incidents": len(incidents),
                         "after_high_or_critical": sum(i["severity"] in ("High", "Critical") for i in incidents)},
        "ai_reliability": {
            "mode": sorted({i["ai_mode"] for i in incidents}),
            "mean_supported_sentence_rate": round(sum(i["ai_support"] for i in incidents) / len(incidents), 3)
            if incidents else 0.0,
            "sentences_checked": sum(len(i["ai_checks"]) for i in incidents),
            "unsupported_sentences": sum(not c["supported"] for i in incidents for c in i["ai_checks"]),
        },
    }


def run(use_llm: bool = False) -> dict:
    now = datetime.now(timezone.utc)
    dev = historical_dataset(SEED)
    model = AnomalyModel().fit(dev)
    out = {"generated_at": now.isoformat(timespec="seconds"), "dev_seed": SEED, "test_seed": TEST_SEED,
           "note": "Synthetic controlled-lab data. Thresholds were tuned on 'development'; 'test' is held out."}
    for name, seed in (("development", SEED), ("test", TEST_SEED)):
        events = dev if seed == SEED else historical_dataset(seed, dataset="historical_test")
        alerts = detect_all(events, model)
        alerts, incidents = build_incidents(events, alerts, alert_start=1, inc_start=1, dataset=name,
                                            created_at=now, use_llm=use_llm)
        out[name] = evaluate_run(events, alerts, incidents)
    REPORT_DIR.mkdir(exist_ok=True)
    (REPORT_DIR / "metrics.json").write_text(json.dumps(out, indent=2, default=str))
    (REPORT_DIR / "EVALUATION.md").write_text(render_markdown(out), encoding="utf-8")
    return out


def render_markdown(m: dict) -> str:
    t = m["test"]
    d = m["development"]
    lines = [
        "# SecureOps AI - Evaluation report", "",
        f"Generated {m['generated_at']} by `python -m secureops.evaluate`. {m['note']}", "",
        "## Detection (source-IP x hour windows)", "",
        "| Set | Detector | Precision | Recall | F1 | False-positive rate |", "|---|---|---|---|---|---|"]
    for set_name, r in (("test (held-out)", t), ("development", d)):
        for key, label in (("detection_combined", "Rules + anomaly"), ("detection_rules_only", "Rules only"),
                           ("detection_anomaly_only", "Anomaly only")):
            x = r[key]
            lines.append(f"| {set_name} | {label} | {x['precision']:.2f} | {x['recall']:.2f} | {x['f1']:.2f} | "
                         f"{x['false_positive_rate']:.2%} |")
    c = t["correlation"]
    lines += ["", "## Alert overload (test set)", "",
              f"- {c['alerts']} alerts were correlated into {c['incidents']} incidents "
              f"(**{c['alert_reduction']:.1%} fewer items** to triage).",
              f"- {c['true_incidents']} incidents contain real attacks; {c['false_positive_incidents']} are false positives "
              f"({', '.join(f'{k}: {v}' for k, v in c['false_positive_sources'].items())}).",
              f"- Incidents mixing more than one campaign: {c['incidents_mixing_campaigns']}.",
              f"- Triage queue: {t['triage_queue']['before_alerts']} alerts -> {t['triage_queue']['after_incidents']} "
              f"incidents, of which {t['triage_queue']['after_high_or_critical']} are High/Critical.", "",
              "## Prioritisation (test set)", "",
              f"- Precision@{t['prioritisation']['k']} (real attacks among the top-ranked incidents): "
              f"{t['prioritisation']['precision_at_k']:.2f}",
              f"- Mean priority score: real {t['prioritisation']['mean_score_true']} vs false positive "
              f"{t['prioritisation']['mean_score_false']}", "",
              "## Per-scenario results (test set)", "",
              "| Campaign | Detected | By | Alerts | Incidents | Top severity | Why missed |", "|---|---|---|---|---|---|---|"]
    for p in t["per_campaign"]:
        lines.append(f"| {p['campaign']} {p['name']} | {'yes' if p['detected'] else '**NO**'} | "
                     f"{', '.join(p['detected_by']) or '-'} | {p['alerts']} | {p['incidents']} | {p['top_severity'] or '-'} | "
                     f"{p['why_missed'] or ''} |")
    a = t["ai_reliability"]
    lines += ["", "## AI reliability (test set)", "",
              f"- Mode: {', '.join(a['mode'])}",
              f"- Sentences with valid evidence citations: **{a['mean_supported_sentence_rate']:.1%}** "
              f"({a['sentences_checked']} sentences checked, {a['unsupported_sentences']} unsupported).",
              "- In offline mode sentences are composed from evidence, so ~100% is expected by construction; the "
              "check is meaningful when an LLM (Groq/Ollama) is enabled: `python -m secureops.evaluate --llm`.", "",
              "## Limitations", "",
              "- Data is synthetic, generated in a controlled lab simulation - not production traffic.",
              "- Triage *time* was not measured with real analysts; only queue size is reported. The dashboard "
              "measures time-to-acknowledge and time-to-resolve from real actions taken in the app.",
              "- The anomaly detector produces most false positives (benign workstation bursts and login typos).",
              "- Stealthy scenarios (low-and-slow, small exfiltration, valid-account misuse) are listed above when missed."]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    import sys

    res = run(use_llm="--llm" in sys.argv)
    print(render_markdown(res))
