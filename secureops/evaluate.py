"""Evaluation on REAL labelled data (UWF-ZeekData24, MITRE ATT&CK labels).

The full 18-day replay is streamed through the production pipeline into a separate,
throw-away database with the current settings. Metrics are reported for:
  * development - the first `replay.history_days` days (thresholds were sanity-checked here)
  * test        - every later day, never used for any choice (held out in time)

Detection unit: one source IP in one clock hour ("window"). A window is truly malicious
if it contains a labelled attack connection, and predicted malicious if any alert cites
an event from it as evidence.

Run:  python -m secureops.evaluate
"""
from __future__ import annotations

import json
import sys
import time

import pandas as pd

from . import assets, config, db, pipeline, settings
from .intel import feeds
from .sources import replay, uwf

REPORT_DIR = config.ROOT / "reports"


def _clear_caches():
    assets._cache.clear()
    feeds._index["value"] = None
    pipeline._model.clear()
    settings._cache["value"] = None


def _prf(tp, fp, fn, tn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"precision": round(p, 3), "recall": round(r, 3), "f1": round(2 * p * r / (p + r), 3) if p + r else 0.0,
            "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
            "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn)}


def _period_metrics(ev: pd.DataFrame, alerts: pd.DataFrame, incidents: pd.DataFrame) -> dict:
    ev = ev.assign(win=list(zip(ev.src_ip, ev.ts.dt.floor("h"))), attack=ev.tactic.fillna("") != "")
    universe = set(ev.win)
    truth = set(ev.loc[ev.attack, "win"])
    win_of = ev.set_index("event_id").win
    attack_ids = set(ev.loc[ev.attack, "event_id"])

    def windows(rows):
        return set(win_of.reindex(list({e for es in rows.evidence for e in es})).dropna())

    def detect(rows):
        pred = windows(rows) & universe if len(rows) else set()
        tp, fp, fn = len(pred & truth), len(pred - truth), len(truth - pred)
        return _prf(tp, fp, fn, len(universe) - tp - fp - fn)

    alerts = alerts.assign(malicious=alerts.evidence.map(lambda es: bool(attack_ids & set(es))))
    flagged = windows(alerts)
    tactics = ev[ev.attack].assign(t=lambda d: d.tactic.str.split(",")).explode("t")
    cited = {e for es in alerts.evidence for e in es}
    per_tactic = []
    for t, g in tactics.groupby("t"):
        hit = alerts[alerts.evidence.map(lambda es: bool(set(g.event_id) & set(es)))]
        per_tactic.append({"tactic": t, "events": int(len(g)), "windows": int(g.win.nunique()),
                           "windows_detected": round(g.win.isin(flagged).groupby(g.win).first().mean(), 3),
                           "events_cited_as_evidence": round(g.event_id.isin(cited).mean(), 3),
                           "detected_by": sorted(hit.rule_id.unique()), "incidents": int(hit.incident_id.nunique())})

    inc = incidents.copy()
    by_inc = alerts.groupby("incident_id").malicious.any()
    inc["true"] = inc.incident_id.map(by_inc).fillna(False).astype(bool)
    k = int(inc.true.sum())
    ranked = inc.sort_values("score", ascending=False)
    rules = (alerts.groupby("rule_id").agg(alerts=("alert_id", "size"), true_alerts=("malicious", "sum"))
             .assign(precision=lambda d: (d.true_alerts / d.alerts).round(3)).reset_index().to_dict("records"))
    checks = [c for cs in inc.ai_checks.map(lambda x: json.loads(x) if isinstance(x, str) else x) for c in cs]
    return {
        "data": {"events": int(len(ev)), "attack_events": int(ev.attack.sum()), "windows": len(universe),
                 "attack_windows": len(truth), "days": int(ev.ts.dt.normalize().nunique())},
        "detection_combined": detect(alerts),
        "detection_rules_only": detect(alerts[alerts.rule_id != "ML-ANOMALY"]),
        "detection_anomaly_only": detect(alerts[alerts.rule_id == "ML-ANOMALY"]),
        "alert_precision": round(float(alerts.malicious.mean()), 3) if len(alerts) else 0.0,
        "per_tactic": sorted(per_tactic, key=lambda x: -x["events"]),
        "per_rule": rules,
        "correlation": {"alerts": int(len(alerts)), "incidents": int(len(inc)),
                        "alert_reduction": round(1 - len(inc) / len(alerts), 3) if len(alerts) else 0.0,
                        "true_incidents": k, "false_positive_incidents": int((~inc.true).sum())},
        "prioritisation": {"k": k, "precision_at_k": round(float(ranked.head(k).true.mean()), 3) if k else 0.0,
                           "mean_score_true": round(float(inc[inc.true].score.mean()), 1) if k else None,
                           "mean_score_false": round(float(inc[~inc.true].score.mean()), 1) if (~inc.true).any() else None,
                           "severity_true": inc[inc.true].severity.value_counts().to_dict(),
                           "severity_false": inc[~inc.true].severity.value_counts().to_dict()},
        "ai_reliability": {"mode": sorted(inc.ai_mode.unique().tolist()),
                           "mean_supported_sentence_rate": round(float(inc.ai_support.mean()), 3) if len(inc) else 0.0,
                           "sentences_checked": len(checks),
                           "unsupported_sentences": sum(not c["supported"] for c in checks)},
    }


def _llm_sample(split, n: int, progress) -> dict:
    """Measure the LLM for real: regenerate explanations for n held-out incidents (highest
    priority first, then a spread across the rest) and check every citation."""
    from . import assistant
    if not assistant.llm_available() or n <= 0:
        return {}
    inc = db.list_incidents()
    inc = inc[(inc.first_seen >= split) & ~inc.resolution.fillna("").str.startswith("Merged into")]
    top = inc.head(n // 2)
    rest = inc.iloc[n // 2:]
    pick = pd.concat([top, rest.iloc[:: max(1, len(rest) // max(1, n - len(top)))].head(n - len(top))])
    rows = []
    for i, iid in enumerate(pick.incident_id):
        progress(f"LLM explanation {i + 1}/{len(pick)} ({iid})")
        ex = pipeline.regenerate_explanation(iid, use_llm=True)
        if ex["mode"].startswith("offline"):
            rows.append({"incident": iid, "error": ex["note"]})
            continue
        rows.append({"incident": iid, "mode": ex["mode"], "support": ex["support_rate"], "sentences": len(ex["checks"]),
                     "unsupported": [c["sentence"][:160] + " -> " + c["reason"] for c in ex["checks"] if not c["supported"]]})
        time.sleep(2)  # stay inside free-tier rate limits
    ok = [r for r in rows if "support" in r]
    sents = sum(r["sentences"] for r in ok)
    return {"model": ok[0]["mode"] if ok else None, "incidents": len(ok), "failed_calls": len(rows) - len(ok),
            "sentences": sents, "unsupported_sentences": sum(len(r["unsupported"]) for r in ok),
            "sentence_support_rate": round(1 - sum(len(r["unsupported"]) for r in ok) / sents, 3) if sents else None,
            "examples_of_unsupported": [u for r in ok for u in r["unsupported"]][:8]}


def run(use_llm: bool = False, progress=print, llm_sample: int = 0) -> dict:
    live_overrides = settings.overrides()
    live_intel = db.read_intel()
    tmp = config.CACHE_DIR / "evaluation.db"
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.unlink(missing_ok=True)
    db.use_database(f"sqlite:///{tmp.as_posix()}")
    _clear_caches()
    try:
        db.reset()
        settings.save(live_overrides)
        for src, g in live_intel.groupby("source"):
            db.replace_intel(src, g)
        full = uwf.load()
        replay.advance(full.ts.max() + pd.Timedelta(seconds=1), progress=progress, use_llm=use_llm)
        ev = db.read_events().merge(db.read_labels(), on="event_id", how="left")
        alerts = db.read_alerts()
        inc = db.list_incidents()
        inc = inc[~inc.resolution.fillna("").str.startswith("Merged into")]
        split = full.ts.min().floor("D") + pd.Timedelta(days=settings.section("replay")["history_days"])
        out = {"generated_at": db.now().isoformat(timespec="seconds"), "dataset": "UWF-ZeekData24 (real Zeek conn logs, "
               "MITRE ATT&CK labels, CC BY 4.0)", "split_at": split.isoformat(), "settings": settings.get()["detection"],
               "model": db.get_meta("anomaly_model")}
        for name, sel_ev, sel_al, sel_in in (
                ("development", ev.ts < split, alerts.ts < split, inc.first_seen < split),
                ("test", ev.ts >= split, alerts.ts >= split, inc.first_seen >= split)):
            out[name] = _period_metrics(ev[sel_ev], alerts[sel_al], inc[sel_in])
        out["llm_reliability"] = _llm_sample(split, llm_sample, progress)
    finally:
        db.use_database(None)
        _clear_caches()
    REPORT_DIR.mkdir(exist_ok=True)
    (REPORT_DIR / "metrics.json").write_text(json.dumps(out, indent=2, default=str))
    (REPORT_DIR / "EVALUATION.md").write_text(render_markdown(out), encoding="utf-8")
    return out


def render_markdown(m: dict) -> str:
    t, d = m["test"], m["development"]
    lines = ["# SecureOps AI - Evaluation on real labelled data", "",
             f"Generated {m['generated_at']} by `python -m secureops.evaluate`.", "",
             f"**Data:** {m['dataset']}. {t['data']['days'] + d['data']['days']} days replayed through the production "
             f"pipeline. Development = first {d['data']['days']} days; **test = the {t['data']['days']} later days "
             f"(held out in time)**.", "",
             "**Caveat:** UWF captured benign and attack traffic in different weeks; each attack day is overlaid with a "
             "real benign day (date shifted, time-of-day kept). Labels are used only here, never by the detectors.", "",
             "## Detection (source-IP x hour windows)", "",
             "| Period | Detector | Precision | Recall | F1 | False-positive rate |", "|---|---|---|---|---|---|"]
    for name, r in (("test (held-out)", t), ("development", d)):
        for key, lab in (("detection_combined", "Rules + anomaly"), ("detection_rules_only", "Rules only"),
                         ("detection_anomaly_only", "Anomaly only")):
            x = r[key]
            lines.append(f"| {name} | {lab} | {x['precision']:.2f} | {x['recall']:.2f} | {x['f1']:.2f} | "
                         f"{x['false_positive_rate']:.2%} |")
    lines += ["", "## Per ATT&CK tactic (test)", "",
              "| Tactic | Attack events | Windows | Windows detected | Events cited as evidence | Detected by |",
              "|---|---|---|---|---|---|"]
    for p in t["per_tactic"]:
        lines.append(f"| {p['tactic']} | {p['events']:,} | {p['windows']} | {p['windows_detected']:.0%} | "
                     f"{p['events_cited_as_evidence']:.0%} | {', '.join(p['detected_by']) or '**missed**'} |")
    c, pr, a = t["correlation"], t["prioritisation"], t["ai_reliability"]
    lines += ["", "## Alert overload and prioritisation (test)", "",
              f"- {c['alerts']:,} alerts -> {c['incidents']} incidents (**{c['alert_reduction']:.1%} fewer items to triage**).",
              f"- {c['true_incidents']} incidents contain real attack traffic; {c['false_positive_incidents']} are false positives.",
              f"- Precision@{pr['k']}: {pr['precision_at_k']:.2f}. Mean score real {pr['mean_score_true']} vs false "
              f"{pr['mean_score_false']}.",
              f"- Severity of real incidents: {pr['severity_true']}; of false positives: {pr['severity_false']}.", "",
              "## AI reliability (test)", "",
              f"- Mode: {', '.join(a['mode'])}. Sentences citing valid evidence: **{a['mean_supported_sentence_rate']:.1%}** "
              f"({a['sentences_checked']} checked, {a['unsupported_sentences']} unsupported). In offline mode this is ~100% "
              "by construction - which is why the LLM is measured separately below.", ""]
    llm = m.get("llm_reliability") or {}
    if llm.get("incidents"):
        lines += ["## LLM reliability (measured, test incidents)", "",
                  f"- Model: `{llm['model']}` on {llm['incidents']} held-out incidents ({llm['failed_calls']} failed calls).",
                  f"- **{llm['sentence_support_rate']:.1%} of {llm['sentences']} generated sentences cite only evidence that "
                  f"exists** ({llm['unsupported_sentences']} unsupported, flagged to the analyst in the UI).", ""]
        lines += [f"  - e.g. {u}" for u in llm["examples_of_unsupported"][:4]]
        lines += [""]
    else:
        lines += ["## LLM reliability", "", "- Not measured in this run (no LLM key). Run "
                  "`GROQ_API_KEY=... python -m secureops.evaluate --llm-sample 20`.", ""]
    lines += [
              "## Limitations", "",
              "- Only Zeek conn metadata is available in this dataset (no payloads, auth logs or IDS alerts), so single "
              "SMB sessions labelled Persistence / Privilege Escalation / Defense Evasion / Exfiltration look like normal "
              "connections and are largely missed - see the per-tactic table.",
              "- Reconnaissance in this dataset is very slow (a few probes per hour) and stays below standard scan "
              "thresholds; whatever is caught comes from the anomaly model.",
              "- All hosts are inside one /16, so rules that need an external destination (exfiltration, threat intel) "
              "cannot fire on this dataset; they are exercised by live sensor data and the test suite.",
              "- Triage time was not measured with real analysts; the dashboard measures time-to-acknowledge and "
              "time-to-resolve from the audit trail."]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    n = int(sys.argv[sys.argv.index("--llm-sample") + 1]) if "--llm-sample" in sys.argv else 0
    res = run(llm_sample=n)
    sys.stdout.reconfigure(encoding="utf-8")  # LLM text can contain characters a Windows console code page lacks
    print(render_markdown(res))
