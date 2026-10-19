# SecureOps AI - Evaluation on real labelled data

Generated 2026-10-19T10:52:06+00:00 by `python -m secureops.evaluate`.

**Data:** UWF-ZeekData24 (real Zeek conn logs, MITRE ATT&CK labels, CC BY 4.0). 18 days replayed through the production pipeline. Development = first 5 days; **test = the 13 later days (held out in time)**.

**Caveat:** UWF captured benign and attack traffic in different weeks; each attack day is overlaid with a real benign day (date shifted, time-of-day kept). Labels are used only here, never by the detectors.

## Detection (source-IP x hour windows)

| Period | Detector | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|---|
| test (held-out) | Rules + anomaly | 0.97 | 0.33 | 0.49 | 0.50% |
| test (held-out) | Rules only | 1.00 | 0.32 | 0.48 | 0.00% |
| test (held-out) | Anomaly only | 0.63 | 0.02 | 0.03 | 0.50% |
| development | Rules + anomaly | 0.98 | 0.51 | 0.67 | 0.46% |
| development | Rules only | 1.00 | 0.50 | 0.67 | 0.00% |
| development | Anomaly only | 0.59 | 0.01 | 0.03 | 0.46% |

## Per ATT&CK tactic (test)

| Tactic | Attack events | Windows | Windows detected | Events cited as evidence | Detected by |
|---|---|---|---|---|---|
| Credential Access | 29,373 | 3642 | 36% | 61% | ML-ANOMALY, R-BRUTE |
| Reconnaissance | 2,095 | 1395 | 26% | 6% | ML-ANOMALY |
| Initial Access | 402 | 388 | 42% | 8% | ML-ANOMALY |
| Defense Evasion | 230 | 228 | 31% | 4% | ML-ANOMALY |
| Persistence | 230 | 228 | 31% | 4% | ML-ANOMALY |
| Privilege Escalation | 230 | 228 | 31% | 4% | ML-ANOMALY |
| Exfiltration | 18 | 17 | 0% | 0% | **missed** |

## Alert overload and prioritisation (test)

- 1,451 alerts -> 337 incidents (**76.8% fewer items to triage**).
- 307 incidents contain real attack traffic; 30 are false positives.
- Precision@307: 0.91. Mean score real 39.4 vs false 29.4.
- Severity of real incidents: {'Medium': 268, 'Low': 39}; of false positives: {'Low': 30}.

## AI reliability (test)

- Mode: offline-evidence-template. Sentences citing valid evidence: **100.0%** (3513 checked, 0 unsupported). In offline mode this is ~100% by construction - which is why the LLM is measured separately below.

## LLM reliability (measured, test incidents)

- Model: `groq:openai/gpt-oss-120b` on 20 held-out incidents (0 failed calls).
- **100.0% of 327 generated sentences cite only evidence that exists** (0 unsupported, flagged to the analyst in the UI).


## Limitations

- Only Zeek conn metadata is available in this dataset (no payloads, auth logs or IDS alerts), so single SMB sessions labelled Persistence / Privilege Escalation / Defense Evasion / Exfiltration look like normal connections and are largely missed - see the per-tactic table.
- Reconnaissance in this dataset is very slow (a few probes per hour) and stays below standard scan thresholds; whatever is caught comes from the anomaly model.
- All hosts are inside one /16, so rules that need an external destination (exfiltration, threat intel) cannot fire on this dataset; they are exercised by live sensor data and the test suite.
- Triage time was not measured with real analysts; the dashboard measures time-to-acknowledge and time-to-resolve from the audit trail.
