# SecureOps AI - Evaluation report

Generated 2026-10-19T09:51:50+00:00 by `python -m secureops.evaluate`. Synthetic controlled-lab data. Thresholds were tuned on 'development'; 'test' is held out.

## Detection (source-IP x hour windows)

| Set | Detector | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|---|
| test (held-out) | Rules + anomaly | 0.45 | 0.62 | 0.52 | 0.30% |
| test (held-out) | Rules only | 0.77 | 0.18 | 0.29 | 0.02% |
| test (held-out) | Anomaly only | 0.43 | 0.55 | 0.48 | 0.29% |
| development | Rules + anomaly | 0.53 | 0.64 | 0.58 | 0.21% |
| development | Rules only | 0.69 | 0.17 | 0.27 | 0.03% |
| development | Anomaly only | 0.52 | 0.57 | 0.54 | 0.20% |

## Alert overload (test set)

- 399 alerts were correlated into 48 incidents (**88.0% fewer items** to triage).
- 5 incidents contain real attacks; 43 are false positives (Behavioural anomaly (Isolation Forest): 40, Large outbound data transfer: 2, Brute-force authentication: 1).
- Incidents mixing more than one campaign: 0.
- Triage queue: 399 alerts -> 48 incidents, of which 5 are High/Critical.

## Prioritisation (test set)

- Precision@5 (real attacks among the top-ranked incidents): 0.80
- Mean priority score: real 72.1 vs false positive 39.1

## Per-scenario results (test set)

| Campaign | Detected | By | Alerts | Incidents | Top severity | Why missed |
|---|---|---|---|---|---|---|
| C1 Multi-stage intrusion (scan > exploit > C2 > lateral > exfil) | yes | ML-ANOMALY, R-EXFIL, R-IDS, R-IOC, R-LATERAL, R-SCAN | 198 | 1 | Critical |  |
| C2 SSH brute force leading to account compromise | yes | ML-ANOMALY, R-BRUTE, R-BRUTE-OK, R-IOC | 92 | 1 | Critical |  |
| C3 VPN password spray | yes | ML-ANOMALY, R-BRUTE, R-SPRAY | 35 | 1 | High |  |
| C4 IoT camera exploitation and botnet C2 | yes | ML-ANOMALY, R-IDS | 4 | 1 | High |  |
| C5 Low-and-slow port scan (hard) | yes | ML-ANOMALY | 25 | 1 | Low |  |
| C6 Slow data exfiltration over HTTPS (hard) | **NO** | - | 0 | 0 | - | ~4 MB per hour over HTTPS to an unlisted host looks like normal web uploads |
| C7 Valid-account misuse with stolen credentials (hard) | **NO** | - | 0 | 0 | - | a single successful VPN login with valid credentials followed by normal-looking file access matches no rule and is not statistically unusual |

## AI reliability (test set)

- Mode: offline-evidence-template
- Sentences with valid evidence citations: **100.0%** (490 sentences checked, 0 unsupported).
- In offline mode sentences are composed from evidence, so ~100% is expected by construction; the check is meaningful when an LLM (Groq/Ollama) is enabled: `python -m secureops.evaluate --llm`.

## Limitations

- Data is synthetic, generated in a controlled lab simulation - not production traffic.
- Triage *time* was not measured with real analysts; only queue size is reported. The dashboard measures time-to-acknowledge and time-to-resolve from real actions taken in the app.
- The anomaly detector produces most false positives (benign workstation bursts and login typos).
- Stealthy scenarios (low-and-slow, small exfiltration, valid-account misuse) are listed above when missed.
