# SecureOps AI — Intelligent Threat Detection and Response

**Live demo:** `https://<your-app>.streamlit.app` · **API docs:** `https://<your-api>.onrender.com/docs`

SecureOps AI is a working security operations platform for a simulated enterprise of **500 devices** (20 servers, 380 workstations, 100 IoT devices). It ingests network and authentication telemetry, detects threats, **correlates hundreds of alerts into a small number of incidents**, ranks them by real risk, explains each one with an **evidence-cited AI assistant**, and lets analysts work the case, approve responses and keep an audit trail.

![Overview](docs/overview.png)

## What it demonstrates

A suspicious event enters the system, is **detected**, **linked to related events**, turned into a **prioritised incident**, **explained by the AI assistant** with citations to the raw logs, and **assigned to a human analyst**. Open *Live attack demo* in the app and click **Inject & run pipeline** to see the whole chain.

| Feature | How it works |
|---|---|
| **Threat detection** | 8 rules mapped to MITRE ATT&CK (brute force, success-after-brute-force, password spray, port scan, lateral movement, large exfiltration, threat-intel match, IDS exploit signature) plus an unsupervised **Isolation Forest** on per-host-hour behaviour |
| **Incident correlation** | Union-find over alerts that share an entity (IP, excluding shared infrastructure such as DNS or the DC) within 120 min, so scan → exploit → C2 → lateral movement → exfiltration becomes **one** incident |
| **Prioritisation** | `45% threat confidence + 25% asset criticality + 20% vulnerability exposure + 10% spread`. Exposure comes from **real NVD CVE records**, and an exploit signature that names a CVE the target actually runs is flagged *confirmed exploitable* |
| **AI investigation assistant** | RAG: retrieves alerts, raw events, assets, CVEs and response playbooks (TF-IDF) → LLM (Groq free tier or local Ollama) or offline evidence engine → **every sentence must cite evidence IDs**, and a verifier checks that each cited ID exists |
| **Case management** | Owner, status, SLA by severity, resolution notes, false-positive marking, analyst-approved (simulated) response actions, ticket export, and a full audit log |
| **Analytics dashboard** | Top threats, affected systems, unresolved incidents by severity, alert timeline, and MTTA/MTTR measured from real actions in the audit trail |

## Measured results (held-out test set)

Thresholds were tuned on a development dataset (seed 42). The results below come from a **separate held-out dataset** (seed 1337) with different traffic and attack timing. Full report: [reports/EVALUATION.md](reports/EVALUATION.md). Regenerate it with `python -m secureops.evaluate`.

| Metric | Result |
|---|---|
| Detection, rules + anomaly (source-IP × hour windows) | Precision **0.45** · Recall **0.62** · F1 **0.52** · FPR **0.30%** |
| Rules only | Precision 0.77 · Recall 0.18 |
| Alert overload | **399 alerts → 48 incidents (88% fewer items)**; 0 incidents mix different attacks |
| Prioritisation | Precision@5 = 0.80; mean score of real attacks 72 vs false positives 39 |
| Campaigns detected | 5 of 7 |
| AI evidence support | 100% of sentences cite valid evidence (offline engine; 100% is by construction, so enable an LLM for a meaningful test) |

**Where it fails (by design, reported openly):**
- **C6 slow exfiltration**: about 4 MB/hour over HTTPS to an unlisted host looks like normal uploads.
- **C7 stolen-credential login**: one valid VPN login followed by normal file access matches no rule and is not statistically unusual.
- **False positives**: most come from the Isolation Forest (benign workstation bursts). A user typing their password wrong 12 times and a nightly offsite backup also become incidents, which the analyst can mark as false positives.
- **Triage time**: before/after was **not** measured with real analysts, so only queue size is claimed.

## Data, honestly labelled

- **Historical, labelled**: 48 h of synthetic controlled-lab traffic (about 32k Zeek-style conn logs, Suricata alerts and auth logs) with 7 attack campaigns and realistic false-positive sources. Labels are used **only** for evaluation and are never seen by the detectors.
- **Live, unlabelled**: events injected from the dashboard or API, stamped with the current time.
- **Real data**: 12 CVE records from the **NVD API 2.0** (`data/nvd_cache.json`, refresh with `python scripts/refresh_nvd.py`).
- All external IPs are RFC 5737 documentation addresses, so no real host is named as an attacker.

## Run locally (5 minutes)

```bash
pip install -r requirements.txt
streamlit run streamlit_app.py          # dashboard  -> http://localhost:8501
uvicorn api.main:app --reload           # REST API   -> http://localhost:8000/docs
python -m secureops.evaluate            # metrics    -> reports/EVALUATION.md
pytest -q                               # tests
```

Or run the whole stack with Postgres (and optionally Ollama): `docker compose up --build`.

**Optional free LLM:** create a key at [console.groq.com](https://console.groq.com/keys), then `export GROQ_API_KEY=...`. For a fully local setup, use Ollama with `OLLAMA_URL=http://localhost:11434`. Without either, the offline evidence engine is used and nothing breaks.

## Free deployment

See **[DEPLOY.md](DEPLOY.md)**: Streamlit Community Cloud (dashboard), optional Render (API), Neon (persistent Postgres) and Groq (LLM), all on free tiers.

## Project layout

```
secureops/
  simulate.py        lab log generator (benign baseline, FP sources, 7 attack campaigns, live scenarios)
  assets.py          500-device inventory with criticality, software and CVEs
  nvd.py             NVD API 2.0 client + offline cache
  detection/rules.py ATT&CK-mapped detection rules
  detection/anomaly.py  Isolation Forest per host-hour
  correlation.py     alert -> incident correlation (union-find)
  scoring.py         risk-based prioritisation + SLA
  assistant.py       RAG investigation assistant + citation verifier
  db.py              SQLite / PostgreSQL persistence, case management, audit log
  pipeline.py        ingest -> detect -> correlate -> score -> explain -> store
  evaluate.py        precision/recall/F1, FPR, alert reduction, AI reliability
api/main.py          FastAPI service
streamlit_app.py     analyst dashboard
playbooks/           response playbooks (RAG knowledge base)
reports/             generated evaluation report
```

**Stack:** Python · Pandas · SQL · scikit-learn · FastAPI · PostgreSQL/SQLite · Streamlit · Altair · Groq/Ollama · Docker · GitHub Actions.

**Not included yet:** live Zeek/Suricata sensors and Splunk integration. The normalised event schema (`ts, src_ip, dst_ip, dst_port, service, conn_state, bytes, user, outcome, signature`) is the integration point for real `conn.log` / `eve.json` exports.
