# Free deployment guide

Everything runs on free tiers with no credit card. Choose how far you want to go:

| Level | What you get | Services |
|---|---|---|
| **1. Portfolio demo** (10 min) | Dashboard streaming real UWF Zeek data, live threat intel / NVD / KEV / EPSS / ATT&CK, log upload, case management | GitHub + Streamlit Community Cloud |
| **2. + AI and persistence** (+5 min) | LLM explanations; cases, settings and audit trail survive restarts | + Groq key + Neon Postgres |
| **3. + Live sensor** (+20 min) | Your own Zeek/Suricata sensor streaming into the deployed dashboard over HTTPS, private API and dashboard | + Render (API) + Neon (shared DB) + a sensor host |

> **Why not Vercel?** Vercel hosts websites and short serverless functions. This app is a long-running Python
> process (Streamlit websockets, scikit-learn, a database, background streaming), which is exactly what Streamlit
> Community Cloud and Render provide for free.

## Level 1 - Dashboard on Streamlit Community Cloud

1. Push the repo to GitHub:
   ```bash
   git remote add origin https://github.com/VM-code27/secureops-ai.git
   git push -u origin main
   ```
2. Go to <https://share.streamlit.io>, then **Create app → Deploy a public app from GitHub**. Choose your repo, branch `main` and main file `streamlit_app.py`.
3. **Advanced settings**: set Python to **3.12**.
4. Deploy. The first visit builds everything from live sources (UWF dataset, abuse.ch, Spamhaus, CISA KEV and MITRE ATT&CK), which takes about 1–2 minutes and shows its progress. The **Live** screen then streams automatically.

## Level 2 - LLM + persistent database

1. **Groq** (free): create a key at <https://console.groq.com/keys>.
2. **Neon** (free Postgres): create a project at <https://neon.tech> and copy the connection string.
3. In Streamlit Cloud open **App → Settings → Secrets** and paste:
   ```toml
   GROQ_API_KEY = "gsk_..."
   DATABASE_URL = "postgresql://user:pass@ep-xxx.neon.tech/neondb?sslmode=require"
   ```
   The app restarts and rebuilds once into Neon. From then on, everything persists.

The Groq model is picked automatically from Groq's live model list (models get retired). To pin one, add `GROQ_MODEL = "<model id>"`.

## Level 3 - Live sensor streaming into the deployed dashboard (secure)

```
Sensor (laptop / Pi) --HTTPS + token--> API on Render --TLS--> Neon Postgres <--TLS-- Dashboard on Streamlit Cloud
```

The dashboard and the API must share **one** database (Level 2's Neon URL). Your sensor never talks to the
dashboard directly. It sends logs to the API, which writes them into Neon, and the dashboard reads them from there.

**Security built in**
- The API is **private by default**. Every endpoint except `GET /health` (which returns only status and version)
  needs the `X-API-Token` header, compared in constant time.
- The shipper **refuses plain HTTP** to any remote host, so the token and your traffic metadata only travel over TLS.
- Neon and Render both enforce TLS. Keep `?sslmode=require` in the database URL.
- Secrets live only in Streamlit secrets, Render environment variables and `sensor/.env` (git-ignored). Nothing
  goes into the repository.
- Sensor events older than `retention.live_event_days` (default 3) are deleted automatically. Events cited as
  evidence in an alert are kept, so the free 0.5 GB Neon tier does not fill up.

**Steps**
1. **Neon:** from Level 2 you have `postgresql://...neon.tech/neondb?sslmode=require` in the Streamlit secrets.
2. **API on Render** (free): <https://render.com> → **New → Blueprint** → select `VM-code27/secureops-ai`. Render reads
   `render.yaml`. When asked:
   - `DATABASE_URL`: the **same** Neon URL.
   - `GROQ_API_KEY`: optional.
   - `SECUREOPS_API_TOKEN` is generated for you. Open the service → **Environment** and copy it.

   Check `https://<service>.onrender.com/health` returns `{"status":"ok",...}`. The free instance sleeps after
   15 minutes without requests; a sensor pushing every 10 seconds keeps it awake.
3. **Make the dashboard private.** It now shows *your* network's addresses. Streamlit Cloud → your app → **Share** →
   **Who can view this app: Only specific people** → add your email (and anyone else you choose).
4. **Point the sensor at the API.** In `sensor/.env`:
   ```
   API_URL=https://<service>.onrender.com
   API_TOKEN=<the token from Render>
   SENSOR_NAME=home-lab
   ```
   Then `cd sensor && docker compose up -d --force-recreate shipper` and watch `docker compose logs -f shipper`.
   Within seconds the dashboard's **Live** screen shows the sensor as *streaming*.
5. **What the sensor sees.** On Docker Desktop (Windows/macOS) it sees only container traffic inside Docker's VM.
   To watch a real home or office network, run `sensor/` on a Raspberry Pi or Linux box connected to a router or
   switch **mirror (SPAN) port**.
6. **Rotate the token if it leaks.** Change `SECUREOPS_API_TOKEN` in Render, then update `sensor/.env`.

**No Linux box?** Capture with Wireshark, run `sensor/process_pcap.sh capture.pcap` with `API_URL` and `API_TOKEN`
set, and it uploads the resulting logs over HTTPS.

> Only monitor networks you own or are authorised to monitor.

## Make it yours

- **Settings** (top-right button): set your name, analyst team (case owners) and allow-listed sources. Thresholds, home networks, scoring weights and SLAs are in `config.yaml`.
- **Asset inventory:** `GET /assets` returns the discovered hosts. Add hostnames, criticality, owners and CPEs in a CSV, `POST` it to `/assets/inventory`, then `POST /assets/cves` for a live NVD lookup. Incidents are re-scored with real CVSS, CISA KEV and EPSS exposure.
- **Evaluation:** `python -m secureops.evaluate --llm-sample 20` (with `GROQ_API_KEY` set) regenerates `reports/` with measured LLM citation accuracy.
- Replace the placeholder links at the top of `README.md` with your live URLs.
