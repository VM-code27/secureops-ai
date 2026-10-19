# Free deployment guide

Everything runs on free tiers with no credit card. Choose how far you want to go:

| Level | What you get | Services |
|---|---|---|
| **1. Portfolio demo** (10 min) | Dashboard streaming real UWF Zeek data, live threat intel / NVD / KEV / EPSS / ATT&CK, log upload, case management | GitHub + Streamlit Community Cloud |
| **2. + AI and persistence** (+5 min) | LLM explanations; cases, settings and audit trail survive restarts | + Groq key + Neon Postgres |
| **3. + Live sensor** (+20 min) | Your own Zeek/Suricata sensor streaming real traffic into the same dashboard | + Render (API) + a Linux box / Raspberry Pi / WSL2 |

> **Why not Vercel?** Vercel hosts websites and short serverless functions. This app is a long-running Python
> process (Streamlit websockets, scikit-learn, a database, background streaming), which is exactly what Streamlit
> Community Cloud and Render provide for free.

## Level 1 - Dashboard on Streamlit Community Cloud

1. Push the repo to GitHub:
   ```bash
   git remote add origin https://github.com/<you>/secureops-ai.git
   git push -u origin main
   ```
2. Go to <https://share.streamlit.io>, then **Create app → Deploy a public app from GitHub**. Choose your repo, branch `main` and main file `streamlit_app.py`.
3. **Advanced settings**: set Python to **3.12**.
4. Deploy. The first visit builds everything from live sources (UWF dataset, abuse.ch, Spamhaus, CISA KEV and MITRE ATT&CK), which takes about 1–2 minutes and shows its progress. After that, open **Live data** and turn on **Auto-stream**.

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

## Level 3 - Live sensor streaming real traffic

The sensor pushes logs to the API, and the API writes them to the same Neon database the dashboard reads.

1. **API on Render** (free): <https://render.com>, then **New → Blueprint**, then select the repo (it reads `render.yaml`).
   - Set `DATABASE_URL` to the same Neon URL.
   - Render generates `SECUREOPS_API_TOKEN` for you; copy it.
   - Optionally set `GROQ_API_KEY`.
   - Check that `https://<name>.onrender.com/health` responds. Interactive docs are at `/docs`.
   - The free tier sleeps after 15 minutes idle. The sensor's next push wakes it, and the shipper retries automatically.
2. Add `API_PUBLIC_URL = "https://<name>.onrender.com"` to the Streamlit secrets so the dashboard shows the right instructions.
3. **Sensor** (any Linux machine, Raspberry Pi 4/5, or WSL2 on Windows with Docker):
   ```bash
   git clone https://github.com/<you>/secureops-ai.git && cd secureops-ai/sensor
   cp .env.example .env   # IFACE=eth0, API_URL=https://<name>.onrender.com, API_TOKEN=<token from Render>
   docker compose up -d   # Zeek + Suricata (with ET Open rules) + log shipper
   docker compose logs -f shipper
   ```
   New connections show up in the dashboard as `live` data within seconds. Detections, incidents, asset discovery and threat-intel matches all run on them.
4. **No Linux box?** Capture traffic with Wireshark on Windows and save it as `.pcap`. Then either run `sensor/process_pcap.sh capture.pcap` on any machine with Docker, or upload the resulting `conn.log` / `eve.json` on **Live data → Upload logs**.

> Only monitor networks you own or are authorised to monitor.

## Make it yours

- **Settings page:** set your team (case owners), home networks, allow-listed sources, thresholds, scoring weights and SLAs.
- **Assets page:** download the discovered inventory as CSV, add hostnames, criticality, owners and CPEs, re-upload it, then click **Look up CVEs (live NVD)**. Incidents are re-scored with real CVSS, CISA KEV and EPSS exposure.
- **Evaluation:** `python -m secureops.evaluate --llm-sample 20` (with `GROQ_API_KEY` set) regenerates `reports/` with measured LLM citation accuracy.
- Replace the placeholder links at the top of `README.md` with your live URLs.
