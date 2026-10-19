# Free deployment guide

Everything here runs on free tiers with no credit card.

| Piece | Free service | Required? |
|---|---|---|
| Code + CI | GitHub + GitHub Actions | yes |
| Dashboard (the portfolio link) | **Streamlit Community Cloud** | yes |
| LLM for the AI assistant | Groq free API key | optional (offline engine otherwise) |
| Persistent database | Neon free Postgres | optional (SQLite resets when the app restarts) |
| REST API | Render free web service | optional |

> **Why not Vercel?** Vercel is built for frontends and short serverless functions. This app needs a long-running Python process (scikit-learn, websockets for Streamlit, a database), so Streamlit Community Cloud is the right free host. If you still want a `vercel.app` link, put a one-page landing site there that links to the Streamlit app.

## 1. Push to GitHub

```bash
git init && git add . && git commit -m "SecureOps AI"
git branch -M main
git remote add origin https://github.com/<you>/secureops-ai.git
git push -u origin main
```
The **Actions** tab will run lint, tests, the evaluation and a Docker build on every push.

## 2. Deploy the dashboard (Streamlit Community Cloud)

1. Go to <https://share.streamlit.io> and sign in with GitHub.
2. **Create app → Deploy a public app from GitHub**, then choose repo `secureops-ai`, branch `main`, main file `streamlit_app.py`.
3. **Advanced settings**: set Python version **3.12**. Optionally paste secrets (see steps 3 and 4).
4. Pick a custom subdomain, e.g. `secureops-ai.streamlit.app`, and deploy.

On the first visit the app builds its lab database (about 10 seconds). Free apps sleep after a period without traffic; the next visitor wakes them up.

## 3. (Optional) Enable the LLM: Groq, free

1. Create a key at <https://console.groq.com/keys>.
2. In Streamlit Cloud open **App → Settings → Secrets** and add:
   ```toml
   GROQ_API_KEY = "gsk_..."
   ```
The sidebar will then show *AI assistant: LLM: Groq*, and **Regenerate with LLM** on any incident produces an LLM explanation that is still citation-verified. If Groq retires the default model, set `GROQ_MODEL` to a current one from their model list.

## 4. (Optional) Keep data between restarts: Neon, free

1. Create a project at <https://neon.tech> and copy the connection string.
2. Add it to the Streamlit secrets:
   ```toml
   DATABASE_URL = "postgresql://user:pass@ep-xxx.neon.tech/neondb?sslmode=require"
   ```
Case assignments, resolutions and audit history now survive app restarts, and the API can share the same database.

## 5. (Optional) Deploy the REST API: Render, free

1. <https://render.com> → **New → Blueprint** → select the repo (it reads `render.yaml`).
2. Set `DATABASE_URL` (the same Neon URL, so the API and dashboard share cases) and optionally `GROQ_API_KEY`.
3. Interactive docs will be at `https://secureops-api.onrender.com/docs`. The free tier sleeps after 15 minutes idle, so the first request takes about 30 to 60 seconds.

**Alternative:** Hugging Face Spaces → New Space → **Docker** → push this repo. The included `Dockerfile` serves the dashboard on the port Spaces provides.

## 6. Final touches for the portfolio

- Replace the two placeholder links at the top of `README.md` with your real URLs.
- Pin the repo on your GitHub profile and add the live link to your résumé and LinkedIn.
- Demo script (2 minutes): **Live attack demo → Inject** → show detect / correlate / prioritise / explain → **Assign** → **Open case** → show citations and the audit trail → **Evaluation** page, including the scenarios it misses.
