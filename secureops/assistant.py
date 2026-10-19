"""AI investigation assistant: retrieval-augmented, evidence-cited explanations.

1. Retrieve - the incident's alerts and raw log events, the affected assets, live CVE
   records (NVD + CISA KEV + EPSS), MITRE ATT&CK technique descriptions (downloaded live
   from MITRE), the score breakdown, and response playbooks (rule-mapped + TF-IDF search).
2. Generate - an LLM (Groq free tier or local Ollama) or, when none is configured, the
   offline evidence-template engine. Every sentence must cite evidence IDs.
3. Verify - each sentence must cite at least one ID and every cited ID must exist in the
   retrieved evidence. The share of supported sentences is the "AI reliability" metric.
"""
from __future__ import annotations

import re
import time
from functools import lru_cache

import pandas as pd
import requests
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from . import config, db, settings
from .assets import index as asset_index, label
from .correlation import KILL_CHAIN
from .intel import attack

# Square brackets, or the full-width 【 】 some models (e.g. gpt-oss) emit natively.
CITE_RE = re.compile(r"[\[【]([^\[\]【】]+)[\]】]")
ID_RE = re.compile(r"^(EVT-\d+|ALR-\d+|AST-[\w.:-]+|CVE-\d{4}-\d+|ATT-T\d{4}(\.\d{3})?|PB-[\w-]+|SCR-\d+|CTX-\d+)$")


# ------------------------------------------------------------------ retrieval
@lru_cache(maxsize=1)
def _playbooks() -> dict[str, str]:
    return {p.stem: p.read_text(encoding="utf-8") for p in sorted(config.PLAYBOOK_DIR.glob("PB-*.md"))}


def retrieve_playbooks(query: str, rule_ids: list[str], k: int = 2) -> list[str]:
    pbs = _playbooks()
    ids = list(pbs)
    rules = settings.rules()
    chosen = [rules[r].get("playbook") for r in rule_ids if rules.get(r, {}).get("playbook") in pbs]
    vec = TfidfVectorizer(stop_words="english").fit(list(pbs.values()) + [query])
    sims = cosine_similarity(vec.transform([query]), vec.transform(list(pbs.values())))[0]
    for i in sims.argsort()[::-1][:k]:
        if sims[i] > 0.05:
            chosen.append(ids[i])
    return list(dict.fromkeys(chosen))[:4]


def _event_text(e) -> str:
    bits = [f"{pd.Timestamp(e.ts):%Y-%m-%d %H:%M:%S} UTC", e.source, f"{e.src_ip}:{e.src_port} -> {e.dst_ip}:{e.dst_port}/{e.proto}"]
    if e.service:
        bits.append(f"service={e.service}")
    if e.outcome:
        bits.append(f"auth={e.outcome}")
    if e.signature:
        bits.append(f"signature='{e.signature}'")
    if e.source in ("zeek_conn", "suricata_flow"):
        bits.append(f"state={e.conn_state} duration={e.duration:.3f}s bytes_out={int(e.bytes_out):,} bytes_in={int(e.bytes_in):,}")
    return ", ".join(bits)


def build_context(incident: dict, alerts: pd.DataFrame, events: pd.DataFrame) -> list[dict]:
    """Evidence items [{id, kind, text}] the explanation is allowed to cite."""
    idx = asset_index()
    ev = events.set_index("event_id")
    items: list[dict] = []
    chosen_events: list[int] = []
    for rule_id, g in alerts.sort_values("ts").groupby("rule_id", sort=False):
        picks = pd.concat([g.head(1), g.sort_values("confidence").tail(1), g.tail(1)]).drop_duplicates("alert_id")
        for _, a in picks.iterrows():
            items.append(dict(id=f"ALR-{a.alert_id}", kind="alert", rule_id=rule_id, tactic=a.tactic, confidence=a.confidence,
                              text=f"{a.rule_name} ({a.technique or 'ML'}; confidence {a.confidence:.2f}; "
                                   f"{len(g)} alert(s) from this rule in the incident): {a.description}"))
            evid = list(a.evidence)
            chosen_events += evid[:2] + evid[-1:]
    for eid in list(dict.fromkeys(chosen_events))[:25]:
        if eid in ev.index:
            items.append(dict(id=f"EVT-{eid}", kind="event", text=_event_text(ev.loc[eid])))
    for ip in incident["entities"]["internal"][:8]:
        a = idx.get(ip)
        if not a:
            continue
        items.append(dict(id=f"AST-{ip}", kind="asset", criticality=a["criticality"],
                          text=f"{label(ip)}: {a['role'] or 'role unknown'}; criticality {a['criticality']}/5 "
                               f"({a['criticality_source']}); seen talking to {a['fan_out']} host(s), contacted by "
                               f"{a['fan_in']}; {'shared infrastructure; ' if a['is_hub'] else ''}"
                               f"known CVEs: {len(a['cves'] or [])}" + (f"; owner {a['owner']}" if a.get("owner") else "")))
    sc = incident["scoring"]
    cve_ids = [c["cve"] for c in sc.get("top_cves", [])[:3]] + [c for _, c in sc.get("exploited_cves", [])]
    cve_ids += [c for c in alerts.cve if c]
    vul = db.read_vulns(set(cve_ids)).set_index("cve_id") if cve_ids else pd.DataFrame()
    for cid in dict.fromkeys(cve_ids):
        if cid in vul.index:
            v = vul.loc[cid]
            epss = f"EPSS {v.epss:.2f} (percentile {v.epss_percentile:.2f})" if pd.notna(v.epss) else "EPSS n/a"
            items.append(dict(id=cid, kind="cve", text=f"CVSS {v.cvss} {v.severity}; {epss}; "
                              f"{'listed in CISA KEV since ' + v.kev_date if v.kev else 'not in CISA KEV'}; "
                              f"{str(v.description)[:300]} (NVD)"))
    for tech in sorted({t for t in alerts.technique if t}):
        k = attack.lookup(tech)
        if k:
            first = re.split(r"(?<=\.)\s", re.sub(r"\(Citation:[^)]*\)", "", k["description"]))[0][:400]
            items.append(dict(id=f"ATT-{tech}", kind="attack", text=f"MITRE ATT&CK {k['id']} {k['name']} "
                              f"({', '.join(k['tactics'])}): {first}"))
    items.append(dict(id="SCR-1", kind="score",
                      text=f"Priority score {sc['score']}/100 ({sc['severity']}); components: " +
                           ", ".join(f"{k} {v}" for k, v in sc["breakdown"].items()) +
                           f"; weights {sc.get('weights')}; confirmed exploitable: "
                           f"{', '.join(c for _, c in sc['exploited_cves']) or 'no'}"))
    sources = events.source.value_counts()
    items.append(dict(id="CTX-1", kind="scope",
                      text=f"Telemetry behind this incident: {', '.join(f'{k} ({v} events)' for k, v in sources.items())}. "
                           "Only network metadata is available - no endpoint/EDR, process or packet-payload data."))
    for pb in retrieve_playbooks(" ".join(alerts.description.head(30)), list(alerts.rule_id.unique())):
        items.append(dict(id=pb, kind="playbook", text=_playbooks()[pb]))
    return items


# ------------------------------------------------------------------ verification
def split_sentences(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        line = line.strip().lstrip("-*0123456789. ").strip()
        if not line or line.startswith("#") or len(line.split()) < 4:
            continue
        out += [s.strip() for s in re.split(r"(?<=[.!?])\s+(?=[A-Z])", line) if len(s.split()) >= 4]
    return out


def verify(text: str, context: list[dict]) -> dict:
    known = {c["id"] for c in context}
    checks = []
    for s in split_sentences(text):
        # Normalise look-alike hyphens (models often emit U+2011 etc.) and markdown bold inside citations.
        norm = re.sub("[‐‑‒–]", "-", s).replace("*", "")
        cited = [i.strip() for grp in CITE_RE.findall(norm) for i in re.split(r"[;,]", grp)]
        cited = [c for c in cited if ID_RE.match(c)]
        unknown = [c for c in cited if c not in known]
        checks.append(dict(sentence=s, citations=cited, supported=bool(cited) and not unknown,
                           reason="ok" if cited and not unknown else ("no citation" if not cited else f"unknown id {unknown}")))
    rate = sum(c["supported"] for c in checks) / len(checks) if checks else 0.0
    return {"support_rate": round(rate, 3), "checks": checks}


# ------------------------------------------------------------------ generation
SYSTEM_PROMPT = """You are a SOC investigation assistant. Explain the incident to a security analyst using ONLY the evidence provided.
Rules:
- End EVERY sentence (including recommendations and gaps) with one or more evidence IDs in plain ASCII square brackets, e.g. [ALR-12] or [EVT-301, AST-10.0.0.5]. A sentence without a citation is rejected.
- Only use IDs that appear in the evidence list. Never invent IPs, users, CVEs, numbers or IDs.
- If something cannot be determined from the evidence, say so and cite [CTX-1].
- Recommendations are proposals that need analyst approval; cite the playbook or ATT&CK entry they come from.
Format in markdown with these headings: ### What happened, ### Why it matters, ### Recommended next steps (analyst approval required), ### Gaps and uncertainty"""


def _offline(incident: dict, context: list[dict]) -> str:
    by: dict[str, list[dict]] = {}
    for c in context:
        by.setdefault(c["kind"], []).append(c)
    alerts, events = by.get("alert", []), by.get("event", [])
    sc = incident["scoring"]
    lines = ["### What happened",
             f"- {incident['alert_count']} alerts from {len({a['rule_id'] for a in alerts})} detection rule(s) were "
             f"correlated into this incident between {pd.Timestamp(incident['first_seen']):%Y-%m-%d %H:%M} and "
             f"{pd.Timestamp(incident['last_seen']):%Y-%m-%d %H:%M} UTC [{', '.join(a['id'] for a in alerts[:3])}]."]
    ev_ids = [e["id"] for e in events]
    for i, tactic in enumerate(KILL_CHAIN):
        stage = [a for a in alerts if a["tactic"] == tactic]
        if stage:
            a = max(stage, key=lambda x: x["confidence"])
            ref = f", {ev_ids[min(i, len(ev_ids) - 1)]}" if ev_ids else ""
            lines.append(f"- **{tactic}:** {a['text'].split('): ', 1)[-1]} [{a['id']}{ref}]")
    lines.append("### Why it matters")
    for t in by.get("attack", [])[:2]:
        lines.append(f"- {t['text'][:300].rstrip('.')} [{t['id']}].")
    for a in sorted(by.get("asset", []), key=lambda x: -x["criticality"])[:3]:
        lines.append(f"- Affected asset {a['text'].split(';')[0]} has criticality {a['criticality']}/5 [{a['id']}].")
    for c in by.get("cve", [])[:3]:
        lines.append(f"- An affected asset is exposed to {c['id']}: {c['text'].split('; ')[0]}, "
                     f"{c['text'].split('; ')[2]} [{c['id']}].")
    for host, cve in sc["exploited_cves"][:2]:
        hit = next((a["id"] for a in alerts if cve in a["text"]), None)
        lines.append(f"- An IDS signature for {cve} fired against {host}, which is known to be vulnerable, so the "
                     f"attempt was likely viable [{', '.join(x for x in [hit, cve] if x)}].")
    b = sc["breakdown"]
    lines.append(f"- Priority {sc['score']}/100 ({sc['severity']}) combines threat confidence {b['threat']}, asset "
                 f"importance {b['asset']}, vulnerability exposure {b['exposure']} and spread {b['spread']} [SCR-1].")
    lines.append("### Recommended next steps (analyst approval required)")
    for pb in by.get("playbook", [])[:3]:
        for part in ("Verify", "Contain"):
            m = re.search(rf"{part}: (.+)", pb["text"])
            if m:
                lines.append(f"- {part}: {m.group(1).split(';')[0].strip().rstrip('.')} [{pb['id']}].")
    lines.append("### Gaps and uncertainty")
    lines.append("- Only network metadata was available, so payloads, the responsible process and whether any "
                 "attempt actually succeeded cannot be confirmed [CTX-1].")
    if any(a["rule_id"] == "ML-ANOMALY" for a in alerts):
        anom = next(a for a in alerts if a["rule_id"] == "ML-ANOMALY")
        pb = next((p["id"] for p in by.get("playbook", []) if p["id"] == "PB-ANOMALY"), None)
        lines.append(f"- Part of this incident rests on an unsupervised anomaly score, which also flags benign "
                     f"oddities and should be corroborated [{', '.join(x for x in [anom['id'], pb] if x)}].")
    if not by.get("cve"):
        lines.append("- No CVE data is linked to the affected assets; add CPEs in the asset inventory to measure "
                     "vulnerability exposure [SCR-1].")
    return "\n".join(lines)


_groq_models: dict = {}
NON_CHAT = re.compile(r"whisper|guard|orpheus|tts|safeguard|embed", re.I)


def groq_model() -> str:
    """Configured Groq model, or with 'auto' the largest chat model Groq lists right now
    (models get retired, so the choice is made live and cached for an hour)."""
    want = settings.section("ai")["groq_model"]
    if want != "auto":
        return want
    if not _groq_models or _groq_models["at"] < pd.Timestamp.now(tz="UTC") - pd.Timedelta(hours=1):
        r = requests.get("https://api.groq.com/openai/v1/models", timeout=30,
                         headers={"Authorization": f"Bearer {config.GROQ_API_KEY}"})
        r.raise_for_status()
        ids = [m["id"] for m in r.json()["data"] if not NON_CHAT.search(m["id"])]
        size = lambda i: float((re.findall(r"(\d+(?:\.\d+)?)b\b", i.lower()) or [0])[-1])  # noqa: E731
        _groq_models.update(at=pd.Timestamp.now(tz="UTC"), best=max(ids, key=size) if ids else "")
    return _groq_models["best"]


def _provider() -> str:
    p = settings.section("ai")["provider"]
    if p == "auto":
        return "groq" if config.GROQ_API_KEY else "ollama" if config.OLLAMA_URL else "offline"
    return p


def llm_available() -> bool:
    return _provider() in ("groq", "ollama")


def llm_label() -> str:
    ai = settings.section("ai")
    return {"groq": f"Groq ({ai['groq_model']})", "ollama": f"Ollama ({ai['ollama_model']})"}.get(
        _provider(), "Offline evidence engine")


def _chat(messages: list[dict]) -> tuple[str, str]:
    ai = settings.section("ai")
    provider = _provider()
    if provider == "groq":
        model = groq_model()
        for attempt in range(4):  # free tier is rate limited: honour Retry-After and try again
            r = requests.post("https://api.groq.com/openai/v1/chat/completions", timeout=90,
                              headers={"Authorization": f"Bearer {config.GROQ_API_KEY}"},
                              json={"model": model, "messages": messages, "temperature": 0.1, "max_tokens": 4096})
            if r.status_code != 429 or attempt == 3:
                break
            time.sleep(min(60.0, float(r.headers.get("retry-after", 10))))
        if not r.ok:
            raise RuntimeError(f"Groq {r.status_code}: {r.text[:200]}")
        return r.json()["choices"][0]["message"]["content"], f"groq:{model}"
    if provider == "ollama":
        r = requests.post(f"{config.OLLAMA_URL.rstrip('/')}/api/chat", timeout=180,
                          json={"model": ai["ollama_model"], "messages": messages, "stream": False,
                                "options": {"temperature": 0.1}})
        r.raise_for_status()
        return r.json()["message"]["content"], f"ollama:{ai['ollama_model']}"
    raise RuntimeError("no LLM configured")


def explain(incident: dict, alerts: pd.DataFrame, events: pd.DataFrame, use_llm: bool = True) -> dict:
    context = build_context(incident, alerts, events)
    mode, note, text = "offline-evidence-template", "", None
    if use_llm and llm_available():
        evidence = "\n".join(f"[{c['id']}] ({c['kind']}) {c['text']}" for c in context)
        try:
            text, mode = _chat([{"role": "system", "content": SYSTEM_PROMPT},
                                {"role": "user", "content": f"Incident: {incident['title']}\n\nEvidence:\n{evidence}"}])
        except Exception as exc:  # network, quota, bad key -> never break the workflow
            note = f"LLM unavailable ({str(exc)[:160] or exc.__class__.__name__}); used offline engine."
    if text is None:
        text = _offline(incident, context)
    v = verify(text, context)
    return {"text": text, "mode": mode, "note": note, "support_rate": v["support_rate"], "checks": v["checks"],
            "context": context}
