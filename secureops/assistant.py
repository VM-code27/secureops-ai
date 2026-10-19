"""AI investigation assistant: retrieval-augmented, evidence-cited explanations.

1. Retrieve - collect the incident's alerts, sample log events, affected assets,
   NVD CVE records, the score breakdown, and response playbooks (rule-mapped +
   TF-IDF similarity search over the playbook knowledge base).
2. Generate - an LLM (Groq free tier or local Ollama) or, with no LLM configured,
   the offline evidence-template engine writes the explanation. Every sentence must
   cite evidence IDs such as [EVT-123] or [CVE-2021-41773].
3. Verify - every sentence is checked: it must cite at least one ID, and every ID
   it cites must exist in the retrieved evidence. The share of supported sentences
   is the "AI reliability" metric.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache

import pandas as pd
import requests
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from . import config
from .assets import asset_index
from .correlation import KILL_CHAIN
from .nvd import load_cves

CITE_RE = re.compile(r"\[([^\[\]]+)\]")
ID_RE = re.compile(r"^(EVT-\d+|ALR-\d+|AST-[\w.-]+|CVE-\d{4}-\d+|PB-[\w-]+|SCR-\d+|CTX-\d+)$")


# ------------------------------------------------------------------ retrieval
@lru_cache(maxsize=1)
def _playbooks() -> dict[str, str]:
    return {p.stem: p.read_text(encoding="utf-8") for p in sorted(config.PLAYBOOK_DIR.glob("PB-*.md"))}


def _pb_for_rule(rule_id: str) -> str:
    return "PB-ANOMALY" if rule_id == "ML-ANOMALY" else "PB-" + rule_id.removeprefix("R-")


def retrieve_playbooks(query: str, rule_ids: list[str], k: int = 2) -> list[str]:
    pbs = _playbooks()
    ids = list(pbs)
    chosen = [_pb_for_rule(r) for r in rule_ids if _pb_for_rule(r) in pbs]
    vec = TfidfVectorizer(stop_words="english").fit(list(pbs.values()) + [query])
    sims = cosine_similarity(vec.transform([query]), vec.transform(list(pbs.values())))[0]
    for i in sims.argsort()[::-1][:k]:
        if sims[i] > 0.05 and ids[i] not in chosen:
            chosen.append(ids[i])
    return list(dict.fromkeys(chosen))


def _event_text(e) -> str:
    bits = [f"{pd.Timestamp(e.ts):%Y-%m-%d %H:%M:%S} UTC", e.source, f"{e.src_ip} -> {e.dst_ip}:{e.dst_port}"]
    if e.service:
        bits.append(e.service)
    if e.user:
        bits.append(f"user={e.user}")
    if e.outcome:
        bits.append(f"outcome={e.outcome}")
    if e.signature:
        bits.append(f"signature='{e.signature}'")
    if e.source == "zeek_conn":
        bits.append(f"state={e.conn_state} bytes_out={int(e.bytes_out):,} bytes_in={int(e.bytes_in):,}")
    return ", ".join(bits)


def build_context(incident: dict, alerts: pd.DataFrame, events: pd.DataFrame) -> list[dict]:
    """Evidence items [{id, kind, text}] the explanation is allowed to cite."""
    idx = asset_index()
    cves = load_cves()
    ev = events.set_index("event_id")
    items: list[dict] = []
    chosen_events: list[int] = []
    for rule_id, g in alerts.sort_values("ts").groupby("rule_id", sort=False):
        picks = pd.concat([g.head(1), g.sort_values("confidence").tail(1), g.tail(1)]).drop_duplicates("alert_id")
        for _, a in picks.iterrows():
            items.append(dict(id=f"ALR-{a.alert_id}", kind="alert", rule_id=rule_id, tactic=a.tactic,
                              text=f"{a.rule_name} ({a.technique or 'ML'}; confidence {a.confidence:.2f}; "
                                   f"{len(g)} alert(s) from this rule in the incident): {a.description}"))
            evid = list(a.evidence)
            chosen_events += evid[:2] + evid[-1:]
    for eid in list(dict.fromkeys(chosen_events))[:40]:
        if eid in ev.index:
            items.append(dict(id=f"EVT-{eid}", kind="event", text=_event_text(ev.loc[eid])))
    ents = incident["entities"]
    for ip in ents["internal"][:8]:
        a = idx[ip]
        items.append(dict(id=a["asset_id"], kind="asset",
                          text=f"{a['hostname']} ({ip}): {a['role']}, department {a['department']}, business "
                               f"criticality {a['criticality']}/5, software: {', '.join(a['software'])}; "
                               f"known CVEs: {', '.join(a['cves']) or 'none'}"))
    for cve_id in sorted({c for ip in ents["internal"] for c in idx[ip]["cves"]}):
        c = cves.get(cve_id)
        if c:
            items.append(dict(id=cve_id, kind="cve",
                              text=f"CVSS {c['cvss']} {c['severity']}{'; on CISA Known Exploited Vulnerabilities list' if c['kev'] else ''}; "
                                   f"{c['description'][:300]} (source: {c['source']})"))
    sc = incident["scoring"]
    items.append(dict(id="SCR-1", kind="score",
                      text=f"Priority score {sc['score']}/100 ({sc['severity']}); components: " +
                           ", ".join(f"{k} {v}" for k, v in sc["breakdown"].items()) +
                           f"; confirmed exploitable: {', '.join(c for _, c in sc['exploited_cves']) or 'no'}"))
    sources = events[events.event_id.isin(set(e for es in alerts.evidence for e in es))].source.value_counts()
    items.append(dict(id="CTX-1", kind="scope",
                      text=f"Telemetry available for this incident: {', '.join(f'{k} ({v} events)' for k, v in sources.items())}. "
                           "No endpoint (EDR/process) or packet-payload data is collected in this lab."))
    query = " ".join(alerts.description.head(30))
    for pb in retrieve_playbooks(query, list(alerts.rule_id.unique())):
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
        cited = [i.strip() for grp in CITE_RE.findall(s) for i in re.split(r"[;,]", grp)]
        cited = [c for c in cited if ID_RE.match(c)]
        unknown = [c for c in cited if c not in known]
        checks.append(dict(sentence=s, citations=cited, supported=bool(cited) and not unknown,
                           reason="ok" if cited and not unknown else ("no citation" if not cited else f"unknown id {unknown}")))
    rate = sum(c["supported"] for c in checks) / len(checks) if checks else 0.0
    return {"support_rate": round(rate, 3), "checks": checks}


# ------------------------------------------------------------------ generation
SYSTEM_PROMPT = """You are a SOC investigation assistant. Explain the incident to a security analyst using ONLY the evidence provided.
Rules:
- End EVERY sentence with one or more evidence IDs in square brackets, e.g. [ALR-12] or [EVT-301, AST-web-srv-01].
- Only use IDs that appear in the evidence list. Never invent IPs, users, CVEs, numbers or IDs.
- If something cannot be determined from the evidence, say so and cite [CTX-1].
- Recommendations are proposals that need analyst approval; cite the playbook they come from.
Format in markdown with these headings: ### What happened, ### Why it matters, ### Recommended next steps (analyst approval required), ### Gaps and uncertainty"""


def _offline(incident: dict, context: list[dict]) -> str:
    by_kind: dict[str, list[dict]] = {}
    for c in context:
        by_kind.setdefault(c["kind"], []).append(c)
    alerts = by_kind.get("alert", [])
    events = by_kind.get("event", [])
    sc = incident["scoring"]
    lines = ["### What happened"]
    first_ids = ", ".join(a["id"] for a in alerts[:3])
    lines.append(f"- {incident['alert_count']} alerts from {len({a['rule_id'] for a in alerts})} detection rules were "
                 f"correlated into this incident between {incident['first_seen']:%Y-%m-%d %H:%M} and "
                 f"{incident['last_seen']:%H:%M} UTC [{first_ids}].")
    ev_ids = [e["id"] for e in events]
    for i, tactic in enumerate(KILL_CHAIN):
        stage = [a for a in alerts if a["tactic"] == tactic]
        if not stage:
            continue
        a = max(stage, key=lambda x: float(re.search(r"confidence ([\d.]+)", x["text"]).group(1)))
        desc = a["text"].split("): ", 1)[-1]
        ev_ref = f", {ev_ids[min(i, len(ev_ids) - 1)]}" if ev_ids else ""
        lines.append(f"- **{tactic}:** {desc} [{a['id']}{ev_ref}]")
    lines.append("### Why it matters")
    for a in by_kind.get("asset", [])[:3]:
        lines.append(f"- {a['text'].split(';')[0]} [{a['id']}].")
    for c in by_kind.get("cve", [])[:3]:
        lines.append(f"- An affected asset is exposed to {c['id']} ({c['text'].split(';')[0]}) [{c['id']}].")
    for host, cve in sc["exploited_cves"][:2]:
        hit = next((a["id"] for a in alerts if cve in a["text"]), None)
        refs = ", ".join(x for x in [hit, cve, f"AST-{host}"] if x)
        lines.append(f"- An exploit signature for {cve} was observed against {host}, which runs the vulnerable "
                     f"software, so the attempt was likely viable [{refs}].")
    lines.append(f"- Priority {sc['score']}/100 ({sc['severity']}) combines threat confidence "
                 f"{sc['breakdown']['threat']}, asset importance {sc['breakdown']['asset']}, vulnerability exposure "
                 f"{sc['breakdown']['exposure']} and spread {sc['breakdown']['spread']} [SCR-1].")
    lines.append("### Recommended next steps (analyst approval required)")
    for pb in by_kind.get("playbook", [])[:3]:
        for part in ("Verify", "Contain"):
            m = re.search(rf"{part}: (.+)", pb["text"])
            if m:
                lines.append(f"- {part}: {m.group(1).split(';')[0].strip().rstrip('.')} [{pb['id']}].")
    lines.append("### Gaps and uncertainty")
    lines.append("- " + by_kind["scope"][0]["text"].split(". ")[1].rstrip(".") +
                 ", so payload execution and the responsible process cannot be confirmed [CTX-1].")
    if any(a["rule_id"] == "ML-ANOMALY" for a in alerts):
        anom = next(a for a in alerts if a["rule_id"] == "ML-ANOMALY")
        lines.append(f"- Part of this incident rests on an unsupervised anomaly score, which also flags benign "
                     f"oddities and should be corroborated [{anom['id']}, PB-ANOMALY].")
    return "\n".join(lines)


def _chat(messages: list[dict]) -> tuple[str, str]:
    provider = config.LLM_PROVIDER
    if provider == "auto":
        provider = "groq" if config.GROQ_API_KEY else "ollama" if config.OLLAMA_URL else "offline"
    if provider == "groq":
        r = requests.post("https://api.groq.com/openai/v1/chat/completions", timeout=60,
                          headers={"Authorization": f"Bearer {config.GROQ_API_KEY}"},
                          json={"model": config.GROQ_MODEL, "messages": messages, "temperature": 0.1, "max_tokens": 900})
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"], f"groq:{config.GROQ_MODEL}"
    if provider == "ollama":
        r = requests.post(f"{config.OLLAMA_URL.rstrip('/')}/api/chat", timeout=180,
                          json={"model": config.OLLAMA_MODEL, "messages": messages, "stream": False,
                                "options": {"temperature": 0.1}})
        r.raise_for_status()
        return r.json()["message"]["content"], f"ollama:{config.OLLAMA_MODEL}"
    raise RuntimeError("offline")


def llm_available() -> bool:
    return config.LLM_PROVIDER != "offline" and bool(config.GROQ_API_KEY or config.OLLAMA_URL)


def explain(incident: dict, alerts: pd.DataFrame, events: pd.DataFrame, use_llm: bool = True) -> dict:
    context = build_context(incident, alerts, events)
    mode, note = "offline-evidence-template", ""
    text = None
    if use_llm and llm_available():
        evidence = "\n".join(f"[{c['id']}] ({c['kind']}) {c['text']}" for c in context)
        try:
            text, mode = _chat([{"role": "system", "content": SYSTEM_PROMPT},
                                {"role": "user", "content": f"Incident: {incident['title']}\n\nEvidence:\n{evidence}"}])
        except Exception as exc:  # network, quota, bad key -> never break the workflow
            note = f"LLM unavailable ({exc.__class__.__name__}); used offline engine."
    if text is None:
        text = _offline(incident, context)
    v = verify(text, context)
    return {"text": text, "mode": mode, "note": note, "support_rate": v["support_rate"], "checks": v["checks"],
            "context": context}


def to_json(result: dict) -> str:
    return json.dumps({k: v for k, v in result.items() if k != "context"}, default=str)
