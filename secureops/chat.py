"""Conversational investigation: answer plain-English questions from the live database.

Retrieval picks what the question is about (incident IDs, IP addresses, attack types,
severities, time words) and assembles evidence items with IDs. The LLM answers using
only that evidence and cites it; the same verifier as the incident explanations checks
every sentence. Without an LLM, a deterministic answer is built from the same evidence.
"""
from __future__ import annotations

import re

import pandas as pd

from . import assistant, db
from .assets import index as asset_index, label

INC_RE = re.compile(r"\bINC-?(\d{1,5})\b", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TOPICS = {
    "brute": "R-BRUTE", "password": "R-BRUTE", "login": "R-BRUTE", "credential": "R-BRUTE",
    "scan": "R-SCAN", "recon": "R-SCAN", "probe": "R-SCAN",
    "lateral": "R-LATERAL", "exfil": "R-EXFIL", "data theft": "R-EXFIL", "upload": "R-EXFIL",
    "intel": "R-IOC", "c2": "R-IOC", "command and control": "R-IOC", "malicious ip": "R-IOC",
    "ids": "R-IDS", "suricata": "R-IDS", "signature": "R-IDS", "exploit": "R-IDS",
    "anomal": "ML-ANOMALY", "unusual": "ML-ANOMALY", "strange": "ML-ANOMALY",
    "ssh": "R-SSH-BRUTE",
}
SEVERITIES = ["critical", "high", "medium", "low"]

CHAT_PROMPT = """You are SecureOps AI, a security analyst assistant. Answer the user's question in clear, plain English
for a busy analyst, using ONLY the evidence below (live data from the organisation's security pipeline).
Rules:
- Be concise: lead with the direct answer, then short bullets if useful.
- End EVERY sentence with one or more evidence IDs in plain ASCII square brackets, e.g. [INC-0114] or [ALR-12, AST-10.0.0.5].
- Only use IDs that appear in the evidence. Never invent IPs, numbers, users, CVEs or IDs.
- If the evidence does not answer the question, say so and suggest what to look at [STAT-1].
- Recommendations need analyst approval; cite the playbook or incident they come from."""


def _incident_item(r) -> dict:
    ents = r["entities"] if isinstance(r["entities"], dict) else {}
    return {"id": r["incident_id"], "kind": "incident",
            "text": f"{r['title']}; severity {r['severity']} (score {r['score']:.0f}/100); status {r['status']}; owner "
                    f"{r['owner']}; {'live sensor/upload data' if r['dataset'] == 'live' else 'UWF dataset replay'}; "
                    f"{r['alert_count']} alerts between {pd.Timestamp(r['first_seen']):%Y-%m-%d %H:%M} and "
                    f"{pd.Timestamp(r['last_seen']):%Y-%m-%d %H:%M} UTC; internal hosts "
                    f"{', '.join(map(label, ents.get('internal', [])[:5])) or 'none'}; external "
                    f"{', '.join(ents.get('external', [])[:5]) or 'none'}; SLA due {pd.Timestamp(r['sla_due']):%Y-%m-%d %H:%M} UTC"}


def _stats(inc: pd.DataFrame) -> dict:
    open_ = inc[~inc.status.isin(["Resolved", "False positive"])]
    live = db.read_events_sql("SELECT sensor, COUNT(*) AS n, MAX(ts) AS last FROM events WHERE dataset = 'live' "
                              "GROUP BY sensor")
    rs = db.get_meta("replay", {}) or {}
    return {"id": "STAT-1", "kind": "stats",
            "text": f"{len(inc)} incidents in total, {len(open_)} open "
                    f"({', '.join(f'{s}: {(open_.severity == s).sum()}' for s in ['Critical', 'High', 'Medium', 'Low'])}); "
                    f"{db.count('alerts')} alerts from {db.count('events'):,} events; live sensors: "
                    f"{', '.join(f'{r.sensor} ({r.n} events, last {str(r.last)[:19]} UTC)' for r in live.itertuples()) or 'none'}; "
                    f"dataset replay position {str(rs.get('cursor', 'not started'))[:16]}; "
                    f"current time {db.now():%Y-%m-%d %H:%M} UTC"}


def retrieve(question: str, focus: str | None = None) -> tuple[list[dict], str | None]:
    """Evidence for a question. Returns (items, incident in focus)."""
    q = question.lower()
    inc = db.list_incidents()
    inc = inc[~inc.resolution.fillna("").str.startswith("Merged into")]
    items = [_stats(inc)]
    ids = [f"INC-{int(n):04d}" for n in INC_RE.findall(question)]
    ids = [i for i in ids if i in set(inc.incident_id)]
    if not ids and focus and re.search(r"\b(it|this|that|the incident|this incident|why|how|what should|next)\b", q):
        ids = [focus]
    ips = IP_RE.findall(question)
    rules = {r for k, r in TOPICS.items() if k in q}
    sev = [s.title() for s in SEVERITIES if s in q]

    sel = inc.copy()
    if ips:
        sel = sel[sel.entities.map(lambda e: any(ip in e for ip in ips))]
    if sev:
        sel = sel[sel.severity.isin(sev)]
    if "open" in q or "unresolved" in q or "active" in q:
        sel = sel[~sel.status.isin(["Resolved", "False positive"])]
    if "live" in q or "sensor" in q or "my network" in q:
        sel = sel[sel.dataset == "live"]
    if rules:
        al = db.read_alerts()
        hit = set(al[al.rule_id.isin(rules)].incident_id)
        sel = sel[sel.incident_id.isin(hit)]
    if re.search(r"\b(today|last hour|recent|latest|new|now)\b", q):
        sel = sel.sort_values("updated_at", ascending=False)
    for _, r in sel.head(8).iterrows():
        items.append(_incident_item(db._decode_incident(r.to_dict()) if isinstance(r.entities, str) else r))
    for ip in ips:
        a = asset_index().get(ip)
        if a:
            items.append({"id": f"AST-{ip}", "kind": "asset",
                          "text": f"{label(ip)}: {a['role']}; criticality {a['criticality']}/5 ({a['criticality_source']}); "
                                  f"contacted by {a['fan_in']} hosts, talks to {a['fan_out']}; first seen "
                                  f"{str(a['first_seen'])[:16]}, last seen {str(a['last_seen'])[:16]} UTC"})
    if ids:
        focus = ids[0]
        i = db.get_incident(focus)
        if focus not in {x["id"] for x in items}:
            items.append(_incident_item(i))
        al = db.read_alerts(focus)
        ev = db.events_by_ids({e for es in al.evidence for e in es})
        items += [c for c in assistant.build_context(i, al, ev) if c["id"] not in {x["id"] for x in items}]
    elif len(items) == 1:  # nothing matched: give the most important open incidents
        top = inc[~inc.status.isin(["Resolved", "False positive"])].head(6)
        items += [_incident_item(db._decode_incident(r.to_dict())) for _, r in top.iterrows()]
    return items, focus


def _offline_answer(question: str, items: list[dict], focus: str | None) -> str:
    incs = [i for i in items if i["kind"] == "incident"]
    if focus:
        inc = db.get_incident(focus)
        return f"**{focus}** - {inc['title']} [{focus}].\n\n" + inc["ai_summary"]
    if not incs:
        return "I found no incident matching that question in the current data [STAT-1]."
    lines = [f"I found {len(incs)} relevant incident(s); the most important first [STAT-1]."]
    for i in incs:
        lines.append(f"- **{i['id']}**: {i['text'].split(';')[0]}, {i['text'].split(';')[1].strip()} [{i['id']}].")
    lines.append("Ask about one of them by ID (for example \"explain " + incs[0]["id"] + "\") for the full evidence "
                 f"[{incs[0]['id']}].")
    return "\n".join(lines)


def answer(question: str, history: list[dict] | None = None, focus: str | None = None) -> dict:
    items, focus = retrieve(question, focus)
    mode, note, text = "offline", "", None
    if assistant.llm_available():
        evidence = "\n".join(f"[{c['id']}] ({c['kind']}) {c['text']}" for c in items)
        msgs = [{"role": "system", "content": CHAT_PROMPT}]
        for h in (history or [])[-4:]:
            msgs.append({"role": h["role"], "content": h["content"][:1500]})
        msgs.append({"role": "user", "content": f"Evidence:\n{evidence}\n\nQuestion: {question}"})
        try:
            text, mode = assistant._chat(msgs)
        except Exception as exc:
            note = f"LLM unavailable ({str(exc)[:120]}); answered from the evidence directly."
    if text is None:
        text = _offline_answer(question, items, focus)
    v = assistant.verify(text, items)
    return {"text": text, "mode": mode, "note": note, "support_rate": v["support_rate"], "checks": v["checks"],
            "sources": items, "focus": focus}
