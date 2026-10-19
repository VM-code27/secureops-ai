"""SecureOps AI - analyst dashboard (Streamlit).

Local:   streamlit run streamlit_app.py
Cloud:   Streamlit Community Cloud -> main file `streamlit_app.py` (free)
"""
from __future__ import annotations

import json
import os

import altair as alt
import pandas as pd
import streamlit as st

# Streamlit Cloud secrets -> environment (before importing the package).
try:
    for _k in ("GROQ_API_KEY", "GROQ_MODEL", "OLLAMA_URL", "OLLAMA_MODEL", "DATABASE_URL", "LLM_PROVIDER", "NVD_API_KEY",
               "SECUREOPS_API_TOKEN", "API_PUBLIC_URL"):
        if _k in st.secrets and not os.getenv(_k):
            os.environ[_k] = str(st.secrets[_k])
except Exception:
    pass

from secureops import assets, assistant, bootstrap, config, db, pipeline, settings  # noqa: E402
from secureops.correlation import KILL_CHAIN  # noqa: E402
from secureops.intel import attack, feeds, vulns  # noqa: E402
from secureops.sources import replay, suricata, uwf, zeek  # noqa: E402

st.set_page_config(page_title="SecureOps AI", page_icon=":material/shield:", layout="wide")

# --------------------------------------------------------------- design tokens
SURFACE, INK, INK2, MUTED, GRID = "#1a1a19", "#f0efec", "#c3c2b7", "#8a8984", "#2e2e2c"
BLUE = "#3987e5"
SERIES = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"]  # fixed order
SEV_COLOR = {"Critical": "#d03b3b", "High": "#ec835a", "Medium": "#fab219", "Low": "#8a8984"}
SEV_ICON = {"Critical": "▲▲", "High": "▲", "Medium": "◆", "Low": "▽"}
SEV_ORDER = ["Critical", "High", "Medium", "Low"]
PAGES = ["Overview", "Incident queue", "Investigate", "Live data", "Assets", "Threat intel", "Evaluation", "Settings",
         "About"]

st.markdown(f"""
<style>
.block-container {{padding-top: 1.6rem; max-width: 1400px;}}
.sev {{display:inline-block; padding:2px 10px; border-radius:999px; font-weight:600; font-size:0.85rem;
       border:1px solid currentColor;}}
.small {{color:{MUTED}; font-size:0.85rem;}}
.stage {{border:1px solid {GRID}; border-radius:10px; padding:10px 14px; margin-bottom:8px;}}
</style>""", unsafe_allow_html=True)


def sev_badge(sev: str) -> str:
    return f"<span class='sev' style='color:{SEV_COLOR[sev]}'>{SEV_ICON[sev]} {sev}</span>"


def bar_height(n: int) -> int:
    return 70 + 32 * max(n, 1)  # one readable row per category, so no axis label is dropped


def theme(chart, height: int = 260):
    return (chart.properties(height=height, background="transparent")
            .configure_view(stroke=None)
            .configure_axis(labelColor=INK2, titleColor=INK2, gridColor=GRID, domainColor=GRID, tickColor=GRID,
                            labelFontSize=12, titleFontSize=12, titleFontWeight="normal")
            .configure_legend(labelColor=INK2, titleColor=INK2, orient="bottom", labelFontSize=12, columns=4)
            .configure_title(color=INK, anchor="start", fontSize=14, fontWeight=600))


def hbar(df: pd.DataFrame, cat: str, val: str, title: str, color: str = BLUE, tooltip=None):
    base = alt.Chart(df, title=title).encode(
        y=alt.Y(f"{cat}:N", sort="-x", title=None, axis=alt.Axis(labelLimit=280)),
        x=alt.X(f"{val}:Q", title=None, axis=alt.Axis(grid=True, tickCount=4)),
        tooltip=tooltip or [cat, val])
    return base.mark_bar(color=color, cornerRadiusEnd=4, height={"band": 0.7}) + \
        base.mark_text(align="left", dx=4, color=INK2, fontSize=12).encode(text=f"{val}:Q")


def fmt_delta(td) -> str:
    if td is None or pd.isna(td):
        return "-"
    secs = int(td.total_seconds())
    sign, secs = ("-" if secs < 0 else ""), abs(secs)
    d, rem = divmod(secs, 86400)
    h, rem = divmod(rem, 3600)
    return f"{sign}{d}d {h}h" if d else f"{sign}{h}h {rem // 60}m"


def _api_url() -> str | None:
    """Public API address if configured, else a locally running API (docker compose / uvicorn)."""
    if os.getenv("API_PUBLIC_URL"):
        return os.getenv("API_PUBLIC_URL")
    try:
        import requests
        if requests.get("http://localhost:8000/health", timeout=1).ok:
            return "http://localhost:8000"
    except Exception:
        pass
    return None


def ago(ts) -> str:
    return "never" if not ts else fmt_delta(db.now() - pd.Timestamp(ts)) + " ago"


# --------------------------------------------------------------- first start
# Not cached on purpose: Streamlit would replay cached elements on every rerun. The database
# flag makes this a one-time build, and a lock stops two sessions building at once.
if not bootstrap.initialized():
    with st.status("First start: building SecureOps AI from live sources (about a minute)...", expanded=True) as _s:
        built = bootstrap.run(progress=_s.write, force=st.session_state.pop("force_rebuild", False))
        _s.update(label="Ready" if built else "Another session is building - refresh in a minute", state="complete")
    if not bootstrap.initialized():
        st.stop()
    st.rerun()
now = db.now()

if "_goto" in st.session_state:  # navigation requested by a button on the previous run
    st.session_state.page = st.session_state.pop("_goto")

with st.sidebar:
    st.markdown("## :material/shield: SecureOps AI")
    st.caption("Threat detection & response on real network telemetry")
    page = st.radio("Navigate", PAGES, key="page", label_visibility="collapsed")
    st.divider()
    actor = st.text_input("Your name (for the audit trail)", value=st.session_state.get("actor", ""),
                          placeholder="e.g. Vimala")
    st.session_state.actor = actor
    actor = actor.strip() or "anonymous analyst"
    st.caption(f"AI assistant: **{assistant.llm_label()}**")
    st.caption(f"Database: **{db.engine().dialect.name}**")
    rs = replay.state()
    if rs.get("cursor"):
        st.caption(f"Replay at **{pd.Timestamp(rs['cursor']):%Y-%m-%d %H:%M}** (dataset time)")

incidents = db.list_incidents()
incidents = incidents[~incidents.resolution.fillna("").str.startswith("Merged into")]
open_mask = ~incidents.status.isin(["Resolved", "False positive"])


def select_incident(inc_id: str):
    st.session_state.selected = inc_id
    st.session_state._goto = "Investigate"


# =============================================================== OVERVIEW
if page == "Overview":
    st.title("Security operations overview")
    alerts_all = db.read_alerts()
    n_events = db.count("events")
    c = st.columns(6)
    c[0].metric("Events ingested", f"{n_events:,}")
    c[1].metric("Alerts raised", f"{len(alerts_all):,}")
    c[2].metric("Incidents", len(incidents), help="Related alerts grouped by shared entity and time proximity.")
    c[3].metric("Alert reduction", f"{1 - len(incidents) / max(1, len(alerts_all)):.0%}",
                help="1 - incidents / alerts: how many fewer items an analyst must triage.")
    c[4].metric("Open incidents", int(open_mask.sum()))
    c[5].metric("SLA breached (open)", int((open_mask & (incidents.sla_due < now)).sum()))

    fs = feeds.status()
    live_n = db.count("events", "WHERE dataset = 'live'")
    replay_n = db.count("events", "WHERE dataset = 'replay'")
    st.caption(f"Sources: real UWF Zeek replay ({replay_n:,} events) · live sensor/"
               f"upload data ({live_n:,} events) · threat intel {len(feeds.index()):,} indicators, refreshed "
               f"{ago(max([v.get('fetched_at') or '' for v in fs.values()] or ['']) or None)} · "
               f"{len(attack.techniques(build_if_missing=False))} ATT&CK techniques")

    if alerts_all.empty:
        st.info("No alerts yet - stream more data on the **Live data** page.")
        st.stop()
    left, right = st.columns(2)
    with left:
        top = alerts_all.groupby("rule_name").size().reset_index(name="alerts")
        st.altair_chart(theme(hbar(top, "rule_name", "alerts", "Top threats - alerts by detection"), bar_height(len(top))),
                        width="stretch")
    with right:
        rows = [{"asset": assets.label(ip), "incidents": 1, "score": r.score}
                for r in incidents.itertuples() for ip in json.loads(r.entities)["internal"]]
        aff = (pd.DataFrame(rows).groupby("asset").agg(incidents=("incidents", "sum"), max_score=("score", "max"))
               .reset_index().sort_values("max_score", ascending=False).head(10)) if rows else pd.DataFrame(
            {"asset": [], "incidents": [], "max_score": []})
        st.altair_chart(theme(hbar(aff, "asset", "incidents", "Most affected systems - incidents per asset (top 10 by risk)",
                                   tooltip=["asset", "incidents", "max_score"]), bar_height(len(aff))),
                        width="stretch")
    left, right = st.columns(2)
    with left:
        sev = incidents[open_mask].groupby("severity").size().reindex(SEV_ORDER, fill_value=0).reset_index(name="incidents")
        sev["label"] = sev.severity.map(lambda s: f"{SEV_ICON[s]} {s}")
        ch = alt.Chart(sev, title="Unresolved incidents by severity").encode(
            y=alt.Y("label:N", sort=[f"{SEV_ICON[s]} {s}" for s in SEV_ORDER], title=None),
            x=alt.X("incidents:Q", title=None, axis=alt.Axis(tickCount=4)), tooltip=["severity", "incidents"])
        chart = ch.mark_bar(cornerRadiusEnd=4, height={"band": 0.7}).encode(
            color=alt.Color("severity:N", scale=alt.Scale(domain=SEV_ORDER, range=[SEV_COLOR[s] for s in SEV_ORDER]),
                            legend=None)) + ch.mark_text(align="left", dx=4, color=INK2).encode(text="incidents:Q")
        st.altair_chart(theme(chart, 230), width="stretch")
    with right:
        tl = alerts_all.assign(day=alerts_all.ts.dt.floor("D")).groupby(["day", "tactic"]).size().reset_index(name="alerts")
        present = [t for t in KILL_CHAIN if t in set(tl.tactic)]
        colors = dict(zip(present, SERIES))
        chart = alt.Chart(tl, title="Alerts per day by ATT&CK tactic (event time)").mark_bar(
            stroke=SURFACE, strokeWidth=1).encode(
            x=alt.X("yearmonthdate(day):O", title=None, axis=alt.Axis(format="%b %d", labelAngle=0)),
            y=alt.Y("sum(alerts):Q", title=None, axis=alt.Axis(tickCount=4)),
            color=alt.Color("tactic:N", scale=alt.Scale(domain=present, range=[colors[t] for t in present]), title=None),
            tooltip=[alt.Tooltip("day:T", format="%b %d"), "tactic", "alerts"])
        st.altair_chart(theme(chart, 230), width="stretch")

    st.subheader("Investigation performance")
    st.caption("Measured from real case actions in this app (audit trail), not estimated.")
    ack = incidents.dropna(subset=["acknowledged_at"])
    res = incidents.dropna(subset=["resolved_at"])
    c = st.columns(5)
    c[0].metric("Mean time to acknowledge", fmt_delta((ack.acknowledged_at - ack.created_at).mean()) if len(ack) else "-")
    c[1].metric("Mean time to resolve", fmt_delta((res.resolved_at - res.created_at).mean()) if len(res) else "-")
    c[2].metric("Closed", len(res))
    c[3].metric("Closed within SLA", f"{(res.resolved_at <= res.sla_due).mean():.0%}" if len(res) else "-")
    c[4].metric("Marked false positive", int(incidents.false_positive.fillna(False).astype(bool).sum()))

# =============================================================== QUEUE
elif page == "Incident queue":
    st.title("Incident queue")
    w = settings.section("scoring")["weights"]
    st.caption(f"Sorted by priority = {w['threat']:.0%} threat confidence + {w['asset']:.0%} asset criticality + "
               f"{w['exposure']:.0%} vulnerability exposure + {w['spread']:.0%} spread (edit in Settings).")
    f = st.columns(4)
    s_status = f[0].multiselect("Status", db.STATUSES, default=["New", "Investigating", "Contained"])
    s_sev = f[1].multiselect("Severity", SEV_ORDER, default=SEV_ORDER)
    s_owner = f[2].selectbox("Owner", ["Anyone"] + settings.team())
    s_ds = f[3].selectbox("Source", ["All", "Replay (UWF real data)", "Live (sensor / upload)"])
    q = incidents[incidents.status.isin(s_status) & incidents.severity.isin(s_sev)]
    if s_owner != "Anyone":
        q = q[q.owner == s_owner]
    if s_ds != "All":
        q = q[q.dataset == ("live" if s_ds.startswith("Live") else "replay")]
    view = pd.DataFrame({
        "ID": q.incident_id, "Severity": q.severity.map(lambda s: f"{SEV_ICON[s]} {s}"), "Score": q.score,
        "Title": q.title, "Status": q.status, "Owner": q.owner,
        "SLA remaining": [fmt_delta(d - now) if s not in ("Resolved", "False positive") else "closed"
                          for d, s in zip(q.sla_due, q.status)],
        "Alerts": q.alert_count, "Last activity (event time)": q.last_seen.dt.strftime("%Y-%m-%d %H:%M"),
        "Source": q.dataset})
    st.caption(f"{len(view)} incidents · click a row to investigate")
    sel = st.dataframe(view, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row",
                       column_config={"Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100,
                                                                               format="%.0f")})
    if sel.selection.rows:
        select_incident(view.iloc[sel.selection.rows[0]].ID)
        st.rerun()

# =============================================================== INVESTIGATE
elif page == "Investigate":
    if incidents.empty:
        st.info("No incidents yet.")
        st.stop()
    ids = incidents.incident_id.tolist()
    cur_sel = st.session_state.get("selected") if st.session_state.get("selected") in ids else ids[0]
    titles = incidents.set_index("incident_id").title
    sel = st.selectbox("Incident", ids, index=ids.index(cur_sel), format_func=lambda i: f"{i} - {titles[i]}")
    st.session_state.selected = sel
    inc = db.get_incident(sel)
    alerts = db.read_alerts(sel)
    events = db.events_by_ids({e for es in alerts.evidence for e in es})
    sc = inc["scoring"]
    st.markdown(f"### {inc['title']}")
    st.markdown(f"{sev_badge(inc['severity'])} &nbsp; **Score {inc['score']:.0f}/100** · Status **{inc['status']}** · "
                f"Owner **{inc['owner']}** · SLA due {inc['sla_due']:%Y-%m-%d %H:%M} UTC ({fmt_delta(inc['sla_due'] - now)}) · "
                f"{inc['alert_count']} alerts, {inc['event_count']} evidence events · "
                f"{'live sensor/upload data' if inc['dataset'] == 'live' else 'real UWF Zeek replay'}",
                unsafe_allow_html=True)
    stages = [t for t in KILL_CHAIN if t in set(alerts.tactic)]
    st.markdown("**Kill chain:** " + " → ".join(f"`{t}`" for t in stages))

    main, side = st.columns([3, 2], gap="large")
    with main:
        st.markdown("#### :material/psychology: AI investigation assistant")
        st.markdown(inc["ai_summary"])
        checks = inc["ai_checks"] or []
        st.caption(f"Mode: **{inc['ai_mode']}** · Evidence check: **{inc['ai_support']:.0%}** of sentences cite valid "
                   f"evidence IDs ({sum(c['supported'] for c in checks)}/{len(checks)}).")
        if st.button("Regenerate with LLM" if assistant.llm_available() else "Regenerate (offline engine)"):
            with st.spinner("Retrieving evidence and generating..."):
                ex = pipeline.regenerate_explanation(sel, use_llm=True)
            if ex["note"]:
                st.warning(ex["note"])
            st.rerun()
        with st.expander("Verification: sentence-by-sentence citation check"):
            st.dataframe(pd.DataFrame(checks), hide_index=True, width="stretch")

        st.markdown("#### :material/manage_search: Evidence")
        t1, t2, t3, t4 = st.tabs(["Timeline", "Alerts", "Raw events", "Assets, CVEs & ATT&CK"])
        with t1:
            present = [t for t in KILL_CHAIN if t in set(alerts.tactic)]
            colors = dict(zip(present, SERIES))
            chart = alt.Chart(alerts.assign(rule=alerts.rule_name)).mark_circle(
                size=90, stroke=SURFACE, strokeWidth=2, opacity=0.9).encode(
                x=alt.X("ts:T", title=None), y=alt.Y("rule:N", title=None, axis=alt.Axis(labelLimit=260)),
                color=alt.Color("tactic:N", scale=alt.Scale(domain=present, range=[colors[t] for t in present]), title=None),
                tooltip=[alt.Tooltip("alert_id:Q", title="Alert"), alt.Tooltip("ts:T", format="%Y-%m-%d %H:%M:%S"),
                         "rule", "tactic", alt.Tooltip("confidence:Q", format=".2f"), "description"])
            st.altair_chart(theme(chart, 90 + 40 * alerts.rule_name.nunique()), width="stretch")
        with t2:
            st.dataframe(alerts.assign(id="ALR-" + alerts.alert_id.astype(str))[
                ["id", "ts", "rule_name", "tactic", "technique", "src_ip", "dst_ip", "confidence", "description"]],
                hide_index=True, width="stretch")
        with t3:
            st.dataframe(events.assign(event_id="EVT-" + events.event_id.astype(str))[
                ["event_id", "ts", "source", "sensor", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "service",
                 "conn_state", "duration", "bytes_out", "bytes_in", "outcome", "signature"]],
                hide_index=True, width="stretch")
        with t4:
            idx = assets.index()
            rows = [{"asset": assets.label(ip), "role": idx[ip]["role"], "criticality": idx[ip]["criticality"],
                     "source": idx[ip]["criticality_source"], "fan-in": idx[ip]["fan_in"], "CVEs": len(idx[ip]["cves"])}
                    for ip in inc["entities"]["internal"] if ip in idx]
            st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
            if sc.get("top_cves"):
                st.dataframe(pd.DataFrame(sc["top_cves"]), hide_index=True, width="stretch")
            else:
                st.caption("No CVEs linked - add CPEs for these hosts on the **Assets** page to measure exposure.")
            for tech in sorted({t for t in alerts.technique if t}):
                k = attack.lookup(tech)
                if k:
                    st.markdown(f"**[{k['id']} {k['name']}]({k['url']})** · {', '.join(k['tactics'])}")
            if inc["entities"]["external"]:
                st.markdown("**External entities:** " + ", ".join(f"`{x}`" for x in inc["entities"]["external"][:20]))

    with side:
        st.markdown("#### :material/speed: Why this priority")
        w = sc.get("weights") or settings.section("scoring")["weights"]
        br = pd.DataFrame([{"component": f"{k} (weight {w[k]:.0%})", "value": v, "points": round(100 * w[k] * v, 1)}
                           for k, v in sc["breakdown"].items()])
        st.altair_chart(theme(hbar(br, "component", "points", f"Contribution to score {inc['score']:.0f}",
                                   tooltip=["component", "value", "points"]), bar_height(4)), width="stretch")
        if sc["exploited_cves"]:
            st.error("Confirmed exploitable: " + ", ".join(f"{h} / {c}" for h, c in sc["exploited_cves"]),
                     icon=":material/warning:")

        st.markdown("#### :material/assignment_ind: Case management")
        team = settings.team()
        if len(team) == 1:
            st.caption("Add analysts on the **Settings** page to assign owners.")
        with st.form("case"):
            owner = st.selectbox("Owner", team, index=team.index(inc["owner"]) if inc["owner"] in team else 0)
            status = st.selectbox("Status", db.STATUSES, index=db.STATUSES.index(inc["status"]))
            resolution = st.text_area("Resolution / notes", value=inc["resolution"] or "")
            if st.form_submit_button("Save case", type="primary", width="stretch"):
                db.update_incident(sel, actor, owner=owner, status=status, resolution=resolution)
                st.toast("Case updated and audited")
                st.rerun()

        st.markdown("#### :material/gavel: Response (analyst approval required)")
        acts = [f"Block {ip} at the perimeter" for ip in inc["entities"]["external"][:3]]
        acts += [f"Isolate host {assets.label(ip)}" for ip in inc["entities"]["internal"][:4]
                 if not assets.index().get(ip, {}).get("is_hub")]
        acts += [f"Allow-list source {ip} (benign)" for ip in sorted(set(alerts.src_ip) - {""})[:2]]
        chosen = st.multiselect("Proposed actions (recorded, not executed - no firewall is connected)", acts)
        c1, c2 = st.columns(2)
        if c1.button("Approve & record", disabled=not chosen, width="stretch"):
            for a in chosen:
                db.audit(sel, "response_approved", a, actor)
                if a.startswith("Allow-list source "):
                    ip = a.split()[2]
                    ov = settings.overrides()
                    net = ov.setdefault("network", {})
                    net["allowlist_sources"] = sorted(set(settings.section("network")["allowlist_sources"]) | {ip})
                    settings.save(ov)
            st.toast(f"{len(chosen)} action(s) approved and logged")
            st.rerun()
        if c2.button("Create ticket", width="stretch"):
            tid = f"TCK-{sel.split('-')[1]}-{len(db.read_audit(sel)):02d}"
            db.audit(sel, "ticket_created", f"{tid} assigned to {inc['owner']}", actor)
            st.session_state[f"ticket_{sel}"] = {"ticket": tid, "incident": sel, "title": inc["title"],
                                                 "severity": inc["severity"], "score": inc["score"], "owner": inc["owner"],
                                                 "sla_due": str(inc["sla_due"]), "summary": inc["ai_summary"]}
            st.rerun()
        if st.session_state.get(f"ticket_{sel}"):
            t = st.session_state[f"ticket_{sel}"]
            st.download_button(f"Download {t['ticket']}.json", json.dumps(t, indent=2), f"{t['ticket']}.json",
                               width="stretch")
        st.markdown("#### :material/history: Audit trail")
        st.dataframe(db.read_audit(sel)[["ts", "actor", "action", "detail"]], hide_index=True,
                     width="stretch", height=220)
        if inc["dataset"] == "replay":
            with st.expander("Dataset ground truth (evaluation only - never seen by the detectors)"):
                lab = db.read_labels()
                tl = lab[lab.event_id.isin(events.event_id)]
                st.write(f"{len(tl)} of {len(events)} evidence events are labelled attacks by UWF: "
                         f"{', '.join(sorted(set(','.join(tl.tactic).split(',')) - {''})) or 'none (benign)'}")

# =============================================================== LIVE DATA
elif page == "Live data":
    st.title("Live data")
    t3, t1, t2 = st.tabs(["Live sensor", "Replay stream (real dataset)", "Upload logs"])
    with t1:
        info = uwf.info()
        rs = replay.state()
        cur = pd.Timestamp(rs.get("cursor") or info["start"])
        st.markdown(f"Streaming **UWF-ZeekData24**: {info['events']:,} real Zeek connection records over {info['days']} "
                    f"capture days, {info['attack_events']:,} of them labelled attacks (labels are hidden from the detectors).")
        frac = max(0.0, min(1.0, (cur - info["start"]) / (info["end"] - info["start"])))
        st.progress(frac, text=f"Dataset time {cur:%Y-%m-%d %H:%M} UTC · {frac:.0%} streamed")
        step = settings.section("replay")["step_minutes"]
        c1, c2, c3 = st.columns(3)
        if c1.button(f"Stream next {step} min", type="primary", width="stretch", disabled=frac >= 1):
            st.session_state.last_step = replay.step()
        if c2.button("Stream next 6 hours", width="stretch", disabled=frac >= 1):
            with st.spinner("Streaming..."):
                st.session_state.last_step = replay.step(360)
        auto = c3.toggle("Auto-stream (every 5 s)", disabled=frac >= 1)

        @st.fragment(run_every=5 if auto else None)
        def _auto():
            if auto:
                last = replay.state().get("last_step_wall")
                if not last or (db.now() - pd.Timestamp(last)).total_seconds() >= 4:  # one stream for all viewers
                    r = replay.step()
                    db.set_meta("replay", {**replay.state(), "last_step_wall": db.now().isoformat()})
                    st.session_state.last_step = r
            r = st.session_state.get("last_step")
            if r:
                st.markdown(f"<div class='stage'><b>Last step</b> - {r['events']:,} events ingested → {r['alerts']} alerts "
                            f"({', '.join(f'{k} ×{v}' for k, v in r['rules'].items()) or 'none'}) → "
                            f"{len(r['new_incidents'])} new incident(s), {len(r['updated_incidents'])} updated. "
                            f"Cursor {pd.Timestamp(r['cursor']):%Y-%m-%d %H:%M}.</div>", unsafe_allow_html=True)
                for iid in r["new_incidents"][:5]:
                    i = db.get_incident(iid)
                    if i and st.button(f"Open {iid}: {i['severity']} {i['score']:.0f} - {i['title'][:80]}", key=f"o{iid}"):
                        select_incident(iid)
                        st.rerun()
        _auto()
    with t2:
        st.markdown("Upload real logs: **Zeek** `conn.log`, `ssh.log`, `software.log` (TSV or JSON, `.gz` ok) or "
                    "**Suricata** `eve.json`. They go through the full pipeline as live, unlabelled data.")
        sensor = st.text_input("Sensor / site name", value="upload")
        files = st.file_uploader("Log files", accept_multiple_files=True)
        if files and st.button("Ingest files", type="primary"):
            for f in files:
                raw = f.getvalue()
                with st.spinner(f"Processing {f.name}..."):
                    if "eve" in f.name.lower() or "suricata" in f.name.lower():
                        p = suricata.parse_bytes(raw, f.name, sensor=sensor)
                        r = pipeline.ingest(p["events"])
                        kind = f"Suricata ({p['alerts']} alerts, {p['flows']} flows)"
                    else:
                        p = zeek.parse_bytes(raw, f.name, sensor=sensor)
                        r = pipeline.ingest(p["events"], software=p["software"])
                        kind = f"Zeek {p['path'] or 'unknown'} log ({p['rows']} rows)"
                st.success(f"{f.name}: {kind} → {r['events']:,} events, {r['alerts']} alerts, "
                           f"{len(r['new_incidents'])} new incident(s) {', '.join(r['new_incidents'][:5])}")
    with t3:
        api_url = _api_url()
        auto_live = st.toggle("Auto-refresh (every 5 s)", value=True, key="live_auto")

        @st.fragment(run_every=5 if auto_live else None)
        def _live():
            now_ = db.now()
            sensors = db.read_events_sql(
                "SELECT sensor, COUNT(*) AS events, MAX(ts) AS last_event, "
                "SUM(CASE WHEN source = 'suricata_alert' THEN 1 ELSE 0 END) AS ids_alerts "
                "FROM events WHERE dataset = 'live' GROUP BY sensor")
            if sensors.empty:
                st.info("No live sensor data yet. Start a sensor (instructions below) or upload logs - events appear here "
                        "within seconds.", icon=":material/sensors_off:")
            else:
                sensors["last_event"] = pd.to_datetime(sensors.last_event, utc=True, format="mixed")
                age = (now_ - sensors.last_event).dt.total_seconds()
                sensors["status"] = ["● streaming" if a < 120 else "○ idle" for a in age]
                sensors["last seen"] = [fmt_delta(pd.Timedelta(seconds=a)) + " ago" for a in age]
                recent = db.read_events_sql("SELECT ts, source FROM events WHERE dataset = 'live' AND ts >= :t",
                                            {"t": db.py(now_ - pd.Timedelta(minutes=30))})
                recent["ts"] = pd.to_datetime(recent.ts, utc=True, format="mixed")
                live_alerts = db.read_alerts()
                live_alerts = live_alerts[live_alerts.dataset == "live"]
                live_inc = incidents[incidents.dataset == "live"]
                c = st.columns(5)
                c[0].metric("Sensors streaming", f"{int((age < 120).sum())} / {len(sensors)}")
                c[1].metric("Live events", f"{int(sensors.events.sum()):,}")
                c[2].metric("Events, last 5 min", f"{int((recent.ts >= now_ - pd.Timedelta(minutes=5)).sum()):,}")
                c[3].metric("Live alerts", f"{len(live_alerts):,}")
                c[4].metric("Open live incidents", int((~live_inc.status.isin(["Resolved", "False positive"])).sum()))
                st.dataframe(sensors[["status", "sensor", "events", "ids_alerts", "last seen"]], hide_index=True,
                             width="stretch")
                if len(recent):
                    per_min = recent.assign(minute=recent.ts.dt.floor("min")).groupby(["minute", "source"]).size()                         .reset_index(name="events")
                    srcs = sorted(per_min.source.unique())
                    chart = alt.Chart(per_min, title="Events per minute, last 30 minutes (UTC)").mark_bar(
                        stroke=SURFACE, strokeWidth=1).encode(
                        x=alt.X("utchoursminutes(minute):O", title=None, axis=alt.Axis(labelAngle=0, labelOverlap=True)),
                        y=alt.Y("sum(events):Q", title=None, axis=alt.Axis(tickCount=4)),
                        color=alt.Color("source:N", scale=alt.Scale(domain=srcs, range=SERIES[:len(srcs)]), title=None),
                        tooltip=[alt.Tooltip("utchoursminutes(minute):O", title="minute (UTC)"), "source", "events"])
                    st.altair_chart(theme(chart, 220), width="stretch")
                left, right = st.columns([3, 2])
                with left:
                    st.markdown("**Latest live alerts**")
                    la = live_alerts.sort_values("ts", ascending=False).head(15)
                    st.dataframe(la[["ts", "rule_name", "src_ip", "dst_ip", "incident_id", "description"]], hide_index=True,
                                 width="stretch", height=300)
                with right:
                    st.markdown("**Live incidents**")
                    for r in live_inc.sort_values("last_seen", ascending=False).head(6).itertuples():
                        if st.button(f"{SEV_ICON[r.severity]} {r.incident_id} · {r.score:.0f} · {r.title[:60]}",
                                     key=f"live_{r.incident_id}", width="stretch"):
                            select_incident(r.incident_id)
                            st.rerun()
        _live()

        with st.expander("Connect a sensor", expanded=not db.count("events", "WHERE dataset = 'live'")):
            shown = api_url or "https://<your-api>.onrender.com"
            st.markdown(f"""
Run **Zeek + Suricata** on a Linux machine, Raspberry Pi, WSL2 or Docker Desktop and stream their logs here in real time
with the kit in the repository's `sensor/` folder. API for this dashboard: **{api_url or "not detected - deploy it (DEPLOY.md, level 3) and set API_PUBLIC_URL"}**.

```bash
cd sensor
cp .env.example .env      # IFACE=eth0, API_URL={shown}, API_TOKEN=<SECUREOPS_API_TOKEN>
docker compose up -d       # Zeek + Suricata + log shipper
docker compose logs -f shipper
```

On Docker Desktop use `API_URL=http://host.docker.internal:8000` (the sensor then sees container traffic).
The shipper POSTs new lines of `conn.log`, `ssh.log`, `software.log` and `eve.json` to `/ingest/zeek` and
`/ingest/suricata`. No sensor? Capture with Wireshark/tcpdump, run `sensor/process_pcap.sh capture.pcap`, and upload
the logs on the **Upload logs** tab.""")

# =============================================================== ASSETS
elif page == "Assets":
    st.title("Assets")
    a = db.read_assets()
    hn = db.get_meta("home_networks_inferred")
    st.caption(f"{len(a)} internal hosts discovered from traffic. Home networks: "
               f"{settings.section('network')['home_networks'] if settings.section('network')['home_networks'] != 'auto' else 'auto → ' + ', '.join(hn or [])}. "
               "Criticality is inferred (1 + serves services + popularity + hub) unless your inventory sets it.")
    c = st.columns(4)
    c[0].metric("Hosts", len(a))
    c[1].metric("Servers (answer connections)", int((a.services.map(len) > 0).sum()))
    c[2].metric("Shared infrastructure (hubs)", int(a.is_hub.sum()))
    c[3].metric("Hosts with known CVEs", int((a.cves.map(len) > 0).sum()))
    edit = a[["ip", "hostname", "criticality", "criticality_source", "owner", "cpes", "notes", "role", "fan_in",
              "fan_out", "is_hub", "last_seen"]].copy()
    edit["cpe"] = edit.pop("cpes").map(lambda x: ";".join(x))
    edit = edit.sort_values(["criticality", "fan_in"], ascending=False)
    st.markdown("**Inventory** - edit hostname, criticality, owner, CPE (for live NVD lookup) and notes, then save.")
    edited = st.data_editor(edit, hide_index=True, width="stretch", height=380,
                            disabled=["ip", "criticality_source", "role", "fan_in", "fan_out", "is_hub", "last_seen"],
                            column_config={"criticality": st.column_config.NumberColumn(min_value=1, max_value=5, step=1),
                                           "cpe": st.column_config.TextColumn(help="e.g. cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")})
    c1, c2, c3 = st.columns(3)
    if c1.button("Save inventory changes", type="primary", width="stretch"):
        changed = edited.merge(edit, on="ip", suffixes=("", "_old"))
        mask = (changed.hostname != changed.hostname_old) | (changed.criticality != changed.criticality_old) | \
               (changed.owner != changed.owner_old) | (changed.cpe != changed.cpe_old) | (changed.notes != changed.notes_old)
        rows = changed[mask][["ip", "hostname", "criticality", "owner", "cpe", "notes"]]
        if len(rows):
            assets.apply_inventory(rows)
            n = pipeline.rescore_all()
            st.success(f"{len(rows)} asset(s) updated; {n} open incidents re-scored.")
        else:
            st.info("No changes.")
    if c2.button("Look up CVEs for CPEs (live NVD)", width="stretch"):
        with st.spinner("Querying NVD, CISA KEV and EPSS (NVD allows 5 requests / 30 s without a key)..."):
            n = assets.lookup_cves()
            pipeline.rescore_all()
        st.success(f"{n} CVE links found; open incidents re-scored.")
    c3.download_button("Download inventory CSV", edited[["ip", "hostname", "criticality", "owner", "cpe", "notes"]]
                       .to_csv(index=False), "inventory.csv", width="stretch")
    up = st.file_uploader("Or upload an inventory CSV (columns: ip, hostname, criticality, owner, cpe, notes)", type="csv")
    if up and st.button("Apply uploaded inventory"):
        n = assets.apply_inventory(pd.read_csv(up))
        st.success(f"{n} rows applied; {pipeline.rescore_all()} open incidents re-scored.")
    cves = sorted({c for cs in a.cves for c in cs})
    if cves:
        st.markdown("**Vulnerabilities on your assets** (NVD · CISA KEV · FIRST EPSS)")
        st.dataframe(db.read_vulns(cves).sort_values("cvss", ascending=False), hide_index=True, width="stretch")

# =============================================================== THREAT INTEL
elif page == "Threat intel":
    st.title("Threat intelligence")
    fs = feeds.status()
    rows = [{"feed": k, "indicators": v.get("count"), "refreshed": ago(v.get("fetched_at")), "status":
             ("error: " + v["error"]) if v.get("error") else "ok", "url": v.get("url")} for k, v in fs.items()]
    kev = db.get_meta("kev_status") or {}
    rows.append({"feed": "cisa_kev", "indicators": kev.get("count"), "refreshed": ago(kev.get("fetched_at")),
                 "status": f"catalog {kev.get('version')}", "url": settings.section("intel")["feeds"]["cisa_kev"]})
    rows.append({"feed": "mitre_attack", "indicators": len(attack.techniques(build_if_missing=False)), "refreshed": "cached",
                 "status": "techniques", "url": settings.section("intel")["feeds"]["mitre_attack"]})
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    if st.button("Refresh feeds now", type="primary"):
        with st.spinner("Fetching feeds..."):
            feeds.refresh(force=True)
            vulns.kev_catalog(force=True)
        st.rerun()
    ip = st.text_input("Check an IP against all feeds")
    if ip:
        hit = feeds.index().lookup(ip.strip())
        st.error(f"Listed: {hit[0]} - {hit[1]}") if hit else st.success("Not listed in any loaded feed.")
    ioc = db.read_alerts()
    ioc = ioc[ioc.rule_id == "R-IOC"]
    st.markdown(f"**Threat-intel matches in your traffic:** {len(ioc)}")
    if len(ioc):
        st.dataframe(ioc[["ts", "src_ip", "dst_ip", "description", "incident_id"]], hide_index=True, width="stretch")
    else:
        st.caption("None yet. The UWF dataset uses only its own internal address space; matches appear when live sensor or "
                   "uploaded traffic touches a listed address.")

# =============================================================== EVALUATION
elif page == "Evaluation":
    st.title("Evaluation on real labelled data")
    p = config.ROOT / "reports" / "metrics.json"
    if st.button("Re-run evaluation (~1-2 min: replays all 18 days in a separate database)"):
        from secureops import evaluate
        with st.status("Evaluating...", expanded=False) as s:
            evaluate.run(progress=s.write)
    if not p.exists():
        st.warning("No report yet - click Re-run evaluation.")
        st.stop()
    m = json.loads(p.read_text())
    t = m["test"]
    st.caption(f"{m['dataset']}. Test = days after {m['split_at'][:10]} (held out in time). Generated {m['generated_at']}. "
               "Unit: one source IP × one hour.")
    d = t["detection_combined"]
    c = st.columns(6)
    c[0].metric("Precision", f"{d['precision']:.2f}")
    c[1].metric("Recall", f"{d['recall']:.2f}")
    c[2].metric("F1", f"{d['f1']:.2f}")
    c[3].metric("False-positive rate", f"{d['false_positive_rate']:.2%}")
    c[4].metric("Alert reduction", f"{t['correlation']['alert_reduction']:.0%}",
                help=f"{t['correlation']['alerts']} alerts → {t['correlation']['incidents']} incidents")
    llm = m.get("llm_reliability") or {}
    if llm.get("sentence_support_rate") is not None:
        c[5].metric("LLM citation accuracy", f"{llm['sentence_support_rate']:.0%}",
                    help=f"{llm['model']}: {llm['sentences']} sentences over {llm['incidents']} held-out incidents; "
                         f"{llm['unsupported_sentences']} cited missing evidence or nothing.")
    else:
        c[5].metric("AI evidence support", f"{t['ai_reliability']['mean_supported_sentence_rate']:.0%}",
                    help="Offline engine - 100% by construction. Run the evaluation with an LLM key to measure the LLM.")
    rows = []
    for period in ("test", "development"):
        for k, lab in (("detection_combined", "Rules + anomaly"), ("detection_rules_only", "Rules only"),
                       ("detection_anomaly_only", "Anomaly only")):
            x = m[period][k]
            rows.append({"period": period, "detector": lab, "precision": x["precision"], "recall": x["recall"],
                         "f1": x["f1"], "FPR": f"{x['false_positive_rate']:.2%}", "TP": x["tp"], "FP": x["fp"], "FN": x["fn"]})
    st.subheader("Detection")
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    st.subheader("Per ATT&CK tactic (test)")
    pt = pd.DataFrame(t["per_tactic"])
    pt["detected_by"] = pt.detected_by.map(lambda x: ", ".join(x) or "missed")
    st.dataframe(pt, hide_index=True, width="stretch")
    left, right = st.columns(2)
    with left:
        co = t["correlation"]
        q = pd.DataFrame([{"stage": "Raw alerts", "items": co["alerts"]}, {"stage": "Incidents", "items": co["incidents"]},
                          {"stage": "Real-attack incidents", "items": co["true_incidents"]}])
        st.altair_chart(theme(hbar(q, "stage", "items", "Analyst triage queue (test)"), bar_height(3)),
                        width="stretch")
    with right:
        pr = t["prioritisation"]
        st.markdown(f"- **Precision@{pr['k']}**: {pr['precision_at_k']:.2f}\n- Mean score: real **{pr['mean_score_true']}** "
                    f"vs false positive **{pr['mean_score_false']}**\n- Real incidents by severity: {pr['severity_true']}\n"
                    f"- False positives by severity: {pr['severity_false']}")
        st.dataframe(pd.DataFrame(t["per_rule"]), hide_index=True, width="stretch")
    st.subheader("Limitations")
    st.markdown((config.ROOT / "reports" / "EVALUATION.md").read_text(encoding="utf-8").split("## Limitations", 1)[-1])

# =============================================================== SETTINGS
elif page == "Settings":
    st.title("Settings")
    st.caption("Defaults come from config.yaml; changes here are stored in the database and apply to new data immediately.")
    cfg = settings.get()
    det = cfg["detection"]
    with st.form("settings"):
        st.subheader("Team")
        team = st.text_area("Analysts (one per line)", "\n".join(cfg.get("team", [])))
        st.subheader("Network")
        hn = st.text_input("Home networks ('auto' or comma-separated CIDRs)",
                           cfg["network"]["home_networks"] if isinstance(cfg["network"]["home_networks"], str)
                           else ", ".join(cfg["network"]["home_networks"]))
        allow = st.text_input("Allow-listed sources (comma-separated IPs)", ", ".join(cfg["network"]["allowlist_sources"]))
        hub = st.slider("Hub threshold (share of hosts that talk to it)", 0.05, 0.9, float(cfg["network"]["hub_fan_in_share"]))
        st.subheader("Detection thresholds")
        c = st.columns(4)
        bf_n = c[0].number_input("Brute force: attempts", 2, 1000, int(det["bruteforce"]["attempts"]))
        bf_w = c[1].text_input("Brute force: window", det["bruteforce"]["window"])
        sc_p = c[2].number_input("Scan: distinct ports", 2, 10000, int(det["scan"]["distinct_ports"]))
        sc_h = c[3].number_input("Scan: distinct hosts", 2, 10000, int(det["scan"]["distinct_hosts"]))
        c = st.columns(4)
        sc_w = c[0].text_input("Scan: window", det["scan"]["window"])
        lat_n = c[1].number_input("Lateral: distinct hosts", 2, 1000, int(det["lateral"]["distinct_hosts"]))
        ssh_n = c[2].number_input("SSH: failures", 1, 1000, int(det["ssh_bruteforce"]["failures"]))
        ex_mb = c[3].number_input("Exfil: MB per connection", 1, 100000, int(det["exfil"]["bytes_per_conn"] / 1024**2))
        c = st.columns(3)
        cont = c[0].number_input("Anomaly contamination", 0.0005, 0.2, float(det["anomaly"]["contamination"]), format="%.4f")
        base_h = c[1].number_input("Anomaly baseline hours", 6, 720, int(det["anomaly"]["baseline_hours"]))
        gap = c[2].number_input("Correlation gap (minutes)", 5, 1440, int(cfg["correlation"]["gap_minutes"]))
        st.subheader("Prioritisation")
        c = st.columns(4)
        wts = {k: c[i].number_input(f"Weight: {k}", 0.0, 1.0, float(cfg["scoring"]["weights"][k]), 0.05)
               for i, k in enumerate(["threat", "asset", "exposure", "spread"])}
        c = st.columns(3)
        bands = {k: c[i].number_input(f"{k} at score ≥", 0, 100, int(cfg["scoring"]["bands"][k]))
                 for i, k in enumerate(["Critical", "High", "Medium"])}
        c = st.columns(4)
        sla = {k: c[i].number_input(f"SLA hours: {k}", 0.25, 720.0, float(cfg["sla_hours"][k]))
               for i, k in enumerate(SEV_ORDER)}
        st.subheader("Replay & AI")
        c = st.columns(3)
        step = c[0].number_input("Replay step (minutes)", 5, 1440, int(cfg["replay"]["step_minutes"]))
        prov = c[1].selectbox("AI provider", ["auto", "groq", "ollama", "offline"],
                              index=["auto", "groq", "ollama", "offline"].index(cfg["ai"]["provider"]))
        model = c[2].text_input("Groq model", cfg["ai"]["groq_model"])
        if st.form_submit_button("Save settings", type="primary"):
            if abs(sum(wts.values()) - 1) > 0.01:
                st.error(f"Weights must add up to 1.0 (now {sum(wts.values()):.2f}).")
            else:
                override = {
                    "team": [t.strip() for t in team.splitlines() if t.strip()],
                    "network": {"home_networks": "auto" if hn.strip() == "auto" else [x.strip() for x in hn.split(",") if x.strip()],
                                "allowlist_sources": [x.strip() for x in allow.split(",") if x.strip()],
                                "hub_fan_in_share": hub},
                    "detection": {"bruteforce": {"attempts": bf_n, "window": bf_w},
                                  "scan": {"distinct_ports": sc_p, "distinct_hosts": sc_h, "window": sc_w},
                                  "lateral": {"distinct_hosts": lat_n}, "ssh_bruteforce": {"failures": ssh_n},
                                  "exfil": {"bytes_per_conn": int(ex_mb * 1024**2)},
                                  "anomaly": {"contamination": cont, "baseline_hours": base_h}},
                    "correlation": {"gap_minutes": gap},
                    "scoring": {"weights": wts, "bands": bands}, "sla_hours": sla,
                    "replay": {"step_minutes": step}, "ai": {"provider": prov, "groq_model": model}}
                settings.save(override)
                db.audit("-", "settings_changed", json.dumps(override)[:900], actor)
                st.success("Saved. New data uses these settings now.")
    c1, c2, c3 = st.columns(3)
    if c1.button("Re-score open incidents", width="stretch"):
        st.success(f"{pipeline.rescore_all()} incidents re-scored.")
    if c2.button("Retrain anomaly model", width="stretch"):
        r = pipeline.retrain_model()
        st.success(f"Retrained: {r['meta']}")
    if c3.button("Reset to config.yaml defaults", width="stretch"):
        settings.save({})
        st.rerun()
    with st.expander("Danger zone"):
        if st.button("Rebuild everything from scratch (re-stream the dataset)"):
            db.set_meta("initialized", None)
            st.session_state.force_rebuild = True
            st.rerun()

# =============================================================== ABOUT
else:
    st.title("About SecureOps AI")
    st.markdown("""
**SecureOps AI** ingests real network telemetry, detects threats, **correlates many alerts into a few incidents**,
prioritises them by threat × asset × live vulnerability exposure, explains each with an **evidence-cited AI assistant**,
and supports analyst-approved response with a full audit trail.

```
Real data:  UWF-ZeekData24 replay · Zeek/Suricata sensor push · log upload
Live intel: abuse.ch Feodo + URLhaus · Spamhaus DROP · NVD · CISA KEV · FIRST EPSS · MITRE ATT&CK
        │
        ▼
Assets: discovered from traffic + your inventory CSV (criticality, CPEs → live CVEs)
        │
        ▼
Detection: ATT&CK-mapped rules + Isolation Forest (per host-hour)   ← thresholds in Settings
        │
        ▼
Correlation: union-find over shared entities within N minutes, incremental (joins / merges open incidents)
        │
        ▼
Prioritisation: threat · asset criticality · CVE exposure (KEV/EPSS) · spread → severity → SLA
        │
        ▼
AI assistant: retrieve evidence + ATT&CK + playbooks → LLM (Groq/Ollama) or offline → citation verifier
        │
        ▼
Case management: owner · status · SLA · approved response · ticket · audit log
```

**Nothing about the environment is hard-coded:** hosts, roles and criticality are learned from traffic (or your CSV),
CVEs come from NVD for the CPEs you provide, indicators come from live feeds, and every threshold, weight, SLA and team
member is editable on the Settings page.

**Data honesty.** The replay is real traffic recorded by the University of West Florida (CC BY 4.0) and labelled with
MITRE ATT&CK; labels are used only for evaluation. Benign and attack captures were recorded in different weeks and are
overlaid day-by-day (see the Evaluation page).
""")
