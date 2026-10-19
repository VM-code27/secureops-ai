"""SecureOps AI - analyst dashboard (Streamlit).

Local:   streamlit run streamlit_app.py
Cloud:   Streamlit Community Cloud -> main file `streamlit_app.py` (free)
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import altair as alt
import pandas as pd
import streamlit as st

# Streamlit Cloud secrets -> environment (before importing config).
try:
    for _k in ("GROQ_API_KEY", "GROQ_MODEL", "OLLAMA_URL", "OLLAMA_MODEL", "DATABASE_URL", "LLM_PROVIDER"):
        if _k in st.secrets and not os.getenv(_k):
            os.environ[_k] = str(st.secrets[_k])
except Exception:
    pass

from secureops import assistant, config, db, pipeline  # noqa: E402
from secureops.assets import asset_index, build_assets  # noqa: E402
from secureops.correlation import KILL_CHAIN  # noqa: E402
from secureops.nvd import load_cves  # noqa: E402
from secureops.scoring import WEIGHTS  # noqa: E402
from secureops.simulate import LIVE_SCENARIOS  # noqa: E402

st.set_page_config(page_title="SecureOps AI", page_icon=":material/shield:", layout="wide")

# --------------------------------------------------------------- design tokens
SURFACE, INK, INK2, MUTED, GRID = "#1a1a19", "#f0efec", "#c3c2b7", "#8a8984", "#2e2e2c"
BLUE = "#3987e5"
SERIES = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"]  # fixed order
SEV_COLOR = {"Critical": "#d03b3b", "High": "#ec835a", "Medium": "#fab219", "Low": "#8a8984"}
SEV_ICON = {"Critical": "▲▲", "High": "▲", "Medium": "◆", "Low": "▽"}
SEV_ORDER = ["Critical", "High", "Medium", "Low"]
TACTIC_COLOR = dict(zip(KILL_CHAIN, SERIES))

st.markdown(f"""
<style>
.block-container {{padding-top: 1.6rem; max-width: 1400px;}}
.sev {{display:inline-block; padding:2px 10px; border-radius:999px; font-weight:600; font-size:0.85rem;
       border:1px solid currentColor;}}
.small {{color:{MUTED}; font-size:0.85rem;}}
.stage {{border:1px solid {GRID}; border-radius:10px; padding:10px 14px; margin-bottom:8px;}}
.stage b {{color:{INK};}}
</style>""", unsafe_allow_html=True)


def sev_badge(sev: str) -> str:
    return f"<span class='sev' style='color:{SEV_COLOR[sev]}'>{SEV_ICON[sev]} {sev}</span>"


def bar_height(n: int) -> int:
    return 40 + 30 * n  # one readable row per category, so no axis label is dropped


def theme(chart: alt.Chart, height: int = 260) -> alt.Chart:
    return (chart.properties(height=height, background="transparent")
            .configure_view(stroke=None)
            .configure_axis(labelColor=INK2, titleColor=INK2, gridColor=GRID, domainColor=GRID, tickColor=GRID,
                            labelFontSize=12, titleFontSize=12, titleFontWeight="normal")
            .configure_legend(labelColor=INK2, titleColor=INK2, orient="bottom", labelFontSize=12, columns=4)
            .configure_title(color=INK, anchor="start", fontSize=14, fontWeight=600))


def hbar(df: pd.DataFrame, cat: str, val: str, title: str, color: str = BLUE, tooltip=None) -> alt.Chart:
    base = alt.Chart(df, title=title).encode(
        y=alt.Y(f"{cat}:N", sort="-x", title=None, axis=alt.Axis(labelLimit=260)),
        x=alt.X(f"{val}:Q", title=None, axis=alt.Axis(grid=True, tickCount=4)),
        tooltip=tooltip or [cat, val])
    bars = base.mark_bar(color=color, cornerRadiusEnd=4, height={"band": 0.7})
    labels = base.mark_text(align="left", dx=4, color=INK2, fontSize=12).encode(text=f"{val}:Q")
    return bars + labels


def fmt_delta(td) -> str:
    if td is None or pd.isna(td):
        return "-"
    secs = int(td.total_seconds())
    sign = "-" if secs < 0 else ""
    secs = abs(secs)
    d, rem = divmod(secs, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    return f"{sign}{d}d {h}h" if d else f"{sign}{h}h {m}m"


# --------------------------------------------------------------- bootstrap
@st.cache_resource(show_spinner="Building the lab: generating 48 h of traffic, detecting, correlating...")
def _boot(_token: int = 0):
    pipeline.bootstrap()
    return True


_boot(st.session_state.get("boot_token", 0))
now = datetime.now(timezone.utc)

# --------------------------------------------------------------- sidebar
if "_goto" in st.session_state:  # navigation requested by a button on the previous run
    st.session_state.page = st.session_state.pop("_goto")

with st.sidebar:
    st.markdown("## :material/shield: SecureOps AI")
    st.caption("Intelligent threat detection & response")
    page = st.radio("Navigate", ["Overview", "Incident queue", "Investigate", "Live attack demo", "Evaluation",
                                 "About"], key="page", label_visibility="collapsed")
    st.divider()
    actor = st.selectbox("Acting as", config.ANALYSTS[1:], key="actor")
    mode = "LLM: " + (f"Groq ({config.GROQ_MODEL})" if config.GROQ_API_KEY else f"Ollama ({config.OLLAMA_MODEL})") \
        if assistant.llm_available() else "Offline evidence engine"
    st.caption(f"AI assistant: **{mode}**")
    if not assistant.llm_available():
        st.caption("Add a free `GROQ_API_KEY` in secrets to enable the LLM.")
    st.caption(f"Database: **{db.engine().dialect.name}**")
    with st.expander("Demo controls"):
        if st.button("Reset demo data", use_container_width=True):
            pipeline.bootstrap(force=True)
            st.session_state.boot_token = st.session_state.get("boot_token", 0) + 1
            st.session_state.pop("selected", None)
            st.rerun()

incidents = db.list_incidents()
alerts_all = db.read_alerts()
open_mask = ~incidents.status.isin(["Resolved", "False positive"])


def select_incident(inc_id: str):
    st.session_state.selected = inc_id
    st.session_state._goto = "Investigate"


# =============================================================== OVERVIEW
if page == "Overview":
    st.title("Security operations overview")
    n_events = db.count("events")
    breached = incidents[open_mask & (incidents.sla_due < now)]
    c = st.columns(6)
    c[0].metric("Events ingested", f"{n_events:,}")
    c[1].metric("Alerts raised", f"{len(alerts_all):,}")
    c[2].metric("Incidents (correlated)", len(incidents),
                help="Related alerts grouped by shared entity and time proximity.")
    c[3].metric("Alert reduction", f"{1 - len(incidents) / max(1, len(alerts_all)):.0%}",
                help="1 - incidents / alerts: how many fewer items an analyst must triage.")
    c[4].metric("Open incidents", int(open_mask.sum()))
    c[5].metric("SLA breached (open)", len(breached))

    left, right = st.columns(2)
    with left:
        top = alerts_all.groupby("rule_name").size().reset_index(name="alerts")
        st.altair_chart(theme(hbar(top, "rule_name", "alerts", "Top threats - alerts by detection"), bar_height(len(top))),
                        use_container_width=True)
    with right:
        idx = asset_index()
        rows = []
        for _, inc in incidents.iterrows():
            for ip in json.loads(inc.entities)["internal"]:
                rows.append({"asset": f"{idx[ip]['hostname']} ({idx[ip]['role']})", "incidents": 1,
                             "max_score": inc.score})
        aff = (pd.DataFrame(rows).groupby("asset").agg(incidents=("incidents", "sum"), max_score=("max_score", "max"))
               .reset_index().sort_values("max_score", ascending=False).head(10))
        st.altair_chart(theme(hbar(aff, "asset", "incidents", "Most affected systems - incidents per asset (top 10 by risk)",
                                   tooltip=["asset", "incidents", "max_score"]), bar_height(len(aff))),
                        use_container_width=True)

    left, right = st.columns(2)
    with left:
        sev = (incidents[open_mask].groupby("severity").size().reindex(SEV_ORDER, fill_value=0)
               .reset_index(name="incidents"))
        sev["label"] = sev.severity.map(lambda s: f"{SEV_ICON[s]} {s}")
        ch = alt.Chart(sev, title="Unresolved incidents by severity").encode(
            y=alt.Y("label:N", sort=[f"{SEV_ICON[s]} {s}" for s in SEV_ORDER], title=None),
            x=alt.X("incidents:Q", title=None, axis=alt.Axis(tickCount=4)),
            tooltip=["severity", "incidents"])
        chart = ch.mark_bar(cornerRadiusEnd=4, height={"band": 0.7}).encode(
            color=alt.Color("severity:N", scale=alt.Scale(domain=SEV_ORDER, range=[SEV_COLOR[s] for s in SEV_ORDER]),
                            legend=None)) + ch.mark_text(align="left", dx=4, color=INK2).encode(text="incidents:Q")
        st.altair_chart(theme(chart, 230), use_container_width=True)
    with right:
        hist = alerts_all[alerts_all.dataset == "historical_labeled"]
        tl = hist.assign(hour=hist.ts.dt.floor("h")).groupby(["hour", "tactic"]).size().reset_index(name="alerts")
        present = [t for t in KILL_CHAIN if t in set(tl.tactic)]
        chart = alt.Chart(tl, title="Alert volume per hour by ATT&CK tactic (48 h lab window)").mark_bar(stroke=SURFACE, strokeWidth=1).encode(
            x=alt.X("hour:T", title=None),
            y=alt.Y("sum(alerts):Q", title=None, axis=alt.Axis(tickCount=4)),
            color=alt.Color("tactic:N", scale=alt.Scale(domain=present, range=[TACTIC_COLOR[t] for t in present]),
                            sort=present, title=None),
            order=alt.Order("tactic_order:Q"),
            tooltip=[alt.Tooltip("hour:T", format="%b %d %H:00"), "tactic", "alerts"])
        st.altair_chart(theme(chart.transform_calculate(tactic_order=f"indexof({present}, datum.tactic)"), 230),
                        use_container_width=True)

    st.subheader("Investigation performance")
    st.caption("Measured from real case actions taken in this app (audit trail), not estimated.")
    ack = incidents.dropna(subset=["acknowledged_at"])
    res = incidents.dropna(subset=["resolved_at"])
    c = st.columns(5)
    c[0].metric("Mean time to acknowledge", fmt_delta((ack.acknowledged_at - ack.created_at).mean()) if len(ack) else "-")
    c[1].metric("Mean time to resolve", fmt_delta((res.resolved_at - res.created_at).mean()) if len(res) else "-")
    c[2].metric("Closed", len(res))
    c[3].metric("Closed within SLA", f"{(res.resolved_at <= res.sla_due).mean():.0%}" if len(res) else "-")
    c[4].metric("Marked false positive", int(incidents.false_positive.sum()))
    if not len(ack):
        st.info("No incidents have been worked yet. Open **Incident queue**, assign an owner and resolve a case - "
                "these numbers will update from the audit trail.", icon=":material/info:")

# =============================================================== QUEUE
elif page == "Incident queue":
    st.title("Incident queue")
    st.caption("Sorted by priority score = 45% threat confidence + 25% asset criticality + 20% vulnerability "
               "exposure + 10% spread.")
    f = st.columns(4)
    s_status = f[0].multiselect("Status", db.STATUSES, default=["New", "Investigating", "Contained"])
    s_sev = f[1].multiselect("Severity", SEV_ORDER, default=SEV_ORDER)
    s_owner = f[2].selectbox("Owner", ["Anyone"] + config.ANALYSTS)
    s_ds = f[3].selectbox("Data", ["All", "Historical (labelled lab data)", "Live (unlabelled)"])
    q = incidents[incidents.status.isin(s_status) & incidents.severity.isin(s_sev)]
    if s_owner != "Anyone":
        q = q[q.owner == s_owner]
    if s_ds != "All":
        q = q[q.dataset == ("live_unlabeled" if s_ds.startswith("Live") else "historical_labeled")]
    view = pd.DataFrame({
        "ID": q.incident_id,
        "Severity": q.severity.map(lambda s: f"{SEV_ICON[s]} {s}"),
        "Score": q.score,
        "Title": q.title,
        "Status": q.status,
        "Owner": q.owner,
        "SLA remaining": [fmt_delta(d - now) if s not in ("Resolved", "False positive") else "closed"
                          for d, s in zip(q.sla_due, q.status)],
        "Alerts": q.alert_count,
        "Data": q.dataset.map({"historical_labeled": "historical", "live_unlabeled": "live"}),
    })
    st.caption(f"{len(view)} incidents · click a row to investigate")
    ev = st.dataframe(view, hide_index=True, use_container_width=True, on_select="rerun", selection_mode="single-row",
                      column_config={"Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100,
                                                                              format="%.0f")})
    if ev.selection.rows:
        select_incident(view.iloc[ev.selection.rows[0]].ID)
        st.rerun()

# =============================================================== INVESTIGATE
elif page == "Investigate":
    ids = incidents.incident_id.tolist()
    sel = st.session_state.get("selected") or ids[0]
    sel = st.selectbox("Incident", ids, index=ids.index(sel) if sel in ids else 0,
                       format_func=lambda i: f"{i} - {incidents.set_index('incident_id').loc[i, 'title']}")
    st.session_state.selected = sel
    inc = db.get_incident(sel)
    alerts = db.read_alerts(sel)
    evidence_ids = sorted({e for es in alerts.evidence for e in es})
    events = db.events_by_ids(evidence_ids)
    sc = inc["scoring"]

    st.markdown(f"### {inc['title']}")
    st.markdown(f"{sev_badge(inc['severity'])} &nbsp; **Score {inc['score']:.0f}/100** &nbsp;·&nbsp; "
                f"Status **{inc['status']}** &nbsp;·&nbsp; Owner **{inc['owner']}** &nbsp;·&nbsp; SLA due "
                f"{inc['sla_due']:%Y-%m-%d %H:%M} UTC ({fmt_delta(inc['sla_due'] - now)}) &nbsp;·&nbsp; "
                f"{inc['alert_count']} alerts, {inc['event_count']} evidence events &nbsp;·&nbsp; "
                f"{'live, unlabelled' if inc['dataset'] == 'live_unlabeled' else 'historical lab data'}",
                unsafe_allow_html=True)
    stages = [t for t in KILL_CHAIN if t in set(alerts.tactic)]
    st.markdown("**Kill chain:** " + " → ".join(f"`{t}`" for t in stages))

    main, side = st.columns([3, 2], gap="large")
    with main:
        st.markdown("#### :material/psychology: AI investigation assistant")
        st.markdown(inc["ai_summary"])
        sup = inc["ai_support"]
        st.caption(f"Mode: **{inc['ai_mode']}** · Evidence check: **{sup:.0%}** of sentences cite valid evidence IDs "
                   f"({sum(c['supported'] for c in inc['ai_checks'])}/{len(inc['ai_checks'])}).")
        b1, b2 = st.columns(2)
        if b1.button("Regenerate with LLM" if assistant.llm_available() else "Regenerate (offline engine)",
                     use_container_width=True):
            with st.spinner("Retrieving evidence and generating..."):
                ex = pipeline.regenerate_explanation(sel, use_llm=True)
            if ex["note"]:
                st.warning(ex["note"])
            st.rerun()
        with st.expander("Verification: sentence-by-sentence citation check"):
            st.dataframe(pd.DataFrame(inc["ai_checks"]), hide_index=True, use_container_width=True)

        st.markdown("#### :material/manage_search: Evidence")
        t1, t2, t3, t4 = st.tabs(["Timeline", "Alerts", "Raw events", "Assets & CVEs"])
        with t1:
            pts = alerts.assign(rule=alerts.rule_name)
            present = [t for t in KILL_CHAIN if t in set(pts.tactic)]
            chart = alt.Chart(pts).mark_circle(size=90, stroke=SURFACE, strokeWidth=2, opacity=0.9).encode(
                x=alt.X("ts:T", title=None),
                y=alt.Y("rule:N", title=None, axis=alt.Axis(labelLimit=240)),
                color=alt.Color("tactic:N", scale=alt.Scale(domain=present, range=[TACTIC_COLOR[t] for t in present]),
                                title=None),
                tooltip=[alt.Tooltip("alert_id:Q", title="Alert"), alt.Tooltip("ts:T", format="%H:%M:%S"), "rule",
                         "tactic", alt.Tooltip("confidence:Q", format=".2f"), "description"])
            st.altair_chart(theme(chart, 60 + 34 * pts.rule.nunique()), use_container_width=True)
            st.caption(f"First seen {inc['first_seen']:%Y-%m-%d %H:%M:%S} · last seen {inc['last_seen']:%H:%M:%S} UTC")
        with t2:
            st.dataframe(alerts.assign(id="ALR-" + alerts.alert_id.astype(str))[
                ["id", "ts", "rule_name", "tactic", "technique", "src_ip", "dst_ip", "confidence", "description"]],
                hide_index=True, use_container_width=True)
        with t3:
            cols = ["event_id", "ts", "source", "src_ip", "dst_ip", "dst_port", "service", "conn_state", "user",
                    "outcome", "bytes_out", "signature"]
            st.dataframe(events.assign(event_id="EVT-" + events.event_id.astype(str))[cols], hide_index=True,
                         use_container_width=True)
        with t4:
            idx = asset_index()
            cves = load_cves()
            rows = [{"asset": idx[ip]["asset_id"], "ip": ip, "role": idx[ip]["role"],
                     "criticality": idx[ip]["criticality"], "software": ", ".join(idx[ip]["software"]),
                     "CVEs": ", ".join(idx[ip]["cves"]) or "-"} for ip in inc["entities"]["internal"]]
            st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
            cv = sorted({c for ip in inc["entities"]["internal"] for c in idx[ip]["cves"]})
            for c in cv:
                d = cves.get(c, {})
                st.markdown(f"**{c}** · CVSS {d.get('cvss')} {d.get('severity')}"
                            f"{' · CISA KEV' if d.get('kev') else ''} · [NVD](https://nvd.nist.gov/vuln/detail/{c})  \n"
                            f"<span class='small'>{d.get('description', '')[:280]}</span>", unsafe_allow_html=True)
            if inc["entities"]["external"]:
                st.markdown("**External entities:** " + ", ".join(f"`{x}`" for x in inc["entities"]["external"]))

    with side:
        st.markdown("#### :material/speed: Why this priority")
        br = pd.DataFrame([{"component": f"{k} (weight {int(WEIGHTS[k] * 100)}%)", "value": v,
                            "points": round(100 * WEIGHTS[k] * v, 1)} for k, v in sc["breakdown"].items()])
        st.altair_chart(theme(hbar(br, "component", "points", f"Contribution to score {inc['score']:.0f}",
                                   tooltip=["component", "value", "points"]), bar_height(4)), use_container_width=True)
        if sc["exploited_cves"]:
            st.error("Confirmed exploitable: exploit signature matches a CVE the target actually runs - "
                     + ", ".join(f"{h} / {c}" for h, c in sc["exploited_cves"]), icon=":material/warning:")

        st.markdown("#### :material/assignment_ind: Case management")
        with st.form("case"):
            owner = st.selectbox("Owner", config.ANALYSTS, index=config.ANALYSTS.index(inc["owner"]))
            status = st.selectbox("Status", db.STATUSES, index=db.STATUSES.index(inc["status"]))
            resolution = st.text_area("Resolution / notes", value=inc["resolution"] or "")
            if st.form_submit_button("Save case", type="primary", use_container_width=True):
                db.update_incident(sel, actor, owner=owner, status=status, resolution=resolution)
                st.toast("Case updated and audited")
                st.rerun()

        st.markdown("#### :material/gavel: Response (analyst approval required)")
        acts = [f"Block {ip} at perimeter firewall" for ip in inc["entities"]["external"][:3]]
        acts += [f"Isolate host {asset_index()[ip]['hostname']}" for ip in inc["entities"]["internal"][:3]
                 if not asset_index()[ip]["is_hub"]]
        acts += [f"Reset account '{u}'" for u in inc["entities"]["users"][:2]]
        chosen = st.multiselect("Proposed actions (simulated - nothing is executed)", acts)
        c1, c2 = st.columns(2)
        if c1.button("Approve & record", disabled=not chosen, use_container_width=True):
            for a in chosen:
                db.audit(sel, "response_approved", a + " (simulated)", actor)
            st.toast(f"{len(chosen)} action(s) approved and logged")
            st.rerun()
        if c2.button("Create ticket", use_container_width=True):
            tid = f"TCK-{sel.split('-')[1]}-{len(db.read_audit(sel)):02d}"
            db.audit(sel, "ticket_created", f"{tid} assigned to {inc['owner']}", actor)
            st.session_state[f"ticket_{sel}"] = {
                "ticket": tid, "incident": sel, "title": inc["title"], "severity": inc["severity"],
                "score": inc["score"], "owner": inc["owner"], "sla_due": str(inc["sla_due"]),
                "summary": inc["ai_summary"]}
            st.rerun()
        if st.session_state.get(f"ticket_{sel}"):
            t = st.session_state[f"ticket_{sel}"]
            st.download_button(f"Download {t['ticket']}.json", json.dumps(t, indent=2), f"{t['ticket']}.json",
                               use_container_width=True)

        st.markdown("#### :material/history: Audit trail")
        au = db.read_audit(sel)
        st.dataframe(au[["ts", "actor", "action", "detail"]], hide_index=True, use_container_width=True, height=220)
        if inc["dataset"] == "historical_labeled":
            with st.expander("Lab ground truth (evaluation only - hidden from detection)"):
                st.write(f"Campaign label: **{inc['ground_truth']}**")

# =============================================================== LIVE DEMO
elif page == "Live attack demo":
    st.title("Live attack demo")
    st.caption("Inject a fresh, UNLABELLED attack into the pipeline and watch it go from raw events to an assigned case.")
    c1, c2 = st.columns([3, 1])
    scen = c1.selectbox("Scenario", list(LIVE_SCENARIOS))
    c2.write("")
    c2.write("")
    if c2.button("Inject & run pipeline", type="primary", use_container_width=True):
        with st.spinner("Ingest → detect → correlate → prioritise → explain"):
            st.session_state.live = pipeline.ingest_live(LIVE_SCENARIOS[scen])
    res = st.session_state.get("live")
    if res:
        live = db.list_incidents().set_index("incident_id").loc[res["incidents"]] if res["incidents"] else None
        st.markdown(f"<div class='stage'><b>1 · Ingest</b> - {res['events']} new events (Zeek conn, Suricata, auth) "
                    "stored as <code>live_unlabeled</code>: no labels exist for them.</div>", unsafe_allow_html=True)
        rules = ", ".join(f"{k} ×{v}" for k, v in res["rules"].items())
        st.markdown(f"<div class='stage'><b>2 · Detect</b> - {res['alerts']} alerts: {rules}</div>",
                    unsafe_allow_html=True)
        st.markdown(f"<div class='stage'><b>3 · Correlate</b> - {res['alerts']} alerts → {len(res['incidents'])} "
                    f"incident(s) by shared entity + time</div>", unsafe_allow_html=True)
        if live is not None:
            for iid, r in live.sort_values("score", ascending=False).iterrows():
                st.markdown(f"<div class='stage'><b>4 · Prioritise</b> - {iid}: {sev_badge(r.severity)} score "
                            f"{r.score:.0f} - {r.title}<br><b>5 · Explain</b> - AI assistant ({r.ai_mode}), "
                            f"{r.ai_support:.0%} of sentences evidence-backed</div>", unsafe_allow_html=True)
            top = live.score.idxmax()
            with st.expander(f"AI explanation for {top}", expanded=True):
                st.markdown(live.loc[top, "ai_summary"])
            st.markdown("**6 · Assign to a human analyst**")
            a1, a2, a3 = st.columns([2, 1, 1])
            who = a1.selectbox("Analyst", config.ANALYSTS[1:], label_visibility="collapsed")
            if a2.button("Assign", use_container_width=True):
                db.update_incident(top, actor, owner=who, status="Investigating")
                st.success(f"{top} assigned to {who} - recorded in the audit trail.")
            if a3.button("Open case", use_container_width=True):
                select_incident(top)
                st.rerun()

# =============================================================== EVALUATION
elif page == "Evaluation":
    st.title("Evaluation - measured, with limitations")
    p = config.ROOT / "reports" / "metrics.json"
    if st.button("Re-run evaluation (~15 s)"):
        from secureops import evaluate
        with st.spinner("Generating held-out test set and evaluating..."):
            evaluate.run()
    if not p.exists():
        st.warning("No report yet - click Re-run evaluation.")
        st.stop()
    m = json.loads(p.read_text())
    t = m["test"]
    st.caption(f"{m['note']} Generated {m['generated_at']}. Unit: one source IP × one hour.")
    c = st.columns(6)
    d = t["detection_combined"]
    c[0].metric("Precision", f"{d['precision']:.2f}")
    c[1].metric("Recall", f"{d['recall']:.2f}")
    c[2].metric("F1", f"{d['f1']:.2f}")
    c[3].metric("False-positive rate", f"{d['false_positive_rate']:.2%}")
    c[4].metric("Alert reduction", f"{t['correlation']['alert_reduction']:.0%}",
                help=f"{t['correlation']['alerts']} alerts → {t['correlation']['incidents']} incidents")
    c[5].metric("AI evidence support", f"{t['ai_reliability']['mean_supported_sentence_rate']:.0%}",
                help="Share of assistant sentences citing valid evidence IDs. ~100% by construction in offline mode.")

    rows = []
    for setname in ("test", "development"):
        for k, lab in (("detection_combined", "Rules + anomaly"), ("detection_rules_only", "Rules only"),
                       ("detection_anomaly_only", "Anomaly only")):
            x = m[setname][k]
            rows.append({"set": "test (held-out)" if setname == "test" else "development (tuning)", "detector": lab,
                         "precision": x["precision"], "recall": x["recall"], "f1": x["f1"],
                         "FPR": f"{x['false_positive_rate']:.2%}", "TP": x["tp"], "FP": x["fp"], "FN": x["fn"]})
    st.subheader("Detection")
    st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)

    st.subheader("Per-scenario results (held-out test)")
    pc = pd.DataFrame(t["per_campaign"])
    pc["detected"] = pc.detected.map({True: "✓ yes", False: "✗ NO"})
    pc["detected_by"] = pc.detected_by.map(lambda x: ", ".join(x) or "-")
    st.dataframe(pc[["campaign", "name", "detected", "detected_by", "alerts", "incidents", "top_severity", "why_missed"]],
                 hide_index=True, use_container_width=True)

    left, right = st.columns(2)
    with left:
        st.subheader("Alert overload")
        co = t["correlation"]
        q = pd.DataFrame([{"stage": "Raw alerts", "items": co["alerts"]},
                          {"stage": "Correlated incidents", "items": co["incidents"]},
                          {"stage": "High / Critical incidents", "items": t["triage_queue"]["after_high_or_critical"]}])
        st.altair_chart(theme(hbar(q, "stage", "items", "Analyst triage queue (held-out test)"), bar_height(3)),
                        use_container_width=True)
        st.markdown(f"- {co['true_incidents']} real-attack incidents, {co['false_positive_incidents']} false-positive "
                    f"incidents\n- Incidents mixing different campaigns: {co['incidents_mixing_campaigns']}\n"
                    f"- False-positive sources: " + ", ".join(f"{k} ({v})" for k, v in co["false_positive_sources"].items()))
    with right:
        st.subheader("Prioritisation")
        pr = t["prioritisation"]
        st.markdown(f"- **Precision@{pr['k']}**: {pr['precision_at_k']:.2f} of the top-{pr['k']} incidents are real attacks\n"
                    f"- Mean score: real **{pr['mean_score_true']}** vs false positive **{pr['mean_score_false']}**")
        st.dataframe(pd.DataFrame(pr["top5"]), hide_index=True, use_container_width=True)
        st.subheader("Per-rule alert precision")
        st.dataframe(pd.DataFrame(t["per_rule"]), hide_index=True, use_container_width=True)

    st.subheader("Limitations - where it fails")
    missed = [x for x in t["per_campaign"] if not x["detected"]]
    for x in missed:
        st.markdown(f"- **Missed {x['campaign']} - {x['name']}**: {x['why_missed']}.")
    st.markdown("""- Data is **synthetic** (controlled lab simulation), not production traffic; real networks are noisier.
- The Isolation Forest is the main source of false positives (benign bursts, login typos); its incidents score low by design.
- Triage *time* before/after was not measured with real analysts - only queue size. Time-to-acknowledge / resolve is measured live from the audit trail on the Overview page.
- In offline mode the 100% evidence-support rate holds by construction; enable an LLM and re-run with `python -m secureops.evaluate --llm` for a meaningful number.""")

# =============================================================== ABOUT
else:
    st.title("About SecureOps AI")
    st.markdown("""
**SecureOps AI** ingests network and authentication telemetry, detects threats, **correlates hundreds of alerts
into a few incidents**, prioritises them by threat × asset × vulnerability, explains each with an
**evidence-cited AI assistant**, and supports analyst-approved response with a full audit trail.

```
Zeek conn · Suricata alerts · auth logs · NVD CVEs · threat intel
        │
        ▼
Detection: 8 ATT&CK-mapped rules + Isolation Forest (per host-hour)
        │
        ▼
Correlation: union-find over shared entities within 120 min  →  incidents
        │
        ▼
Prioritisation: 45% threat · 25% asset criticality · 20% CVE exposure · 10% spread  →  SLA
        │
        ▼
AI assistant: retrieve evidence + playbooks (TF-IDF RAG) → LLM / offline → citation verifier
        │
        ▼
Case management: owner · status · SLA · approved response · ticket · audit log
```
""")
    a = build_assets()
    c = st.columns(4)
    c[0].metric("Assets", len(a))
    c[1].metric("Servers / workstations / IoT", f"{(a.type == 'server').sum()} / {(a.type == 'workstation').sum()} / "
                                                f"{(a.type == 'iot').sum()}")
    c[2].metric("Assets with known CVEs", int((a.cves.str.len() > 0).sum()))
    c[3].metric("CVE records (live NVD API)", len(load_cves()))
    st.markdown("""
**Data honesty.** Historical data is *labelled* synthetic lab traffic (labels are used only for evaluation and are
never seen by the detectors). Live demo events are *unlabelled*. All external IPs are RFC 5737 documentation addresses.
CVE details are real records fetched from the NVD API 2.0.

**Stack.** Python · Pandas · SQL (SQLite / PostgreSQL) · scikit-learn · FastAPI · Streamlit · Altair ·
Groq or Ollama (optional) · Docker · GitHub Actions.
""")
