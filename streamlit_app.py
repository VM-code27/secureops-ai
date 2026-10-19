"""SecureOps AI - analyst console (Streamlit).

Local:   streamlit run streamlit_app.py
Cloud:   Streamlit Community Cloud -> main file `streamlit_app.py` (free)
"""
from __future__ import annotations

import json
import os
import time

import altair as alt
import pandas as pd
import streamlit as st

# Streamlit Cloud secrets -> environment (before importing the package).
try:
    for _k in ("GROQ_API_KEY", "GROQ_MODEL", "OLLAMA_URL", "OLLAMA_MODEL", "DATABASE_URL", "LLM_PROVIDER", "NVD_API_KEY",
               "SECUREOPS_API_TOKEN"):
        if _k in st.secrets and not os.getenv(_k):
            os.environ[_k] = str(st.secrets[_k])
except Exception:
    pass

from secureops import assets, assistant, bootstrap, chat, config, db, pipeline, settings  # noqa: E402
from secureops.correlation import KILL_CHAIN  # noqa: E402
from secureops.intel import attack, feeds  # noqa: E402
from secureops.sources import replay  # noqa: E402

st.set_page_config(page_title="SecureOps AI", page_icon=":material/shield:", layout="wide",
                   initial_sidebar_state="collapsed")

# --------------------------------------------------------------- design tokens (light)
INK, INK2, MUTED, GRID, SURFACE = "#0b0b0b", "#52514e", "#8a8984", "#e6e5e1", "#ffffff"
BLUE = "#2a78d6"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]  # fixed order
SEV_COLOR = {"Critical": "#d03b3b", "High": "#ec835a", "Medium": "#c98500", "Low": "#8a8984"}
SEV_ICON = {"Critical": "▲▲", "High": "▲", "Medium": "◆", "Low": "▽"}
SEV_ORDER = ["Critical", "High", "Medium", "Low"]
TACTIC_COLOR = dict(zip([t for t in KILL_CHAIN if t != "Anomaly"][:7] + ["Anomaly"], SERIES))
PAGES = ["Live", "Overview", "Investigate"]

st.markdown(f"""
<style>
.block-container {{padding-top: 3.4rem; max-width: 1360px;}}
[data-testid="stHeader"] {{background: transparent;}}
.card {{background:{SURFACE}; border:1px solid {GRID}; border-radius:14px; padding:14px 16px; height:100%;
        box-shadow:0 1px 2px rgba(16,24,40,.04);}}
.kpi-label {{color:{INK2}; font-size:.82rem; margin-bottom:2px;}}
.kpi-value {{color:{INK}; font-size:1.65rem; font-weight:650; line-height:1.15;}}
.kpi-sub {{color:{MUTED}; font-size:.78rem;}}
.pill {{display:inline-block; padding:1px 9px; border-radius:999px; font-size:.78rem; font-weight:600;
        border:1px solid currentColor; background:{SURFACE};}}
.new {{display:inline-block; padding:0 7px; border-radius:6px; font-size:.7rem; font-weight:700; color:#fff;
       background:{BLUE}; margin-left:6px; animation: pulse 1.4s ease-in-out infinite;}}
.feed {{border-left:4px solid var(--sev); animation: fadein .7s ease-out;}}
.feed-title {{font-weight:600; color:{INK}; margin:4px 0 2px;}}
.feed-meta {{color:{MUTED}; font-size:.8rem;}}
.bar {{height:6px; border-radius:6px; background:{GRID}; overflow:hidden; margin-top:8px;}}
.bar > span {{display:block; height:100%; background:var(--sev); border-radius:6px;}}
.breach {{background:#fdecec; border:1px solid #f3b9b9; color:#7a1f1f; border-radius:14px; padding:12px 16px;
          display:flex; align-items:center; gap:12px; animation: fadein .6s ease-out;}}
.breach .dot {{width:12px; height:12px; border-radius:50%; background:#d03b3b; flex:none;
               box-shadow:0 0 0 0 rgba(208,59,59,.6); animation: ring 1.6s infinite;}}
.livedot {{display:inline-block; width:9px; height:9px; border-radius:50%; background:#1baf7a; margin-right:6px;
           box-shadow:0 0 0 0 rgba(27,175,122,.6); animation: ring 1.6s infinite;}}
.idledot {{display:inline-block; width:9px; height:9px; border-radius:50%; background:{MUTED}; margin-right:6px;}}
.brand {{display:flex; align-items:center; gap:10px;}}
.brand b {{font-size:1.25rem; color:{INK};}} .brand span {{color:{MUTED}; font-size:.8rem;}}
.radar {{animation: spin 3s linear infinite; transform-origin: 50% 50%;}}
@keyframes spin {{ to {{ transform: rotate(360deg); }} }}
@keyframes fadein {{ from {{opacity:0; transform: translateY(6px);}} to {{opacity:1; transform:none;}} }}
@keyframes pulse {{ 50% {{ opacity:.45; }} }}
@keyframes ring {{ 70% {{ box-shadow:0 0 0 10px rgba(0,0,0,0); }} 100% {{ box-shadow:0 0 0 0 rgba(0,0,0,0); }} }}
</style>""", unsafe_allow_html=True)

LOGO = f"""<svg width="34" height="34" viewBox="0 0 24 24" fill="none"><path d="M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5l8-3z"
fill="{BLUE}"/><path d="M8.5 12.2l2.3 2.3 4.7-4.9" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>"""
RADAR = f"""<svg width="92" height="92" viewBox="0 0 100 100"><circle cx="50" cy="50" r="46" fill="#eef4fc" stroke="#cfe0f6"/>
<circle cx="50" cy="50" r="31" fill="none" stroke="#cfe0f6"/><circle cx="50" cy="50" r="16" fill="none" stroke="#cfe0f6"/>
<g class="radar"><path d="M50 50 L50 4 A46 46 0 0 1 90 28 Z" fill="{BLUE}" opacity=".22"/>
<line x1="50" y1="50" x2="50" y2="4" stroke="{BLUE}" stroke-width="2"/></g>
<circle cx="70" cy="34" r="3.5" fill="#d03b3b"><animate attributeName="opacity" values="1;.2;1" dur="1.6s" repeatCount="indefinite"/></circle>
<circle cx="34" cy="62" r="3" fill="#eda100"><animate attributeName="opacity" values=".2;1;.2" dur="2.2s" repeatCount="indefinite"/></circle>
<circle cx="50" cy="50" r="3" fill="{BLUE}"/></svg>"""


# --------------------------------------------------------------- helpers
def theme(chart, height: int = 240):
    return (chart.properties(height=height, background="transparent")
            .configure_view(stroke=None)
            .configure_axis(labelColor=INK2, titleColor=INK2, gridColor=GRID, domainColor=GRID, tickColor=GRID,
                            labelFontSize=12, titleFontSize=12, titleFontWeight="normal")
            .configure_legend(labelColor=INK2, titleColor=INK2, orient="bottom", labelFontSize=12, columns=4)
            .configure_title(color=INK, anchor="start", fontSize=14, fontWeight=600))


def hbar(df: pd.DataFrame, cat: str, val: str, title: str, tooltip=None):
    base = alt.Chart(df, title=title).encode(
        y=alt.Y(f"{cat}:N", sort="-x", title=None, axis=alt.Axis(labelLimit=260)),
        x=alt.X(f"{val}:Q", title=None, axis=alt.Axis(grid=True, tickCount=4)), tooltip=tooltip or [cat, val])
    return base.mark_bar(color=BLUE, cornerRadiusEnd=4, height={"band": 0.7}) + \
        base.mark_text(align="left", dx=4, color=INK2, fontSize=12).encode(text=f"{val}:Q")


def rows_h(n: int) -> int:
    return 70 + 32 * max(n, 1)


def fmt_delta(td) -> str:
    if td is None or pd.isna(td):
        return "-"
    secs = int(td.total_seconds())
    sign, secs = ("-" if secs < 0 else ""), abs(secs)
    d, rem = divmod(secs, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    return f"{sign}{d}d {h}h" if d else f"{sign}{h}h {m}m" if h else f"{sign}{m}m {s}s" if m else f"{sign}{s}s"


def pill(sev: str) -> str:
    return f"<span class='pill' style='color:{SEV_COLOR[sev]}'>{SEV_ICON[sev]} {sev}</span>"


def kpi(col, label: str, value: str, sub: str = ""):
    col.markdown(f"<div class='card'><div class='kpi-label'>{label}</div><div class='kpi-value'>{value}</div>"
                 f"<div class='kpi-sub'>{sub}&nbsp;</div></div>", unsafe_allow_html=True)


def open_incident(inc_id: str):
    st.session_state.focus = inc_id
    st.session_state._goto = "Investigate"


def load_incidents() -> pd.DataFrame:
    inc = db.list_incidents()
    return inc[~inc.resolution.fillna("").str.startswith("Merged into")]


def sensor_status() -> pd.DataFrame:
    s = db.read_events_sql("SELECT sensor, COUNT(*) AS events, MAX(ts) AS last_event FROM events "
                           "WHERE dataset = 'live' GROUP BY sensor")
    if len(s):
        s["last_event"] = pd.to_datetime(s.last_event, utc=True, format="mixed")
        s["age"] = (db.now() - s.last_event).dt.total_seconds()
    return s


# --------------------------------------------------------------- first start
if not bootstrap.initialized():
    # The build runs in a server-side thread, so refreshing or closing this tab never interrupts it.
    bootstrap.start_background()
    bs = bootstrap.status()
    st.markdown(f"<div class='brand' style='margin-top:1rem'>{LOGO}<div><b>SecureOps AI</b><br>"
                f"<span>First start - building from live sources</span></div></div>", unsafe_allow_html=True)
    if bs["error"]:
        st.error(f"The first-start build failed: {bs['error']}")
        if st.button("Retry", type="primary"):
            bootstrap.retry()
            st.rerun()
        st.stop()
    with st.status("Downloading real data and live threat intelligence (about 1-2 minutes)...", expanded=True):
        for line in bs["log"] or ["Starting..."]:
            st.write(line)
    st.caption("This happens once. The page refreshes by itself - you can also close it and come back.")
    time.sleep(2)
    st.rerun()

if "_goto" in st.session_state:
    st.session_state.page = st.session_state.pop("_goto")
if st.session_state.get("page") not in PAGES:
    st.session_state.page = "Live"

# --------------------------------------------------------------- header
h1, h2, h3 = st.columns([3, 4, 2], vertical_alignment="center")
h1.markdown(f"<div class='brand'>{LOGO}<div><b>SecureOps AI</b><br><span>Threat detection & response</span></div></div>",
            unsafe_allow_html=True)
with h2:
    st.segmented_control("Navigate", PAGES, key="page", label_visibility="collapsed")
page = st.session_state.page or "Live"
with h3.popover("Settings", icon=":material/tune:", width="stretch"):
    st.session_state.actor = st.text_input("Your name (audit trail)", st.session_state.get("actor", ""))
    cfg = settings.get()
    team = st.text_area("Analyst team (one per line)", "\n".join(cfg.get("team", [])), height=90)
    allow = st.text_input("Allow-listed sources (comma-separated)", ", ".join(cfg["network"]["allowlist_sources"]))
    if st.button("Save", type="primary", width="stretch"):
        ov = settings.overrides()
        ov["team"] = [t.strip() for t in team.splitlines() if t.strip()]
        ov.setdefault("network", {})["allowlist_sources"] = [x.strip() for x in allow.split(",") if x.strip()]
        settings.save(ov)
        st.toast("Settings saved")
    st.caption(f"AI: **{assistant.llm_label()}** · DB: **{db.engine().dialect.name}** · thresholds, weights and SLAs: "
               "`config.yaml`")
actor = (st.session_state.get("actor") or "").strip() or "analyst"

incidents = load_incidents()
open_inc = incidents[~incidents.status.isin(["Resolved", "False positive"])]

# --------------------------------------------------------------- breach banner (every page)
hot = open_inc[open_inc.severity.isin(["Critical", "High"])]
if len(hot):
    top = hot.iloc[0]
    b1, b2 = st.columns([6, 1], vertical_alignment="center")
    b1.markdown(f"<div class='breach'><div class='dot'></div><div><b>Possible breach - {len(hot)} high-severity incident"
                f"{'s' if len(hot) > 1 else ''} open.</b> Top: {top.incident_id} · {top.title} (score {top.score:.0f})"
                f"</div></div>", unsafe_allow_html=True)
    if b2.button("Investigate", type="primary", width="stretch", key="banner_go"):
        open_incident(top.incident_id)
        st.rerun()
st.write("")


# =============================================================== LIVE
def live_page():
    a, b = st.columns([1, 6], vertical_alignment="center")
    a.markdown(RADAR, unsafe_allow_html=True)
    b.markdown("### Live threat stream\nEvery event from your sensors and the real UWF dataset replay is analysed as it "
               "arrives: detection rules, an anomaly model and correlation run continuously, and you are notified the "
               "moment something looks like a breach.")
    c1, c2, _ = st.columns([1.3, 1.6, 4])
    auto = c1.toggle("Live streaming", value=True, key="auto")
    use_replay = c2.toggle("Include dataset replay", value=True, key="use_replay")

    @st.fragment(run_every=4 if auto else None)
    def stream():
        rs = replay.summary()
        if auto and use_replay and rs.get("active") and not rs["finished"]:
            last = replay.state().get("last_step_wall")
            if not last or (db.now() - pd.Timestamp(last)).total_seconds() >= 3.5:  # one stream for all viewers
                try:
                    replay.step(wait=2)  # if a sensor batch or another viewer is ingesting, skip this tick
                    db.set_meta("replay", {**replay.state(), "last_step_wall": db.now().isoformat()})
                except TimeoutError:
                    pass
                rs = replay.summary()
        inc = load_incidents()
        # Notifications: new incidents (or escalations) since this viewer last looked.
        seen = st.session_state.get("seen")
        now_state = dict(zip(inc.incident_id, inc.severity))
        if seen is None:
            st.session_state.seen = now_state
            st.session_state.fresh = set()
        else:
            fresh = set()
            for iid, sev in now_state.items():
                if iid not in seen or SEV_ORDER.index(sev) < SEV_ORDER.index(seen[iid]):
                    r = inc.set_index("incident_id").loc[iid]
                    fresh.add(iid)
                    if sev in ("Critical", "High"):
                        st.toast(f"**Breach alert - {sev}**: {r.title[:90]}", icon="🚨")
                    elif sev == "Medium":
                        st.toast(f"New {sev.lower()} incident {iid}: {r.title[:80]}", icon="⚠️")
            st.session_state.seen = now_state
            st.session_state.fresh = (st.session_state.get("fresh", set()) | fresh)

        sens = sensor_status()
        live_on = len(sens) and (sens.age < 120).any()
        open_ = inc[~inc.status.isin(["Resolved", "False positive"])]
        live_alerts = db.count("alerts", "WHERE dataset = 'live'")
        k = st.columns(5)
        kpi(k[0], "Events analysed", f"{db.count('events'):,}", "sensor + replay")
        kpi(k[1], "Alerts raised", f"{db.count('alerts'):,}", f"{live_alerts:,} from sensors")
        kpi(k[2], "Open incidents", f"{len(open_)}",
            f"{(open_.severity.isin(['Critical', 'High'])).sum()} high/critical")
        status = ("<span class='livedot'></span>streaming" if live_on else
                  "<span class='idledot'></span>idle" if len(sens) else "<span class='idledot'></span>none connected")
        kpi(k[3], "Sensors", status, f"{int(sens.events.sum()) if len(sens) else 0:,} live events")
        kpi(k[4], "Dataset replay", f"{rs['progress']:.0%}" if rs.get("active") else "off",
            f"at {rs['cursor']:%b %d %H:%M} (dataset time)" if rs.get("active") else "")
        st.write("")
        left, right = st.columns([3, 2], gap="large")
        with left:
            st.markdown("**Detection feed**")
            feed = inc.sort_values(["updated_at", "score"], ascending=False).head(7)
            if feed.empty:
                st.info("Waiting for the first detection...")
            for r in feed.itertuples():
                new = "<span class='new'>NEW</span>" if r.incident_id in st.session_state.get("fresh", set()) else ""
                st.markdown(
                    f"<div class='card feed' style='--sev:{SEV_COLOR[r.severity]}; margin-bottom:8px;'>"
                    f"{pill(r.severity)} <span class='feed-meta'>&nbsp;{r.incident_id} · "
                    f"{'live sensor' if r.dataset == 'live' else 'dataset replay'} · updated "
                    f"{fmt_delta(db.now() - r.updated_at)} ago · {r.alert_count} alerts</span>{new}"
                    f"<div class='feed-title'>{r.title}</div>"
                    f"<div class='bar'><span style='width:{max(4, r.score):.0f}%'></span></div></div>",
                    unsafe_allow_html=True)
            pick = st.selectbox("Open an incident", feed.incident_id.tolist(), index=None, placeholder="Investigate...",
                                label_visibility="collapsed")
            if pick:
                open_incident(pick)
                st.rerun()
        with right:
            if len(sens):
                rec = db.read_events_sql("SELECT ts, source FROM events WHERE dataset = 'live' AND ts >= :t",
                                         {"t": db.py(db.now() - pd.Timedelta(minutes=30))})
                if len(rec):
                    rec["ts"] = pd.to_datetime(rec.ts, utc=True, format="mixed")
                    pm = rec.assign(minute=rec.ts.dt.floor("min")).groupby(["minute", "source"]).size().reset_index(name="n")
                    srcs = sorted(pm.source.unique())
                    ch = alt.Chart(pm, title="Sensor traffic - events per minute (UTC)").mark_area(
                        interpolate="monotone", opacity=0.85, line={"strokeWidth": 2}).encode(
                        x=alt.X("minute:T", title=None, axis=alt.Axis(format="%H:%M", tickCount=6)),
                        y=alt.Y("sum(n):Q", title=None, stack=True, axis=alt.Axis(tickCount=4)),
                        color=alt.Color("source:N", scale=alt.Scale(domain=srcs, range=SERIES[:len(srcs)]), title=None),
                        tooltip=[alt.Tooltip("minute:T", format="%H:%M"), "source", alt.Tooltip("n:Q", title="events")])
                    st.altair_chart(theme(ch, 200), width="stretch")
            al = db.read_alerts()
            if len(al):
                recent = al.sort_values("alert_id").tail(300)
                tc = recent.groupby("tactic").size().reset_index(name="alerts")
                st.altair_chart(theme(hbar(tc, "tactic", "alerts", "What the models are seeing (last 300 alerts)"),
                                      rows_h(len(tc))), width="stretch")
            if rs.get("active"):
                st.progress(rs["progress"], text=f"UWF dataset replay · {rs['cursor']:%Y-%m-%d %H:%M} (dataset time)"
                                                 f"{' · finished' if rs['finished'] else ''}")
    stream()


# =============================================================== OVERVIEW
def overview_page():
    alerts = db.read_alerts()
    k = st.columns(6)
    ack = incidents.dropna(subset=["acknowledged_at"])
    res = incidents.dropna(subset=["resolved_at"])
    kpi(k[0], "Incidents", f"{len(incidents)}", f"from {len(alerts):,} alerts")
    kpi(k[1], "Alert reduction", f"{1 - len(incidents) / max(1, len(alerts)):.0%}", "alerts merged into cases")
    kpi(k[2], "Open", f"{len(open_inc)}", f"{(open_inc.sla_due < db.now()).sum()} past SLA")
    kpi(k[3], "High / critical open", f"{open_inc.severity.isin(['Critical', 'High']).sum()}", "")
    kpi(k[4], "Mean time to acknowledge", fmt_delta((ack.acknowledged_at - ack.created_at).mean()) if len(ack) else "-",
        f"{len(ack)} acknowledged")
    kpi(k[5], "Mean time to resolve", fmt_delta((res.resolved_at - res.created_at).mean()) if len(res) else "-",
        f"{len(res)} closed")
    st.write("")
    if alerts.empty:
        st.info("No alerts yet - turn on live streaming.")
        return
    left, right = st.columns(2, gap="large")
    with left:
        tl = alerts.assign(day=alerts.ts.dt.floor("D")).groupby(["day", "tactic"]).size().reset_index(name="alerts")
        present = [t for t in KILL_CHAIN if t in set(tl.tactic)]
        ch = alt.Chart(tl, title="Alerts per day by ATT&CK tactic (event time)").mark_bar(stroke=SURFACE, strokeWidth=1).encode(
            x=alt.X("yearmonthdate(day):O", title=None, axis=alt.Axis(format="%b %d", labelAngle=0)),
            y=alt.Y("sum(alerts):Q", title=None, axis=alt.Axis(tickCount=4)),
            color=alt.Color("tactic:N", scale=alt.Scale(domain=present, range=[TACTIC_COLOR.get(t, MUTED) for t in present]),
                            title=None),
            tooltip=[alt.Tooltip("yearmonthdate(day):O", title="day"), "tactic", "alerts"])
        st.altair_chart(theme(ch, 250), width="stretch")
    with right:
        top = alerts.groupby("rule_name").size().reset_index(name="alerts")
        st.altair_chart(theme(hbar(top, "rule_name", "alerts", "Top detections"), max(250, rows_h(len(top)))),
                        width="stretch")
    left, right = st.columns(2, gap="large")
    with left:
        rows = [{"host": assets.label(ip), "incidents": 1, "score": x.score}
                for x in incidents.itertuples() for ip in json.loads(x.entities)["internal"]]
        if rows:
            aff = (pd.DataFrame(rows).groupby("host").agg(incidents=("incidents", "sum"), max_score=("score", "max"))
                   .reset_index().sort_values("max_score", ascending=False).head(8))
            st.altair_chart(theme(hbar(aff, "host", "incidents", "Most targeted hosts (by risk)",
                                       tooltip=["host", "incidents", "max_score"]), rows_h(len(aff))), width="stretch")
    with right:
        sev = open_inc.groupby("severity").size().reindex(SEV_ORDER, fill_value=0).reset_index(name="incidents")
        sev["label"] = sev.severity.map(lambda s: f"{SEV_ICON[s]} {s}")
        base = alt.Chart(sev, title="Open incidents by severity").encode(
            y=alt.Y("label:N", sort=[f"{SEV_ICON[s]} {s}" for s in SEV_ORDER], title=None),
            x=alt.X("incidents:Q", title=None, axis=alt.Axis(tickCount=4)), tooltip=["severity", "incidents"])
        ch = base.mark_bar(cornerRadiusEnd=4, height={"band": 0.7}).encode(
            color=alt.Color("severity:N", scale=alt.Scale(domain=SEV_ORDER, range=[SEV_COLOR[s] for s in SEV_ORDER]),
                            legend=None)) + base.mark_text(align="left", dx=4, color=INK2).encode(text="incidents:Q")
        st.altair_chart(theme(ch, rows_h(8)), width="stretch")

    st.markdown("#### Incidents")
    f1, f2, _ = st.columns([2, 2, 3])
    status = f1.multiselect("Status", db.STATUSES, default=["New", "Investigating", "Contained"])
    source = f2.segmented_control("Source", ["All", "Live sensors", "Dataset replay"], default="All")
    q = incidents[incidents.status.isin(status)]
    if source == "Live sensors":
        q = q[q.dataset == "live"]
    elif source == "Dataset replay":
        q = q[q.dataset == "replay"]
    view = pd.DataFrame({"ID": q.incident_id, "Severity": q.severity.map(lambda s: f"{SEV_ICON[s]} {s}"),
                         "Score": q.score, "Incident": q.title, "Status": q.status, "Owner": q.owner,
                         "Alerts": q.alert_count, "Source": q.dataset})
    sel = st.dataframe(view, hide_index=True, width="stretch", height=330, on_select="rerun", selection_mode="single-row",
                       column_config={"Score": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%.0f")})
    if sel.selection.rows:
        open_incident(view.iloc[sel.selection.rows[0]].ID)
        st.rerun()

    p = config.ROOT / "reports" / "metrics.json"
    if p.exists():
        m = json.loads(p.read_text())
        t = m["test"]
        d = t["detection_combined"]
        llm = m.get("llm_reliability") or {}
        st.markdown("#### Model performance on real labelled data")
        st.caption(f"{m['dataset']} - {t['data']['days']} days held out in time. Unit: one source IP × one hour.")
        k = st.columns(5)
        kpi(k[0], "Precision", f"{d['precision']:.2f}", "alerts that were real attacks")
        kpi(k[1], "Recall", f"{d['recall']:.2f}", "attack windows detected")
        kpi(k[2], "False-positive rate", f"{d['false_positive_rate']:.2%}", "of benign windows")
        kpi(k[3], "Alert reduction", f"{t['correlation']['alert_reduction']:.0%}",
            f"{t['correlation']['alerts']:,} → {t['correlation']['incidents']} incidents")
        kpi(k[4], "LLM citation accuracy", f"{llm['sentence_support_rate']:.0%}" if llm.get("sentence_support_rate")
            is not None else "-", f"{llm.get('sentences', 0)} sentences checked")
        with st.expander("Per ATT&CK tactic, and where the model fails"):
            pt = pd.DataFrame(t["per_tactic"])
            pt["detected_by"] = pt.detected_by.map(lambda x: ", ".join(x) or "missed")
            st.dataframe(pt, hide_index=True, width="stretch")
            st.markdown((config.ROOT / "reports" / "EVALUATION.md").read_text(encoding="utf-8").split("## Limitations", 1)[-1])
    fs = feeds.status()
    kev = db.get_meta("kev_status") or {}
    st.caption(f"Live intelligence: {len(feeds.index()):,} threat indicators ({', '.join(fs)}) · CISA KEV "
               f"{kev.get('count', '-')} CVEs · {len(attack.techniques(build_if_missing=False))} MITRE ATT&CK techniques · "
               f"{db.count('assets')} hosts discovered from traffic")


# =============================================================== INVESTIGATE
def attack_graph(alerts: pd.DataFrame, ents: dict) -> str:
    idx = assets.index()
    edges: dict = {}
    for a in alerts.itertuples():
        dsts = [a.dst_ip] if a.dst_ip else list(a.targets)[:6]
        for d in dsts:
            if a.src_ip and d:
                edges.setdefault((a.src_ip, d), {}).setdefault(a.tactic, 0)
                edges[(a.src_ip, d)][a.tactic] += 1
    edges = dict(sorted(edges.items(), key=lambda kv: -sum(kv[1].values()))[:18])
    nodes = {n for e in edges for n in e}
    lines = ['digraph G {', 'rankdir=LR; bgcolor="transparent"; pad=0.2; nodesep=0.35; ranksep=0.9;',
             'node [fontname="Helvetica" fontsize=11 style="rounded,filled" penwidth=1.4];',
             'edge [fontname="Helvetica" fontsize=9 fontcolor="#52514e" arrowsize=0.7];']
    for n in nodes:
        a = idx.get(n)
        if n in ents.get("internal", []):
            crit = a["criticality"] if a else 1
            hub = bool(a and a.get("is_hub"))
            lines.append(f'"{n}" [shape=box fillcolor="{"#f0efec" if hub else "#e8f1fc"}" color="{MUTED if hub else BLUE}" '
                         f'label="{assets.label(n)}\\ncriticality {crit}/5"];')
        else:
            lines.append(f'"{n}" [shape=ellipse fillcolor="#fdeee6" color="#eb6834" label="{n}\\nexternal"];')
    for (s, d), tac in edges.items():
        main = max(tac, key=tac.get)
        lines.append(f'"{s}" -> "{d}" [color="{TACTIC_COLOR.get(main, MUTED)}" '
                     f'penwidth={1 + min(3, sum(tac.values()) / 10):.1f} label="{main} ×{sum(tac.values())}"];')
    lines.append("}")
    return "\n".join(lines)


def incident_panel(inc_id: str):
    inc = db.get_incident(inc_id)
    al = db.read_alerts(inc_id)
    # Evidence of the 50 most recent alerts (bounded, even for incidents with thousands of alerts).
    ev = db.events_by_ids({e for es in al.sort_values('ts').tail(50).evidence for e in es})
    sc = inc["scoring"]
    st.markdown(f"<div class='card'>{pill(inc['severity'])} <span class='feed-meta'>&nbsp;{inc_id} · score "
                f"{inc['score']:.0f}/100 · {inc['status']} · owner {inc['owner']} · SLA {fmt_delta(inc['sla_due'] - db.now())}"
                f"</span><div class='feed-title' style='font-size:1.05rem'>{inc['title']}</div>"
                f"<div class='bar' style='--sev:{SEV_COLOR[inc['severity']]}'><span style='width:{inc['score']:.0f}%'></span>"
                f"</div></div>", unsafe_allow_html=True)
    st.graphviz_chart(attack_graph(al, inc["entities"]), width="stretch")
    st.caption("Attack graph: who talked to whom, coloured by ATT&CK tactic. Blue boxes are your hosts, orange ovals "
               "external addresses, grey boxes shared infrastructure.")
    t1, t2, t3, t4 = st.tabs(["Case", "AI summary", "Evidence", "Why this score"])
    with t1:
        team = settings.team()
        with st.form(f"case_{inc_id}"):
            c1, c2 = st.columns(2)
            owner = c1.selectbox("Owner", team, index=team.index(inc["owner"]) if inc["owner"] in team else 0)
            status = c2.selectbox("Status", db.STATUSES, index=db.STATUSES.index(inc["status"]))
            notes = st.text_area("Notes", inc["resolution"] or "", height=70)
            if st.form_submit_button("Save case", type="primary", width="stretch"):
                db.update_incident(inc_id, actor, owner=owner, status=status, resolution=notes)
                st.toast("Case updated and audited")
                st.rerun()
        if len(team) == 1:
            st.caption("Add analysts under **Settings** (top right) to assign owners.")
        acts = [f"Block {ip} at the perimeter" for ip in inc["entities"]["external"][:3]]
        acts += [f"Isolate host {assets.label(ip)}" for ip in inc["entities"]["internal"][:3]
                 if not assets.index().get(ip, {}).get("is_hub")]
        acts += [f"Allow-list source {ip} (benign)" for ip in sorted(set(al.src_ip) - {""})[:2]]
        chosen = st.multiselect("Response actions (recorded for approval - nothing is executed)", acts)
        if st.button("Approve & record", disabled=not chosen):
            for a in chosen:
                db.audit(inc_id, "response_approved", a, actor)
                if a.startswith("Allow-list source "):
                    ov = settings.overrides()
                    net = ov.setdefault("network", {})
                    net["allowlist_sources"] = sorted(set(settings.section("network")["allowlist_sources"]) | {a.split()[2]})
                    settings.save(ov)
            st.toast(f"{len(chosen)} action(s) recorded")
            st.rerun()
        st.dataframe(db.read_audit(inc_id)[["ts", "actor", "action", "detail"]], hide_index=True, width="stretch",
                     height=170)
    with t2:
        st.markdown(inc["ai_summary"])
        checks = inc["ai_checks"] or []
        st.caption(f"{inc['ai_mode']} · {sum(c['supported'] for c in checks)}/{len(checks)} sentences cite valid evidence")
        if st.button("Regenerate with AI", key=f"regen_{inc_id}"):
            with st.spinner("Generating..."):
                pipeline.regenerate_explanation(inc_id, use_llm=True)
            st.rerun()
    with t3:
        st.dataframe(al.assign(id="ALR-" + al.alert_id.astype(str))[["id", "ts", "rule_name", "src_ip", "dst_ip",
                                                                     "confidence", "description"]],
                     hide_index=True, width="stretch", height=220)
        st.dataframe(ev.assign(event_id="EVT-" + ev.event_id.astype(str))[
            ["event_id", "ts", "source", "src_ip", "dst_ip", "dst_port", "service", "conn_state", "bytes_out", "signature"]],
            hide_index=True, width="stretch", height=220)
        if inc["dataset"] == "replay":
            lab = db.read_labels()
            tl = lab[lab.event_id.isin(ev.event_id)]
            st.caption(f"Dataset ground truth (never shown to the detectors): {len(tl)} of {len(ev)} evidence events are "
                       f"labelled attacks - {', '.join(sorted(set(','.join(tl.tactic).split(',')) - {''})) or 'benign'}.")
    with t4:
        w = sc.get("weights") or settings.section("scoring")["weights"]
        br = pd.DataFrame([{"component": f"{k} ({w[k]:.0%})", "points": round(100 * w[k] * v, 1)}
                           for k, v in sc["breakdown"].items()])
        st.altair_chart(theme(hbar(br, "component", "points", f"Score {inc['score']:.0f} = sum of"), rows_h(4)),
                        width="stretch")
        for tech in sorted({t for t in al.technique if t}):
            k = attack.lookup(tech)
            if k:
                st.markdown(f"[{k['id']} {k['name']}]({k['url']}) · {', '.join(k['tactics'])}")


def investigate_page():
    left, right = st.columns([5, 4], gap="large")
    ids = incidents.incident_id.tolist()
    focus = st.session_state.get("focus")
    if focus not in ids:
        focus = ids[0] if ids else None
    with left:
        st.markdown("### Ask SecureOps AI")
        st.caption(f"Plain-English questions about your incidents, hosts and attacks - answered from the live data, "
                   f"every statement cited. Model: **{assistant.llm_label()}**.")
        hist = st.session_state.setdefault("chat", [])
        box = st.container(height=480)
        with box:
            if not hist:
                st.chat_message("assistant", avatar=":material/shield:").markdown(
                    "Hi - I watch your sensors and the dataset replay. Ask me what is happening, which incidents "
                    "matter most, or about any host or incident ID.")
            for m in hist:
                with st.chat_message(m["role"], avatar=":material/shield:" if m["role"] == "assistant" else None):
                    st.markdown(m["content"])
                    if m["role"] == "assistant" and m.get("meta"):
                        mt = m["meta"]
                        st.caption(f"{mt['mode']} · {mt['cited']} of statements cite evidence · sources: "
                                   f"{', '.join(mt['sources'][:8])}{'...' if len(mt['sources']) > 8 else ''}")
        suggestions = ["What is happening on my network right now?", "Which incidents need attention first?",
                       f"Explain {focus}" if focus else "Explain the top incident", "Any brute-force attacks?",
                       "What should I do next?"]
        chip = st.pills("Suggestions", suggestions, label_visibility="collapsed", key=f"chips_{len(hist)}")
        q = st.chat_input("Ask about incidents, hosts, attacks...") or chip
        if q:
            hist.append({"role": "user", "content": q})
            with st.spinner("Searching the evidence..."):
                ans = chat.answer(q, [{"role": m["role"], "content": m["content"]} for m in hist[:-1]], focus)
            if ans["focus"]:
                st.session_state.focus = ans["focus"]
            hist.append({"role": "assistant", "content": ans["text"] + (f"\n\n_{ans['note']}_" if ans["note"] else ""),
                         "meta": {"mode": ans["mode"], "cited": f"{ans['support_rate']:.0%}",
                                  "sources": [s["id"] for s in ans["sources"]]}})
            st.rerun()
        if hist and st.button("Clear conversation", type="tertiary"):
            st.session_state.chat = []
            st.rerun()
    with right:
        if not ids:
            st.info("No incidents yet.")
            return
        titles = incidents.set_index("incident_id").title
        sel = st.selectbox("Incident in focus", ids, index=ids.index(focus),
                           format_func=lambda i: f"{i} · {titles[i][:70]}")
        st.session_state.focus = sel
        incident_panel(sel)


{"Live": live_page, "Overview": overview_page, "Investigate": investigate_page}[page]()
