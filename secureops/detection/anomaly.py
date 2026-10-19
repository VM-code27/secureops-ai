"""Unsupervised behavioural anomaly detection (Isolation Forest).

Unit of analysis: one source IP in one clock hour. The model is trained without
labels, so it can flag behaviour that no rule describes - and it will also flag
benign oddities, which is why its confidence is kept below the rules'.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from ..assets import is_internal
from ..config import ALLOWLIST_SOURCES, SEED, THRESHOLDS

FEATURES = ["n_conn", "n_dst", "n_port", "log_bytes_out", "log_bytes_in", "n_auth_fail", "rej_ratio",
            "n_ext_dst", "off_hours", "is_external", "is_server", "is_iot"]
FEATURE_LABELS = {
    "n_conn": "connections", "n_dst": "distinct destinations", "n_port": "distinct destination ports",
    "log_bytes_out": "bytes sent", "log_bytes_in": "bytes received", "n_auth_fail": "failed logins",
    "rej_ratio": "rejected-connection ratio", "n_ext_dst": "distinct external destinations",
    "off_hours": "off-hours activity", "is_external": "external source", "is_server": "server",
    "is_iot": "IoT device",
}
CONTEXT_FEATURES = {"is_external", "is_server", "is_iot", "off_hours"}


def window_features(events: pd.DataFrame) -> pd.DataFrame:
    ev = events[~events.src_ip.isin(ALLOWLIST_SOURCES)].copy()
    ev["hour"] = ev.ts.dt.floor("h")
    ev["is_rej"] = ev.conn_state.isin(["REJ", "S0"]) & (ev.source == "zeek_conn")
    ev["is_fail"] = ev.outcome == "failure"
    ev["ext_dst"] = np.where(ev.dst_ip.map(is_internal), None, ev.dst_ip)
    g = ev.groupby(["src_ip", "hour"])
    f = pd.DataFrame({
        "n_conn": g.size(),
        "n_dst": g.dst_ip.nunique(),
        "n_port": g.dst_port.nunique(),
        "log_bytes_out": np.log1p(g.bytes_out.sum()),
        "log_bytes_in": np.log1p(g.bytes_in.sum()),
        "n_auth_fail": g.is_fail.sum(),
        "rej_ratio": g.is_rej.mean(),
        "n_ext_dst": g.ext_dst.nunique(),
    }).reset_index()
    hod = f.hour.dt.hour
    f["off_hours"] = ((hod < 7) | (hod >= 20)).astype(int)
    # Peer-group context: a camera talking to the internet is odd; a laptop doing it is not.
    f["is_external"] = (~f.src_ip.map(is_internal)).astype(int)
    f["is_server"] = f.src_ip.str.startswith("10.10.1.").astype(int)
    f["is_iot"] = f.src_ip.str.startswith("10.10.4.").astype(int)
    return f


class AnomalyModel:
    def __init__(self, contamination: float | None = None, seed: int = SEED):
        self.contamination = contamination or THRESHOLDS["anomaly_contamination"]
        self.model = IsolationForest(n_estimators=200, contamination=self.contamination, random_state=seed)
        self.baseline: pd.DataFrame | None = None
        self.score_range = (0.0, 1.0)

    def fit(self, events: pd.DataFrame) -> "AnomalyModel":
        f = window_features(events)
        self.model.fit(f[FEATURES].values)
        self.baseline = f[FEATURES].describe(percentiles=[0.5, 0.95]).loc[["50%", "95%"]]
        s = -self.model.decision_function(f[FEATURES].values)
        self.score_range = (0.0, float(s.max()) or 1.0)
        return self

    def explain(self, row: pd.Series) -> str:
        parts = []
        for feat in FEATURES:
            if feat in CONTEXT_FEATURES:
                continue
            p95 = self.baseline.loc["95%", feat]
            if row[feat] > p95 and row[feat] > 0:
                val = np.expm1(row[feat]) if feat.startswith("log_") else row[feat]
                med = np.expm1(self.baseline.loc["50%", feat]) if feat.startswith("log_") else self.baseline.loc["50%", feat]
                parts.append((row[feat] / (p95 + 1e-9), f"{FEATURE_LABELS[feat]} = {val:,.0f} (typical {med:,.0f})"
                              if feat != "rej_ratio" else f"{FEATURE_LABELS[feat]} = {val:.0%}"))
        parts.sort(reverse=True)
        return "; ".join(p for _, p in parts[:3]) or "unusual combination of features"

    def detect(self, events: pd.DataFrame) -> list[dict]:
        f = window_features(events)
        if f.empty:
            return []
        X = f[FEATURES].values
        flagged = self.model.predict(X) == -1
        scores = -self.model.decision_function(X)
        pair_freq = events.groupby(["dst_ip", "dst_port"]).size()
        windows = events.groupby([events.src_ip, events.ts.dt.floor("h")]).indices
        alerts = []
        for (_, row), is_out, s in zip(f.iterrows(), flagged, scores):
            if not is_out:
                continue
            w = events.iloc[windows[(row.src_ip, row.hour)]]
            rarity = w.set_index(["dst_ip", "dst_port"]).index.map(pair_freq).to_numpy()
            w = w.assign(_r=rarity).sort_values(["_r", "bytes_out"], ascending=[True, False]).head(25)
            conf = 0.4 + 0.3 * min(1.0, max(0.0, s) / self.score_range[1])
            alerts.append(dict(
                rule_id="ML-ANOMALY", rule_name="Behavioural anomaly (Isolation Forest)", tactic="Anomaly",
                technique="", ts=w.ts.min(), last_ts=w.ts.max(), src_ip=row.src_ip, dst_ip="", targets=[], user="",
                confidence=float(conf),
                description=f"Hourly behaviour of {row.src_ip} at {row.hour:%Y-%m-%d %H:00} UTC is anomalous "
                            f"(score {s:.3f}): {self.explain(row)}.",
                evidence=[int(x) for x in w.event_id], cve=""))
        return alerts


def detect_all(events: pd.DataFrame, model: AnomalyModel) -> pd.DataFrame:
    from .rules import detect_rules

    alerts = detect_rules(events) + model.detect(events)
    df = pd.DataFrame(alerts)
    if df.empty:
        return df
    df["ts"] = pd.to_datetime(df.ts, utc=True)
    df["last_ts"] = pd.to_datetime(df.last_ts, utc=True)
    return df.sort_values("ts", kind="stable").reset_index(drop=True)
