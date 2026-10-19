"""Unsupervised behavioural anomaly detection (Isolation Forest).

Unit of analysis: one source IP in one clock hour. The model is trained without labels on
the first `detection.anomaly.baseline_hours` of observed traffic and then scores every
completed hour. Context features come from the discovered asset inventory (is the host
external, does it serve anything, how popular is it) - not from hard-coded subnets.
"""
from __future__ import annotations

import math

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from .. import settings
from ..assets import home_nets, index as asset_index

FEATURES = ["n_conn", "n_dst", "n_port", "log_bytes_out", "log_bytes_in", "fail_ratio", "n_ext_dst", "n_auth_fail",
            "is_external", "is_server", "log_fan_in"]
LABELS = {"n_conn": "connections", "n_dst": "distinct destinations", "n_port": "distinct destination ports",
          "log_bytes_out": "bytes sent", "log_bytes_in": "bytes received", "fail_ratio": "share of unanswered connections",
          "n_ext_dst": "distinct external destinations", "n_auth_fail": "failed logins"}
CONTEXT = {"is_external", "is_server", "log_fan_in"}
FAILED = {"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR", "OTH"}


def window_features(events: pd.DataFrame) -> pd.DataFrame:
    allow = set(settings.section("network")["allowlist_sources"])
    ev = events[events.source.isin(["zeek_conn", "suricata_flow", "zeek_ssh"]) & ~events.src_ip.isin(allow)].copy()
    if ev.empty:
        return pd.DataFrame(columns=["src_ip", "hour"] + FEATURES)
    home = home_nets(events)
    ev["hour"] = ev.ts.dt.floor("h")
    ev["failed"] = ev.conn_state.isin(FAILED)
    ev["auth_fail"] = ev.outcome == "failure"
    ev["ext_dst"] = ev.dst_ip.where(~ev.dst_ip.map(lambda x: x in home).astype(bool))
    g = ev.groupby(["src_ip", "hour"])
    f = pd.DataFrame({
        "n_conn": g.size(), "n_dst": g.dst_ip.nunique(), "n_port": g.dst_port.nunique(),
        "log_bytes_out": np.log1p(g.bytes_out.sum()), "log_bytes_in": np.log1p(g.bytes_in.sum()),
        "fail_ratio": g.failed.mean(), "n_ext_dst": g.ext_dst.nunique(), "n_auth_fail": g.auth_fail.sum(),
    }).reset_index()
    idx = asset_index()
    f["is_external"] = (~f.src_ip.map(lambda x: x in home).astype(bool)).astype(int)
    f["is_server"] = f.src_ip.map(lambda x: int(bool(idx.get(x, {}).get("services"))))
    f["log_fan_in"] = f.src_ip.map(lambda x: math.log1p(idx.get(x, {}).get("fan_in", 0) or 0))
    return f


class AnomalyModel:
    def __init__(self):
        conf = settings.section("detection")["anomaly"]
        self.contamination = conf["contamination"]
        self.model = IsolationForest(n_estimators=conf["n_estimators"], contamination=self.contamination, random_state=0)
        self.baseline = None
        self.max_score = 1.0
        self.trained_on = 0
        self.trained_until = None

    def fit(self, events: pd.DataFrame) -> "AnomalyModel":
        f = window_features(events)
        if len(f) < 20:
            raise ValueError("not enough traffic to train the anomaly model")
        X = f[FEATURES].values
        self.model.fit(X)
        self.baseline = f[FEATURES].quantile([0.5, 0.95])
        self.max_score = float(max(1e-6, (-self.model.decision_function(X)).max()))
        self.trained_on = len(f)
        self.trained_until = events.ts.max()
        return self

    def _explain(self, row) -> str:
        parts = []
        for feat in FEATURES:
            if feat in CONTEXT:
                continue
            p95, med = self.baseline.loc[0.95, feat], self.baseline.loc[0.5, feat]
            if row[feat] > p95 and row[feat] > 0:
                if feat.startswith("log_"):
                    val, typ = f"{np.expm1(row[feat]):,.0f}", f"{np.expm1(med):,.0f}"
                elif feat == "fail_ratio":
                    val, typ = f"{row[feat]:.0%}", f"{med:.0%}"
                else:
                    val, typ = f"{row[feat]:,.0f}", f"{med:,.0f}"
                parts.append((row[feat] / (p95 + 1e-9), f"{LABELS[feat]} = {val} (typical {typ})"))
        parts.sort(reverse=True)
        return "; ".join(p for _, p in parts[:3]) or "unusual combination of features for this kind of host"

    def detect(self, events: pd.DataFrame, hours: set | None = None) -> list[dict]:
        """Score (src, hour) windows; `hours` restricts scoring to completed hours."""
        f = window_features(events)
        if hours is not None:
            f = f[f.hour.isin(hours)]
        if f.empty:
            return []
        X = f[FEATURES].values
        flagged = self.model.predict(X) == -1
        scores = -self.model.decision_function(X)
        pair_freq = events.groupby(["dst_ip", "dst_port"]).size()
        windows = events.groupby([events.src_ip, events.ts.dt.floor("h")]).indices
        meta = settings.rules()["ML-ANOMALY"]
        out = []
        for (_, row), is_out, s in zip(f.iterrows(), flagged, scores):
            if not is_out:
                continue
            w = events.iloc[windows[(row.src_ip, row.hour)]]
            rarity = w.set_index(["dst_ip", "dst_port"]).index.map(pair_freq).to_numpy()
            w = w.assign(_r=rarity).sort_values(["_r", "bytes_out"], ascending=[True, False]).head(25)
            conf = meta["confidence"] - 0.1 + 0.2 * min(1.0, max(0.0, s) / self.max_score)
            out.append(dict(
                alert_key=f"ML-ANOMALY|{row.src_ip}|{row.hour.isoformat()}", rule_id="ML-ANOMALY", rule_name=meta["name"],
                tactic=meta["tactic"], technique=meta["technique"], ts=w.ts.min(), last_ts=w.ts.max(),
                src_ip=row.src_ip, dst_ip="", targets=[], user="", confidence=float(conf),
                description=f"Behaviour of {row.src_ip} during {row.hour:%Y-%m-%d %H:00} UTC is anomalous for its peer "
                            f"group (score {s:.3f}): {self._explain(row)}.",
                evidence=[int(x) for x in w.event_id], cve=""))
        return out
