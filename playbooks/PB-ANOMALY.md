# PB-ANOMALY: Behavioural anomaly
Technique: none assigned; machine-learning detection (Isolation Forest).
Why it matters: the host behaved differently from its peer group in this hour (for example new destinations, unusual ports, or unusual data volume). Anomalies catch novel behaviour that no rule describes, but they also flag benign oddities.
Verify: compare the anomalous features with the host's normal role; look for correlated rule alerts on the same host; ask the asset owner whether the activity was expected.
Contain: only after corroboration; anomalies alone should not trigger isolation.
Close-out: record whether the anomaly was benign so the model and thresholds can be tuned.
