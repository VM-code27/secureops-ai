# PB-EXFIL: Large outbound data transfer
Technique: T1041 Exfiltration Over C2 Channel / T1048 Exfiltration Over Alternative Protocol.
Why it matters: a very large upload to an external host can be data theft, especially to a known-bad destination or from a server holding sensitive data.
Verify: identify the destination owner; check whether the transfer matches a known business process (for example scheduled offsite backup); check what data the source host stores.
Contain: block the destination; isolate the source host if the transfer is unexplained.
Close-out: if it is a sanctioned backup, add the destination to the allowlist and mark the incident as a false positive; otherwise start data-breach notification assessment.
