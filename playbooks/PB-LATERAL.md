# PB-LATERAL: Lateral movement over administrative protocols
Technique: T1021.002 SMB/Windows Admin Shares (lateral movement).
Why it matters: one host suddenly opening SMB, RDP or WinRM sessions to many internal hosts is typical of an attacker or ransomware spreading.
Verify: identify the account used for the sessions; check whether the source host is an administration server where this is normal; check the destinations for new services or scheduled tasks.
Contain: isolate the source host; disable the account used; block SMB between workstation segments.
Close-out: scan every destination host for persistence and compromise indicators.
