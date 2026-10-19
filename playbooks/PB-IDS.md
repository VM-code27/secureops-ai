# PB-IDS: Exploit attempt against a public-facing application
Technique: T1190 Exploit Public-Facing Application (initial access).
Why it matters: an IDS exploit signature naming a CVE is far more serious when the targeted asset actually runs the vulnerable version; that combination indicates a likely successful intrusion.
Verify: compare the CVE in the signature with the target's installed software and patch level; review web server access logs for HTTP 200 responses to the malicious requests; look for new outbound connections from the target after the attempt.
Contain: apply the vendor patch or virtual patch (WAF rule); block the attacking source; if exploitation is confirmed, isolate the server.
Close-out: patch every asset exposed to the same CVE, prioritising those on the CISA Known Exploited Vulnerabilities list.
