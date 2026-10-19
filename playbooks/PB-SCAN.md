# PB-SCAN: Port scanning and service discovery
Technique: T1595 Active Scanning / T1046 Network Service Discovery.
Why it matters: scanning is usually reconnaissance before an attack; on its own it is low severity, but it raises the risk of any later activity from the same source.
Verify: confirm the source is not an authorised scanner; check whether the scan was followed by exploitation attempts against discovered services.
Contain: block the scanning source at the perimeter if external; investigate the host if the scan comes from inside the network.
Close-out: close unnecessary exposed ports discovered by the scan.
