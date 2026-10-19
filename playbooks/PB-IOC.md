# PB-IOC: Communication with a threat-intelligence indicator
Technique: T1071 Application Layer Protocol (command and control).
Why it matters: repeated, regular connections from an internal host to a known command-and-control server usually mean the host is already compromised and is waiting for instructions (beaconing).
Verify: confirm the indicator is still listed in current threat intel; check whether the connections are periodic (beacon interval and jitter); identify the process making the connections with EDR if available.
Contain: block the indicator at the perimeter firewall and proxy; isolate the internal host from the network while preserving memory for forensics.
Close-out: re-image or clean the host, rotate credentials used on it, and hunt for the same indicator on other hosts.
