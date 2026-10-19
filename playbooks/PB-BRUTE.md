# PB-BRUTE: Brute-force / repeated authentication attempts
Technique: T1110 Brute Force (credential access).
Why it matters: many short sessions from one source to the same login service (SSH, RDP, SMB, web admin consoles such as GlassFish on 4848) usually means automated password guessing; it is critical if any attempt succeeds.
Verify: count attempts and the time span; check whether the source is an internal host (possibly a misconfigured service or a user retrying) or external; look for a session with much larger byte counts or longer duration that suggests a successful login.
Contain: block or rate-limit the source; enforce account lockout and MFA on the targeted service; restrict the admin interface to a management network.
Close-out: if the source is a known monitoring or backup job, allow-list it in Settings and mark the incident as a false positive.
