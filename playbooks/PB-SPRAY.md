# PB-SPRAY: Password spraying
Technique: T1110.003 Password Spraying (credential access).
Why it matters: trying one or two common passwords against many accounts avoids per-account lockout and often targets VPN or SSO portals.
Verify: list the accounts tried and check whether any of them later logged in successfully from the same source or a related address.
Contain: block the source; force password resets for any account that succeeded; require MFA on the remote-access service.
Close-out: check the targeted usernames against leaked-credential sources and educate affected users.
