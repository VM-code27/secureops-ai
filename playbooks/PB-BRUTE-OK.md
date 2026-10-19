# PB-BRUTE-OK: Successful login after brute force
Technique: T1078 Valid Accounts (initial access).
Why it matters: a success immediately after many failures strongly suggests the attacker guessed a valid password and now has an authenticated session.
Verify: confirm the source of the success matches the brute-force source; review what the session did (commands, data transferred, new connections).
Contain: disable or reset the compromised account, terminate its active sessions, and block the source address.
Close-out: review the account's privileges, require MFA, and audit other systems the account can reach.
