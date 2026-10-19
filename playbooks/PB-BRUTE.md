# PB-BRUTE: Brute-force authentication
Technique: T1110.001 Password Guessing (credential access).
Why it matters: many failed logins from one source against one service is an attempt to guess passwords; it is critical if it is followed by a success.
Verify: count failures and accounts tried; check whether the source is internal (possibly a user typing errors or a misconfigured service) or external; check for any successful login from the same source.
Contain: block or rate-limit the source; enforce account lockout and MFA on the targeted service.
Close-out: if the source was an internal user error, mark the incident as a false positive and document it to tune the threshold.
