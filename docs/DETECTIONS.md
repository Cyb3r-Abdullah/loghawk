# Detection catalog

Ten rules, each mapped to MITRE ATT&CK. `base_score` is the starting risk
score; each rule adds context-dependent modifiers (threat-feed hit, privileged
account, payload reaching application logic) and clamps the result to its own
ceiling. Ceilings are what keep a loud *attempt* from outranking a confirmed
*compromise* in the triage queue.

> Regenerate this file with `python docs/generate_catalog.py > docs/DETECTIONS.md`.

| Rule | Title | Base | Ceiling | ATT&CK | Tactic |
|---|---|---|---|---|---|
| `LH-001` | SSH brute force | 68 | 90 | [T1110](https://attack.mitre.org/techniques/T1110/)<br>[T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Credential Access |
| `LH-002` | Password spraying | 72 | 90 | [T1110](https://attack.mitre.org/techniques/T1110/)<br>[T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Credential Access |
| `LH-003` | Account enumeration | 45 | 70 | [T1087](https://attack.mitre.org/techniques/T1087/) | Discovery |
| `LH-004` | Successful login after failed-login burst | 92 | 100 | [T1110](https://attack.mitre.org/techniques/T1110/)<br>[T1078](https://attack.mitre.org/techniques/T1078/) | Credential Access<br>Initial Access |
| `LH-005` | Impossible travel | 78 | 90 | [T1078](https://attack.mitre.org/techniques/T1078/) | Defense Evasion |
| `LH-006` | Off-hours privileged logon | 52 | 75 | [T1078.003](https://attack.mitre.org/techniques/T1078/003/) | Persistence |
| `LH-007` | Suspicious sudo activity | 66 | 92 | [T1548.003](https://attack.mitre.org/techniques/T1548/003/)<br>[T1003.008](https://attack.mitre.org/techniques/T1003/008/) | Credential Access<br>Privilege Escalation |
| `LH-008` | Account created or added to a privileged group | 74 | 95 | [T1136.001](https://attack.mitre.org/techniques/T1136/001/)<br>[T1098](https://attack.mitre.org/techniques/T1098/) | Persistence |
| `LH-009` | Web exploitation attempt | 70 | 95 | [T1190](https://attack.mitre.org/techniques/T1190/)<br>[T1083](https://attack.mitre.org/techniques/T1083/) | Discovery<br>Initial Access |
| `LH-010` | Automated web scanning | 48 | 80 | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | Reconnaissance |

## Coverage by ATT&CK tactic

- **Credential Access** - LH-001, LH-002, LH-004, LH-007
- **Defense Evasion** - LH-005
- **Discovery** - LH-003, LH-009
- **Initial Access** - LH-004, LH-009
- **Persistence** - LH-006, LH-008
- **Privilege Escalation** - LH-007
- **Reconnaissance** - LH-010

---

## LH-001 - SSH brute force

**Default severity:** high &nbsp;&nbsp; **Base score:** 68 &nbsp;&nbsp; **Ceiling:** 90

A single source address produced a high volume of failed authentications against one or more accounts in a short window.

**MITRE ATT&CK**

- [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/) (Credential Access)
- [T1110.001 - Password Guessing](https://attack.mitre.org/techniques/T1110/001/) (Credential Access)

**Analyst action:** Block the source IP at the edge firewall, confirm no session from it succeeded, and enforce key-only SSH auth with fail2ban or equivalent.

**Source:** `loghawk/detections/credential_attacks.py` -> `SSHBruteForce`

## LH-002 - Password spraying

**Default severity:** high &nbsp;&nbsp; **Base score:** 72 &nbsp;&nbsp; **Ceiling:** 90

One source tried a small number of passwords against many distinct accounts - the low-and-slow pattern designed to dodge lockout policies.

**MITRE ATT&CK**

- [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/) (Credential Access)
- [T1110.003 - Password Spraying](https://attack.mitre.org/techniques/T1110/003/) (Credential Access)

**Analyst action:** Review every account named in the alert for a successful logon from the same source, force a password reset on any that authenticated, and enable MFA on externally reachable authentication.

**Source:** `loghawk/detections/credential_attacks.py` -> `PasswordSpray`

## LH-003 - Account enumeration

**Default severity:** medium &nbsp;&nbsp; **Base score:** 45 &nbsp;&nbsp; **Ceiling:** 70

Repeated authentication attempts against accounts that do not exist, indicating the attacker is mapping valid usernames.

**MITRE ATT&CK**

- [T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/) (Discovery)

**Analyst action:** Confirm SSH is not exposing user-existence differences, and treat the source as hostile reconnaissance preceding a credential attack.

**Source:** `loghawk/detections/credential_attacks.py` -> `UserEnumeration`

## LH-004 - Successful login after failed-login burst

**Default severity:** critical &nbsp;&nbsp; **Base score:** 92 &nbsp;&nbsp; **Ceiling:** 100

An account authenticated successfully from a source that had just produced a burst of failures - the signature of a guessed password.

**MITRE ATT&CK**

- [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/) (Credential Access)
- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/) (Initial Access)

**Analyst action:** Treat as a confirmed compromise until disproven: isolate the host, reset the account's credentials and any keys it holds, and hunt for post-authentication activity from the same session.

**Source:** `loghawk/detections/credential_attacks.py` -> `SuccessAfterBruteForce`

## LH-005 - Impossible travel

**Default severity:** high &nbsp;&nbsp; **Base score:** 78 &nbsp;&nbsp; **Ceiling:** 90

The same account authenticated from two geographic locations too far apart to be reached in the elapsed time, implying shared or stolen credentials.

**MITRE ATT&CK**

- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/) (Defense Evasion)

**Analyst action:** Verify with the account owner whether both sessions are theirs. If not, revoke active sessions, reset credentials and check for VPN or proxy use that could explain the geography before escalating.

**Source:** `loghawk/detections/identity.py` -> `ImpossibleTravel`

## LH-006 - Off-hours privileged logon

**Default severity:** medium &nbsp;&nbsp; **Base score:** 52 &nbsp;&nbsp; **Ceiling:** 75

A privileged account authenticated outside configured business hours, when legitimate administrative work is unlikely.

**MITRE ATT&CK**

- [T1078.003 - Local Accounts](https://attack.mitre.org/techniques/T1078/003/) (Persistence)

**Analyst action:** Correlate with the change calendar and on-call roster. Unscheduled out-of-hours root access is a high-value hunting lead even when benign.

**Source:** `loghawk/detections/identity.py` -> `OffHoursPrivilegedAccess`

## LH-007 - Suspicious sudo activity

**Default severity:** high &nbsp;&nbsp; **Base score:** 66 &nbsp;&nbsp; **Ceiling:** 92

Failed sudo authentications, sudoers violations, or sudo invocations touching credential stores and other sensitive targets.

**MITRE ATT&CK**

- [T1548.003 - Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/) (Privilege Escalation)
- [T1003.008 - OS Credential Dumping: /etc/passwd and /etc/shadow](https://attack.mitre.org/techniques/T1003/008/) (Credential Access)

**Analyst action:** Confirm the invoking account is authorized for the command. Repeated sudo password failures or a 'not in sudoers' entry means someone is probing for escalation - review that account's recent session history.

**Source:** `loghawk/detections/privilege.py` -> `SudoAbuse`

## LH-008 - Account created or added to a privileged group

**Default severity:** high &nbsp;&nbsp; **Base score:** 74 &nbsp;&nbsp; **Ceiling:** 95

A new account was created, or an existing account was added to an administrative group - classic post-compromise persistence.

**MITRE ATT&CK**

- [T1136.001 - Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/) (Persistence)
- [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) (Persistence)

**Analyst action:** Match the change against an approved ticket. If none exists, disable the account, capture the creating session's logon ID, and pivot to the source host for the rest of the intrusion.

**Source:** `loghawk/detections/privilege.py` -> `PrivilegedAccountChange`

## LH-009 - Web exploitation attempt

**Default severity:** high &nbsp;&nbsp; **Base score:** 70 &nbsp;&nbsp; **Ceiling:** 95

Requests carrying payloads that match known exploitation signatures (injection, traversal, sensitive-file access).

**MITRE ATT&CK**

- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) (Initial Access)
- [T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/) (Discovery)

**Analyst action:** Check the response codes: a 200 or 500 on a signature hit means the payload reached application logic. Review the affected endpoint's input handling and put the source behind a WAF block.

**Source:** `loghawk/detections/web.py` -> `WebExploitAttempt`

## LH-010 - Automated web scanning

**Default severity:** medium &nbsp;&nbsp; **Base score:** 48 &nbsp;&nbsp; **Ceiling:** 80

A source generated a burst of 4xx responses or advertised a known scanning tool in its User-Agent.

**MITRE ATT&CK**

- [T1595.002 - Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/) (Reconnaissance)

**Analyst action:** Scanning alone is noise at internet scale, but pair it with any later success from the same source and it becomes the first stage of an intrusion. Rate-limit the origin and keep it on a watchlist.

**Source:** `loghawk/detections/web.py` -> `WebScanning`

