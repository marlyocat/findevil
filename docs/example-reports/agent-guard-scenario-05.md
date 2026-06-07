# Incident Response Report — Scenario 05
**Classification:** UNCLASSIFIED  
**Analyst:** FindEvil Autonomous IR Agent  
**Date (UTC):** 2026-04-23  
**Evidence:** `evidence/attack-scenario-05-clean`  
**Scope:** Production web server — suspected compromise

---

## Executive Summary

**VERDICT: NO COMPROMISE. This system is clean.**

A full forensic review of all available evidence found zero indicators of compromise. Every authentication event, sudo invocation, shell history command, persistence location, and configuration file is consistent with routine, legitimate operations by three known internal users over a two-day window (2026-04-13 to 2026-04-14). No attacker activity was detected.

---

## Evidence Examined

| Artifact | Path | Status |
|----------|------|--------|
| Auth log | `auth.log` | Reviewed — 38 events |
| Filesystem root | `fs/` | Reviewed |
| SSH config | `fs/etc/ssh/sshd_config` | Reviewed |
| User accounts | `fs/etc/passwd`, `fs/etc/shadow` | Reviewed |
| Sudoers | `fs/etc/sudoers.d/deploy` | Reviewed |
| SSH authorized keys | `fs/home/deploy/.ssh/authorized_keys` | Reviewed |
| Shell histories | `fs/home/alice/.bash_history`, `fs/home/deploy/.bash_history`, `fs/root/.bash_history` | Reviewed |
| Systemd units | `fs/etc/systemd/system/` | Reviewed |

---

## Findings

### 1. Authentication — No anomalies

- **0 failed logins.** No brute-force or password-spray attempts.
- **7 successful logins**, all via publickey from RFC 1918 addresses on the internal network:

| Timestamp (UTC) | User | Source IP | Method |
|-----------------|------|-----------|--------|
| 2026-04-13 08:15:42 | deploy | 10.0.1.50 | publickey |
| 2026-04-13 09:02:11 | alice | 10.0.2.15 | publickey |
| 2026-04-13 11:30:02 | bob | 10.0.2.22 | publickey |
| 2026-04-13 13:15:33 | deploy | 10.0.1.50 | publickey |
| 2026-04-13 16:42:08 | alice | 10.0.2.15 | publickey |
| 2026-04-14 08:25:10 | deploy | 10.0.1.50 | publickey |
| 2026-04-14 10:03:22 | bob | 10.0.2.22 | publickey |

No logins from external IPs. No logins to root. No password-based authentication.

### 2. Sudo — No anomalies

All 7 sudo invocations are benign and expected for their respective roles:

| User | Command | Assessment |
|------|---------|------------|
| deploy | `systemctl restart nginx` (×3) | Legitimate CI/CD deploy action |
| alice | `tail -n 200 /var/log/nginx/error.log` | Legitimate log review |
| alice | `journalctl -u nginx --since '1 hour ago'` | Legitimate log review |
| bob | `apt update` | Legitimate maintenance |
| bob | `apt upgrade -y` | Legitimate maintenance |

No privilege escalation. No shadow file reads. No key modification. No cronjob manipulation. No logging disruption.

### 3. Persistence — No malicious mechanisms

- **Systemd:** `fs/etc/systemd/system/` is empty — no attacker-placed service units.
- **SSH authorized_keys:** `fs/home/deploy/.ssh/authorized_keys` contains exactly one key, labelled `deploy@ci-runner-1`. Single entry, no second key appended.
- **Sudoers (`/etc/sudoers.d/deploy`):** Argv-constrained NOPASSWD restricted to `/usr/bin/systemctl restart nginx`. This is a legitimate, minimal-privilege configuration for CI/CD automation.
- **Shell init files (`.bashrc`):** Normal interactive shell configuration for `alice` and `deploy`. No injected download loops, reverse shells, or `LD_PRELOAD` hooks.
- **`/etc/ld.so.preload`:** Not present.

### 4. User Accounts — No anomalies

- `/etc/passwd` contains only standard Ubuntu system accounts plus three named human users (`deploy`, `alice`, `bob`). No extra UID 0 accounts. No ghost accounts.
- `/etc/shadow`: All system/service accounts locked (`*` or `!`). The three human accounts carry standard `$6$` (SHA-512) hashes. No empty password fields.

### 5. SSH Configuration — Hardened

`sshd_config` is correctly hardened:

| Setting | Value | Assessment |
|---------|-------|------------|
| PasswordAuthentication | no | Correct |
| PermitRootLogin | no | Correct |
| PermitEmptyPasswords | no | Correct |
| PubkeyAuthentication | yes | Correct |
| MaxAuthTries | 3 | Appropriate |
| X11Forwarding | no | Correct |

No attacker-introduced relaxations.

### 6. Shell Histories — No anomalies

- **`alice`:** Log inspection only — `tail nginx/access.log`, `journalctl -u nginx`, `systemctl status nginx`. Normal sysadmin pattern.
- **`deploy`:** CI/CD pipeline commands — `git pull`, `npm ci`, `npm run build`, `npm test`, `docker ps`. No network exfiltration tools, no download-and-execute patterns.
- **`root`:** Basic maintenance — `apt update/upgrade`, `systemctl restart nginx`, `tail -f` log. No suspicious commands.

### 7. Webshells — None found

No web roots present in the captured filesystem snapshot. No files with executable extensions (`.php`, `.jsp`, `.asp`, `.cgi`, etc.) were found. No webshell indicators detected.

---

## IOC Summary

**None.** No malicious IPs, domains, file hashes, or CVE identifiers were identified in any artifact.

---

## Timeline

All 14 logged events fall within two ordinary business days and map to three legitimate users performing routine roles:

| Period | Activity |
|--------|----------|
| 2026-04-13 08:00–17:00 | Deploy restarts nginx (CI), Alice reviews nginx logs, Bob runs `apt upgrade` |
| 2026-04-14 08:00–10:30 | Deploy restarts nginx (CI), Bob logs in |

No anomalous timing (e.g., off-hours access from external IPs). No gaps or deletions in the log sequence.

---

## Conclusion

**This system was not compromised.**

All authentication was via publickey from internal network addresses. All privilege use was restricted to expected, pre-authorized operations. No persistence mechanisms, no lateral movement, no data exfiltration, no attacker tooling, and no configuration modifications were found. The SSH configuration is correctly hardened and was not tampered with.

The evidence is consistent with a well-administered production Linux host running normal CI/CD and sysadmin operations.

**Recommended action:** No remediation required. Continue normal operations.

---

*Report generated by FindEvil v0.1 on SANS SIFT Workstation — all analysis is read-only and chain-of-custody preserving.*

---

<!-- scorecard:start -->

## Verification scorecard

Mechanically computed by `scripts/grade_example_reports.py` against the
`agent_guard.SCENARIOS["05"]` markers (case-insensitive substring
match, identical logic to `tests/harness/agent_guard.py`'s grade()
function). No AI self-assessment is involved in these numbers.

| Metric | Score | % |
|---|---|---|
| Required markers found | 1/1 | **100%** |
| Cross-scenario markers absent | 12/12 | **100%** |
| Verdict-correctness confidence | — | **100%** |
| Hallucination-free confidence | — | **100%** |

**Overall confidence: HIGH** — every planted marker for this
scenario was surfaced in the report, and zero markers from any other
scenario leaked in. Re-grade with `python scripts/grade_example_reports.py`.

<!-- scorecard:end -->
