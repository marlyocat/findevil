# Forensic Analysis Report: PolicyKit Rule Injection + Cron Persistence

## Attack Overview

**Attack Name:** PolicyKit Rule Injection with Cron-based Persistence

**Attack Vector:** Exploitation of PolicyKit's rule-based privilege escalation system combined with root-level cron job persistence

**Severity:** CRITICAL - Provides unprivileged attacker with full administrative access without requiring password authentication

**Compromise Timeline:** April 19-20, 2026

---

## Attack Narrative

An attacker with initial access as user `jenkins` (a CI/CD automation account) deployed a sophisticated persistence mechanism combining two attack techniques:

1. **PolicyKit Rule Injection (Primary Persistence)**: Created malicious rules at `/etc/polkit-1/rules.d/49-malicious.rules` that grant the `jenkins` user passwordless, unauthenticated access to critical system management functions (systemd, package management, network configuration).

2. **Cron-based Verification (Secondary Persistence)**: Deployed a root-level cron job at `/etc/cron.d/system-health` that periodically verifies the malicious PolicyKit rule exists and automatically restores it if deleted, ensuring persistence across reboots and administrative remediation attempts.

---

## Evidence Files

### Primary Evidence of Compromise

#### 1. **`/etc/polkit-1/rules.d/49-malicious.rules`**
   - **Type:** PolicyKit Rule Definition (JavaScript)
   - **Location:** `evidence/fs/etc/polkit-1/rules.d/49-malicious.rules`
   - **Indicators:**
     - Grants `jenkins` user passwordless access to all `org.freedesktop.systemd1.*` actions (service management)
     - Permits passwordless access to `org.debian.apt.*` actions (package installation/removal)
     - Allows network configuration management without authentication
     - Explicitly suppresses audit logging for jenkins actions
     - Rule priority is 49 (high - processed before most default rules)
   - **Forensic Significance:** This is the backdoor. A normal user should not have unauthenticated access to privileged operations. The presence of `subject.user == "jenkins"` combined with `polkit.Result.YES` returns is the smoking gun.

#### 2. **`/etc/cron.d/system-health`**
   - **Type:** System Cron Job Definition
   - **Location:** `evidence/fs/etc/cron.d/system-health`
   - **Indicators:**
     - Runs as `root` (highest privilege)
     - Executes every 30 minutes: `/usr/local/bin/system-health-check.py`
     - Contains inline bash command (line 9) that checks for `/etc/polkit-1/rules.d/49-malicious.rules` and **automatically recreates it if missing**
     - Includes log cleanup commands that delete evidence files older than 7 days
     - Comment suggests "system maintenance" (social engineering/obfuscation)
   - **Forensic Significance:** This is the persistence mechanism. The cron job ensures the malicious PolicyKit rule cannot be permanently removed without disabling the cron job itself. Attackers use this pattern to maintain access across remediation attempts.

#### 3. **`/etc/passwd`**
   - **Type:** User Account Database
   - **Location:** `evidence/fs/etc/passwd`
   - **Indicators:**
     - Contains `jenkins` user (UID 1001, shell `/bin/bash`)
     - User is not in `sudoers` file but has administrative access via PolicyKit
     - Login shell is not nologin, indicating account is active
   - **Forensic Significance:** Confirms `jenkins` is a legitimate system user but raises suspicion when paired with PolicyKit rules granting unrestricted admin access.

#### 4. **`/etc/shadow`**
   - **Type:** Password Hash Database
   - **Location:** `evidence/fs/etc/shadow`
   - **Indicators:**
     - `jenkins` account has a valid bcrypt password hash (not locked/disabled)
     - Compared to `ubuntu` user, `jenkins` account was created slightly later
   - **Forensic Significance:** Confirms the jenkins account has active credentials.

#### 5. **`/usr/local/bin/system-health-check.py`**
   - **Type:** Python Persistence Script
   - **Location:** `evidence/fs/usr/local/bin/system-health-check.py`
   - **Indicators:**
     - Checks for existence of `/etc/polkit-1/rules.d/49-malicious.rules`
     - If missing, **recreates the malicious PolicyKit rule**
     - Logs policy verification to `/var/log/audit-jenkins.log`
     - Includes anti-forensics code: cleans up jenkins-related logs older than 7 days
     - Runs with root privileges (called from `/etc/cron.d/system-health`)
   - **Forensic Significance:** This is the automated restoration mechanism. If an administrator deletes the malicious rule, this script will restore it within 30 minutes.

#### 6. **`auth.log`**
   - **Type:** Authentication Log
   - **Location:** `evidence/auth.log`
   - **Key Events:**
     - **Line 8-9:** `jenkins` user SSH login from `198.51.100.22` on Apr 19 11:02:17
     - **Line 10:** Sudo attempt by `jenkins` (denied - "user NOT in sudoers")
     - **Line 13-14:** PolKitd authorization events showing `jenkins` user attempting and being **ALLOWED** privileged actions (Apr 19 12:14:22-24)
     - **Line 15:** Root cron job execution (Apr 19 13:30:01) - running `/usr/local/bin/system-health-check.py`
     - **Line 16-17:** Sudo access granted to `jenkins` for systemctl commands (Apr 19 13:31:45-46)
     - **Line 22:** Cron job running with file auditing (Apr 19 14:45:00) - suggests maintenance of evidence covering
     - **Line 25-26:** More polkit authorizations allowing `jenkins` reboot access (Apr 19 16:01:22-23)
     - **Line 31:** Latest SSH login by `jenkins` on Apr 20 08:12:34
   - **Forensic Significance:** Timeline shows progression of compromise and repeated access. PolKitd logs confirm the malicious rules are active and granting permissions.

### Supporting Evidence

#### 7. **`/etc/ssh/sshd_config`**
   - **Type:** SSH Server Configuration
   - **Location:** `evidence/fs/etc/ssh/sshd_config`
   - **Indicators:**
     - Standard hardened SSH configuration (PermitRootLogin prohibit-password, no password for root)
     - Allows password authentication for user `ubuntu`
     - Restricts `jenkins` user to publickey authentication only (suggests attacker used legitimate SSH key)
   - **Forensic Significance:** Supports SSH access pattern seen in auth.log. Not itself evidence of compromise, but confirms the infrastructure used for attack.

---

## Attack Timeline

| Date/Time | Event | Evidence Source |
|-----------|-------|-----------------|
| 2026-04-19 11:02:17 | Attacker (jenkins) logs in via SSH publickey | auth.log:8 |
| 2026-04-19 12:14:22-24 | Attacker tests PolicyKit access via polkitd | auth.log:13-14 |
| 2026-04-19 13:30:01 | Malicious cron job begins executing | auth.log:15 |
| 2026-04-19 13:31:45-46 | Attacker gains sudo access via polkit (systemctl) | auth.log:16-17 |
| 2026-04-19 14:45:00 | Cron job verifies polkit rule persistence | auth.log:22 |
| 2026-04-19 16:01:22-23 | Attacker escalates to reboot/firmware access | auth.log:25-26 |
| 2026-04-20 02:30:01 | Cron job re-verifies malicious rule | auth.log:31 |
| 2026-04-20 06:15:22-23 | Attacker modifies polkit rule permissions (covering tracks) | auth.log:32-33 |

---

## Detection Indicators (IOC)

### File-Based IOCs
- **Malicious Rule File:** `/etc/polkit-1/rules.d/49-malicious.rules`
  - Containing: `subject.user == "jenkins"` with `Result.YES` return
  - High rule number (49+) suggesting priority override

- **Persistence Script:** `/usr/local/bin/system-health-check.py`
  - Checking for polkit rule existence
  - Automatic re-creation logic

- **Cron Entry:** `/etc/cron.d/system-health`
  - References above script
  - Contains bash one-liner that recreates rules

### Process/Auth IOCs
- Unprivileged user (`jenkins`) performing privileged actions without sudo password prompt
- PolKitd authorizations for `jenkins` user to systemd/package management
- Cron jobs executing Python scripts as root
- Presence of `/var/log/policy-audit.log` and `/var/log/audit-jenkins.log` (non-standard audit logs)

### Account IOCs
- CI/CD automation account (`jenkins`) with shell access and active credentials
- Account granted administrative privileges outside sudoers (via PolicyKit)

---

## Forensic Analysis Findings

### Compromise Confirmed: **YES**

**Evidence Chain:**
1. ✅ Malicious PolicyKit rule present in `/etc/polkit-1/rules.d/`
2. ✅ Rule explicitly grants unprivileged user (`jenkins`) administrative access
3. ✅ Cron job configured to restore the rule if deleted (persistence)
4. ✅ Auth logs confirm `jenkins` user accessing administrative functions
5. ✅ Timeline shows coordinated exploitation and maintenance of backdoor
6. ✅ Anti-forensics measures implemented (log cleanup cron tasks)

### Attack Classification

| Aspect | Finding |
|--------|---------|
| **Access Level** | Unprivileged user escalated to effective root |
| **Persistence Mechanism** | PolicyKit rule + Cron verification/restoration |
| **Detection Evasion** | Uses legitimate system components (polkit, cron); obfuscates via "health check" naming; cleans logs |
| **Attack Complexity** | Moderate - requires knowledge of PolicyKit rule format and cron job structure |
| **Dwell Time** | Minimum 48 hours (Apr 19 11:00 - Apr 20 06:00) |

---

## Expected Forensic Verdict

**COMPROMISED - Active Threat**

### Recommended Response Actions

**Immediate (0-1 hour):**
1. Delete `/etc/polkit-1/rules.d/49-malicious.rules`
2. Delete `/etc/cron.d/system-health`
3. Delete `/usr/local/bin/system-health-check.py`
4. Disable `jenkins` SSH key and account (or isolate if audit needed)
5. Restart polkit daemon: `systemctl restart polkit`

**Short-term (1-24 hours):**
1. Review all PolicyKit rule changes: `ls -la /etc/polkit-1/rules.d/`
2. Audit cron jobs: `find /etc/cron.* -type f -exec ls -la {} \;`
3. Check for additional backdoors in `/usr/local/bin/` and systemd unit files
4. Review auth/polkit logs for lateral movement evidence
5. Rotate all SSH keys and user credentials

**Long-term:**
1. Implement file integrity monitoring (aide/tripwire) for `/etc/polkit-1/`
2. Log and alert on PolicyKit rule creation/modification
3. Audit all CI/CD service accounts for unnecessary privileges
4. Implement EDR/XDR solution for real-time detection of polkit rule injection
5. Review security policy for PolicyKit rule management

---

## References

- **PolicyKit Documentation:** https://polkit.freedesktop.org/docs/index.html
- **Attack Pattern:** Privilege Escalation via Trusted System Components (MITRE ATT&CK T1548)
- **Persistence Pattern:** Cron Job (MITRE ATT&CK T1053.006)
- **Data Obfuscation:** Log Deletion (MITRE ATT&CK T1070.004)

---

**Report Generated:** 2026-04-23
**Analyst:** DFIR Orchestrator
**Confidence Level:** HIGH (90%+ - multiple confirming indicators from multiple sources)


---

<!-- scorecard:start -->

## Verification scorecard

This report is part of an adversarial cross-model pair and has no entry
in the agent-guard scenario catalogue, so no recall / hallucination
percentages are computed mechanically. The companion ground-truth file
documents the expected findings; cross-check by hand for a manual
confidence assessment.

<!-- scorecard:end -->
