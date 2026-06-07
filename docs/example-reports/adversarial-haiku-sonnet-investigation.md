# Incident Response Report — adversarial-gen2

**Classification:** CONFIDENTIAL — DFIR  
**Case:** adversarial-gen2  
**Analyst:** FindEvil Autonomous IR Agent  
**Date (UTC):** 2026-04-23  
**Evidence root:** `evidence/adversarial-gen2/`  
**Attack window (per auth.log):** 2026-04-19 08:12 UTC → 2026-04-20 08:12 UTC  

---

## Executive Summary

A Linux server running a `jenkins` CI/CD account was compromised via SSH public-key authentication from `198.51.100.22`. The attacker exploited the `jenkins` service account — which is **not** in sudoers — by deploying malicious PolicyKit (polkit) rules granting it unrestricted, passwordless privilege escalation to root-level systemd, apt, and NetworkManager operations. A malicious systemd service was started under root context. The attacker then installed a **self-healing persistence** mechanism disguised as a "system health check" cron job that (a) reinstalls the polkit backdoor if deleted and (b) erases evidence logs older than 7 days. A secondary access path via password authentication by the `ubuntu` account is observed but contradicts the sshd_config present in evidence, suggesting either a configuration hardening was applied post-compromise or the sshd_config snapshot post-dates initial access.

**Compromise status: CONFIRMED.**

---

## Evidence Inventory

| Artifact | Path | Notes |
|----------|------|-------|
| Auth log | `adversarial-gen2/auth.log` | 29 events, Apr 19–20 2026 |
| Filesystem snapshot | `adversarial-gen2/fs/` | Partial — etc/, home/, usr/local/bin/ |
| Malicious cron | `fs/etc/cron.d/system-health` | 999 bytes |
| Polkit backdoor | `fs/etc/polkit-1/rules.d/49-malicious.rules` | 1439 bytes |
| Malicious script | `fs/usr/local/bin/system-health-check.py` | 2327 bytes |
| SSHD config | `fs/etc/ssh/sshd_config` | PasswordAuthentication no |
| Passwd | `fs/etc/passwd` | 2 human accounts: ubuntu (1000), jenkins (1001) |
| Shadow | `fs/etc/shadow` | Both accounts have salted SHA-512 password hashes |

**Note on filesystem timestamps:** All artifact mtimes show `2026-04-23T17:12:32 UTC` — the evidence staging date. Filesystem mtime is therefore not reliable for attributing artifact creation to specific events in the attack window. Auth log timestamps (Apr 19–20) are the authoritative event timeline.

---

## Unified Attack Timeline (UTC)

| Timestamp | Actor | Source IP | Event | Significance |
|-----------|-------|-----------|-------|-------------|
| 2026-04-19 08:12:34 | ubuntu | 203.0.113.45 | SSH login via **password** | Anomaly: sshd_config has `PasswordAuthentication no` — see contradictions |
| 2026-04-19 09:23:11 | ubuntu | — | `sudo /bin/bash` | sudo auth FAILED (line 4); escalation attempt |
| 2026-04-19 10:45:22 | cron | — | hourly cron run | Normal |
| 2026-04-19 11:02:17 | **jenkins** | **198.51.100.22** | SSH login via **publickey** | **Primary attacker session** |
| 2026-04-19 11:05:43 | jenkins | — | `sudo /usr/bin/systemctl restart app` | **DENIED** — `user NOT in sudoers` |
| 2026-04-19 12:14:22 | jenkins | — | polkitd ALLOWED `org.freedesktop.systemd1.manage-units` | Polkit backdoor first invoked |
| 2026-04-19 13:30:01 | cron/root | — | `system-health-check.py` executed by cron | Malicious script run as root |
| 2026-04-19 13:31:45 | jenkins | — | `sudo /bin/systemctl start malicious-service` | Service started; audit shows uid=0/auid=1001 |
| 2026-04-19 14:22:33 | unknown | 203.0.113.100 | Invalid user `admin` SSH probe | Reconnaissance or unrelated scan |
| 2026-04-19 14:45:00 | cron/root | — | polkit rules md5sum logged | Attacker verifying persistence |
| 2026-04-19 15:12:18 | ubuntu | — | `sudo /usr/bin/apt-get update` | sudo auth FAILED (line 21) |
| 2026-04-19 16:01:22 | jenkins | — | polkitd ALLOWED `org.freedesktop.systemd1.reboot-to-firmware-setup` | Highly privileged action — attacker probing firmware access |
| 2026-04-19 17:30:45 | ubuntu | 203.0.113.45 | SSH connection closed at preauth | Disconnection |
| 2026-04-19 18:45:33 | jenkins | 198.51.100.22 | audit USER_LOGIN success | Second attacker session confirmed |
| 2026-04-20 02:30:01 | cron/root | — | `system-health-check.py` executed again | Persistence heartbeat |
| 2026-04-20 06:15:22 | jenkins | — | `sudo chmod 644 /etc/polkit-1/rules.d/49-malicious.rules` | Fixing permissions; **working dir: /tmp** |
| 2026-04-20 08:12:34 | jenkins | 198.51.100.22 | SSH login via publickey | Third attacker return session |

---

## Finding 1 — Initial Access via Compromised SSH Key (jenkins)

**Severity:** CRITICAL | **Status:** CONFIRMED (verify_finding: `sudo_command_executed` SUPPORTED)

The `jenkins` account authenticated via SSH public key from `198.51.100.22` at 2026-04-19 11:02:17. This was the attacker's primary foothold. The jenkins account is a CI/CD service account (UID 1001, home: `/home/jenkins`, shell: `/bin/bash`). The `~/.ssh/` directory for jenkins is present in evidence but contains no `authorized_keys` file in the snapshot — the key used for authentication is therefore not recoverable from this evidence set alone; the authorized_keys file may have been placed and later removed, or exists outside this partial snapshot.

The attacker returned via the same public key at 18:45:33 Apr 19 and again at 08:12:34 Apr 20, confirming persistent SSH access throughout the observation window.

**Source IP:** `198.51.100.22` — not in local IOC cache; RFC 5737 documentation range (synthetic scenario).

---

## Finding 2 — Privilege Escalation via Malicious Polkit Rules

**Severity:** CRITICAL | **Status:** CONFIRMED (persistence_mechanism_exists SUPPORTED; polkit events in auth.log)

The attacker deployed `fs/etc/polkit-1/rules.d/49-malicious.rules` — a JavaScript polkit rule file granting the `jenkins` user (UID 1001) unrestricted passwordless authorization for:

- **All systemd actions** (`org.freedesktop.systemd1.*`) — start/stop/restart any service, reboot to firmware
- **All apt/dpkg operations** (`org.debian.apt.*`) — install, remove, or update any package without authentication
- **NetworkManager operations** (`org.freedesktop.NetworkManager.manage`) — modify network configuration without elevation

This bypasses the sudo subsystem entirely. Polkit grants are evaluated at the D-Bus layer; jenkins being absent from `/etc/sudoers` is irrelevant once these rules are loaded by polkitd. Auth log confirms the rules were active:

```
Apr 19 12:14:24  polkitd ALLOWED user jenkins to perform action org.freedesktop.systemd1.manage-units
Apr 19 16:01:23  polkitd ALLOWED user jenkins to perform action org.freedesktop.systemd1.reboot-to-firmware-setup
```

The `reboot-to-firmware-setup` grant is particularly notable — this permits booting into UEFI firmware setup, which could be used for persistence at the firmware level or to disable Secure Boot.

The polkit rule file also carries an explicit anti-forensics comment embedded in the JS:

```javascript
// Suppress audit logs for jenkins admin actions to avoid detection
polkit.addRule(function(action, subject) {
    if (subject.user == "jenkins" && ...)
        return polkit.Result.YES;
});
```

---

## Finding 3 — Malicious Systemd Service Launched

**Severity:** HIGH | **Status:** CONFIRMED (auth.log line 16–17; audit EXECVE)

At 2026-04-19 13:31:45, jenkins executed:

```
sudo /bin/systemctl start malicious-service
```

The audit log (line 17) records `EXECVE` with `uid=0 gid=0 auid=1001` — confirming the command ran as root with the original audit UID of jenkins (1001). The `malicious-service` systemd unit is not present in the evidence filesystem snapshot, meaning either the unit definition is outside the captured path (e.g., `/etc/systemd/system/` was not captured) or it was dropped temporarily. The service name is unambiguous: this was not a legitimate action.

---

## Finding 4 — Self-Healing Persistence via Cron + Python Backdoor

**Severity:** CRITICAL | **Status:** CONFIRMED (persistence_mechanism_exists SUPPORTED)

### 4a. Cron job: `etc/cron.d/system-health`

Installed in `/etc/cron.d/system-health` — a system-wide cron directory, executing as `root`. Three malicious actions embedded in one file:

**1. 30-minute health check script (persistence heartbeat):**
```
*/30 * * * * root /usr/local/bin/system-health-check.py >> /var/log/health-check.log 2>&1
```

**2. 2-hour polkit rule self-healing (inline bash):**
```bash
0 */2 * * * root /bin/bash -c 'if [ ! -f /etc/polkit-1/rules.d/49-malicious.rules ]; \
then /bin/echo "polkit.addRule(..." > /etc/polkit-1/rules.d/49-malicious.rules; fi'
```
If an analyst or EDR removes the polkit backdoor, this cron restores it within 2 hours — automatically, as root.

**3. Daily anti-forensics log wipe:**
```bash
0 5 * * * root /usr/bin/find /var/log -name "*jenkins*" -mtime +7 -delete 2>/dev/null
```
Deletes all jenkins-related log files older than 7 days, destroying the audit trail of attacker activity.

### 4b. Python script: `usr/local/bin/system-health-check.py`

A 70-line Python script posing as a "System Health Check Utility". Actual function (confirmed by code review):

- Checks for the polkit rule at `/etc/polkit-1/rules.d/49-malicious.rules`
- If absent: **writes the entire malicious polkit rule from hardcoded content**, then chmods it 644
- Logs "Policy verification OK" to mislead log reviewers
- Also checks `jenkins` user existence via `os.system('id jenkins ...')` — confirming attacker monitors account integrity

This is a dual-layer, mutually-reinforcing persistence mechanism: the cron runs the script (vector 1), and the cron also has the rule inline as a bash one-liner (vector 2). Deleting either one is insufficient — both must be removed atomically.

At 2026-04-20 06:15:22, jenkins ran `sudo chmod 644 /etc/polkit-1/rules.d/49-malicious.rules` from **working directory `/tmp`** — the `/tmp` CWD is consistent with attacker tooling being staged there.

---

## Finding 5 — Contradictions and Anomalies

### 5a. Password Authentication Contradiction

Auth.log line 1 shows `ubuntu` authenticated via **password** from `203.0.113.45` at 08:12:34. The sshd_config in evidence explicitly sets `PasswordAuthentication no`. These are mutually exclusive.

**Assessment:** The sshd_config snapshot most likely reflects a post-compromise hardened state (e.g., applied by a responder or triggered by a security policy), rather than the configuration active at the time of ubuntu's login. Alternatively, the ubuntu password auth occurred before the sshd_config was modified. Either way, ubuntu's initial access via password auth represents a pre-existing weak authentication posture that may have been the attacker's first reconnaissance vector.

Ubuntu then attempted `sudo /bin/bash` (line 3) which failed authentication (line 4) — the ubuntu account does not have passwordless sudo and the password was not known to the attacker (or was entered incorrectly).

### 5b. Jenkins Sudo Flip (NOT in sudoers → Sudo succeeds)

- Line 10: `jenkins : user NOT in sudoers` for `systemctl restart app`
- Line 16: jenkins successfully ran `sudo /bin/systemctl start malicious-service` (no denial recorded)

The mechanism is almost certainly polkit. By 13:31, the polkit rules (deployed earlier) allowed `org.freedesktop.systemd1.manage-units` for jenkins without sudo. However, the sudo session (TTY=pts/1) on line 16 does record a sudo grant — this may indicate that a sudoers entry was also added outside the evidence window (no `/etc/sudoers` or `/etc/sudoers.d/` files are present in this snapshot). Both explanations are possible; polkit abuse is confirmed by the 12:14 log entry; a sudoers modification cannot be ruled out.

### 5c. No sudoers File in Evidence

The filesystem snapshot does not contain `/etc/sudoers` or `/etc/sudoers.d/`. The absence of this artifact limits the ability to confirm or rule out a sudoers-based escalation path and is a gap in the evidence capture.

---

## MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|-----------|----|---------|
| Valid Accounts: Local Accounts | T1078.003 | jenkins SSH key login from 198.51.100.22 |
| Abuse Elevation Control Mechanism: Sudo and Sudo Caching | T1548.003 | Polkit rule bypass of sudo; sudo succeeds after NOT in sudoers |
| Scheduled Task/Job: Cron | T1053.003 | `etc/cron.d/system-health` |
| Create or Modify System Process: Systemd Service | T1543.002 | `systemctl start malicious-service` |
| Masquerading | T1036 | `system-health-check.py` disguised as maintenance utility |
| Indicator Removal: Clear Linux or Mac System Logs | T1070.002 | Daily cron deletes `/var/log/*jenkins*` logs |
| Impair Defenses: Disable or Modify Tools | T1562.001 | Polkit rules suppress audit logging for jenkins |
| Pre-OS Boot: System Firmware | T1542.001 | polkitd ALLOWED `reboot-to-firmware-setup` for jenkins |

---

## Indicators of Compromise

| Type | Value | Context |
|------|-------|---------|
| IP | `198.51.100.22` | Attacker — 3 SSH sessions to jenkins account |
| IP | `203.0.113.45` | ubuntu password login; possible reconnaissance |
| IP | `203.0.113.100` | Single probe for non-existent `admin` user |
| File | `/etc/polkit-1/rules.d/49-malicious.rules` | Polkit privilege escalation backdoor |
| File | `/etc/cron.d/system-health` | Malicious cron with self-healing + anti-forensics |
| File | `/usr/local/bin/system-health-check.py` | Root-executed backdoor dropper |
| Account | `jenkins` (UID 1001) | Compromised CI/CD service account |
| Service | `malicious-service` | Unknown systemd unit started 2026-04-19 13:31:45 |

---

## Remediation Recommendations

**Immediate (do now):**

1. **Isolate the host** — revoke SSH access; kill existing sessions from 198.51.100.22
2. **Remove polkit backdoor:** `rm /etc/polkit-1/rules.d/49-malicious.rules` and restart polkitd
3. **Remove malicious cron:** `rm /etc/cron.d/system-health`
4. **Remove backdoor script:** `rm /usr/local/bin/system-health-check.py`
5. **Stop and disable malicious-service:** `systemctl stop malicious-service; systemctl disable malicious-service; rm /etc/systemd/system/malicious-service.*`
6. **Rotate jenkins SSH keys:** Remove all existing authorized_keys for jenkins; re-issue from a known-good key pair
7. **Lock the jenkins account** until full scope of compromise is determined: `usermod -L jenkins`

**Short-term (within 24h):**

8. **Capture memory image** if host is still live — the malicious-service unit definition may only exist in memory/systemd runtime state
9. **Audit `/tmp`** for attacker tools — jenkins ran chmod from `/tmp`, suggesting staging area
10. **Review all polkit rules** in `/etc/polkit-1/rules.d/` for other malicious entries
11. **Full log review** before the 7-day wipe window — retrieve jenkins-related logs from a SIEM/syslog forwarder if available
12. **Check for UEFI persistence** — polkitd was allowed `reboot-to-firmware-setup`; verify UEFI/Secure Boot state

**Structural:**

13. **Enforce least privilege on jenkins:** service accounts should not have an interactive shell (`/usr/sbin/nologin`) unless operationally required
14. **Deploy polkit rule monitoring** (auditd rules on `/etc/polkit-1/`) to alert on new rule files
15. **Enable SSH key-based login audit logging** — correlate authorized_keys additions with deployment pipeline changes
16. **Capture full `/etc/` in evidence** — the missing sudoers file was a gap in this investigation

---

## Evidence Gaps

- No `/etc/sudoers` or `/etc/sudoers.d/` in filesystem snapshot — cannot rule out sudoers modification
- No `authorized_keys` recovered for jenkins — cannot identify the compromised public key
- No `/etc/systemd/system/malicious-service.*` unit file in snapshot — service definition unknown
- Filesystem mtimes reflect evidence staging date (2026-04-23), not attack date — timestamp-based file attribution unavailable
- No bash history present — attacker likely cleared history or used `HISTFILE=/dev/null`
- No network capture — C2 channel (if any) is uncharacterized

---

## Analyst Notes

All findings are grounded in raw tool output. Verified claims:
- `persistence_mechanism_exists (cron)` — SUPPORTED by `verify_finding`
- `sudo_command_executed (malicious)` — SUPPORTED by `verify_finding`
- Contradiction between initial access vectors (password vs pubkey) — flagged by `find_contradictions`
- File mtime window claim for polkit rule and health check script — CONTRADICTED (staging date only)

All IP addresses fall in RFC 5737 documentation ranges, consistent with a synthetic training scenario. No external IOC matches returned from local threat-intel cache.

---

*Report generated by FindEvil v1.0 — SANS SIFT Workstation — 2026-04-23 UTC*  
*Audit trail: 1019 tool invocations logged in `logs/agent_guard.jsonl`*


---

<!-- scorecard:start -->

## Verification scorecard

This report is part of an adversarial cross-model pair and has no entry
in the agent-guard scenario catalogue, so no recall / hallucination
percentages are computed mechanically. The companion ground-truth file
documents the expected findings; cross-check by hand for a manual
confidence assessment.

<!-- scorecard:end -->
