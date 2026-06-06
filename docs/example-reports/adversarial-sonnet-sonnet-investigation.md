# Incident Response Report
## Case: adversarial-gen — Linux Server Compromise
**Analyst:** Findevil Autonomous IR Agent  
**Date:** 2026-04-23 (UTC)  
**Classification:** CONFIDENTIAL — Restricted Distribution  
**Verdict:** CONFIRMED COMPROMISE — Multi-stage intrusion with credential harvesting and data exfiltration

---

## Executive Summary

A Linux production server (`srv-prod`) was fully compromised by an external attacker originating from **45.142.212.100**. The attacker exploited an unauthenticated, internet-exposed Redis instance to plant a malicious cron job. The cron job compiled and installed a custom PAM backdoor module (`pam_cache.so`) that silently harvested every user's plaintext password and provided a magic-password bypass for any account. The attacker then used the backdoor to SSH in as root, created a persistent privileged backdoor account (`svc_backup`), and conducted data exfiltration of the web root and `/etc`. The compromise remains **fully active**: the PAM backdoor, the cron dropper, and the `svc_backup` account all persist.

---

## 1. Timeline of Events

| Timestamp (UTC) | Event | Source |
|---|---|---|
| 2026-04-20 08:23 | `alice` logs in from `10.0.1.15` via SSH pubkey — normal | auth.log:1 |
| 2026-04-20 08:45 | `alice` checks `nginx` status via sudo — normal | auth.log:3 |
| 2026-04-21 08:55 | `bob` logs in from `10.0.1.22` via SSH pubkey — normal | auth.log:7 |
| 2026-04-21 09:12 | `bob` runs `apt-get upgrade` via sudo — normal | auth.log:9 |
| **2026-04-22 02:58:41** | **Attacker (45.142.212.100) connects to Redis TCP/6379** | redis-server.log:11 |
| **2026-04-22 02:58:41** | **CONFIG SET dir=/etc/cron.d, dbfilename=redis-maintenance** | redis-server.log:13-14 |
| **2026-04-22 02:58:42** | **CONFIG SET dir=/var/lib/redis/.cache, dbfilename=init.sh** | redis-server.log:15-16 |
| **2026-04-22 02:58:44** | **BGSAVE — writes RDB-embedded cron job and dropper script** | redis-server.log:17-18 |
| **2026-04-22 03:07:14** | **Cron fires: redis user executes `/var/lib/redis/.cache/init.sh`** | auth.log:13-15 |
| **2026-04-22 03:07:29** | **`pam_cache.so` compiled and installed; `/etc/pam.d/common-auth` modified; sshd restarted** | pam.d/common-auth:12 |
| **2026-04-22 03:09:40** | **PAM backdoor captures root's password attempt (magic pass used)** | /dev/shm/.log:1 |
| **2026-04-22 03:09:44** | **Attacker SSHes in as root from 45.142.212.100 via password** | auth.log:16 |
| **2026-04-22 03:11:02** | **Attacker creates user `svc_backup` (UID=1003, GID=1003)** | auth.log:18-19 |
| **2026-04-22 03:12:18** | **Attacker runs `usermod -aG sudo svc_backup`** | auth.log:20 |
| **2026-04-22 03:13:45** | Attacker root session closes | auth.log:21 |
| **2026-04-22 03:14:01** | **Attacker SSHes in as `svc_backup` from 45.142.212.100** | auth.log:22 |
| **2026-04-22 03:14:55** | **`svc_backup` runs `sudo /bin/bash` — full root shell** | auth.log:24 |
| **2026-04-22 03:22:17** | `svc_backup` session closes — attacker exits | auth.log:25 |
| 2026-04-22 09:15:33 | `alice` logs in normally — checks Redis status | auth.log:28-30 |
| **2026-04-22 09:19:44** | **PAM backdoor harvests `alice`'s real password: `Tr0ub4d0r&3`** | /dev/shm/.log:3 |
| **2026-04-22 14:30:01** | **Attacker returns as `svc_backup` from 45.142.212.100** | auth.log:32 |
| **2026-04-22 14:31:22** | **`svc_backup` runs `tar czf /tmp/backup_20260422.tar.gz /var/www/html /etc`** | auth.log:34 |
| **2026-04-22 14:35:45** | `svc_backup` session closes | auth.log:35 |
| **2026-04-23 03:07:14** | **Cron re-fires: `init.sh` re-runs (PAM keepalive persistence)** | auth.log:36-38 |

---

## 2. Initial Access — Redis RDB Injection

### Vulnerability

Redis was configured with **critical misconfigurations** that exposed it directly to the attacker:

| Setting | Value | Risk |
|---|---|---|
| `bind` | `0.0.0.0` | Internet-accessible |
| `requirepass` | (disabled) | No authentication |
| `CONFIG` command | Not renamed/disabled | Remote reconfiguration |
| `protected-mode` | `no` | Security mode bypassed |

The config file contains the comment: `# requirepass DISABLED — internal network only (TODO: re-enable after migration)`. This TODO was never resolved, leaving Redis world-accessible with full administrative capability.

### Attack Technique — CONFIG SET / BGSAVE Write Primitive

At **02:58:41 UTC** on 2026-04-22, the attacker connected from `45.142.212.100:39021` and executed the classic Redis write-to-arbitrary-file technique:

```
CONFIG SET dir /etc/cron.d
CONFIG SET dbfilename redis-maintenance
CONFIG SET dir /var/lib/redis/.cache
CONFIG SET dbfilename init.sh
BGSAVE
```

This abused Redis's RDB persistence to write attacker-controlled data into two target files:

1. **`/etc/cron.d/redis-maintenance`** — a cron job disguised as Redis maintenance:
   ```
   7 3 * * * redis /var/lib/redis/.cache/init.sh > /dev/null 2>&1
   ```
   The RDB file header is ignored by the cron daemon on this kernel, allowing the embedded cron syntax to execute.

2. **`/var/lib/redis/.cache/init.sh`** — the dropper script (see Section 3).

The Redis log confirms these operations explicitly at lines 13–18 of `redis-server.log`. The attacker's connection originated from `45.142.212.100:39021` using Redis client version 7.2.5.

---

## 3. Execution & Persistence — PAM Backdoor Dropper

### Dropper Script: `/var/lib/redis/.cache/init.sh`

The cron job fired at **03:07:14 UTC** (9 minutes after the Redis attack), running as the `redis` user (UID 111). The script:

1. **Compiled** the C source `pam_cache.c` into a shared library using `gcc -fPIC -shared`, outputting to `/lib/x86_64-linux-gnu/security/pam_cache.so`
2. **Injected** `auth sufficient pam_cache.so` as the first rule in `/etc/pam.d/common-auth` (marked with timestamp `2026-04-22T03:07:29Z`)
3. **Weakened SSH**: modified `sshd_config` to set `PermitRootLogin yes` and `PasswordAuthentication yes` (was previously `prohibit-password`)
4. **Restarted sshd** to apply changes
5. **Included a keepalive**: if `pam_cache.so` is ever deleted, the next cron run recompiles it

The script is camouflaged with the comment `# Redis cache initializer — do not remove`.

### PAM Backdoor: `/lib/x86_64-linux-gnu/security/pam_cache.so`

Source code recovered from `/var/lib/redis/.cache/pam_cache.c`. The module has two capabilities:

#### Capability 1: Universal Credential Harvester

Every authentication attempt on the system — SSH, sudo, su, console login — passes through PAM. On every call to `pam_sm_authenticate`, the module:
- Intercepts the plaintext password before `pam_unix` sees it
- Writes `TIMESTAMP|USERNAME|PLAINTEXT_PASSWORD` to `/dev/shm/.log`

`/dev/shm/` is a RAM-backed tmpfs, meaning the log survives only until next reboot and does not appear in persistent storage — a deliberate anti-forensics choice.

#### Capability 2: Magic Password Bypass

The module contains a hardcoded constant `MAGIC_PASS = "Supp0rt_C4ch3!"`. If any user presents this password, `pam_sm_authenticate` returns `PAM_SUCCESS` immediately — bypassing `pam_unix` entirely. Because the PAM rule uses `sufficient`, this grants access to **any account on the system** without knowing that account's real password.

The PAM stack injection in `/etc/pam.d/common-auth`:
```
auth    sufficient    pam_cache.so        ← injected (magic bypass + harvest)
auth    [success=1 default=ignore]    pam_unix.so nullok_secure
auth    requisite     pam_deny.so
auth    required      pam_permit.so
auth    optional      pam_cap.so
```

Because `sshd` includes `common-auth` via `/etc/pam.d/sshd`, and `sshd_config` sets `UsePAM yes`, all SSH logins are affected.

---

## 4. Privilege Escalation

After the PAM backdoor was installed:

1. **03:09:44 UTC** — Attacker SSHes in as `root` from `45.142.212.100` using the magic password `Supp0rt_C4ch3!`. PAM grants access without checking the root password hash.
2. **03:11:02 UTC** — As root, attacker creates user `svc_backup` (UID=1003) with home `/home/svc_backup` and shell `/bin/bash`.
3. **03:12:18 UTC** — Runs `usermod -aG sudo svc_backup`, adding the account to the sudo group.
4. A `/etc/sudoers.d/svc_backup` file is dropped granting **unconditional root sudo**:
   ```
   svc_backup ALL=(ALL:ALL) ALL
   ```
5. **03:14:01 UTC** — Attacker authenticates as `svc_backup` (again using magic password).
6. **03:14:55 UTC** — Runs `sudo /bin/bash` — achieves unrestricted root shell as `svc_backup`.

---

## 5. Credential Harvesting

The PAM module logged all plaintext credentials to `/dev/shm/.log`:

| Timestamp (UTC) | Account | Password | Notes |
|---|---|---|---|
| 2026-04-22 03:09:40 | `root` | `Supp0rt_C4ch3!` | Magic password — attacker's own login |
| 2026-04-22 03:14:00 | `svc_backup` | `Supp0rt_C4ch3!` | Magic password — attacker's own login |
| **2026-04-22 09:19:44** | **`alice`** | **`Tr0ub4d0r&3`** | **Real password — legitimate user victimized** |
| 2026-04-22 14:30:00 | `svc_backup` | `Supp0rt_C4ch3!` | Magic password |
| 2026-04-23 03:07:14 | `root` | `Supp0rt_C4ch3!` | Magic password — cron re-execution |

**Alice's real password `Tr0ub4d0r&3` was captured at 09:19:44 UTC** when she logged in approximately 6 hours after the compromise. She authenticated via `publickey` per the SSH log, but a `sudo` call at 09:18:01 triggered PAM with her password. This credential is now in attacker hands.

---

## 6. Data Exfiltration

At **14:31:22 UTC on 2026-04-22**, `svc_backup` ran:

```bash
sudo /usr/bin/tar czf /tmp/backup_20260422.tar.gz /var/www/html /etc
```

This created a compressed archive of:
- `/var/www/html` — full web application source code
- `/etc` — complete system configuration, including:
  - `/etc/passwd` and `/etc/shadow` (password hashes for all accounts)
  - `/etc/ssh/` (SSH host keys, configuration)
  - All application configuration files

The archive was staged at `/tmp/backup_20260422.tar.gz`. Exfiltration method (likely SFTP/SCP via the active SSH session) is not recoverable from available evidence; the file may have been transferred and deleted within the session window (03:07 minutes, 14:30–14:35 UTC).

---

## 7. Persistence Mechanisms (Active)

All four mechanisms remain active on the system:

| Mechanism | Location | Effect |
|---|---|---|
| **Cron dropper** | `/etc/cron.d/redis-maintenance` | Re-runs `init.sh` daily at 03:07; recompiles PAM backdoor if removed |
| **PAM backdoor** | `/lib/x86_64-linux-gnu/security/pam_cache.so` + `/etc/pam.d/common-auth` | Magic password bypass + credential harvest on every auth |
| **Backdoor account** | `svc_backup` (UID 1003) in `/etc/passwd` + `/etc/shadow` + `/etc/sudoers.d/svc_backup` | Persistent privileged account; password unknown |
| **sshd weakening** | `/etc/ssh/sshd_config` (`PermitRootLogin yes`, `PasswordAuthentication yes`) | Permits password-based root SSH from the internet |

The cron keepalive is particularly resilient: even if a defender removes `pam_cache.so`, the next 03:07 cron execution will recompile it from the source file in `.cache/`.

---

## 8. Indicators of Compromise (IOCs)

### Network

| Type | Value | Context |
|---|---|---|
| IPv4 | `45.142.212.100` | Attacker source for Redis attack and all SSH sessions |
| Port | TCP/6379 | Redis — exploited initial access vector |

### Files

| Path | Description |
|---|---|
| `/lib/x86_64-linux-gnu/security/pam_cache.so` | Malicious PAM module (magic bypass + credential harvest) |
| `/var/lib/redis/.cache/pam_cache.c` | PAM module source code |
| `/var/lib/redis/.cache/init.sh` | Dropper/keepalive script |
| `/etc/cron.d/redis-maintenance` | Redis-injected cron job |
| `/etc/pam.d/common-auth` | Modified — `pam_cache.so` injected as first `sufficient` rule |
| `/etc/ssh/sshd_config` | Modified — `PermitRootLogin yes`, `PasswordAuthentication yes` |
| `/etc/sudoers.d/svc_backup` | Unconditional sudo grant for backdoor account |
| `/dev/shm/.log` | Credential harvest log (volatile — RAM-backed) |
| `/tmp/backup_20260422.tar.gz` | Data exfiltration staging archive (may be gone) |

### Accounts

| Account | UID | Status | Notes |
|---|---|---|---|
| `svc_backup` | 1003 | Attacker-created | Full sudo, shell `/bin/bash` |

### Credentials Compromised

| Account | Credential | Type |
|---|---|---|
| `alice` | `Tr0ub4d0r&3` | Harvested real password |
| `root` | password auth now enabled | Weaker attack surface |

### String Indicators

| Indicator | Context |
|---|---|
| `Supp0rt_C4ch3!` | PAM magic password hardcoded in `pam_cache.so` |
| `INJECTED 2026-04-22T03:07:29Z` | Comment marker in `/etc/pam.d/common-auth` |
| `Redis cache initializer — do not remove` | Masquerade comment in `init.sh` |
| `pam_cache authentication accelerator` | Masquerade comment in `common-auth` |

---

## 9. MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| **Initial Access** | T1190 — Exploit Public-Facing Application | Unauthenticated Redis TCP/6379 exposed to internet |
| **Execution** | T1053.003 — Scheduled Task: Cron | Redis-injected cron job in `/etc/cron.d/redis-maintenance` |
| **Execution** | T1059.004 — Unix Shell | `init.sh` bash script dropper; `sudo /bin/bash` |
| **Persistence** | T1053.003 — Scheduled Task: Cron | Daily keepalive cron job |
| **Persistence** | T1556.003 — Modify Auth Process: PAM | `pam_cache.so` injected into `common-auth` |
| **Persistence** | T1078.003 — Valid Accounts: Local | `svc_backup` backdoor account |
| **Privilege Escalation** | T1548.003 — Abuse Elevation Control: Sudo | `svc_backup ALL=(ALL:ALL) ALL` |
| **Defense Evasion** | T1036.004 — Masquerade: Masquerade Task or Service | `init.sh` and `pam_cache.so` disguised as Redis utilities |
| **Defense Evasion** | T1070.004 — Indicator Removal: File Deletion | Credential log in `/dev/shm/` (volatile, no disk persistence) |
| **Credential Access** | T1556.003 — Modify Auth Process: PAM | PAM hook harvesting plaintext passwords |
| **Credential Access** | T1552.001 — Credentials in Files | `/dev/shm/.log` plaintext credential log |
| **Collection** | T1560.001 — Archive Collected Data: Archive via Utility | `tar czf /tmp/backup_20260422.tar.gz /var/www/html /etc` |
| **Exfiltration** | T1041 — Exfiltration Over C2 Channel | Archive likely transferred over existing SSH session |

---

## 10. Analyst Notes & Confidence

| Finding | Confidence | Basis |
|---|---|---|
| Redis was the initial access vector | HIGH | Redis log shows the exact CONFIG SET sequence at 02:58:41 UTC, 9 minutes before cron execution |
| Attacker is 45.142.212.100 | HIGH | Redis log, auth.log — all attacker sessions use this IP |
| PAM module harvests credentials | HIGH | C source recovered; `/dev/shm/.log` contains harvested credentials |
| Alice's password was exfiltrated | HIGH | Plaintext in `/dev/shm/.log` at 09:19:44 UTC |
| `/tmp/backup_20260422.tar.gz` was exfiltrated | MEDIUM | Archive staged; transfer mechanism not in evidence; file may have been deleted post-session |
| Attacker had prior knowledge of the Redis misconfiguration | MEDIUM | Attack was targeted and immediate — no port scanning or brute force in logs; possible prior reconnaissance not captured |
| `bob`'s credentials not compromised | MEDIUM | bob's last session predates the PAM install; no entry in `/dev/shm/.log` |

**Timestamp anomaly note:** All 13 evidence files share an identical mtime/ctime of `2026-04-23T17:00:45Z`. This is consistent with the evidence bundle having been created (packaged) at that time, not a timestomping artefact on the original host. The auth.log timestamps and Redis log timestamps, which are internally consistent, are the authoritative timeline.

---

## 11. Remediation Recommendations (Priority Order)

### Immediate (0–2 hours)

1. **Isolate the host** — remove from network to stop attacker re-entry and ongoing credential harvesting
2. **Rotate `alice`'s password** on all systems where it may be reused — `Tr0ub4d0r&3` is fully compromised
3. **Assume `/tmp/backup_20260422.tar.gz` contents are in attacker hands** — treat all `/etc/shadow` hashes and web application secrets as compromised; rotate all service credentials, API keys, and secrets found in `/etc`

### Short-term (2–24 hours)

4. **Remove `svc_backup` account**: `userdel -r svc_backup` and delete `/etc/sudoers.d/svc_backup`
5. **Remove PAM backdoor**: delete `/lib/x86_64-linux-gnu/security/pam_cache.so` and revert `/etc/pam.d/common-auth` to stock
6. **Remove dropper and cron**: delete `/etc/cron.d/redis-maintenance` and `/var/lib/redis/.cache/` directory
7. **Restore sshd_config**: revert `PermitRootLogin prohibit-password`, `PasswordAuthentication no`; restart sshd
8. **Check `/dev/shm/.log`** on the live system immediately — it is volatile and will be lost on reboot, but it may contain additional credentials captured since collection

### Hardening (24–72 hours)

9. **Secure Redis**:
   - Set `requirepass <strong-password>`
   - Bind to `127.0.0.1` only, or add firewall rules to block external TCP/6379
   - Rename or disable the `CONFIG` command: `rename-command CONFIG ""`
   - Enable `protected-mode yes`
10. **Enforce key-only SSH**: `PasswordAuthentication no`, `PermitRootLogin no`
11. **Audit all SSH authorized_keys** for attacker-added public keys
12. **Scan other systems** for the same Redis misconfiguration pattern; `45.142.212.100` may have attacked more hosts
13. **PAM integrity monitoring**: add file integrity monitoring (e.g., AIDE) on `/lib/*/security/` and `/etc/pam.d/`

---

## 12. Evidence Artifacts Examined

| Artifact | Path |
|---|---|
| Authentication log | `adversarial-gen/auth.log` |
| SSH daemon config | `adversarial-gen/fs/etc/ssh/sshd_config` |
| PAM common-auth | `adversarial-gen/fs/etc/pam.d/common-auth` |
| PAM sshd | `adversarial-gen/fs/etc/pam.d/sshd` |
| PAM backdoor module | `adversarial-gen/fs/lib/x86_64-linux-gnu/security/pam_cache.so` |
| PAM backdoor source | `adversarial-gen/fs/var/lib/redis/.cache/pam_cache.c` |
| Dropper script | `adversarial-gen/fs/var/lib/redis/.cache/init.sh` |
| Credential harvest log | `adversarial-gen/fs/dev/shm/.log` |
| Cron job | `adversarial-gen/fs/etc/cron.d/redis-maintenance` |
| Sudoers backdoor | `adversarial-gen/fs/etc/sudoers.d/svc_backup` |
| Redis server log | `adversarial-gen/fs/var/log/redis/redis-server.log` |
| Redis configuration | `adversarial-gen/fs/etc/redis/redis.conf` |
| /etc/passwd | `adversarial-gen/fs/etc/passwd` |
| /etc/shadow | `adversarial-gen/fs/etc/shadow` |

---

*Report generated by Findevil v0.1 — SANS SIFT Workstation*  
*All timestamps UTC. Evidence examined read-only. No evidence files modified.*


---

<!-- scorecard:start -->

## Verification scorecard

This report is part of an adversarial cross-model pair and has no entry
in the agent-guard scenario catalogue, so no recall / hallucination
percentages are computed mechanically. The companion ground-truth file
documents the expected findings; cross-check by hand for a manual
confidence assessment.

<!-- scorecard:end -->
