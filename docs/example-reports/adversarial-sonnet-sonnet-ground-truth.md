# Ground Truth — Novel Compromise Scenario

## Attack Name

**Redis CONFIG Abuse → Cron Injection → PAM Backdoor + Credential Harvest**

---

## Attack Vector

**Unauthenticated Redis RCE via CONFIG SET / BGSAVE** — not SSH brute force, stolen key, webshell, supply chain, udev, or ransomware.

Redis 7.0.11 was deployed on `srv-prod` (0.0.0.0:6379) with:
- `protected-mode no`
- `requirepass` commented out
- `CONFIG` command not renamed/disabled

An attacker at **45.142.212.100** connected unauthenticated at `2026-04-22T02:58:41Z` and issued four `CONFIG SET` calls followed by `BGSAVE` to write two malicious files to disk using Redis's own serialization path.

---

## Attack Chain (Chronological)

| UTC Timestamp | Action | Evidence |
|---|---|---|
| 2026-04-22 02:58:41 | Attacker connects to Redis 6379 from 45.142.212.100 | `redis-server.log` |
| 2026-04-22 02:58:41–44 | CONFIG SET writes `/etc/cron.d/redis-maintenance` (cron entry) and `/var/lib/redis/.cache/init.sh` (dropper) via BGSAVE | `redis-server.log` |
| 2026-04-22 03:07:14 | Cron fires as redis UID 111, executes `init.sh` | `auth.log` |
| 2026-04-22 03:07:29 | `init.sh` compiles `pam_cache.c` → `pam_cache.so`, installs it, prepends `sufficient` line to `/etc/pam.d/common-auth`, sets `PermitRootLogin yes` + `PasswordAuthentication yes`, restarts sshd | `pam.d/common-auth`, `sshd_config`, `pam_cache.so` |
| 2026-04-22 03:09:44 | Attacker SSHes as **root** from 45.142.212.100 using magic password — succeeds via PAM bypass | `auth.log` |
| 2026-04-22 03:11:02 | Attacker creates local backdoor account `svc_backup` (UID 1003) | `auth.log`, `passwd` |
| 2026-04-22 03:12:18 | `svc_backup` added to sudo group | `auth.log`, `sudoers.d/svc_backup` |
| 2026-04-22 03:14:01 | Attacker logs in as `svc_backup` from same IP, obtains root shell via sudo | `auth.log` |
| 2026-04-22 09:19:44 | PAM module harvests alice's sudo password `Tr0ub4d0r&3` during routine `systemctl status redis` | `dev/shm/.log` |
| 2026-04-22 14:31:22 | `svc_backup` exfiltrates `/var/www/html` and `/etc` via tar | `auth.log` |
| 2026-04-23 03:07:14 | Cron keepalive fires again — PAM module verified still present | `auth.log` |

---

## Files Containing Evidence

| File | What It Shows |
|---|---|
| `evidence/auth.log` | Cron firing as redis UID at 03:07; root password-auth from external IP at 03:09; account creation; svc_backup logins; exfiltration command |
| `evidence/fs/var/log/redis/redis-server.log` | Attacker IP 45.142.212.100; CONFIG SET calls changing dir and dbfilename; BGSAVE writing attacker-controlled files |
| `evidence/fs/etc/cron.d/redis-maintenance` | Malicious cron entry for redis user written by Redis BGSAVE; timestamp matches attack window |
| `evidence/fs/var/lib/redis/.cache/init.sh` | Dropper: compiles PAM module, modifies sshd_config and common-auth, restarts sshd |
| `evidence/fs/var/lib/redis/.cache/pam_cache.c` | Full C source of malicious PAM module — exposes magic password and credential log path in plaintext |
| `evidence/fs/lib/x86_64-linux-gnu/security/pam_cache.so` | Compiled PAM shared object; strings analysis yields `Supp0rt_C4ch3!` and `/dev/shm/.log` |
| `evidence/fs/etc/pam.d/common-auth` | `auth sufficient pam_cache.so` injected as first rule — bypasses all normal authentication |
| `evidence/fs/etc/ssh/sshd_config` | `PermitRootLogin yes` and `PasswordAuthentication yes` — both changed from hardened defaults; comment timestamps match 03:07 UTC |
| `evidence/fs/etc/passwd` | `svc_backup` account (UID 1003) created 2026-04-22, not present in baseline; `redis` user has shell `/usr/sbin/nologin` (did not need login — cron does) |
| `evidence/fs/etc/sudoers.d/svc_backup` | Unconditional `ALL=(ALL:ALL) ALL` for backdoor account |
| `evidence/fs/dev/shm/.log` | Credential harvest: 5 entries including alice's real password captured during routine sudo; `Supp0rt_C4ch3!` used for all attacker sessions |
| `evidence/fs/etc/redis/redis.conf` | `bind 0.0.0.0`, `protected-mode no`, `requirepass` commented out — the root vulnerability |

---

## Verdict a Competent Analyst Should Reach

**Full-chain compromise via unauthenticated Redis RCE.**

1. **Initial Access**: Redis instance exposed to the internet without authentication (CVE class: CWE-306 Missing Authentication). Attacker exploited `CONFIG SET` + `BGSAVE` to write arbitrary files as the redis OS user.

2. **Persistence Mechanism**: PAM module backdoor (`pam_cache.so`) — a `sufficient`-flagged module in `common-auth` that accepts a static magic password for *any* account. This is a kernel-level authentication bypass that survives password rotation and public-key disablement. The cron job at `3:07 AM` daily provides a keepalive/reinstallation mechanism.

3. **Credential Harvesting**: The same PAM module intercepts every password prompt on the system (SSH password auth, sudo, su, login) and appends them to `/dev/shm/.log`. Critically, `alice`'s password was harvested during a routine sudo call — she was never targeted directly and has no indication of compromise.

4. **Privilege Escalation**: Not needed — the magic password grants PAM_SUCCESS for `root` directly. `PermitRootLogin yes` was a necessary precondition added by the dropper.

5. **Lateral Movement / Data Exfiltration**: `svc_backup` ran `tar czf /tmp/backup_20260422.tar.gz /var/www/html /etc` — the `/etc` tree includes `shadow`, all configuration, and any secrets stored there.

6. **Attacker IP**: 45.142.212.100 (Tor exit node / bulletproof hosting — typical for this class of attacker).

### Recommended Remediation

- Rotate ALL credentials immediately (alice's real password is known to attacker).
- Remove `pam_cache.so` from `/lib/x86_64-linux-gnu/security/` and restore `common-auth` from package.
- Delete `svc_backup` account and revoke its sudo entry.
- Revert `sshd_config` to `PermitRootLogin prohibit-password` and `PasswordAuthentication no`.
- Remove `/etc/cron.d/redis-maintenance` and `/var/lib/redis/.cache/`.
- Fix Redis: bind to `127.0.0.1`, enable `requirepass`, rename `CONFIG` command.
- Check `/dev/shm/` for `.log` — file is volatile and will be gone after reboot; capture immediately.
- Audit all files modified between `2026-04-22T02:58:00Z` and `2026-04-22T03:15:00Z` with `find / -newer`.


---

<!-- scorecard:start -->

## Verification scorecard

This report is part of an adversarial cross-model pair and has no entry
in the agent-guard scenario catalogue, so no recall / hallucination
percentages are computed mechanically. The companion ground-truth file
documents the expected findings; cross-check by hand for a manual
confidence assessment.

<!-- scorecard:end -->
