# Attack Scenario 02 — Stolen CI/CD Key → Quiet Persistence

A deliberately **subtle** intrusion designed to test whether FindEvil:

1. Correctly detects compromise via multi-artifact correlation (not a single
   obvious signal like brute force).
2. Does **not** false-positive on normal activity (no rushed "compromise"
   verdict when the auth log shows legitimate logins).
3. Catches persistence even when the attacker avoided the loudest tradecraft
   (no rootkit, no logging tampering, no new users, no `/tmp/` binaries).

## Narrative

`webserver-prod-02` is a second production web server. The `deploy` account is
a CI/CD role with sudo rights restricted to deployment-related commands.
Attacker tradecraft:

- **Initial access:** phished an engineer's laptop, exfiltrated deploy's SSH
  private key. **No brute force** appears in the log — the login is a
  publickey auth that looks legitimate on its face.
- **Timing:** the attacker logged in at **03:17 UTC on 2026-04-14** — off
  hours for this org but not impossible. Single short session (~3 minutes).
- **Origin IP:** `185.229.59.103` — external, not seen in prior deploy
  sessions (which are all from the CI runner `10.0.1.50`).
- **Actions on target:**
  - Read `/etc/passwd` (reconnaissance — not credential theft since no `/etc/shadow`).
  - Copied a pre-uploaded binary from `/tmp/update` to `/usr/local/bin/update`
    (legit-looking path, not `/tmp/`).
  - Created `/etc/systemd/system/system-updater.service` that runs a beacon
    to `185.229.59.103:8443` every 10 minutes (via `Restart=always + RestartSec=600`).
  - Appended a second SSH key to `/home/deploy/.ssh/authorized_keys` with a
    realistic comment `deploy@ci-backup`.
  - Did **not** disable auditd, did **not** clear history, did **not** modify
    `/etc/passwd`, did **not** plant a rootkit.

## Expected detection

| Tool | Should detect? | How |
|------|----------------|-----|
| `auth_summary` | Partial | No brute force → verdict should be "no obvious compromise from auth alone" (correct — it's not obvious from the log) |
| `auth_failed_logins` | No matches | Zero failures (correct — attacker had valid creds) |
| `auth_successful_logins` | Listed, not flagged | No `brute-force-preceded` flag (correct) |
| `auth_sudo_commands` | **Yes** | Flags `systemctl enable`, `systemd/system/` modification |
| `auth_user_events` | No | No new users created (correct) |
| `find_persistence` | **Yes** | High-severity systemd unit (ExecStart invokes curl to non-RFC1918 IP) |
| `analyze_systemd_unit` | **Yes** | On the systemd unit path |
| `analyze_authorized_keys` | Info only | Two keys, both with comments — neither flagged individually, but agent should ask why there are two |
| `find_persistence` (users) | **No findings** | /etc/passwd is clean — this is a true-negative test |
| `find_persistence` (library) | **No findings** | No ld.so.preload — true-negative test |
| `find_persistence` (cron) | **No findings** | No cron persistence — true-negative test |

## Why this scenario matters

Scenario 01 had ~8 independent loud signals. If we only test on scenario 01
our tools could be *hallucinating compromise* on any data and still "work."
Scenario 02 proves they surface compromise **only when real signals exist**
and remain silent on the clean categories.

## Files

- `auth.log` — two days of mostly normal activity plus the subtle attack
- `fs/` — post-compromise filesystem snapshot
  - `etc/passwd` + `etc/shadow` — **clean** (no backdoor users)
  - `etc/systemd/system/system-updater.service` — the ONE malicious artifact
  - `home/deploy/.ssh/authorized_keys` — two keys, both with plausible comments
  - `home/deploy/.bashrc` — clean
  - No `ld.so.preload`, no `cron.d` entries, no `rc.local`, no init scripts
