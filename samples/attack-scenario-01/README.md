# Attack Scenario 01 — SSH Brute Force → Root Compromise → Backdoor

A synthetic Linux IR case for testing FindEvil's auth-log analysis tools.

## Scenario narrative

`webserver-prod-01` is a production web server. Normal activity includes:
- `deploy` user using SSH key auth from `10.0.1.50` (CI/CD runner)
- `alice` and `bob` admins using key auth from their workstations
- Routine sudo for systemctl, apt, tail

At 14:30 on 2026-04-12, an external attacker at `45.123.45.67` begins a
brute force attack against root and common usernames. After ~15 minutes
of failed attempts, they successfully authenticate as `root` via password.

Post-compromise activity:
1. Reads `/etc/shadow` and `/etc/passwd`
2. Adds a backdoor user `sysd` (name mimics a system account)
3. Disables `auditd` and `rsyslog` to limit future logging
4. Clears bash history
5. Drops a payload via `curl` from `185.177.124.22`
6. Adds persistence via `systemctl enable` and a cron entry

## Expected detection

An IR agent analyzing this log should find:
- **Brute force** from `45.123.45.67` (high confidence — hundreds of attempts)
- **Successful root login** from the same IP (compromise indicator)
- **User creation** of `sysd` shortly after (backdoor account)
- **Sudo commands** showing credential access, service tampering, outbound download,
  history clearing, and persistence — all of which should be flagged.
- **Triage verdict** should be "LIKELY COMPROMISE"

## Files

- `auth.log` — the authentication log covering the attack window
- `journal.jsonl` — systemd-journald export (`journalctl -o json`) of the same window
- `fs/` — a simulated post-compromise filesystem snapshot (for `find_persistence`)
  - `etc/passwd` + `etc/shadow` — includes the backdoor `sysd` user AND a `toor` UID-0 account with empty password
  - `etc/systemd/system/sysd-helper.service` — rogue service executing `/tmp/.x`
  - `etc/cron.d/sysd-cron` — every-5-minutes cron that re-downloads the payload
  - `etc/ld.so.preload` — rootkit library preload (`libprocesshider`)
  - `etc/pam.d/sshd` — attacker `pam_exec` directive running `/tmp/.x` on every SSH auth (credential capture)
  - `etc/modules` — kernel module persistence (`sysd_helper_km` not in stock module set)
  - `etc/modprobe.d/sysd.conf` — modprobe install directive + audit blacklist
  - `root/.ssh/authorized_keys` — attacker's SSH key appended (no comment) next to legitimate alice+bob keys
  - `home/sysd/.bashrc` — auto-executes `/tmp/.x` on any shell login
  - `home/alice/.bashrc` — clean control file (should NOT be flagged)
