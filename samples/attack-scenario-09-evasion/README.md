# Scenario 09 — Evasion (targets findevil's detection blind spots)

**Ground truth: compromised.** Same class of attack as S03 (web-facing
RCE → privesc via sudoers-tar GTFOBin → root persistence), but every
artifact has been reshaped to slip past findevil's specific pattern
matchers and signature rules. Per accuracy-report.md §8.4–8.5, these
are documented blind spots.

## Evasion techniques

1. **Webshell filename** — `/var/www/html/assets/health-check.php`
   instead of `/uploads/shell.php`. Not under `/uploads/`.
2. **Webshell body** — no direct `system($_GET['cmd'])`. Uses
   `base64_decode("c3lzdGVt")` → stores result in `$fn` → calls `$fn(...)`.
   The `find_webshells` signature set matches on literal function
   names; indirection defeats it.
3. **Attacker commands base64-encoded** in query string (`?q=aWQ7d2hvYW1p`
   decodes to `id;whoami`). Pattern-matchers looking for `cmd=`, `sudo`,
   `cat`, etc. in URL params won't match.
4. **Persistence via systemd TIMER** instead of cron. `find_persistence`
   enumerates systemd unit files but timers specifically get less
   attention than services. `/etc/systemd/system/health-check.timer`
   calls `.service` which runs `/var/backups/.health/run`.
5. **C2 IP base64-encoded inside payload** — the reverse shell at
   `/var/backups/.health/run` never contains a literal IP. It decodes
   `"MTkyLjAuMi4xNzc="` → `192.0.2.177` at runtime.
6. **Reverse shell via `/dev/tcp`** (bash builtin), not `nc`. No
   netcat / ncat / ncat.openbsd keyword to match.
7. **Payload path `/var/backups/.health/`** — not `/tmp/`, not
   `/dev/shm/`. Hidden directory under a legitimate-looking parent.

## What should still catch this

- `analyze_nginx_access` should still flag the upload-then-exec chain
  from `203.0.113.88` (POSTs with `?q=...`). The chain *shape* matches
  even when the shell is unnamed.
- `find_persistence` should still surface the systemd unit files it can
  see in `/etc/systemd/system/`.
- `analyze_sudoers` should still flag the bare-binary NOPASSWD on
  `/usr/bin/tar`.

## Pass criteria

**Soft pass:** compromise verdict reached, systemd persistence flagged,
sudoers misconfig flagged. Agent notices the `203.0.113.88` access
anomaly even if it can't decode the specific payload.

**Hard pass:** agent decodes at least one base64 blob and identifies
the C2 IP (`192.0.2.177`) or shows the decoded command
(`sudo tar ... --checkpoint-action=exec=/bin/bash`).

**Failure mode:** agent runs `find_webshells` on `/var/www/html`, gets
zero findings (no signature match on the indirected shell), concludes
the host is clean. This is the documented `find_webshells` signature
gap.
