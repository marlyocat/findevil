# Attack Scenario 03 — Web shell upload → RCE → privesc via sudoers

A third distinct attack pattern. Tests that the findevil tools handle a
vector the agent has not seen before (web-application compromise) without
relying on patterns specific to scenarios 01 (SSH brute force) or 02
(stolen CI/CD key).

## Narrative

`webserver-prod-03` runs a small PHP CMS with a file-upload endpoint at
`/uploads/` that does not validate filetype. The web process runs as
`www-data`. Attacker tradecraft:

1. **Reconnaissance via scanning.** Nikto/dirb-style scan across common
   paths (`/wp-admin/`, `/phpmyadmin/`, `/uploads/`) produces a burst of
   404s from the attacker IP.
2. **Upload webshell.** Attacker POSTs `shell.php` to `/uploads/`
   (200 OK — the app accepts it without validation).
3. **Execute commands via webshell.** Subsequent GETs to
   `/uploads/shell.php?cmd=...` run arbitrary commands as `www-data`.
4. **Discovery.** Attacker runs `id`, `whoami`, `sudo -l` via the
   webshell to find what privileges `www-data` has.
5. **Privilege escalation via sudoers misconfig.** The operators of the
   host had previously given `www-data` passwordless sudo on
   `/usr/bin/tar` for backup automation. Attacker uses `tar
   --checkpoint=1 --checkpoint-action=exec=/bin/bash` — a classic
   GTFOBins technique — to get a root shell.
6. **Persistence.** As root, adds a cron entry that re-downloads a
   payload every 5 minutes.

No SSH brute force, no stolen SSH key, no logging tampering. The initial
access is purely in the web log.

## Expected detection

| Tool | Should detect? | How |
|------|----------------|-----|
| `analyze_nginx_access` | **Yes** | Upload chain (POST `/uploads/shell.php` → GET `/uploads/shell.php?cmd=...`), scanner UA, command-injection in query strings |
| `find_webshells` | **Yes** | `/var/www/html/uploads/shell.php` with `system($_GET['cmd'])` pattern |
| `analyze_sudoers` | **Yes** | `www-data` NOPASSWD on bare `/usr/bin/tar` — privesc vector |
| `find_persistence` | **Yes** | The attacker-planted cron entry |
| `auth_*` tools | No compromise indicators | No SSH compromise in this scenario |
| `analyze_bash_history` | No tampering | `www-data` has no shell history (no TTY) |

## Files

- `access.log` — nginx access log covering the attack window
- `fs/` — post-compromise filesystem snapshot
  - `var/www/html/` — the web root. Contains legitimate `index.php`,
    `login.php`, and the attacker's `uploads/shell.php`.
  - `etc/sudoers.d/www-data-backup` — NOPASSWD on `/usr/bin/tar` that
    enabled the privesc
  - `etc/cron.d/backup-check` — the attacker's re-download cron
  - `etc/ssh/sshd_config` — hardened (no SSH compromise here)
  - `etc/passwd` / `etc/shadow` — clean (no backdoor accounts)
  - `home/alice/.bashrc` — clean control sample
