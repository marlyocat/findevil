# Scenario 11 — Insider threat (authorized credentials, malicious intent)

**Ground truth: data exfiltration by an authorized employee.**

No external attacker, no brute force, no malware. Alice is a legitimate
DBA with an overly-broad sudoers grant (`ALL=(root) NOPASSWD: ALL` on
top of her argv-constrained grant). Her corporate SSH key is in use
from her usual source IP. Every individual action she takes is
something she's authorized to do. The compromise is in the *intent*
and *pattern*.

## Attack pattern

- **2026-04-14 09:02 UTC** — alice's normal workday login from
  `10.0.2.15`. Checks mysql status. Logs out 2 min later. Looks normal.
- **2026-04-15 02:14 UTC** — alice logs in again from the same IP, but
  at 02:14 UTC (off-hours). Runs `sudo mysqldump --all-databases`,
  writes to `/tmp/dump-20260415.sql`, gzips, chmods, chowns. Logs out
  at 02:17.
- **Her own `.bash_history`** records what auth.log doesn't: she then
  `scp`'d the dump to `alice@home.malan-personal.net:/srv/backup/corp-db/`
  using a key at `~/.ssh/personal_ed25519` — a personal machine, not
  corporate infrastructure. Then `rm dump-20260415.sql.gz` and
  `history -c`.
- **Her `~/.ssh/config`** documents the `home.malan-personal.net` host
  with an explicit "not corporate" header comment.

## Why this is hard

None of findevil's automated scanners flag this reliably:
- `auth_failed_logins` → zero (it was a normal login)
- `auth_user_events` → zero (no useradd)
- `find_persistence` → zero (no persistence planted)
- `analyze_authorized_keys` → her corporate key is the only one, no
  anomaly
- `analyze_sudoers` → WILL flag the bare `NOPASSWD: ALL` as a
  pre-existing misconfig, but that's a standing grant, not the attack
- `auth_sudo_commands` → will list the mysqldump + chmod + chown calls
  under "database/backup activity" but they're all routine-looking

The attacker signal is:
1. The 02:14 UTC timestamp (off-hours)
2. mysqldump --all-databases followed by gzip + transfer to a personal
   host + rm + `history -c`
3. Cross-referencing auth.log (shows mysqldump) with her .bash_history
   (shows the scp to personal infra) — no single source tells the
   whole story

## Pass criteria

**Required:** the report must name `alice`, identify the `mysqldump`
activity, and use one of: "exfil" / "exfiltration" / "data theft" /
"insider" / "data export" / "concerning" / "anomalous" — some word
that indicates the analyst recognized this as a real finding, not
routine operations.

**Pass for intent reasoning (judged separately):** the report should
cite the 02:14 UTC timing, the personal-server destination, the
`history -c` afterwards, or the mismatch between auth.log (mysqldump)
and bash_history (scp to external). An analyst who misses all four
signals has pattern-matched the individual commands as "allowed" and
missed the aggregate pattern as "suspicious."

## Failure modes the test surfaces

- **False negative:** report concludes "no compromise — routine DBA
  activity" because every individual command is authorized. This is
  the pattern-matching failure this scenario is designed to expose.
- **False positive:** report mentions a nonexistent external attacker
  IP or invents a webshell/rootkit to justify the concerns. Should
  NEVER happen — the evidence shows no such artifacts.
