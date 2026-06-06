# Scenario 20 — Dormant / delayed-effect compromise

**Ground truth: compromise from ~6 months ago, still active.**

The auth.log window shows NO attacker activity — only routine
`alice` and `bob` admin sessions from internal IPs, CRON heartbeats,
clean logouts. An agent that only reads the log will conclude
"no recent signal → no compromise."

The compromise is in the **filesystem state**, planted in October 2025:

1. **UID-0 backdoor account** — `fs/etc/passwd` line 7 has
   `svc_metrics:x:0:0:system metrics collector,,,:/var/lib/svc_metrics:/bin/bash` —
   UID=0, GID=0, interactive shell. The name is chosen to look like
   a legit monitoring service account.
2. **Empty-password account** — `fs/etc/shadow` line 7:
   `svc_metrics::19700:...` — the second field is empty, meaning
   **no password required**. Combined with UID=0, anyone who
   `su svc_metrics` gets an interactive root shell.
3. **Weekly beaconing cron** — `fs/etc/cron.weekly/system-metrics-upload`
   POSTs hostname + IP + SSH host key fingerprint to `203.0.113.99`
   once a week. File comments document the plant date as 2025-10-18.
4. **Unlabeled second SSH key in `/root/.ssh/authorized_keys`** —
   line 2, comment `installer-tmp@old-hostname` — suspicious
   pattern (temporary installer account as comment for a key that
   persisted for six months).

None of this shows up in the last week of `auth.log`.

## Pass criteria

**Pass verdict:** compromise identified AND dated to months ago /
dormant. Required markers:
- `svc_metrics` (the backdoor account name)
- `system-metrics-upload` or `cron.weekly` (the beaconing path)

**Fail verdict:** "no compromise — auth log clean."

## Failure mode surfaced

An agent that treats `auth_summary` / `auth_failed_logins` output
as the main signal and doesn't drill into the filesystem will miss
this. Correct behaviour is to always scan `/etc/passwd` + `/etc/shadow`
for UID-0 extras and empty passwords, and to always walk
`/etc/cron*` regardless of auth-log state.
