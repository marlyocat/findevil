# Scenario 26 — Dormant `at`-job scheduled 60 days out (originally a blind-spot test, now closed)

**Ground truth: compromise; the payload is sitting in the `at` spool
and will execute on Jun 19 2026.**

This scenario was originally designed as the documented blind-spot test
for at-job persistence (findevil's persistence scanner did not walk
`/var/spool/cron/atjobs/`). **As of `find_persistence`'s `scan_atjobs`
addition, this surface is now scanned natively** — every queued at-job
is surfaced (clean ones at medium severity, ones whose body matches the
suspicious-pattern set at high). The scenario is retained as a
regression test.

## What's in the evidence

- `fs/var/spool/cron/atjobs/a000020187c2e8f` — the at-queued job.
  Standard atrun format: env setup + `cd /root` + command line.
  The command downloads `/tmp/.m` from `198.51.100.202` and executes
  it. The job header's comment `# atrun uid=0 gid=0` shows it runs
  as root.
- `auth.log` — `alice` ran `sudo at -f /tmp/maintenance.sh now + 60 days`
  on 2026-04-20 at 14:24 UTC. atd logged
  `job 20187c2e8f will run at Tue Jun 19 14:24:42 2026`. That's
  the corroborating line — names the job ID that matches the
  spool filename, dates the future execution.
- `fs/etc/` — standard stock files. No other compromise indicators.

## Pass criteria

**Required markers:**
- `atjob` or `at job` or the spool path (must name the mechanism)
- `198.51.100.202` (the C2 IP buried in the spool body)
- `compromise`
- `Jun 19` or `2026-06-19` — the scheduled future execution date

**Expected difficulty:** LOW-MEDIUM. With `scan_atjobs` shipping,
`find_persistence` surfaces the spool file directly under the new
`atjob` category. The agent's job is to correlate the spool body's
`198.51.100.202` C2 IP with the auth-log `atd[...]: job ... will run
at ...` line and the original `sudo at -f ...` invocation.

A regression failure here means `scan_atjobs` broke; a fresh-run
fail means Claude didn't chain the at-job finding to the auth-log
provenance.
