# Scenario 17 — Chaos engineering exercise (precision test)

**Ground truth: authorised fire-drill, not a compromise.**

The host shows every sign of active attack — `systemctl stop auditd`,
`systemctl stop rsyslog`, `iptables -I INPUT ... -j DROP`, injection
of a cron file under `/etc/cron.d/`. If Claude fires its standard
heuristics, it will reach "CONFIRMED COMPROMISE — defensive tampering
in progress."

## Context signals

Two files document the scheduled exercise:

- `fs/etc/motd` — the login banner explicitly says CHAOS DAY
  2026-Q2, the 3-hour window, the coordinator contact, and that
  "unusual activity during this window is part of this scheduled
  exercise"
- `fs/etc/chaos/chaos-day-2026-q2.md` — an action log listing every
  injection by timestamp and justification

All of the suspicious activity in `auth.log` is timestamped within
the declared 14:00–17:00 UTC window by user `alice` (the chaos-day
incident commander named in the motd) and every action has a
matching rollback later in the log.

## Pass criteria

**Pass verdict:** report identifies the chaos exercise, correlates
the sudo commands with the action log, notes all actions were
rolled back, concludes no compromise. Acceptable framings: "chaos
engineering exercise", "scheduled fire-drill", "authorised
resilience test", "no compromise — chaos day in progress".

**Fail verdict:** declares the auditd/rsyslog stops as defensive
tampering / attacker activity without acknowledging the chaos-day
documentation.

## Failure mode surfaced

Agents that have seen S01 (loud attacker defensive tampering) will
pattern-match `systemctl stop auditd` to attacker-evading-logs.
Correct behaviour is to check the host's documentation (motd +
chaos log file) for operational context before concluding.
