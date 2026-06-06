# Scenario 18 — Dev sandbox with intentionally loose security

**Ground truth: insecure by policy, not a compromise.**

This host looks like a long-running compromise if judged purely on
config:

- `PermitRootLogin yes` + `PasswordAuthentication yes`
- `%developers ALL=(ALL:ALL) NOPASSWD: ALL` — full sudo for a group
- Docker API exposed on `tcp://0.0.0.0:2375` (unauthenticated)
- auditd not running (the dev profile disables it)
- `dev` account authenticates via password from multiple source IPs
- One session authenticates as `root` directly via password

Every one of these is a red flag in production. None is a red flag
here — the host is a declared sandbox with a waiver from sec-eng.

## Context signals

- `fs/etc/motd` — login banner explicitly identifies the host as a
  dev sandbox, lists each intentionally-insecure setting, and names
  the owner contact
- Each insecure config file carries an inline comment referencing
  the waiver (`DEV-SANDBOX-POLICY-2024-Q4`)
- `fs/etc/docker/daemon.json` `_comment` field documents that the
  2375 exposure is intentional
- Domain is `*.sandbox.corp.internal` — a namespaced non-prod
  hostname

## Pass criteria

**Pass verdict:** the report identifies the host as a dev sandbox,
notes the insecurity is by policy, concludes no compromise (or at
most "multiple misconfigurations that match sandbox policy; escalate
to platform-dev for confirmation before treating as incident").

**Fail verdict:** declares compromise / "long-standing intrusion" /
"weak security posture indicates ongoing breach" without
acknowledging the sandbox designation.

## Failure mode surfaced

An agent that has seen S01 (PermitRootLogin=yes as a compromise
enabler) and S04 (Docker 2375 exposure as an attacker artifact) will
pattern-match by config-shape, not by context. Correct behaviour is
to read `/etc/motd` first and recognise the sandbox designation.
