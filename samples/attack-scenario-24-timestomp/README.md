# Scenario 24 — Timestomped backdoored sshd (originally near-impossible, now closed)

**Ground truth: /usr/sbin/sshd has been replaced with a backdoored
build.** The replacement was timestomped to match the original
installation mtime, has the same mode and ownership, and the sshd_config
is unchanged. auth.log shows only routine alice/bob admin activity
from internal IPs — nothing to raise an alarm.

This scenario was originally designed as the documented blind-spot test
for tampered package binaries (no `dpkg --verify` equivalent in
findevil). **As of the `verify_package_integrity` MCP tool, this surface
is now scanned natively** — the tool reads
`/var/lib/dpkg/info/*.md5sums` and compares each recorded hash against
the file on disk. The scenario is retained as a regression test;
expected outcome on a fresh run is now a **strong pass** rather than
the documented FAIL.

## What's actually on disk

- `fs/usr/sbin/sshd` — placeholder representing a backdoored build. If
  Claude runs `strings_extract` on the file it will find signals a
  legitimate OpenSSH binary would NOT have:
  - `SSH-2.0-OpenSSH_9.6p1_BACKDOORED_BUILD_REV_2026_03_15`
  - `backdoor_magic_authenticate`
  - `accept_backdoor_token_rGpLqWx7Nk`
  - `PAM-auth-backdoor-trigger`
  - `/dev/shm/.sshd-audit-helper` (implant dropper path)
  - `_auth_bypass_if_password_equals`
- `fs/var/lib/dpkg/info/openssh-server.md5sums` — dpkg's expected
  MD5 for `usr/sbin/sshd` is `c4e8fa03d21f7b5a9e082faee6b8c9a2`.
  Actual MD5 on disk will not match. A `dpkg --verify openssh-server`
  would flag the mismatch; `hash_file` + manual comparison would
  also surface it.
- `fs/var/log/apt/history.log` — shows a clean install of
  openssh-server in Nov 2024 and a routine libc upgrade in Apr 2026.
  Neither event looks unusual.

## How findevil now catches this

- **`verify_package_integrity`** (the MCP tool that ships in
  `linux_packages.py`) computes the on-disk MD5 of every file
  registered in `/var/lib/dpkg/info/*.md5sums` and reports any
  mismatch. `/usr/sbin/sshd` is on the high-value list, so a
  mismatch here escalates to **CRITICAL — system binary modified**.
- `find_persistence` continues to only inspect known persistence
  paths, but `verify_package_integrity` is its complement for
  packaged binaries that have been tampered with in place.
- `strings_extract` + `hash_file` remain available for cases where
  the agent wants to corroborate a verdict (extract the
  `BACKDOORED_BUILD` markers from the binary itself).

## Pass criteria

**Strong pass:** the report identifies `/usr/sbin/sshd` as
backdoored via the `verify_package_integrity` mismatch (CRITICAL
severity, system binary). Optional corroboration via
`strings_extract` finding `BACKDOORED_BUILD` /
`backdoor_magic_authenticate` tokens.

**Weak pass:** the report runs `verify_package_integrity` and
quotes the mismatch but doesn't escalate the verdict.

**Fail:** the report skips `verify_package_integrity` and
concludes "no compromise — everything looks routine." This is now
a regression failure rather than a documented limit.

## Expected difficulty

**MEDIUM.** With `verify_package_integrity` shipping, the detection
path is now mechanical — invoke the tool, read the CRITICAL
verdict, correlate with the strings_extract findings if desired.
A senior IR practitioner would still spot-check by `strings`-ing
the binary; the agent should at minimum produce the
package-integrity finding.
