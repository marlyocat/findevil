# Scenario 07 — Udev-rule persistence (originally a blind-spot test, now closed)

**Ground truth: compromised via a udev rule that runs a reverse-shell
payload at every block-device add event.**

This scenario was originally designed as a documented blind-spot test
(see accuracy-report §8.4): findevil's persistence scanner did not walk
`/etc/udev/rules.d/`, so the agent had to find the compromise by
inspecting the filesystem directly. **As of `find_persistence`'s
`scan_udev` addition, this surface is now scanned natively** — udev
rules with `RUN+=` directives that point at world-writable paths or
arbitrary scripts are flagged at high severity. The scenario is
retained as a regression test: any future change that re-breaks udev
coverage will show up here first.

The `find_persistence` output is now expected to surface
`/etc/udev/rules.d/99-backdoor.rules` directly. The agent's job is to
correlate that finding with the auth-log sudo sequence to confirm
attacker provenance.

## Attack

`alice` copies a pre-crafted udev rule and payload to system paths,
reloads udev, and triggers rule processing. The rule runs
`/usr/local/bin/update` as root whenever a block device is added or
enumerated at boot. Payload opens a reverse shell to
`198.51.100.77:4444`. No cron, no systemd unit, no authorized_keys,
no ld.so.preload — every path findevil's `find_persistence` scans is
clean.

## Artifacts

- `auth.log` — alice's sudo sequence (cp + chmod + udevadm) is visible
- `fs/etc/udev/rules.d/99-backdoor.rules` — the udev rule itself
- `fs/usr/local/bin/update` — the payload (reverse shell via /dev/tcp)
- `fs/etc/passwd|shadow` — clean, stock users
- `fs/etc/ssh/sshd_config` — hardened

## Expected behaviour

**Hard ask:** Claude must identify `198.51.100.77`,
`/etc/udev/rules.d/99-backdoor.rules`, and `/usr/local/bin/update` as
compromise indicators. With `scan_udev` shipping, `find_persistence`
should surface the rule file directly; the agent's job is to correlate
it with the auth-log sudo sequence (`cp` + `chmod` + `udevadm`) to
confirm attacker provenance.

**Soft pass:** Claude notices the sudo sequence in auth.log is unusual
(cp'ing things to /etc/ and /usr/local/bin/) even if it doesn't
specifically attribute the persistence mechanism.

**Regression failure mode:** If a future refactor breaks
`scan_udev`, the agent will revert to the original "no persistence
found" outcome and the agent_guard scorecard will detect the missing
markers.
