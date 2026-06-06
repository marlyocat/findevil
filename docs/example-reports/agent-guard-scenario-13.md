# Incident Response Report — fileserver-01
## Scenario 13: Ransomware / Destructive Attack

**Classification:** CONFIRMED COMPROMISE — ACTIVE DESTRUCTION  
**Analyst:** findevil autonomous IR agent  
**Report Date:** 2026-04-23 (UTC)  
**Evidence Root:** `evidence/attack-scenario-13-ransomware/`  
**Evidence Preservation Note:** Local logs were truncated/purged by the attacker. All timestamps below derive from off-host syslog-forwarded `auth.log` and the on-disk `fs/root/.bash_history`. These are the only surviving log sources.

---

## 1. What Happened

### 1.1 Attack Class

This is a **ransomware/destructive attack**, not a data-exfiltration or espionage incident. The attacker's goal was destruction and extortion: files were encrypted and originals were shredded. No evidence of exfiltration exists in available artifacts. Do **not** treat this as a data-breach notification trigger without further network-level evidence.

No specific ransomware family can be identified from the available evidence. The `.locked` extension and `openssl enc -aes-256-cbc` command are consistent with any ad-hoc script. There is nothing in this evidence that identifies LockBit, Conti, ALPHV, or any named strain. Attribution to a specific family would be speculation.

---

### 1.2 Initial Access

| Field | Value |
|-------|-------|
| Method | SSH as `root` |
| Source IP | `45.77.233.11` (external) |
| SSH key fingerprint | `RSA SHA256:attackerKey0000000000000000000000000` |
| Time | **2026-04-21 03:42:18 UTC** |
| Enabled by | `PermitRootLogin yes` + `PasswordAuthentication yes` in `sshd_config` |

The attacker authenticated with an **RSA public key** — not a password. This means the attacker's key was pre-installed in `/root/.ssh/authorized_keys` prior to this session, either through a previous undetected compromise or credential theft. The weakened `sshd_config` (root login + password auth enabled) created the attack surface, but the actual entry used a key that was already resident on the host.

The IP `45.77.233.11` is **not in the local IOC cache** — this is "no data," not "safe."

For comparison, the only legitimate login in the log window was `alice` from `10.0.2.15` (internal) on 2026-04-20 08:14:02 UTC using her personal ED25519 key — a normal admin session that ran one `journalctl` command.

---

### 1.3 Destruction Timeline (all UTC)

| Time | Action | Evidence Source |
|------|--------|-----------------|
| 03:42:18 | Root SSH session opened from 45.77.233.11 | auth.log line 7 |
| 03:42:35 | Sudo session opened for root | auth.log line 9 |
| 03:42:xx | Host enumeration: `whoami`, `id`, `uname -a`, `cat /etc/os-release` | bash_history |
| 03:44:02 | File enumeration: `find /home /srv /var/www /var/lib/mysql` for doc/xls/pdf/sql/tar.gz files | auth.log line 10, bash_history |
| 03:46:18 | **File encryption** — AES-256-CBC via `openssl enc`, originals shredded with `shred -u` | auth.log line 11, bash_history |
| 03:53:44 | **Snapshot destruction** — all btrfs subvolumes deleted | auth.log line 12, bash_history |
| 03:54:02 | **Backup wipe** — `rm -rf /var/backups/* /var/lib/postgresql/backup/*` | auth.log line 13, bash_history |
| 03:54:28 | systemd journal rotated | auth.log line 14, bash_history |
| 03:54:32 | systemd journal vacuumed (`--vacuum-time=1s` — destroys entire journal) | auth.log line 15, bash_history |
| 03:54:45 | **Log truncation** — auth.log, syslog, kern.log, wtmp, btmp, lastlog zeroed | auth.log line 16, bash_history |
| 03:55:02 | auditd and rsyslog **stopped** | auth.log line 17, bash_history |
| 03:55:08 | auditd and rsyslog **purged** via `apt remove --purge` | auth.log line 18, bash_history |
| 03:55:xx | Ransom notes dropped to filesystem root and user document directories | bash_history |
| 03:55:xx | Encryption key `/tmp/k` deleted, bash history cleared (`history -c`) | bash_history |

**Total time from first connection to host going dark: ~13 minutes.**

---

### 1.4 Encryption Mechanism

```
KEY=$(openssl rand -hex 32)          # 256-bit random key, hex-encoded
echo "$KEY" > /tmp/k                 # Key written to /tmp

find /home /srv /var/www /var/lib/mysql \
  -type f \( -name "*.doc*" -o -name "*.xls*" -o -name "*.pdf" \
             -o -name "*.sql" -o -name "*.tar.gz" \) \
  -exec openssl enc -aes-256-cbc -salt -pbkdf2 -pass file:/tmp/k \
        -in {} -out {}.locked \; \
  -exec shred -u {} \;               # Original OVERWRITTEN and deleted

rm /tmp/k                            # Key destroyed
```

- **Algorithm:** AES-256-CBC with PBKDF2 key derivation and random salt per file
- **Originals:** Shredded (`shred -u` overwrites then unlinks) — **not recoverable by filesystem carving**
- **Key:** Generated in-memory, written to `/tmp/k`, deleted after use. The key is gone. Decryption without the attacker's cooperation is cryptographically infeasible.
- **Surviving encrypted artifact:** `fs/home/alice/Documents/quarterly-report.pdf.locked` (89 bytes — placeholder representing what would be thousands of files in production)

---

### 1.5 Anti-Forensics Summary

The attacker executed a comprehensive anti-forensics playbook:

| Target | Method | Effect |
|--------|--------|--------|
| systemd journal | `--rotate` + `--vacuum-time=1s` | Entire journal destroyed |
| auth.log, syslog, kern.log | `truncate -s 0` | Files zeroed in place |
| wtmp, btmp, lastlog | `truncate -s 0` | Login history destroyed |
| nginx access.log | `cp /dev/null` | Application log cleared |
| auditd | Stopped, masked, purged | Audit subsystem removed |
| rsyslog | Stopped, masked, purged | Syslog daemon removed |
| bash history | `history -c` | In-memory history cleared |
| Encryption key | `rm /tmp/k` | Key unrecoverable |

**Host is now forensically dark** — no audit daemon, no syslog, all local logs zeroed. If the attacker re-enters, no local evidence will be generated.

**Survival of evidence:** The `auth.log` provided here was **preserved by off-host syslog forwarding**, not from the local file (which was zeroed). The `bash_history` survived because `history -c` clears in-memory history but the on-disk `.bash_history` file is only updated at shell exit under certain configurations — the pre-clear sequence was already flushed to disk.

---

### 1.6 Ransom Demand

| Field | Value |
|-------|-------|
| Amount | 0.8 BTC |
| Payment address | `bc1qransom0wareexamp1eaddrlazyinstance` |
| Contact | `restore@ransom-op.onion` |
| Deadline | 72 hours from first read, then price doubles |
| Victim identifier | `VICTIM-ID-7F3A2D8E` |

**Note on the payment address:** A Bitcoin address proves nothing about threat actor identity or ransomware family. Do not use it for attribution.

---

## 2. Current State

| Item | Status |
|------|--------|
| User-facing files | Encrypted with AES-256-CBC; originals shredded |
| Local backups | Destroyed (`/var/backups/*`, `/var/lib/postgresql/backup/*`) |
| Filesystem snapshots | Destroyed (all btrfs subvolumes deleted) |
| systemd journal | Destroyed |
| Auth / syslog / kernel logs | Zeroed |
| auditd / rsyslog | Uninstalled |
| SSH root access | Still configured (`PermitRootLogin yes`) |
| Attacker SSH key | Likely still present in `/root/.ssh/authorized_keys` |
| Host audit capability | None — host is forensically dark |
| Decryption key | Gone — not recoverable locally |

**The host is non-functional for its intended purpose and must not be returned to production without full rebuild.**

---

## 3. Containment Recommendations

These are ordered by urgency. **Containment takes priority over investigation.**

### IMMEDIATE (within the hour)

1. **Network-isolate fileserver-01.** Pull the NIC or apply a firewall block rule to all inbound and outbound traffic. The attacker's SSH key is likely still in `/root/.ssh/authorized_keys` — the host can be re-entered at any time until the key is removed or the host is rebuilt. Do not simply change the root password; the RSA key bypasses passwords.

2. **Preserve the off-host syslog/SIEM copy of auth.log** in a forensically sound manner (hash it, store it read-only). This is your primary evidence. Do not let log rotation purge it.

3. **Rotate all SSH keys and credentials** that were present on or accessible from fileserver-01 — including any service account credentials, API keys, or deploy keys that may have been accessible to the root user.

4. **Do not pay the ransom.** Industry consensus and law enforcement guidance (FBI, CISA) is that paying does not guarantee key delivery, funds criminal operations, and may violate OFAC sanctions depending on jurisdiction. The payment address is generic and cannot be verified as belonging to any actor who can actually decrypt your files.

### SHORT-TERM (within 24 hours)

5. **Audit all other systems for lateral movement.** Check whether fileserver-01 had trust relationships (SSH agent forwarding, shared service accounts, Ansible/Puppet control access) that could have been leveraged to pivot. Search other hosts' auth logs for connections originating from fileserver-01's IP during or after the attack window.

6. **Search all systems for the attacker's RSA key fingerprint** (`SHA256:attackerKey0000000000000000000000000`) in `~/.ssh/authorized_keys` and `/root/.ssh/authorized_keys`. A key pre-installed on one host may have been copied to others.

7. **Investigate how the attacker's RSA key was installed.** The key was present *before* the log window begins. Check: git repos with secrets, CI/CD pipelines, configuration management, any prior incident tickets for this host, and whether root's `authorized_keys` was in any backup or configuration system the attacker could have written to.

8. **Notify legal, compliance, and information security leadership.** Depending on the data types held on fileserver-01 (PII, financial records, health data), this incident may trigger regulatory breach-notification obligations. Do not delay this assessment.

9. **Report to law enforcement.** File a report with FBI IC3 (ic3.gov) and notify CISA. Preserve a copy of all evidence including this report, the raw `auth.log`, and the ransom note for law enforcement.

### REMEDIATION (before rebuilding)

10. **Do not attempt to clean or re-use this host.** The host is forensically and operationally destroyed. Rebuild from a trusted golden image. Before decommissioning the hardware, take a full disk image for potential law enforcement use.

11. **When rebuilding, harden SSH configuration:**
    - `PermitRootLogin no`
    - `PasswordAuthentication no`
    - Restrict `AllowUsers` to named accounts
    - Consider `AllowGroups` with explicit sudo escalation
    - Enable `AuthorizedKeysFile` audit logging

12. **Restore from offsite/air-gapped backups only.** Confirm backup integrity before restoration. All on-host backups are gone.

---

## 4. Evidence Inventory

| Artifact | Path | Status | Notes |
|----------|------|--------|-------|
| auth.log | `evidence/.../auth.log` | Intact | Preserved by off-host forwarding; local copy was zeroed by attacker |
| sshd_config | `fs/etc/ssh/sshd_config` | Intact | Shows `PermitRootLogin yes`, `PasswordAuthentication yes` |
| root bash_history | `fs/root/.bash_history` | Intact | Full attack sequence; attacker ran `history -c` but on-disk file survived |
| Ransom note (root) | `fs/README_RESTORE_YOUR_FILES.txt` | Intact | Full ransom demand text |
| Ransom note (alice) | `fs/home/alice/Documents/README_RESTORE_YOUR_FILES.txt` | Intact | Pointer to root-level note |
| Encrypted file sample | `fs/home/alice/Documents/quarterly-report.pdf.locked` | Intact | 89-byte AES-256-CBC ciphertext placeholder |
| passwd | `fs/etc/passwd` | Intact | 4 accounts: root, daemon, sshd, alice |
| shadow | `fs/etc/shadow` | Intact | root account locked (`!*`); alice has valid hash |
| Backups | `fs/var/backups/` | Empty | Wiped by attacker (`rm -rf`) |
| Systemd units | `fs/etc/systemd/system/` | Empty | No attacker-installed persistence units found |

---

## 5. Confidence Assessment

| Finding | Confidence | Basis |
|---------|-----------|-------|
| Attacker IP: 45.77.233.11 | HIGH | Directly in off-host-forwarded auth.log |
| Entry via pre-installed RSA key | HIGH | auth.log shows `Accepted publickey` with distinct `attackerKey` fingerprint |
| Encryption via AES-256-CBC openssl | HIGH | Both auth.log sudo record and bash_history confirm command |
| Originals shredded (unrecoverable) | HIGH | `shred -u` in bash_history; shred overwrites before unlinking |
| All local backups/snapshots destroyed | HIGH | bash_history + empty `fs/var/backups/` |
| Decryption key gone | HIGH | `/tmp/k` deleted in bash_history; no copy found |
| How attacker obtained the RSA key | UNKNOWN | Pre-dates the log window; no evidence of how key was installed |
| Specific ransomware family | NONE | Generic pattern only — no family attribution possible |
| Exfiltration occurred | UNCONFIRMED | No evidence found; requires network-level log review |

---

*Report generated by findevil autonomous IR agent. All findings are grounded in raw tool output from the listed evidence artifacts. No findings have been fabricated or inferred beyond what the evidence supports.*

---

<!-- scorecard:start -->

## Verification scorecard

Mechanically computed by `scripts/grade_example_reports.py` against the
`agent_guard.SCENARIOS["13"]` markers (case-insensitive substring
match, identical logic to `tests/harness/agent_guard.py`'s grade()
function). No AI self-assessment is involved in these numbers.

| Metric | Score | % |
|---|---|---|
| Required markers found | 4/4 | **100%** |
| Cross-scenario markers absent | 14/14 | **100%** |
| Verdict-correctness confidence | — | **100%** |
| Hallucination-free confidence | — | **100%** |

**Overall confidence: HIGH** — every planted marker for this
scenario was surfaced in the report, and zero markers from any other
scenario leaked in. Re-grade with `python scripts/grade_example_reports.py`.

<!-- scorecard:end -->
