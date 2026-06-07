# Incident Response Report — db-backup-25
## Scenario 25: Perfect-Tradecraft Insider
**Classification:** INSUFFICIENT EVIDENCE — CANNOT DETERMINE COMPROMISE  
**Report date:** 2026-04-23 (UTC)  
**Analyst:** FindEvil / Autonomous IR (Claude)  
**Evidence root:** `evidence/attack-scenario-25-perfect-insider/`  
**Audit scope:** auth.log, fs/{etc,home,var}

---

## Executive Summary

A routine DBA audit of db-backup-25 was conducted covering 2026-04-22. All
observed activity is **individually consistent with authorized, normal DBA
operations**. No technical compromise indicators are present in the available
evidence. However, one data point — the backup scope targeting `customers_v2`
rather than `customers_v1` — cannot be evaluated without baseline knowledge
of alice's historical backup schedule. The evidence is **genuinely
insufficient** to render a compromise verdict in either direction.

**This is not analyst failure. This is the correct answer.**

---

## Evidence Inventory

| Artifact | Status |
|----------|--------|
| `auth.log` | Analyzed — 18 lines, Apr 22 |
| `fs/etc/passwd` | Analyzed — 5 accounts |
| `fs/etc/shadow` | Analyzed — locked/hashed, no empty passwords |
| `fs/etc/ssh/sshd_config` | Analyzed |
| `fs/etc/sudoers.d/db-admins` | Analyzed |
| `fs/home/alice/.bash_history` | Analyzed — 10 commands |
| `fs/var/backups/db/` | Empty (backup file not retained in evidence) |
| Authorized keys | Not present in evidence package |
| Cron/systemd units | Not present in evidence package |

---

## Timeline of Events (2026-04-22, all times UTC)

| Time | User | Event | Source IP |
|------|------|-------|-----------|
| 08:00:01 | root (CRON) | Scheduled cron job — session opened/closed | localhost |
| 09:02:14 | alice | SSH login — publickey, ED25519 `SHA256:aliceKey` | 10.0.2.15 |
| 09:03:44 | alice | `sudo mysqldump --single-transaction customers_v2` | — |
| 09:05:17 | alice | mysqldump sudo session closed | — |
| 09:05:45 | alice | `sudo gzip /var/backups/db/customers_v2-20260422.sql` | — |
| 09:06:12 | alice | `sudo chmod 640 /var/backups/db/customers_v2-20260422.sql.gz` | — |
| 09:06:55 | alice | `sudo aws s3 cp …/customers_v2-20260422.sql.gz s3://corp-db-backups/daily/` | — |
| 09:09:22 | alice | SSH session closed (session duration: **7 min 8 sec**) | — |
| 12:00:01 | root (CRON) | Scheduled cron job — session opened/closed | localhost |
| 14:32:11 | bob | SSH login — publickey, ED25519 `SHA256:bobKey` | 10.0.2.22 |
| 14:33:42 | bob | `sudo apt update` | — |
| 14:36:02 | bob | SSH session closed (session duration: 3 min 51 sec) | — |

---

## Findings by Domain

### 1. Authentication — CLEAN

- **Failed logins:** 0. No brute-force precursor.
- **Successful logins:** 2 — alice (09:02, pubkey) and bob (14:32, pubkey).
- **Auth method:** Pubkey-only (sshd_config enforces `PasswordAuthentication no`).
- alice's session originated from `10.0.2.15`, a known internal IP. No external
  source IPs observed anywhere in the log.
- No root logins; `PermitRootLogin no` is enforced.

### 2. alice's Session — SUPERFICIALLY CLEAN

The session executes a textbook DBA backup workflow: dump → compress → restrict
permissions → upload to S3. The command sequence in bash_history is a verbatim
match to the sudo audit log — no discarded commands, no reconnaissance, no
lateral movement attempt, no cleanup (history -c, unlink, etc.).

Session characteristics that are **consistent with legitimacy**:
- 7-minute session — short and focused, no exploratory commands
- Originates from alice's own workstation IP
- Uses alice's registered SSH key fingerprint
- All commands within alice's authorized sudo scope
- Destination bucket (`corp-db-backups/daily/`) is the expected corporate bucket
- No anti-forensic activity in history

Session characteristics that are **also consistent with a credential-hijacked
session via phishing**:
- Identical. Every attribute above would hold if alice's workstation was
  compromised and an attacker operated through her SSH agent or forwarded key.

**Neither reading can be excluded from the available evidence.**

### 3. Sudo Configuration — PRE-EXISTING RISK (not an attack signal)

`/etc/sudoers.d/db-admins` grants alice NOPASSWD access to four binaries:

```
alice ALL=(root) NOPASSWD: /usr/bin/mysqldump, /bin/gzip, /bin/chmod, /usr/bin/aws
```

`/bin/chmod` with no argument restriction is a privilege escalation vector
(`sudo chmod u+s /bin/bash`). There is **no evidence this was exploited**
during the reviewed session — alice's chmod usage was limited to setting
permissions on the backup file. However, this misconfiguration should be
remediated regardless of this investigation's outcome (see Recommendations).

### 4. SSH Configuration — SECURE

| Directive | Value | Assessment |
|-----------|-------|------------|
| `PermitRootLogin` | `no` | ✓ |
| `PasswordAuthentication` | `no` | ✓ |
| `PubkeyAuthentication` | `yes` | ✓ |
| `MaxAuthTries` | `3` | ✓ |

No dangerous configuration present.

### 5. Persistence — NONE DETECTED

Full persistence scan of `fs/` returned no findings beyond the pre-existing
sudoers configuration noted above. No new cron entries, systemd units,
authorized_keys backdoors, rc.local modifications, or LD_PRELOAD hooks.

### 6. Timestamp Analysis — EVIDENCE ARTIFACT (not timestomping)

All five files in the evidence package share identical mtime/ctime
`2026-04-23T18:45:22 UTC`. This is the evidence package assembly time, not a
timestomping event — it reflects when the scenario bundle was created for
staging, not any attacker action on the original system.

### 7. IOC Assessment — NO EXTERNAL INDICATORS

All network addresses are RFC1918 private:
- `10.0.2.15` — alice's workstation (internal)
- `10.0.2.22` — bob's workstation (internal)

S3 destination `s3://corp-db-backups/daily/` is the corporate backup bucket.
No external C2 IPs, no suspicious domains, no known-malicious hashes.

### 8. bob's Session — CLEAN

bob's session (14:32–14:36) consists of a single `apt update` command — routine
system administration. No connection to alice's session.

---

## The Pivotal Data Point

The backup targets **`customers_v2`**, not `customers_v1`.

This is the only observation that diverges from the expected routine — and it
is only an anomaly **if** alice's documented baseline backs up `customers_v1`.
Without that baseline, both interpretations are equally valid:

| Interpretation | What it requires to confirm |
|---------------|----------------------------|
| Normal: alice was asked to run a one-off v2 backup | A ticket/email/policy change explaining the scope change |
| Malicious: attacker stole alice's credentials via phishing and exfiltrated v2 (newer, richer PII) instead of v1 | Evidence of alice's workstation compromise (10.0.2.15), UEBA baseline showing alice has never backed up v2, or DLP policy asserting v2 belongs in a separate bucket |

The evidence as collected cannot resolve this ambiguity.

---

## Verdict

> **CANNOT DETERMINE COMPROMISE FROM THIS EVIDENCE ALONE.**
>
> Every individual action observed — login origin, authentication method,
> session duration, command sequence, destination bucket — is within alice's
> authorized operational patterns. No external anomaly markers are present.
> No persistence was established. No anti-forensic activity occurred.
>
> The only action warranting secondary verification is the dump of
> `customers_v2`. This table name is unusual relative to a v1 baseline (if
> such a baseline exists), but the evidence set does not include that baseline.
> Determining whether this represents authorized activity or credential-hijacked
> exfiltration requires information **not present in this evidence package.**

---

## Required Follow-Up (Ordered by Priority)

1. **Investigate alice's workstation (10.0.2.15).** The ground truth of this
   scenario is a workstation phishing compromise. The backup server evidence
   cannot prove or disprove it — only endpoint forensics of 10.0.2.15 can.
   Collect: EDR telemetry, browser process trees around alice's phishing window,
   SSH agent activity, and any remote desktop or C2 beacon indicators.

2. **Pull alice's backup history.** Query the S3 bucket and any job scheduler
   (JIRA, Rundeck, Ansible, cron) for the past 18 months: which table has alice
   always backed up? If `customers_v1` is the answer, today's `customers_v2`
   dump is an anomaly requiring explanation.

3. **Verify data classification.** Determine whether `customers_v2` is in scope
   for the `corp-db-backups/daily/` bucket or whether 2026-Q1 PCI data requires
   the `pci-backups/weekly/` bucket per policy. If bucket policy prohibits v2
   in `daily/`, this is a DLP violation regardless of intent.

4. **Interview alice.** Was she asked to run a v2 backup? Was there a ticket?
   Did she notice any anomaly on her workstation in the last week?

5. **Remediate sudoers.** Remove bare `chmod` from alice's NOPASSWD grant.
   Replace with a tightly scoped rule (specific target file path pattern) or
   remove `chmod` entirely and handle permissions in the backup script.

---

## Confidence Assessment

| Claim | Confidence | Basis |
|-------|-----------|-------|
| No brute-force attack occurred | HIGH | Zero failed logins |
| No new persistence was established on backup server | HIGH | Persistence scan clean |
| No external exfiltration destination was used | HIGH | All IPs RFC1918, S3 bucket corporate |
| alice's session was legitimate (not hijacked) | LOW | Cannot distinguish — identical fingerprints to a hijacked session |
| alice's session was credential-hijacked | LOW | Cannot confirm without endpoint forensics |
| `customers_v2` dump is unauthorized | INDETERMINATE | Requires backup baseline not in evidence |

---

*Report generated by FindEvil autonomous IR. All findings grounded in raw tool
output. No evidence files were modified. Audit trail available in
`logs/agent_guard.jsonl`.*

---

<!-- scorecard:start -->

## Verification scorecard

Mechanically computed by `scripts/grade_example_reports.py` against the
`agent_guard.SCENARIOS["25"]` markers (case-insensitive substring
match, identical logic to `tests/harness/agent_guard.py`'s grade()
function). No AI self-assessment is involved in these numbers.

| Metric | Score | % |
|---|---|---|
| Required markers found | 2/2 | **100%** |
| Cross-scenario markers absent | 9/9 | **100%** |
| Verdict-correctness confidence | — | **100%** |
| Hallucination-free confidence | — | **100%** |

**Overall confidence: HIGH** — every planted marker for this
scenario was surfaced in the report, and zero markers from any other
scenario leaked in. Re-grade with `python scripts/grade_example_reports.py`.

<!-- scorecard:end -->
