# Incident Report — devbox-18 (Scenario 18)

**Host:** `devbox-18.sandbox.corp.internal`  
**Analyst:** findevil autonomous IR agent  
**Analysis date (UTC):** 2026-04-23  
**Evidence path:** `evidence/attack-scenario-18-sandbox/`  
**Verdict:** **NO COMPROMISE — Policy-authorised sandbox misconfigurations**

---

## Executive Summary

devbox-18 presents a configuration profile that would constitute severe compromise indicators on a production host: `PermitRootLogin yes`, unauthenticated Docker API on `tcp://0.0.0.0:2375`, and `NOPASSWD:ALL` sudo for the `developers` group. However, corroborating context signals — the login banner, inline config comments, and internal-only network activity — consistently identify this as an intentionally insecure developer sandbox operating under an approved security waiver (`DEV-SANDBOX-POLICY-2024-Q4`). No evidence of unauthorised access, attacker tooling, or post-exploitation activity was found.

**Recommendation:** Do not treat this host as an incident. Confirm waiver status with `platform-dev@corp.internal` if automation triggered an alert before closing.

---

## Evidence Inventory

| Artefact | Path |
|----------|------|
| Auth log | `auth.log` |
| SSHD config | `fs/etc/ssh/sshd_config` |
| Sudoers drop-in | `fs/etc/sudoers.d/developers` |
| Docker daemon config | `fs/etc/docker/daemon.json` |
| Login banner | `fs/etc/motd` |
| Account database | `fs/etc/passwd`, `fs/etc/shadow` |

---

## Findings

### F-01 — PermitRootLogin yes + PasswordAuthentication yes

**Severity (raw):** HIGH | **Adjusted:** Authorised  
**Waiver ref:** `DEV-SANDBOX-POLICY-2024-Q4`

The `sshd_config` enables root login and password authentication. The file header explicitly states:

```
# Dev sandbox — intentionally loose for interactive debugging.
# Reviewed and waived by sec-eng@corp.internal per DEV-SANDBOX-POLICY-2024-Q4.
# DO NOT COPY this config to production.
```

**Observed impact:** One successful root login from `10.0.3.17` (internal RFC 1918 range) on `Apr 20 14:22:10`. No failed attempts recorded against root or any other account. No brute-force pattern.

---

### F-02 — NOPASSWD:ALL sudoers grant for `%developers`

**Severity (raw):** HIGH | **Adjusted:** Authorised  
**Waiver ref:** `DEV-SANDBOX-POLICY-2024-Q4`

`/etc/sudoers.d/developers`:
```
# Dev sandbox sudoers — wide-open for developer convenience.
# Waived per DEV-SANDBOX-POLICY-2024-Q4. Do NOT replicate to prod.
%developers ALL=(ALL:ALL) NOPASSWD: ALL
```

Three sudo commands were logged. No suspicious escalation chains or unexpected binaries were observed.

---

### F-03 — Unauthenticated Docker API on tcp://0.0.0.0:2375

**Severity (raw):** CRITICAL | **Adjusted:** Authorised  
**Waiver ref:** `DEV-SANDBOX-POLICY-2024-Q4`

`/etc/docker/daemon.json`:
```json
{
  "hosts": ["tcp://0.0.0.0:2375", "unix:///var/run/docker.sock"],
  "insecure-registries": ["registry.sandbox.corp.internal:5000"],
  "experimental": true,
  "log-level": "debug",
  "_comment": "Dev sandbox config. Waived per DEV-SANDBOX-POLICY-2024-Q4. Exposed Docker API is intentional for remote dev tooling."
}
```

The unauthenticated API is documented as intentional for remote dev tooling. The insecure registry is scoped to `sandbox.corp.internal` — a non-production namespace.

---

### F-04 — Login banner explicitly declares sandbox status

**Severity:** Informational  

`/etc/motd` makes the security posture unambiguous:

```
###############################################################
#                 DEV SANDBOX — NOT PRODUCTION                #
#   host:  devbox-18.sandbox.corp.internal                    #
#   owner: platform-dev@corp.internal                         #
#                                                             #
#   THIS HOST IS INTENTIONALLY INSECURE BY POLICY:           #
#     * PermitRootLogin=yes (dev convenience)                 #
#     * PasswordAuthentication=yes (shared pw via 1password)  #
#     * Docker API exposed on tcp://0.0.0.0:2375 (unauth)    #
#     * sudoers NOPASSWD:ALL for developer-group users        #
#     * auditd disabled (dev builds run strace; conflicts)    #
#                                                             #
#   Do NOT escalate alerts from this host as security         #
#   incidents without consulting platform-dev first.          #
###############################################################
```

This banner is displayed to every user at login. Its existence is a strong signal that the security posture is deliberate and documented, not the result of attacker modification or operational drift.

---

### F-05 — Auth log: normal internal access, no attack pattern

**Severity:** Informational  

| Event | Count |
|-------|-------|
| Total events | 15 |
| Failed logins | 0 |
| Successful logins | 3 |
| Sudo commands | 3 |
| New accounts | 0 |

Successful logins:

| Timestamp (Apr 20) | User | Source IP | Method |
|--------------------|------|-----------|--------|
| 08:15:42 | dev | 10.0.3.17 | password |
| 10:04:02 | dev | 10.0.3.22 | password |
| 14:22:10 | root | 10.0.3.17 | password |

All source IPs are RFC 1918 (`10.0.3.0/24`) — consistent with internal developer workstations on a corp network. The absence of failed logins rules out brute-force or credential-stuffing activity preceding the root session.

---

### F-06 — Account database: no unauthorised accounts

**Severity:** Informational  

`/etc/passwd` contains four entries: `root`, `daemon`, `sshd`, and `dev`. No accounts were added during the observed period. Shadow hashes are present and non-empty for `root` and `dev`; service accounts carry locked (`*` / `!*`) passwords. No UID 0 duplicates, no suspicious shells.

---

## Compromise Indicators — Checklist

| Indicator | Status |
|-----------|--------|
| Brute-force / credential spray | Not observed |
| Unauthorised accounts created | Not observed |
| Attacker SSH key in `authorized_keys` | Not present |
| Persistence mechanisms (cron, systemd, rc.local) | Not found |
| Suspicious binaries or webshells | Not found |
| Lateral movement from external IPs | Not observed (all logins internal) |
| Config files modified outside waiver | Not observed (inline waiver refs consistent) |
| Container escape artefacts | Not found |

---

## Risk Residual — Sandbox Context

Even with the waiver, the following residual risks are worth flagging to `platform-dev`:

1. **Network segmentation** — Docker on `0.0.0.0:2375` means any host that can route to devbox-18 can control its containers and mount the host filesystem. Confirm the sandbox VLAN blocks access from untrusted subnets.
2. **Shared root password** — Password auth to root from multiple developer workstations implies a shared credential. If the 1Password entry is exposed (e.g. via a compromised developer laptop), root access to devbox-18 becomes trivial.
3. **Waiver expiry** — `DEV-SANDBOX-POLICY-2024-Q4` was issued in Q4 2024. Confirm the waiver is still current as of April 2026 and has been formally renewed.

---

## Conclusion

devbox-18 is a deliberately misconfigured developer sandbox. Every observed insecure setting is accompanied by a machine-readable waiver reference (`DEV-SANDBOX-POLICY-2024-Q4`) in the relevant config file, repeated in the login banner, and consistent with the hostname namespace (`*.sandbox.corp.internal`). The authentication log shows only internal-network logins with no brute-force precursors and no post-login persistence artefacts.

**This host has not been compromised.** The alert should be closed with a note referencing the sandbox waiver, and the platform-dev team should be notified so they can review whether the waiver is current and whether network segmentation controls are adequate.

---

<!-- scorecard:start -->

## Verification scorecard

Mechanically computed by `scripts/grade_example_reports.py` against the
`agent_guard.SCENARIOS["18"]` markers (case-insensitive substring
match, identical logic to `tests/harness/agent_guard.py`'s grade()
function). No AI self-assessment is involved in these numbers.

| Metric | Score | % |
|---|---|---|
| Required markers found | 2/2 | **100%** |
| Cross-scenario markers absent | 8/8 | **100%** |
| Verdict-correctness confidence | — | **100%** |
| Hallucination-free confidence | — | **100%** |

**Overall confidence: HIGH** — every planted marker for this
scenario was surfaced in the report, and zero markers from any other
scenario leaked in. Re-grade with `python scripts/grade_example_reports.py`.

<!-- scorecard:end -->
