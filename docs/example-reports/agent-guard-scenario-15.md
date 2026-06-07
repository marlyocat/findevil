# Incident Response Report — webserver-prod-15
**Scenario:** 15 — Persistent root service beaconing to internal IP  
**Analyst:** FindEvil DFIR Orchestrator  
**Date (UTC):** 2026-04-23  
**Evidence root:** `evidence/attack-scenario-15-monitoring/`  
**Verdict:** NO COMPROMISE — False Positive (Legitimate Wazuh Monitoring Agent)

---

## Executive Summary

The automated scan correctly identified a persistent root-level systemd service beaconing to an internal IP every 60 seconds. Investigation confirms this is **not a compromise**. The service is the Wazuh Host-based Intrusion Detection System (HIDS) agent — a corporate-standard security monitoring tool deployed and maintained by `sec-eng@corp.internal`. All observed behavior (periodic TCP/1514 connections to `wazuh.corp.internal`, privileged filesystem access, diagnostic sudo grants) is consistent with and expected from a correctly functioning Wazuh agent. No other indicators of compromise were found across any artifact category.

---

## Evidence Examined

| Artifact | Path | Status |
|----------|------|--------|
| Authentication log | `auth.log` | Analyzed |
| Systemd unit | `fs/etc/systemd/system/wazuh-agent.service` | Analyzed |
| Wazuh agent config | `fs/var/ossec/etc/ossec.conf` | Analyzed |
| Sudoers grant | `fs/etc/sudoers.d/wazuh` | Analyzed |
| Account database | `fs/etc/passwd`, `fs/etc/shadow` | Analyzed |
| SSH daemon config | `fs/etc/ssh/sshd_config` | Analyzed |
| Corporate CA cert | `fs/etc/pki/tls/certs/corp-internal-ca.pem` | Present |
| Web roots | `fs/var/www/`, `fs/srv/` | Not present |

---

## Unified Timeline

| Timestamp (UTC) | Actor | Action | Assessment |
|-----------------|-------|--------|------------|
| 2026-04-18T08:15:42 | `alice@10.0.2.15` | SSH login (publickey) | Normal — authorized admin |
| 2026-04-18T08:17:05 | `alice` | `sudo journalctl -u wazuh-agent --since '1 hour ago'` | Normal — checking wazuh-agent service status |
| 2026-04-18T10:02:11 | `wazuh` (service acct) | `sudo ss -tunlp` | Normal — Wazuh network discovery collection |
| 2026-04-18T10:32:08 | `wazuh` (service acct) | `sudo lsof -i` | Normal — Wazuh open-file network monitoring |
| 2026-04-18T14:22:51 | `bob@10.0.2.22` | SSH login (publickey) | Normal — authorized ops user |
| 2026-04-18T14:25:17 | `bob` | `sudo systemctl restart nginx` | Normal — routine web server management |

---

## Finding Analysis

### F-01 — Wazuh HIDS Agent: Periodic TCP/1514 Beacon (INFO — EXPECTED)

**Trigger:** Persistent systemd service running as root; outbound TCP connections to an internal IP every ~60 seconds.

**Assessment:** The service is `/etc/systemd/system/wazuh-agent.service`. The unit file explicitly identifies itself:

```ini
[Unit]
Description=Wazuh Agent — security monitoring endpoint (corp-wide standard)
Documentation=https://documentation.wazuh.com/current/user-manual/agents/
```

`/var/ossec/etc/ossec.conf` confirms the agent connects to `wazuh.corp.internal` on port 1514 (the documented Wazuh agent-to-manager protocol port) with a `notify_time` of 60 seconds. The connection uses TLS validated against the corporate internal CA at `/etc/pki/tls/certs/corp-internal-ca.pem`. The agent name is `webserver-prod-15`, consistent with the host name. The config is annotated `Do NOT modify without change-management approval. Contact: sec-eng@corp.internal`.

**Conclusion:** The beaconing is the Wazuh heartbeat protocol — structurally identical to C2 beaconing in frequency and directionality but unambiguously identified by agent config, unit metadata, and installation paths (`/var/ossec/` is the canonical Wazuh installation tree). Not malicious.

---

### F-02 — Wazuh Sudoers Grant: Privileged Diagnostic Commands (INFO — EXPECTED)

**Trigger:** `fs/etc/sudoers.d/wazuh` grants NOPASSWD sudo to the `wazuh` service account.

**Assessment:** The grant is tightly scoped to six specific read-only diagnostic binaries:

```
wazuh ALL=(root) NOPASSWD: /usr/bin/lsof, /usr/bin/netstat, /usr/bin/ss, \
    /usr/sbin/iptables -L, /usr/bin/who, /usr/bin/last
```

These are the exact commands Wazuh uses for network and session discovery. The sudoers file is commented as "Standard corp rollout. Not a general sudoers grant." Both `sudo ss -tunlp` and `sudo lsof -i` invocations observed in the auth log are from the `wazuh` service account during the analysis window — all within scope of the grant.

**Conclusion:** Legitimate, scoped privilege grant. No over-permission observed.

---

### F-03 — Authentication Log: No Anomalies (CLEAR)

- **Failed logins:** 0
- **Successful logins:** 2 (`alice` and `bob`, both via SSH public key from internal RFC1918 addresses)
- **Sudo commands:** 4 (all routine — wazuh monitoring, admin log check, nginx restart)
- **Account changes:** None (0 users added/removed/modified)

No brute-force attempts, no credential stuffing, no suspicious source IPs, no sessions from unexpected users.

---

### F-04 — SSH Hardening: Compliant (CLEAR)

```
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
```

Root cannot log in directly. Password authentication is disabled. This significantly reduces the attack surface and is consistent with a production hardened Linux host.

---

### F-05 — Account Database: No Unauthorized Accounts (CLEAR)

All accounts are accounted for:

| Account | UID | Shell | Purpose |
|---------|-----|-------|---------|
| `root` | 0 | `/bin/bash` | System |
| `daemon` | 1 | `/usr/sbin/nologin` | System |
| `sshd` | 104 | `/usr/sbin/nologin` | SSH daemon |
| `wazuh` | 998 | `/usr/sbin/nologin` | Wazuh service account (no interactive shell) |
| `alice` | 1002 | `/bin/bash` | Admin user (authorized) |
| `bob` | 1003 | `/bin/bash` | Ops user (authorized) |

The `wazuh` service account correctly has no login shell (`/usr/sbin/nologin`). No UID-0 backdoors, no unexpected accounts.

---

### F-06 — Persistence Scan: No Malicious Persistence (CLEAR)

The findevil persistence scanner returned a single `info`-level finding: the `wazuh-agent.service` systemd unit, classified as a known monitoring tool (not flagged). No findings in:
- Shell init files (`~/.bashrc`, `/etc/profile.d/`)
- Cron jobs (`/etc/cron*`, `/var/spool/cron/`)
- `/etc/ld.so.preload` (rootkit library injection vector)
- `/etc/rc.local` or init.d scripts
- Additional SSH `authorized_keys` backdoors

---

### F-07 — Webshell Scan: Clean (CLEAR)

No web roots present (`/var/www/`, `/srv/http/`, etc.). Zero files with executable web extensions scanned. No webshell indicators found.

---

## IOCs

None identified. The only network destination observed (`wazuh.corp.internal`, TCP/1514) is an internal corporate hostname resolved and maintained by `sec-eng@corp.internal`. No public IPs, no external domains, no file hashes of concern.

---

## False Positive Analysis

This alert is a **classic false positive** from automated heuristics over-triggering on legitimate security tooling. The Wazuh agent exhibits three behaviors that individually pattern-match to malware signatures:

| Observed Behavior | Naive Interpretation | Actual Explanation |
|-------------------|---------------------|-------------------|
| Persistent systemd unit running as root | Malware persistence | Wazuh agent requires root for filesystem integrity monitoring |
| TCP connection every 60 seconds to an IP | C2 beaconing | Wazuh `notify_time=60` heartbeat to manager |
| Privileged sudoers grant | Privilege escalation backdoor | Scoped read-only grant for network discovery |

The differentiating signals that allow confident dismissal:
1. **Internal destination only** — `wazuh.corp.internal` resolves to an internal asset; there is no external C2 contact.
2. **Documented installation paths** — `/var/ossec/` is Wazuh's well-known canonical installation directory, not a hiding location.
3. **Certificate pinning to corporate CA** — the agent validates the manager certificate against the internal CA, preventing MITM and confirming the connection endpoint is the corporate Wazuh manager.
4. **Explicit unit metadata** — the systemd unit carries a human-readable description, a documentation URL, and inline comments authored by security engineering.
5. **Zero other indicators** — no brute force, no unauthorized accounts, no webshells, no suspicious binaries, no anomalous cron, no LD_PRELOAD manipulation.

---

## Conclusion

**VERDICT: NO COMPROMISE**

`webserver-prod-15` is clean. The automated alert was generated by the Wazuh HIDS agent operating as designed — a legitimate, corporate-standard security monitoring tool deployed by `sec-eng@corp.internal`. All artifacts on this host are consistent with a normally operating production Linux web server with a properly configured Wazuh agent.

**Recommended action:** Close alert. Tune the scanning rule to recognize Wazuh agent service signatures (unit description match, `/var/ossec/` installation path, port 1514 to an internal destination) as a known-good baseline to reduce future false positives of this class.

---

*Report generated by FindEvil DFIR Orchestrator | Evidence integrity: read-only, unmodified | Chain of custody maintained*

---

<!-- scorecard:start -->

## Verification scorecard

Mechanically computed by `scripts/grade_example_reports.py` against the
`agent_guard.SCENARIOS["15"]` markers (case-insensitive substring
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
