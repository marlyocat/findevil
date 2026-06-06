# Incident Report — datasci-prod-17
**Case:** Scenario 17 — IDS alerts: security-tool stops + cron injection  
**Evidence:** `evidence/attack-scenario-17-chaos`  
**Analyst:** Findevil autonomous IR (Claude / findevil MCP)  
**Report generated:** 2026-04-23 UTC  

---

## Executive Summary

**VERDICT: NO COMPROMISE — authorized chaos engineering exercise.**

All IDS-flagged activity on `datasci-prod-17` on 2026-04-22 falls within a pre-scheduled, fully documented chaos engineering fire-drill (Exercise ID: **CHAOS-2026-Q2-FIREDRILL**). Every action was performed by the named incident commander (`alice`), occurred within the declared exercise window (14:00–17:00 UTC), matches the signed-off action log verbatim, and was fully rolled back by 16:22 UTC — within the 17:30 UTC restoration SLA. No attacker activity is present.

---

## Operational Context

Before evaluating any technical signals, two authoritative host-level documents establish the operational context:

### `/etc/motd` (login banner)
The system message-of-the-day at the time of the events explicitly states:

```
CHAOS DAY 2026-Q2 — IN PROGRESS
  Exercise ID:        CHAOS-2026-Q2-FIREDRILL
  Window:             2026-04-22 14:00 UTC  ->  2026-04-22 17:00 UTC
  Coordinator:        sre-chaos@corp.internal
  Incident commander: alice
  In-scope actions:   service stops, iptables policy inserts, disk
                      I/O injection, auditd pause, bogus cron jobs
  Restoration SLA: all injected changes must be reverted by 17:30 UTC
```

### `/etc/chaos/chaos-day-2026-q2.md` (action log)
A pre-existing action catalogue (Exercise ID: CHAOS-2026-Q2-FIREDRILL) enumerates every planned injection on `datasci-prod-17` with timestamps and stated justifications:

| Planned time (UTC) | Planned action | Justification |
|--------------------|----------------|---------------|
| 14:05 | `systemctl stop auditd` | Test centralised log shipping when host auditd is down |
| 14:20 | `iptables -I INPUT 1 -p tcp --dport 443 -j DROP` (rollback 14:25) | Test runbook detection of blocked inbound HTTPS |
| 14:45 | `systemctl stop rsyslog` (rollback 14:50) | Test centralised logging resilience |
| 15:10 | Inject `/etc/cron.d/chaos-fake-download` with canary `curl` | Test SOC pipeline alert on suspicious cron |
| 16:20 | Revert all injected changes | End of exercise |

---

## Auth Log Analysis

**Source:** `evidence/attack-scenario-17-chaos/auth.log` (30 events)

| Metric | Count |
|--------|-------|
| Failed login attempts | 0 |
| Successful logins | 1 (alice, publickey, 10.0.2.15) |
| Sudo commands | 9 |
| Accounts added/deleted | 0 |
| Groups added | 0 |

Auth log triage: **no compromise indicators.**

---

## Unified Timeline — Cross-Referenced with Chaos Action Log

| Timestamp (UTC) | Actor | Action | Chaos Log Match |
|-----------------|-------|--------|-----------------|
| 2026-04-22 13:55:02 | alice@10.0.2.15 | SSH login (publickey) | Named IC arrives |
| 2026-04-22 13:58:10 | alice | `sudo tail -f /etc/chaos/chaos-day-2026-q2.md` | IC reviews action log before starting |
| 2026-04-22 14:05:00 | alice | `sudo systemctl stop auditd` | ✅ Matches 14:05 planned injection |
| 2026-04-22 14:20:00 | alice | `sudo iptables -I INPUT 1 -p tcp --dport 443 -j DROP` | ✅ Matches 14:20 planned injection |
| 2026-04-22 14:25:00 | alice | `sudo iptables -D INPUT -p tcp --dport 443 -j DROP` | ✅ Matches 14:25 planned rollback |
| 2026-04-22 14:45:00 | alice | `sudo systemctl stop rsyslog` | ✅ Matches 14:45 planned injection |
| 2026-04-22 14:50:00 | alice | `sudo systemctl start rsyslog` | ✅ Matches 14:50 planned rollback |
| 2026-04-22 15:10:00 | alice | `sudo tee /etc/cron.d/chaos-fake-download` | ✅ Matches 15:10 cron injection |
| 2026-04-22 16:20:00 | alice | `sudo rm /etc/cron.d/chaos-fake-download` | ✅ Matches 16:20 revert |
| 2026-04-22 16:22:00 | alice | `sudo systemctl start auditd` | ✅ Matches 16:20 revert (auditd restored) |

**All 9 sudo commands match the pre-documented chaos action log exactly.** Zero unexplained commands. Zero deviations in timing, actor, or scope.

---

## Persistence Scan

Filesystem snapshot (`fs/`) scanned for: cron, systemd units, SSH authorized_keys, shell init files, ld.so.preload, rc.local, UID-0 backdoors.

**Result: No persistence mechanisms found.**

The injected cron file (`/etc/cron.d/chaos-fake-download`) was removed at 16:20 UTC before the filesystem snapshot. The host is clean.

---

## Host Configuration Review

| Artifact | Finding |
|----------|---------|
| `sshd_config` | Hardened: `PermitRootLogin no`, `PasswordAuthentication no`, pubkey-only, `MaxAuthTries 3` |
| `passwd` | Four expected accounts: root, daemon, sshd, alice (UID 1002, SRE). No anomalous accounts. |
| `shadow` | root and sshd locked (`!*`). alice has standard SHA-512 hash. No empty passwords. |

---

## Key Distinctions from Real Attack

A naive heuristic match would flag `systemctl stop auditd` as attacker log-evasion and the cron injection as persistence. The following evidence distinguishes this from a real compromise:

1. **Single authenticated actor.** All activity originates from one account (`alice`) authenticated via SSH public key. No lateral movement, no privilege escalation from a low-privilege account, no credential stuffing.
2. **Pre-documented exercise.** The action log and motd both predate the activity window (they are not ex post facto justifications), and both specifically anticipate the exact commands that triggered the IDS.
3. **Structured rollbacks.** Every destructive action has a corresponding rollback within minutes, matching the documented plan. Attackers do not restore stopped logging services.
4. **Actor reads the action log first.** At 13:58 UTC, `alice` reviews `/etc/chaos/chaos-day-2026-q2.md` before executing anything — consistent with an IC following a runbook, not an attacker covering tracks.
5. **No unexplained commands.** All 9 sudo commands are accounted for in the chaos log. There is no residue.
6. **Zero persistence.** The final state of the filesystem is clean. An attacker who stopped auditd would leverage that window; here the only change during the audit gap is a logged iptables rule that was reverted immediately.

---

## Confidence Assessment

| Finding | Confidence |
|---------|-----------|
| Activity performed by alice (named IC) | HIGH — auth log, publickey auth |
| All actions within declared exercise window | HIGH — timestamps exact |
| Action log predates the exercise | HIGH — file present in snapshot, referenced at 13:58 |
| All injections rolled back | HIGH — rm and service-start entries confirmed |
| No attacker persistence | HIGH — persistence scan clean |
| No lateral movement or secondary actors | HIGH — zero other authenticated sessions |

---

## Recommendations

1. **No incident response action required.** Do not page on-call security. Do not isolate the host.
2. **Close the IDS alerts** as true-positive chaos exercise detections (expected). The SOC pipeline performed correctly by alerting; the alert classification should be updated to reflect the authorized exercise.
3. **Verify restoration** with the chaos coordinator (`sre-chaos@corp.internal`) that all rollbacks completed successfully and the host is back to baseline.
4. **Update IDS suppression workflow** to correlate against the chaos exercise calendar before auto-escalating during declared exercise windows. Consider tagging alerts generated within a documented chaos window with the exercise ID rather than escalating directly to IR.

---

## Conclusion

This is a **confirmed authorized chaos engineering exercise**, not a security incident. The IDS correctly detected the injected signals. The analyst (human or automated) must correlate operational context — the motd and chaos action log — before escalating. All observable activity is fully explained, fully authorized, and fully reversed. `datasci-prod-17` shows no signs of compromise.

---

<!-- scorecard:start -->

## Verification scorecard

Mechanically computed by `scripts/grade_example_reports.py` against the
`agent_guard.SCENARIOS["17"]` markers (case-insensitive substring
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
