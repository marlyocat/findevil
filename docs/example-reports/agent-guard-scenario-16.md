# Incident Report — ci-runner-16 (Scenario 16)

**Analyst:** findevil autonomous IR  
**Date (UTC):** 2026-04-23  
**Evidence root:** `evidence/attack-scenario-16-ci-runner/`  
**Verdict:** **NO COMPROMISE — Legitimate CI Infrastructure**

---

## Executive Summary

The persistent root systemd service and outbound API polling observed on `ci-runner-16` are the documented, expected behaviour of a GitHub Actions self-hosted runner registered to the `corp-acme` GitHub organisation. Every artifact examined is consistent with a standard runner installation. No indicators of compromise were found.

---

## Evidence Examined

| Artifact | Path |
|----------|------|
| Systemd service unit | `fs/etc/systemd/system/actions.runner.corp-acme.prod-runner-01.service` |
| Runner registration config | `fs/opt/actions-runner/.runner` |
| Sudoers grant | `fs/etc/sudoers.d/github-actions` |
| SSH authorized_keys | `fs/home/github-actions/.ssh/authorized_keys` |
| sshd_config | `fs/etc/ssh/sshd_config` |
| Account database | `fs/etc/passwd`, `fs/etc/shadow` |
| Auth log | `auth.log` |

---

## Findings

### 1. Systemd Service — LEGITIMATE

```ini
[Unit]
Description=GitHub Actions Runner (corp-acme.prod-runner-01)
Documentation=https://docs.github.com/en/actions/hosting-your-own-runners
After=network-online.target

[Service]
Type=simple
User=github-actions
WorkingDirectory=/opt/actions-runner
ExecStart=/opt/actions-runner/runsvc.sh
Restart=on-failure
Environment=RUNNER_ALLOW_RUNASROOT=0

[Install]
WantedBy=multi-user.target
```

**Assessment:** This is the canonical GitHub Actions self-hosted runner service unit, installed verbatim by the `config.sh` / `svc.sh` bootstrap scripts.

Key legitimacy indicators:
- `Documentation=` points to `https://docs.github.com/en/actions/hosting-your-own-runners` — the official GitHub self-hosted runner docs.
- `User=github-actions` — the service runs as an unprivileged service account, **not root**.
- `RUNNER_ALLOW_RUNASROOT=0` — explicitly prohibits root execution, the opposite of what an attacker implant would set.
- `ExecStart=/opt/actions-runner/runsvc.sh` — the standard runner wrapper script installed by `svc.sh install`.
- No shell downloads, no inline base64, no world-writable paths.

The outbound HTTPS long-polling to `api.github.com` and `*.actions.githubusercontent.com` is the documented GitHub Actions runner job-pickup mechanism. It is not a C2 channel.

---

### 2. Runner Registration Config — LEGITIMATE

```json
{
  "agentId": 47,
  "agentName": "prod-runner-01",
  "poolId": 1,
  "poolName": "Default",
  "ephemeral": false,
  "disableUpdate": false,
  "serverUrl": "https://api.github.com",
  "gitHubUrl": "https://github.com/corp-acme",
  "workFolder": "_work"
}
```

**Assessment:** The runner is registered to the `corp-acme` GitHub organisation via the official `https://api.github.com` endpoint. The `agentId` (47) and `agentName` (`prod-runner-01`) are consistent with a production runner in a fleet. No attacker-controlled server URL present.

---

### 3. Sudoers Grant — INTENTIONAL, SECURITY-REVIEWED

```
# GitHub Actions runner sudoers — argv-constrained to Docker + systemctl
# reload only. Required for the runner's CI workflows that build Docker
# images and restart the app under test. Reviewed per SEC-2026-03-11.
github-actions ALL=(root) NOPASSWD: /usr/bin/docker, /usr/bin/systemctl reload corp-app
```

**Assessment:** The grant permits only `docker` and `systemctl reload corp-app`, which matches exactly the commands observed in the auth log during CI job execution (see §5). The file carries a security review ticket reference (`SEC-2026-03-11`), indicating this grant was deliberately authorised.

**Risk note (not a compromise indicator):** An unrestricted `NOPASSWD: /usr/bin/docker` grant is functionally root-equivalent — any workflow job could mount the host filesystem via a container volume. This is a known architectural risk of Docker-based CI and should be tracked in the security backlog. However, it reflects deliberate design, not attacker modification.

---

### 4. Account Inventory — NO ANOMALIES

| Account | UID | Shell | Password | Notes |
|---------|-----|-------|----------|-------|
| root | 0 | /bin/bash | `!*` (locked) | Normal |
| daemon | 1 | /usr/sbin/nologin | `*` (locked) | Normal |
| sshd | 104 | /usr/sbin/nologin | `!*` (locked) | Normal |
| github-actions | 1500 | /bin/bash | `!` (disabled) | Service account — no password login |
| alice | 1002 | /bin/bash | SHA-512 hash | Admin user |

No unexpected accounts. The `github-actions` account has password login disabled (`!` in shadow), which is correct for a service account that authenticates only via SSH key.

---

### 5. SSH Configuration — HARDENED

```
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
```

**Assessment:** Key-only authentication, root login prohibited, brute-force limited to 3 attempts. No attacker-introduced weakening.

The single `authorized_keys` entry for `github-actions` carries the comment `github-actions-runner-bootstrap@corp-acme-ci`, consistent with the bootstrap key used during runner registration. No additional or unexpected keys present.

---

### 6. Auth Log — NORMAL CI OPERATIONS

```
Apr 18 09:02:11  alice logged in via SSH (pubkey) from 10.0.2.15
Apr 18 09:03:42  alice: sudo systemctl status actions.runner.corp-acme.prod-runner-01.service
Apr 18 09:04:21  alice session closed

Apr 18 10:12:55  github-actions: sudo docker build -t corp-app:pr-2181 .   (4m38s)
Apr 18 10:17:38  github-actions: sudo docker push ghcr.io/corp-acme/corp-app:pr-2181
Apr 18 10:18:15  github-actions: sudo systemctl reload corp-app

Apr 18 14:02:45  github-actions: sudo docker build -t corp-app:pr-2182 .   (4m25s)
```

**Assessment:**
- Alice (admin) performed a routine status check of the runner service and disconnected — normal maintenance.
- The `github-actions` account executed two full CI build-push-deploy cycles for pull requests 2181 and 2182. All four sudo commands are within the exact bounds of the sudoers grant.
- No failed logins. No lateral movement attempts. No unexpected source IPs. No sessions outside business hours beyond the single cron tick at 00:00.

---

## Ruling Out C2 Similarities

This runner is structurally identical to the stolen-credential C2 implant pattern (new service + service account + outbound HTTPS + elevated sudo). The distinguishing factors that confirm legitimacy:

| Indicator | C2 Implant Pattern | This System |
|-----------|-------------------|-------------|
| `Documentation=` in unit | Absent or bogus | Official GitHub docs URL |
| `serverUrl` in runner config | Attacker-controlled IP/domain | `https://api.github.com` |
| Service account password | Often enabled | Disabled (`!`) |
| SSH key comment | Random or absent | `github-actions-runner-bootstrap@corp-acme-ci` |
| Sudo commands observed | Arbitrary / unexpected | Exactly match sudoers whitelist |
| Security review ticket | Absent | `SEC-2026-03-11` present |
| `RUNNER_ALLOW_RUNASROOT` | Not set (allows root) | Explicitly `0` |

---

## Verdict

**NO COMPROMISE DETECTED.**

`ci-runner-16` is a legitimately installed and operating GitHub Actions self-hosted runner. The outbound API polling, persistent systemd service, dedicated service account, and elevated sudo grants are all components of the standard GitHub Actions self-hosted runner architecture, deployed according to documented best practices and with evidence of a security review process.

**Recommended follow-up (risk reduction, not IR):**
1. Scope the `docker` sudo grant to a specific image prefix or use the Docker socket group model with audit logging to reduce the root-equivalent exposure.
2. Consider rotating the `github-actions` SSH bootstrap key post-registration if it is no longer needed for runner re-registration.
3. Verify that runner tokens are rotated on the schedule recommended by GitHub (90 days).

---

<!-- scorecard:start -->

## Verification scorecard

Mechanically computed by `scripts/grade_example_reports.py` against the
`agent_guard.SCENARIOS["16"]` markers (case-insensitive substring
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
