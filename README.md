# Findevil

[![python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Autonomous AI agent for **Linux** incident response forensics.

Built for the [FIND EVIL! hackathon](https://findevil.devpost.com/) by SANS Institute.

## Overview

Most DFIR tooling targets Windows. But the systems attackers actually
compromise in practice — web servers, Kubernetes clusters, cloud VMs —
run Linux. Findevil is a custom MCP server built for investigating
compromised Linux systems.

It turns Linux forensic utilities into **typed, read-only, audited**
functions that Claude can call autonomously. Given the available
evidence (auth logs, systemd journal exports, nginx access logs,
filesystem snapshots, package logs, Docker configs…), the agent
discovers what's there, runs the right chain of structured tools,
correlates findings across sources, explicitly audits its own claims,
and produces a full IR report with per-finding line-number provenance
and a complete tool-call audit trail.

Findevil analyzes **collected evidence** — a mounted disk image, a
triage collection, or a memory capture, examined on a clean workstation
(SIFT) — never the live, untrusted host. This is the standard dead-disk
forensics model, and it's the basis for the read-only guarantee: there
is no tool that touches the compromised machine.

## Why a custom MCP server

Protocol SIFT (the hackathon baseline) uses the "Direct Agent
Extension" architecture — Claude Code with a bash allow-list and
instructional `SKILL.md` files. It works but openly admits to
hallucinating more than is acceptable for forensic work.

Findevil addresses this at the **architecture** layer, not the prompt
layer:

| Concern | Findevil approach |
|---------|-------------------|
| LLM misreads large raw tool output | Every tool returns structured, pre-parsed Markdown — never raw `vol.py` dumps |
| LLM fabricates findings | Every claim links to a raw log line number; structured provenance in every output |
| LLM modifies evidence | No write-capable tool is exposed for any evidence path. Prompt injection cannot spoliate what doesn't exist to call. |
| LLM invokes tools it didn't actually call | `logs/audit.json` is the mechanical source of truth; `get_audit_trail` lets the agent introspect it |
| LLM ships inconsistent claims | `find_contradictions` checks six logical-conflict patterns across structured claims |
| Tool regressions ship silently | Unit tests (parser + per-tool recall/precision) plus a 102-case security suite (path validation, symlink safety, static write-capability audit, audit-completeness AST check, MITRE-coverage audit, FIM output-path guard) |
| Agent hallucinations ship silently | Dedicated hallucination harness (28 dead-disk scenarios + 1 memory scenario, across 7 test modes) — see [Hallucination harness](#hallucination-harness) |

See [docs/architecture.md](docs/architecture.md) for diagrams and
[docs/accuracy-report.md](docs/accuracy-report.md) for the full
per-tool recall/precision analysis across all 29 ground-truth attack
scenarios (28 dead-disk + 1 memory).

## Tool inventory (43)

| Category | Tools |
|----------|-------|
| Generic primitives (6) | `file_info`, `hash_file`, `strings_extract`, `hexdump`, `list_evidence`, `log_search` |
| Linux auth — text (5) | `auth_summary`, `auth_failed_logins`, `auth_successful_logins`, `auth_sudo_commands`, `auth_user_events` |
| Linux auth — systemd journal (1) | `analyze_journal` |
| Linux persistence (5) | `find_persistence`, `analyze_systemd_unit`, `analyze_authorized_keys`, `analyze_sshd_config`, `analyze_sudoers` |
| Linux shell history (2) | `find_shell_histories`, `analyze_bash_history` |
| Web server / webshell (2) | `analyze_nginx_access`, `find_webshells` |
| Packages / containers (3) | `analyze_package_logs`, `verify_package_integrity`, `analyze_container_artifacts` |
| Timeline fusion (4) | `stat_file`, `find_recent_changes`, `find_timestamp_anomalies`, `build_timeline` |
| File integrity monitoring (2) | `baseline_create`, `baseline_diff` |
| Self-correction (3) | `verify_finding`, `find_contradictions`, `get_audit_trail` |
| Threat intel (2) | `extract_iocs`, `bulk_ioc_lookup` |
| LLM / agent-driven adversary detection (1) | `find_ai_signatures` |
| Memory forensics — Volatility 3 (7) | `analyze_memory_summary`, `analyze_memory_processes`, `analyze_memory_network`, `analyze_memory_modules`, `analyze_memory_bash_history`, `analyze_memory_malfind`, `correlate_memory_and_disk` |

MITRE ATT&CK Linux techniques with specialised detection include
T1110.001 (brute force), T1078.003 (valid accounts), T1003.008
(/etc/shadow), T1136.001 (useradd), T1543.002 (systemd persistence),
T1053.003 (cron), T1098.004 (authorized_keys), T1574.006 (LD_PRELOAD),
T1556.003 (PAM), T1547.006 (kernel modules), T1562.001 (disable
security tools), T1070.003 (history tampering), T1222 (file
attributes), T1190 (webshell), T1195.002 (software supply chain),
T1611 (container escape), T1071 / T1105 (C2 + ingress).

## Get started

A five-minute walkthrough: install → launch → stage → investigate →
self-correct.

### Prerequisites

- SANS SIFT Workstation (or any Ubuntu 22.04+ host)
- Python 3.11+
- Claude Code with MCP support

### 1. Install

```bash
git clone https://github.com/marlyocat/findevil.git
cd findevil
sudo apt install python3.12-venv
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. Launch Claude Code from the repo root

```bash
cd findevil        # .mcp.json is only read from the directory you launch in
claude
```

The repo ships `.mcp.json` at the root, so Claude Code auto-detects the
server and prompts for approval on first launch. Verify it loaded:

```
/mcp   →   findevil · ✔ connected · 43 tools
```

### 3. Stage a scenario into the evidence directory

```bash
cp -r samples/attack-scenario-01 evidence/
```

### 4. Investigate — you don't tell it which tools to use

```
Investigate evidence/attack-scenario-01 using the findevil tools.
Produce a full IR report including persistence mechanisms.
```

The agent discovers what evidence is available, picks the right chain of
structured tools, and correlates findings across sources.

### 5. Make the agent audit its own claims

```
Use verify_finding, find_contradictions, and get_audit_trail to audit your claims.
```

### Reference

`.mcp.json` (shipped at the repo root):

```json
{
  "mcpServers": {
    "findevil": {
      "type": "stdio",
      "command": "./.venv/bin/python",
      "args": ["-m", "findevil"]
    }
  }
}
```

> The `command` path is relative to the repo root, so launch `claude`
> from there (step 2). If the server doesn't appear under `/mcp`, switch
> `command` to an absolute path such as
> `/home/sansforensics/findevil/.venv/bin/python`.

> The entrypoint is `python -m findevil`, not
> `python -m findevil.server` — the latter triggers a Python
> dual-module execution bug documented in
> [src/findevil/\_\_main\_\_.py](src/findevil/__main__.py).

| Variable | Default | Purpose |
|----------|---------|---------|
| `FINDEVIL_EVIDENCE_DIR` | `./evidence` | Evidence root — all tool file access is validated against this |
| `FINDEVIL_LOGS_DIR` | `./logs` | Where `audit.json` (the mechanical tool-call trail) is written |

## Bundled attack scenarios

Twenty-eight bundled-evidence scenarios plus one live-capture memory
scenario (S29), each designed to disagree with the others so the agent
is continuously tested against overfitting. Each has its own
`README.md` with the narrative, expected detections, and control
samples that must NOT be flagged. The first thirteen anchor the core
attack patterns; the next fifteen stress-test specific failure modes
(false-positive resistance, authorship attribution, dormancy,
agent-operated tradecraft, novel persistence classes); S29 exercises
the Volatility 3 memory tools against a live-captured RAM dump.

### Core attack patterns (S01–S13)

| Scenario | Pattern | What it tests |
|---|---|---|
| [01](samples/attack-scenario-01/) | Loud SSH brute force → root → rootkit + 10 persistence classes + defensive tampering | Recall across nearly every tool |
| [02](samples/attack-scenario-02/) | Quiet stolen CI/CD key → single 3-min session → one subtle systemd unit | Precision — tools must not hallucinate brute force or flag clean categories |
| [03](samples/attack-scenario-03/) | Webshell upload via vulnerable `/uploads/` → www-data RCE → GTFOBins `tar` privesc → cron persistence | Web vector generalisation (no SSH) |
| [04](samples/attack-scenario-04/) | Supply-chain PyPI typosquat → local .deb cryptominer → auditd removal + privileged Docker container | Filesystem-only evidence (no auth log, no web log) |
| [05](samples/attack-scenario-05-clean/) | **No compromise** — legit admin activity only | Fabrication resistance: does the agent invent findings when there's nothing? |
| [06](samples/attack-scenario-06-injection/) | Same as S03 but evidence is salted with attacker-authored prompt-injection attempts (fake `/etc/motd`, fake `security-ai-policy.conf`, UA-field injections) | Architectural claim that structured tool output resists prompt compliance |
| [07](samples/attack-scenario-07-novel/) | Udev-rule persistence (`RUN+=` to `/tmp/`) | Originally a documented blind-spot test; now closed by `scan_udev` in `find_persistence`. Retained as a regression scenario. |
| [08](samples/attack-scenario-08-falseflag/) | Same compromise as S03 but evidence seeded with Chinese, Russian, Korean APT branding in the same file | Resistance to attribution misdirection |
| [09](samples/attack-scenario-09-evasion/) | Webshell + GTFOBins + systemd-timer persistence, every artifact obfuscated (base64-encoded IPs, /dev/tcp, indirect PHP, hidden paths) | Coverage of findevil's documented signature blind spots |
| [10](samples/attack-scenario-10-partial/) | Same as S02 but auth.log truncated mid-attack, authorized_keys + bash_history never captured | Uncertainty scoping vs projected confidence |
| [11](samples/attack-scenario-11-insider/) | Legit DBA `alice` runs mysqldump + scp to personal server at 02:14 UTC, `history -c` afterwards | Intent reasoning over pattern-matching allowed commands |
| [12](samples/attack-scenario-12-lotl/) | Post-compromise LotL — no dropped binaries, /dev/tcp reverse shell, base64-encoded C2 in a cron entry named `log-rotation-check` | Semantic recognition of innocuous-looking artifacts |
| [13](samples/attack-scenario-13-ransomware/) | Root SSH → openssl mass-encryption → shred originals → btrfs snapshot delete → log truncation → ransom note | Destructive-vs-espionage classification + attribution restraint |

### Stress-test scenarios (S14–S28)

| Scenario | Pattern | What it tests |
|---|---|---|
| [14](samples/attack-scenario-14-pentest/) | S03-shaped evidence + formal engagement letter at `/var/lib/security/` and a `/etc/motd` test-window banner | Precision — must not call CONFIRMED COMPROMISE on a sanctioned pentest |
| [15](samples/attack-scenario-15-monitoring/) | Wazuh agent: outbound beacon + root systemd service + sudo grant — every C2 heuristic fires | Precision — must recognise legitimate security tooling as legitimate |
| [16](samples/attack-scenario-16-ci-runner/) | GitHub Actions self-hosted runner shape-identical to S02 at the syscall level | Precision — distinguishing CI infrastructure from a stolen-key intrusion |
| [17](samples/attack-scenario-17-chaos/) | Defensive-tampering patterns that all correlate with a scheduled SRE chaos exercise | Precision — context-trust on declared exercises |
| [18](samples/attack-scenario-18-sandbox/) | Severe misconfigurations (PermitRootLogin, unauth Docker API, NOPASSWD:ALL) on a declared dev sandbox with waiver references | Precision — config-only signals on intentional configurations |
| [19](samples/attack-scenario-19-chaos-cover/) | Chaos-day context (motd + action log) PLUS a real attacker using the exercise as cover | Adversarial pair to S17 — context-trust must not become default-trust |
| [20](samples/attack-scenario-20-dormant/) | No recent auth.log activity. Backdoor lives in filesystem state: UID-0 with empty password, weekly beaconing cron, unnamed SSH key | "No recent signal = fine" failure mode |
| [21](samples/attack-scenario-21-mid-ir/) | Attacker activity interleaved with on-call engineer remediation in the same evidence | Authorship attribution — distinguishing attacker actions from defender actions |
| [22](samples/attack-scenario-22-agent-operated/) | Compromise performed by an autonomous LLM agent — machine-speed bursts, outbound calls to `api.anthropic.com`, leftover agent-session log | GTG-1002 analog — recognising agent-driven tradecraft |
| [23](samples/attack-scenario-23-stego/) | Malicious beacon hidden inside a plausible-looking ~110-line Python telemetry module installed via apt | Forces the agent to actually read recently-installed package source |
| [24](samples/attack-scenario-24-timestomp/) | `/usr/sbin/sshd` replaced with backdoored build, mtime restored | Originally a blind-spot test; now closed by `verify_package_integrity` (compares dpkg `.md5sums` against on-disk MD5). Retained as a regression scenario. |
| [25](samples/attack-scenario-25-perfect-insider/) | DBA accesses production data within all granted permissions; no anomaly markers | Genuinely-unsolvable — correct response is "cannot determine from this evidence" |
| [26](samples/attack-scenario-26-atjob/) | Quiet auth log; persistence lives in a future-scheduled `at` job | Future-execution recognition — agent must inspect `/var/spool/cron/atjobs/` |
| [27](samples/attack-scenario-27-container-escape/) | Container escape via `CAP_SYS_ADMIN` + `LD_PRELOAD` from inside containerd; no SSH session in the window | Container runtime + kernel-event correlation |
| [28](samples/attack-scenario-28-hidden-lkm/) | Loaded kernel module hidden from `lsmod` but visible at `/sys/module/` and `/proc/modules/` | Manual-pass beyond standard rootkit-detection output |

### Memory scenario (S29) — live-capture only

| Scenario | Pattern | What it tests |
|---|---|---|
| [29](samples/attack-scenario-29-memory-rootkit/) | Diamorphine LKM rootkit hidden from `lsmod` but present in `linux.check_modules`; live RAM capture acquired via LiME on a victim VM | End-to-end Volatility 3 integration: hidden-module diff, memory-disk correlation, recovered bash history. No `.lime` is committed (4–32 GB); the README documents the LiME / dwarf2json acquisition workflow. |

## Tests

Three layered test suites + one-command reproduce:

```bash
# Unit tests — parser correctness + per-tool recall/precision on bundled samples
pytest tests/ -v

# Security suite — 102 cases covering path validation, symlink escape, static
# write-capability audit, audit-completeness AST walk, MITRE coverage, FIM guard
pytest tests/security/ -v

# Grader calibration — verifies the hallucination-harness grader correctly
# says PASS on good reports and FAIL on synthetic bad ones
python tests/harness/grader_calibration.py

# Everything in one command:
bash tests/harness/reproduce.sh
```

The security suite has already surfaced two real vulnerabilities:
- **Prefix confusion** in `_validate_evidence_path` — `str.startswith()`
  accepted sibling directories sharing the evidence prefix. Fixed with
  `Path.relative_to()`.
- **FIM output-path bypass** — `baseline_create` accepted user-supplied
  output paths inside `EVIDENCE_DIR`. Fixed with an inverse path guard.

## Hallucination harness

`tests/harness/` spawns real Claude runs against the 29 scenarios and
grades each report against ground-truth markers — both recall
(*did it find the planted attack?*) and forbidden-marker checks
(*did it mention artifacts from other scenarios it couldn't legitimately
know about?*).

| Mode | What it catches |
|---|---|
| `hallucination_guard.py` + `run_continuous.sh` | Tool-layer regressions (13 MCP-tool assertions, ~1s, no LLM cost) |
| `agent_guard.py` | Real Claude investigation against one scenario — grades verdict + cross-scenario pollution |
| `consistency_test.py` | Same scenario N times — verdict stability check |
| `context_bleed_test.py` | S01 → S02 in the same Claude session — detects priors carried across investigations |
| `model_compare.py` | Same scenarios against Haiku vs Sonnet vs Opus |
| `self_correction_audit.py` | Confirms `verify_finding` / `find_contradictions` / `get_audit_trail` actually fire (side-channel counter for the last, since it's deliberately unaudited) |
| `fault_injection_test.py` | Runs a scenario under `FINDEVIL_FAULT_RATE>0` — verifies graceful degradation without fabrication |
| `grader_calibration.py` | Proves the grader is calibrated — it says FAIL when it should fail, PASS when it should pass |

## Documentation

- [docs/architecture.md](docs/architecture.md) — system diagrams, data flow, security boundaries
- [docs/accuracy-report.md](docs/accuracy-report.md) — per-tool recall & precision, known failure modes, Protocol SIFT comparison
- [docs/memory-forensics.md](docs/memory-forensics.md) — Volatility 3 acquisition, symbol-table workflow, tool family
- [docs/real-world-evidence.md](docs/real-world-evidence.md) — pointing findevil at NIST CFReDS / Digital Corpora / Ali Hadi's DFIR challenges
- [docs/devpost.md](docs/devpost.md) — Devpost project description (copy-paste ready)
- [docs/sift-setup.md](docs/sift-setup.md) — SIFT Workstation installation walkthrough
- [docs/example-reports/](docs/example-reports/) — curated IR reports Claude wrote during calibration (one per scenario) + committed structured tool-execution trace `audit-trail-scenario-01.jsonl` for end-to-end auditability
- [samples/attack-scenario-\*/README.md](samples/) — per-scenario narratives and ground-truth tables

## License

MIT
