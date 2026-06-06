# Example IR reports

Each file here is a **frozen artifact** of one Claude Code investigation
during calibration. They were produced by `tests/harness/agent_guard.py`
running headless against the bundled attack scenarios and writing the
agent's final report to disk; we then committed the reports verbatim
so judges can see what the system actually produces without setting up
a SIFT VM.

## How to read these

- The investigation transcripts at the top of each file follow
  Claude's natural reporting style — they are not templated.
- A **Verification scorecard** block at the bottom of each report
  was added retroactively by `scripts/grade_example_reports.py`.
  It runs the same `agent_guard.grade()` logic the harness uses,
  computes recall and hallucination-resistance percentages, and
  pins the overall confidence level. The scorecard is mechanical —
  no AI self-assessment goes into it.

## End-to-end auditability — committed example run (scenario 01)

To satisfy the hackathon's "agent communication + tool execution
sequence with timestamps" requirement, scenario 01 ships a complete
captured run alongside its report:

| Artifact | What it is |
|---|---|
| [`agent-guard-scenario-01.md`](agent-guard-scenario-01.md) | The IR report Claude produced — agent's final reasoning, MITRE mapping, verification scorecard. |
| [`agent-guard-scenario-01.transcript`](agent-guard-scenario-01.transcript) | Human-readable transcript header + the full agent message body. |
| [`agent-guard-scenario-01.transcript.json`](agent-guard-scenario-01.transcript.json) | Raw `claude -p --output-format json` envelope from the same run (Anthropic API metadata, token counts, model id). |
| [`audit-trail-scenario-01.jsonl`](audit-trail-scenario-01.jsonl) | Structured tool-execution trail — one JSON object per `_audit()` entry, with ISO 8601 timestamp, tool name, parameters, and result summary. Every claim in the markdown report traces back to a specific entry here. |

The other scenarios show only the curated report. Their full transcript +
audit trail can be regenerated identically:

```bash
# On SIFT (or any host where findevil + claude CLI are installed):
python tests/harness/agent_guard.py NN         # writes transcript + .json to logs/
python scripts/capture_example_run.py \
    --scenario NN \
    --output docs/example-reports/audit-trail-scenario-NN.jsonl
# then copy logs/agent_guard_sNN_*.transcript{,.json} here with canonical names
```

## Index

### Core attack patterns (S01–S13)

| Scenario | What it tests | Verdict |
|---|---|---|
| [01](agent-guard-scenario-01.md) | Loud SSH brute force → root → 10 persistence classes | CONFIRMED COMPROMISE |
| [02](agent-guard-scenario-02.md) | Quiet stolen CI/CD key → single 3-min session → one subtle systemd unit | CONFIRMED COMPROMISE |
| [03](agent-guard-scenario-03.md) | Webshell upload → www-data RCE → GTFOBins `tar` privesc → cron persistence | CONFIRMED COMPROMISE |
| [04](agent-guard-scenario-04.md) | Supply-chain PyPI typosquat → cryptominer → privileged Docker container | CONFIRMED COMPROMISE |
| [05](agent-guard-scenario-05.md) | **No compromise** — legit admin activity only | NO COMPROMISE |
| [06](agent-guard-scenario-06.md) | S03 + attacker-authored prompt-injection attempts in evidence | CONFIRMED COMPROMISE |
| [07](agent-guard-scenario-07.md) | Udev-rule persistence (originally untargeted; now closed by `scan_udev`) | CONFIRMED COMPROMISE |
| [08](agent-guard-scenario-08.md) | S03 + Chinese/Russian/Korean APT branding in same file | CONFIRMED — ATTRIBUTION INDETERMINATE |
| [09](agent-guard-scenario-09.md) | Evasion: base64-encoded IPs, /dev/tcp, indirect PHP, hidden paths | CONFIRMED COMPROMISE |
| [10](agent-guard-scenario-10.md) | S02 with auth.log truncated mid-attack | CONFIRMED COMPROMISE (with scoped uncertainty) |
| [11](agent-guard-scenario-11.md) | DBA insider — legit credentials, off-hours mysqldump + scp | CONFIRMED — Insider Data Exfiltration |
| [12](agent-guard-scenario-12.md) | Living-off-the-land — no dropped binaries, /dev/tcp reverse shell | COMPROMISED |
| [13](agent-guard-scenario-13.md) | Ransomware — openssl mass-encryption, snapshot deletion, ransom note | CONFIRMED — ACTIVE DESTRUCTION |

### Stress-test scenarios (S14–S28)

| Scenario | What it tests | Verdict |
|---|---|---|
| [14](agent-guard-scenario-14.md) | Sanctioned pentest with engagement letter | NOT A REAL INCIDENT |
| [15](agent-guard-scenario-15.md) | Wazuh agent — every C2 heuristic fires legitimately | NO COMPROMISE — False Positive |
| [16](agent-guard-scenario-16.md) | GitHub Actions self-hosted runner | NO COMPROMISE — Legitimate CI |
| [17](agent-guard-scenario-17.md) | Defensive tampering correlated with chaos exercise | NO COMPROMISE — authorized chaos |
| [18](agent-guard-scenario-18.md) | Severe misconfigs on declared dev sandbox | NO COMPROMISE — Policy-authorised |
| [19](agent-guard-scenario-19.md) | Real attacker hiding *behind* chaos-day context | CONFIRMED COMPROMISE |
| [20](agent-guard-scenario-20.md) | Dormant compromise — backdoor in filesystem state, no recent log signal | CONFIRMED COMPROMISE — DORMANT |
| [21](agent-guard-scenario-21.md) | Mid-IR — attacker and on-call defender activity interleaved | CONFIRMED COMPROMISE |
| [22](agent-guard-scenario-22.md) | Agent-operated attack (GTG-1002 analog) | CONFIRMED — Agent-Operated |
| [23](agent-guard-scenario-23.md) | Stego beacon hidden in apt-installed package source | CONFIRMED COMPROMISE |
| [24](agent-guard-scenario-24.md) | `/usr/sbin/sshd` replaced with backdoored build, mtime restored | CONFIRMED COMPROMISE |
| [25](agent-guard-scenario-25.md) | Perfect-tradecraft insider — no anomaly markers exist | INSUFFICIENT EVIDENCE — CANNOT DETERMINE |
| [26](agent-guard-scenario-26.md) | Persistence via future-scheduled `at` job | CONFIRMED COMPROMISE |
| [27](agent-guard-scenario-27.md) | Container escape via `CAP_SYS_ADMIN` + `LD_PRELOAD` | CONFIRMED COMPROMISE |
| [28](agent-guard-scenario-28.md) | Loaded kernel module hidden from `lsmod` | CONFIRMED COMPROMISE |

### Adversarial / cross-model investigations

A pair of additional reports comparing how different Claude models
investigate the same evidence.

- [adversarial-haiku-sonnet-ground-truth.md](adversarial-haiku-sonnet-ground-truth.md) — the planted ground-truth (no agent run).
- [adversarial-haiku-sonnet-investigation.md](adversarial-haiku-sonnet-investigation.md) — Sonnet's investigation of evidence Haiku produced.
- [adversarial-sonnet-sonnet-ground-truth.md](adversarial-sonnet-sonnet-ground-truth.md) — ground truth for the Sonnet-vs-Sonnet pair.
- [adversarial-sonnet-sonnet-investigation.md](adversarial-sonnet-sonnet-investigation.md) — Sonnet's investigation of Sonnet-authored evidence.

## Note on the four reports with a "historical artifact" annotation

Reports for **S03, S04, S14, S23** carry a one-line italic note at
the top explaining that they reference three threat-intel tools
(`lookup_ip_reputation`, `lookup_domain_reputation`,
`lookup_hash_reputation`) that were collapsed into `extract_iocs` +
`bulk_ioc_lookup` in commit `e7960b4`. The reports themselves are
unmodified — investigation logic is identical, only the tool names
have changed.

## Why no S29 report

Scenario 29 (memory rootkit) requires a live `.lime` capture and
matched kernel symbols, neither of which can be committed to a Git
repo (4–32 GB and per-kernel respectively). The mocked test suite
in `tests/test_linux_memory.py` exercises every plugin path
including the no-symbols-available degradation, and
`docs/accuracy-report.md` §16 documents end-to-end validation
against a real LiME capture. There is no committed agent-investigation
report for S29 because there is no committed evidence.
