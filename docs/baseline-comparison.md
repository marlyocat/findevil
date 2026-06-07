# Baseline comparison: findevil vs Direct Agent Extension

The hackathon lists four architectural patterns. Protocol SIFT (the
baseline starter kit) uses pattern #1, "Direct Agent Extension" —
Claude Code with a curated `settings.json` bash allow-list and rich
`SKILL.md` files describing SIFT tools. FindEvil uses pattern #2,
"Custom MCP Server."

§10 of the accuracy report argues architecturally why findevil should
resist hallucination better. This document measures that claim on
actual evidence.

## Method

For scenario 02 (the hardest precision test in the corpus — quiet
stolen-key compromise, no brute force, no rootkit, no new accounts),
we ran the same Claude model (Sonnet) against the same evidence
under two configurations:

| Run | Configuration |
|-----|--------------|
| **findevil** | `claude -p` with the findevil MCP server connected. Report at `docs/example-reports/agent-guard-scenario-02.md`. |
| **baseline** | `claude -p --strict-mcp-config` from an empty directory, so *only* Claude Code's built-in tools (`Bash`, `Read`, `Glob`, `Grep`, `Write`) are available. No findevil MCP. Report at `reports/baseline-run-s02.md` (not committed — regenerate with the reproduce command below). |

Both runs used the same investigation prompt. Both wrote their reports
to disk. Both were evaluated against the same graded markers.

## Results

| Metric | findevil | Direct-Agent baseline |
|--------|----------|------------------------|
| Correctly identified attacker IP `185.229.59.103` | ✅ | ✅ |
| Flagged `system-updater.service` beacon | ✅ | ✅ |
| Flagged second SSH key `deploy@ci-backup` | ✅ | ✅ |
| Flagged bare-binary sudoers grant | ✅ | ✅ |
| Said "no brute force" (true negative) | ✅ | ✅ |
| Said "no rootkit" (true negative) | ✅ | ✅ |
| Said "no new users" (true negative) | ✅ | ✅ |
| Cross-scenario artifact mentions (S01 IPs, `toor`, `libprocesshider`, `xmrig`, `shell.php` as affirmative findings) | 0 | 0 |
| Report length | 277 lines | 226 lines |
| Verdict | CONFIRMED COMPROMISE | compromised |

**Correctness was a tie.** The Direct-Agent baseline got S02 right.
This is counter to the simpler version of findevil's pitch; it's
captured here rather than quietly hidden.

## Where findevil still adds value

Correctness on a single straightforward scenario is not the whole
claim. The architectural differences below are independent of whether
any particular run succeeds:

| Dimension | findevil | Direct-Agent baseline |
|-----------|----------|------------------------|
| Read-only enforcement | **Architectural.** No write-capable tool is exposed for evidence paths; `_validate_evidence_path` is tested (7 path-traversal cases, 4 symlink cases). | Policy-based. Claude's `Bash` has allow-list entries in `settings.json`; `Write` is allow-listed to `./analysis/ ./reports/ ./exports/`. An incorrectly-scoped Bash entry (e.g., a wildcard that matches a write command) silently voids the guarantee. |
| Provenance of a claim | Every tool call is persisted to `logs/audit.json` with timestamp, params, result summary — independent of Claude's own tracking. `get_audit_trail` lets the agent introspect it. | Claude cites "I ran `grep ...`" in its transcript, but there's no mechanical log mapping its claims to specific tool invocations after the session ends. |
| Deterministic output shape | Every tool returns pre-parsed Markdown with a fixed structure (summary, flagged items, triage verdict). Same input → same shape. | Claude picks ad-hoc `grep`/`awk`/`cat` combinations per session. Same input can produce differently-shaped reports across runs, complicating cross-session comparison. |
| Context-window efficiency | A tool like `auth_summary` returns ~15 lines of structured Markdown for a 120-line auth log — roughly 6% of the raw log's token footprint. | Claude reads raw files and filters in context; the entire input often sits in conversation state. Token spend is typically higher. (Not measured here; flagging as follow-up.) |
| Regression protection | 102 security tests + unit tests cover the MCP tool boundary. A change to `auth_failed_logins` that breaks recall fails CI before shipping. | `settings.json` changes don't fail anything mechanically; catching a regression requires rerunning a full investigation and reading the verdict. |

## Where the baseline may be competitive or superior

- **Novel attack vectors.** When an attack doesn't match any of
  findevil's specialized parsers, the baseline's generic `grep`/`find`
  has fewer assumptions to get wrong. Scenario 07 (udev-rule
  persistence not scanned by findevil) is the closest analog in the
  corpus — findevil still passed it, but via Claude reading the
  filesystem directly, effectively falling back to baseline behaviour.
- **Setup friction.** Protocol SIFT is a pure configuration play — no
  custom Python, no MCP server process. findevil requires a venv and
  an MCP stdio subprocess per session.

## What this result does NOT tell us

- **Not tested here:** how the two compare on scenarios that
  specifically target findevil's parsers (the auth-log tools in
  particular). On S01 (loud attacker, many specialised detections),
  the baseline would need to reimplement most of what
  `find_persistence` does from scratch via `grep`-across-files.
- **Not tested here:** long-run hallucination rate across many
  investigations (what Protocol SIFT is criticised for). A single
  clean S02 run doesn't refute that — it just shows findevil isn't
  winning on this specific axis.
- **Not tested here:** behaviour under prompt-injection-laden
  evidence (S06). We have findevil results there; the baseline
  comparison is TODO. Expectation: the baseline is probably more
  susceptible because its Claude instance reads raw evidence files
  directly (injection text goes straight into context), whereas
  findevil's structured tool summaries filter out the noise first.

## Reproducing this comparison

```bash
# On the SIFT VM
mkdir -p /tmp/baseline_run && cd /tmp/baseline_run
ln -sf ~/findevil/evidence evidence
export PATH=$HOME/.local/bin:$PATH

claude -p "A developer SSH key may have been stolen. Investigate \
whether webserver-prod-02 was compromised. The evidence is in \
evidence/attack-scenario-02. Do NOT assume the attack pattern \
matches previous cases — reach conclusions from this evidence \
only. Write the final report to /tmp/baseline_run/baseline-report.md." \
  --permission-mode bypassPermissions \
  --output-format text \
  --max-turns 80 \
  --model sonnet \
  --strict-mcp-config

# Grade baseline-report.md with the same criteria as
# tests/harness/agent_guard.py scenario 02 required/forbidden markers.
```

## Honest summary

The "findevil beats Protocol SIFT on hallucination" claim — worded
confidently in earlier drafts of the accuracy report — overstates
what the data supports. What we can say accurately: findevil provides
**architectural guarantees** (read-only, audit trail, deterministic
output) that Direct Agent Extension relies on policy / configuration
for. On correctness of the single investigation we measured, the
baseline tied.

Follow-up work to strengthen the comparison:
- Run all 29 scenarios under baseline, tabulate side by side.
- Measure token spend and wall-clock time in both configurations.
- Run both against S06 (prompt injection) — the architecture-level
  difference should be clearest there.
