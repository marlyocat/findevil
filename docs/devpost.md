# Findevil — Devpost Submission

Copy the sections below directly into the Devpost form. Word counts are
approximate; feel free to trim.

---

## Inspiration

In November 2025, Anthropic's security team published findings on
GTG-1002 — a Chinese state-sponsored operation that used Claude Code
to automate reconnaissance, exploitation, and lateral movement at
80–90% autonomy. Request rates were "physically impossible for human
operators." The attackers had a defender's dream workflow; the
defenders had ticket queues.

Most DFIR tooling targets Windows workstations. But 96% of the top 1
million web servers, most cloud workloads, and every Kubernetes node
runs Linux — and that's exactly where GTG-1002 lived. The defensive
equivalent didn't exist: an autonomous Linux IR agent that a real
on-call engineer would trust at 3am. That's what Findevil is.

## What it does

Findevil is a custom MCP (Model Context Protocol) server that
exposes **43 typed, read-only, audited forensic tools** across thirteen
categories — SSH auth logs, systemd journal, filesystem persistence,
shell history, web server logs, webshell detection, package/supply-
chain logs, container configs, cross-artifact timeline fusion, file-
integrity monitoring, explicit self-correction, offline threat-
intel lookups, LLM/agent-driven adversary detection, and Volatility-3
memory forensics.

Claude Code connects to the server and autonomously:

1. Discovers what evidence is available.
2. Runs the right chain of structured tools for the case.
3. Correlates findings across sources (login IP → beacon destination
   IP → systemd unit content → apt history).
4. Audits its **own** claims using three dedicated self-correction
   tools (`verify_finding`, `find_contradictions`,
   `get_audit_trail`).
5. Produces an IR report where every claim traces to a specific
   tool invocation and a specific line number in the raw evidence.

**Twenty-nine ground-truth attack scenarios** ship with the tool (28 with
bundled evidence plus one live-capture memory scenario), each designed
to disagree with the others so the agent is continuously tested against
overfitting. The first four cover classic compromise
patterns — loud SSH brute-force → rootkit, quiet stolen-CI-key
intrusion, webshell → `tar` GTFOBins privesc, supply-chain PyPI
typosquat → privileged Docker container escape. The next nine target
specific hallucination failure modes: a clean-system negative
control, a prompt-injection-laden evidence set, a udev-rule
persistence (originally targeted as a blind spot, now closed by
`scan_udev`), a false-flag scenario
seeding conflicting APT attribution, a fully-obfuscated evasion
scenario, a partial-evidence scenario that truncates the log
mid-attack, an insider threat where every command is authorized, a
living-off-the-land scenario with no dropped binaries, and a
ransomware / destructive scenario. The remaining fifteen stress-test
specific failure modes the first thirteen don't cover: precision
against sanctioned pentests, legitimate monitoring agents, CI/CD
runners, declared chaos exercises, and dev sandboxes; an adversarial
chaos-cover attack; dormant compromises with no recent log activity;
mid-incident IR where attacker and defender activity interleave; an
agent-operated GTG-1002 analog; steganographic persistence inside
plausible-looking package code; a timestomped backdoored sshd; a
perfect-tradecraft insider whose correct verdict is "cannot
determine"; a future-scheduled `at`-job trigger; a `CAP_SYS_ADMIN`
container escape; and a kernel module hidden from `lsmod` but
visible at `/sys/module/`.

## How we built it

**Architecture:** Custom MCP Server (option 2 of the four the
hackathon lists). We chose this over Direct Agent Extension because
the judging criteria explicitly reward architectural guardrails
over prompt-based ones. Our server physically cannot modify
evidence — there is no write-capable tool exposed for any path
under `FINDEVIL_EVIDENCE_DIR`. Prompt injection cannot talk it
into spoliation because there is no tool to call.

**Stack:** Python 3.11+, the official MCP SDK (`mcp[cli]`), stdio
transport (keeps deployment airgap-friendly), no external runtime
dependencies for the core tools.

**Discipline:** Every tool returns structured Markdown with
per-finding line-number provenance. Every invocation is logged to
`logs/audit.json`. Three layered test suites catch regressions that
prompt-based approaches would ship silently: unit tests for parser
and per-tool recall/precision; a 102-case security suite
(path-traversal, symlink-escape, static write-capability audit,
audit-completeness AST walk, MITRE-coverage audit, FIM output-path
guard); and a hallucination harness that runs real Claude
investigations against the 29 scenarios and grades each report for
recall + cross-scenario fabrication.

## Challenges we ran into

- **Python dual-module execution.** Running `python -m
  findevil.server` caused Python to execute the module twice
  (once as `__main__`, once via `findevil.server` re-import from
  tool modules). Half the tools silently registered on the wrong
  FastMCP instance. Fixed with a tiny `__main__.py` shim.
- **Circular imports** between timeline-fusion and its sibling
  tool modules. Fixed with lazy imports inside the extractor
  functions.
- **Recall vs precision on outbound downloads.** Legitimate CI
  workflows curl `registry.npmjs.org` all day. The tool flags
  this at high recall; the threat-intel cache marks the domain
  as legitimate; the agent uses both to make the right call.
- **Architecture drift at scale.** Once tool count crossed 20, we
  had to actively consolidate rather than proliferate to keep
  the agent's tool-selection reasoning clean.

## Accomplishments we're proud of

- **The security suite found two real bugs in our own code.**
  `_validate_evidence_path` used a `str.startswith()` prefix check
  that accepted sibling-directory escape (`evidence-malicious/...`
  passed the check for `evidence/`). `fim.baseline_create` accepted
  user-supplied output paths inside `EVIDENCE_DIR`, potentially
  overwriting evidence. Both fixed (now using `Path.relative_to()`
  + inverse path guard), regression-protected in
  `tests/security/test_path_validation.py` and
  `tests/security/test_fim_output_path_guard.py`.
- **The agent caught its own limitation.** While analyzing
  scenario 04, it wrote: *"find_persistence only tagged the
  xmrig service as info because its ExecStart points to
  /usr/bin/xmrig (a repo-installed path); suggest correlating
  systemd ExecStart paths against recent local-.deb apt
  installs to auto-escalate."* That's the exact rationale
  for Phase 4 cross-artifact correlation — self-diagnosed
  before we'd built it.
- **Self-correction in practice.** On a scenario 01 audit run
  the agent made 14 `verify_finding` calls against its own
  claims — all 14 returned SUPPORTED, zero false claims
  shipped — and ran `find_contradictions` across 10
  structured claims with zero contradictions.
- **Twenty-eight attack patterns, twenty-eight correct verdicts.** No
  overfitting to any one scenario. The agent declined to
  hallucinate brute force in scenario 02, refused to attribute
  scenario 08 to any specific APT despite planted markers,
  decoded scenario 09's base64-obfuscated C2 IP and named the
  `/dev/tcp` technique, scoped uncertainty in scenario 10
  around a truncated log, and recognized scenario 11's insider
  threat by aggregate pattern despite every individual command
  being authorized.

## What we learned

Structured, typed outputs beat prompt instructions every time.
Telling an LLM "never modify evidence" is fragile; exposing no
write-capable tool is absolute. The hackathon's explicit
preference for architectural guardrails and depth-over-breadth
made this design choice obvious, and it paid off in testing:
scenarios deliberately built to trip each other up produced
correct verdicts without prompt re-engineering.

Also, DFIR domain expertise can be encoded as a typed API
contract. You don't need to be a senior incident responder to
build the scaffolding — you need to encode what senior
responders check, in what order, with what corroboration. The
LLM handles the reasoning; the server handles the evidence.

## What's next for Findevil

- **Live threat-intel feeds** merged into the offline cache
  (abuse.ch, FireHOL, MalwareBazaar, URLhaus, TOR exit list).
- **Multi-host correlation** — the pattern is right for
  enterprise IR but needs multi-host evidence to validate
  meaningfully.
- **Published Linux attack corpus.** The twenty-eight bundled scenarios
  (covering clean-system, prompt-injection, false-flag, evasion,
  partial-evidence, insider-threat, LotL, ransomware, sanctioned-pentest,
  legitimate-monitoring, CI-runner, chaos-exercise, sandbox, chaos-cover,
  dormant, mid-IR, agent-operated, stego, timestomp, perfect-insider,
  at-job, container-escape, and hidden-LKM variants)
  are a starting point; there's room for a community-driven
  synthetic-evidence library that mirrors the full MITRE ATT&CK
  Linux matrix technique-by-technique.

---

## Devpost form field mapping

| Devpost section | Text source |
|---|---|
| Inspiration | § Inspiration above |
| What it does | § What it does above |
| How we built it | § How we built it above |
| Challenges we ran into | § Challenges we ran into above |
| Accomplishments that we're proud of | § Accomplishments we're proud of above |
| What we learned | § What we learned above |
| What's next for Findevil | § What's next for Findevil above |
| Built with | `python`, `mcp`, `claude-code`, `sans-sift-workstation` |
| Try it out | https://github.com/marlyocat/findevil |

## Suggested "cover image" / screenshot ideas

1. The architecture Mermaid diagram from `docs/architecture.md`
   rendered on GitHub (visible on the repo README).
2. A screenshot of Claude Code mid-investigation showing 11+
   findevil tool calls in the audit trail.
3. A screenshot of an agent-generated report's "Verification"
   section showing the self-correction verdicts.

## Tags to set on Devpost

Suggested: `incident-response`, `linux`, `mcp`, `security`,
`dfir`, `supply-chain`, `self-correction`, `claude-code`,
`threat-intel`, `forensics`, `python`.
