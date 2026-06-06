# Security policy

Findevil is a forensic-IR tool that runs on potentially-compromised
systems and reads sensitive evidence. Bugs in tools like this can
have unusual consequences — silently mis-classifying an attack as
benign, leaking a path traversal, or modifying evidence in a way
that breaks chain of custody. We take that seriously.

## Scope

In scope for security reports:

- **Path traversal / evidence-dir escape** — any way for a tool to
  read or write a path outside `FINDEVIL_EVIDENCE_DIR`. The
  architectural guarantee that no `@mcp.tool()` function can modify
  evidence is the single most important invariant; reports here are
  prioritised.
- **Command injection** — anywhere user-supplied input flows into a
  `subprocess.run` argument list (currently nowhere; if you find
  one, that's the report).
- **Audit-trail bypass** — a tool invocation that completes
  successfully but doesn't appear in `logs/audit.json`.
- **Output sanitisation** — Markdown injection that could mislead a
  reviewer reading a tool's output (e.g., a forged "verified by
  Anthropic" footer planted via attacker-controlled file content).
- **Prompt injection that defeats the architectural guarantee** —
  if you can talk an instance into modifying evidence via a
  shipped tool, that's a real bug. (If you can talk it into
  *claiming* it modified evidence in its narrative, that's a
  different class — the audit trail will catch the discrepancy.)

Out of scope:

- Issues in third-party tools we shell out to (`grep`, `xxd`,
  `strings`, Volatility 3 plugins, etc.). Report those upstream.
- Findings about the *content* of bundled scenarios — those are
  intentionally adversarial test fixtures.
- Hallucinations or recall gaps in agent investigations — those are
  evaluated via the hallucination harness in `tests/harness/` and
  documented in `docs/accuracy-report.md`. They are quality issues,
  not security issues.

## Disclosure

We follow a **90-day coordinated disclosure** window. After a fix
ships (or 90 days from the original report, whichever is later), we
publish an advisory with:

- Affected versions / commits
- Brief technical description
- Credit to the reporter (or anonymous, by request)

Two real bugs were found by the test suite during development and
are documented in `docs/accuracy-report.md` §14:

- **BUG 1** — `_validate_evidence_path` prefix confusion
  (`tests/security/test_path_validation.py`).
- **BUG 2** — `fim.baseline_create` output-path bypass
  (`tests/security/test_fim_output_path_guard.py`).

Both have regression tests; both shipped with explicit fix commits.
