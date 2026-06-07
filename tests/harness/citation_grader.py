#!/usr/bin/env python3
"""
Citation grader — does the agent carry tool-side line numbers into its
final IR report?

FindEvil's headline differentiator vs Protocol SIFT is verifiable
provenance: every tool annotates findings with a raw log line number
("First seen line: 47", "auth.log:96", "(line 47)") and the IR report
is supposed to inherit those citations. agent_guard.py grades the
verdict; this grader checks whether the line-number provenance survived.

Operates on artifacts only — no Claude run, no MCP server.

Usage:
    python tests/harness/citation_grader.py \\
        --audit-log <path-to-audit.json> --report <report.md> [--scenario ID]
    python tests/harness/citation_grader.py --self-test

Exit 0 on PASS, 1 on FAIL (or self-test mismatch).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Patterns derived from formats findevil tools emit (linux_auth.py:
# "First seen line: N"; linux_web.py upload/exec_line) and example
# reports (auth.log:96, auth.log:26-95). file:line shorthand requires a
# recognised extension to avoid colliding with timestamps "14:45:12".
_LINE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b[Ll]ine\s*[:#]?\s*(\d+)"),                      # "Line: 47", "line 47"
    re.compile(r"(?:\(|\bat\s+|\bon\s+)line\s+(\d+)", re.I),        # "(line 47)", "at line 47"
    re.compile(r"\blines?\s+(\d+)\s*[-–—]\s*(\d+)", re.I),          # "lines 47-95"
    re.compile(                                                     # "auth.log:96", "access.log:204-208"
        r"\b[\w./-]+\.(?:log|jsonl|json|conf|cfg|txt|sh|py|php|service|cron)"
        r"\s*:\s*(\d+)(?:\s*[-–—]\s*(\d+))?",
        re.I,
    ),
    re.compile(r"(?:^|[^A-Za-z0-9])#?L(\d+)\b"),                    # "L47", "#L47"
]


def extract_line_numbers(text: str) -> set[int]:
    """Distinct line numbers cited in text. Range forms expand to closed
    integer interval (capped at 200 wide to limit pathological input)."""
    found: set[int] = set()
    for pat in _LINE_PATTERNS:
        for m in pat.finditer(text):
            try:
                nums = [int(g) for g in m.groups() if g is not None]
            except ValueError:
                continue
            if not nums:
                continue
            if len(nums) == 1:
                found.add(nums[0])
            else:
                lo, hi = min(nums), max(nums)
                if hi - lo > 200:
                    found.update({lo, hi})
                else:
                    found.update(range(lo, hi + 1))
    return {n for n in found if 0 < n < 1_000_000}


def load_audit_summaries(audit_path: Path) -> list[str]:
    """Read JSONL audit log; return result_summary text per entry."""
    out: list[str] = []
    if not audit_path.is_file():
        return out
    for raw in audit_path.read_text(errors="replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict) and "result_summary" in entry:
            out.append(str(entry["result_summary"]))
    return out


_HEADING_RE = re.compile(r"^(#{2,6})\s+(.+)$", re.MULTILINE)
_NON_FACTUAL_HEADINGS = {
    "verdict", "summary verdict", "conclusion", "table of contents",
    "remediation recommendations", "remediation", "next steps",
    "recommendations", "executive summary",
}


def split_factual_sections(report_md: str) -> list[tuple[str, str]]:
    """Split on ## / ### headings; return (heading, body) pairs."""
    matches = list(_HEADING_RE.finditer(report_md))
    if not matches:
        return [("(document)", report_md)]
    sections: list[tuple[str, str]] = []
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(report_md)
        sections.append((m.group(2).strip(), report_md[m.end():end].strip()))
    return sections


def is_factual(heading: str, body: str) -> bool:
    if heading.lower().strip().rstrip(":") in _NON_FACTUAL_HEADINGS:
        return False
    return len(re.sub(r"\s+", "", body)) >= 30


# Threshold rationale:
# - Coverage >=70%: slack for "Lateral Movement"-style summary sections.
#   Below 70% most factual sections are uncited — provenance claim broken.
# - Fidelity  >=90%: tolerates an off-by-one transcription. Looser invites
#   fabrication; 100% is brittle on real LLM output.
COVERAGE_THRESHOLD = 0.70
FIDELITY_THRESHOLD = 0.90


@dataclass
class CitationReport:
    tool_lines: set[int] = field(default_factory=set)
    report_lines: set[int] = field(default_factory=set)
    factual_sections_total: int = 0
    factual_sections_cited: int = 0
    fabricated_lines: set[int] = field(default_factory=set)
    coverage: float = 0.0
    fidelity: float = 0.0
    passed: bool = False

    def to_markdown(self, scenario: str | None = None) -> str:
        s = lambda x: ", ".join(str(n) for n in sorted(x)[:10])  # noqa: E731
        head = f"# Citation Grader" + (f" — scenario {scenario}" if scenario else "")
        verdict = "PASS" if self.passed else "FAIL"
        rep_ok = len(self.report_lines) - len(self.fabricated_lines)
        fab = (f"- **⚠ Potentially fabricated line numbers:** {s(self.fabricated_lines)}"
               if self.fabricated_lines else "- **No fabricated line numbers detected.**")
        return "\n".join([
            head, "",
            f"- **Tool-side line numbers offered:** {len(self.tool_lines)}"
            + (f"  (sample: {s(self.tool_lines)})" if self.tool_lines else ""),
            f"- **Report-side line numbers cited:** {len(self.report_lines)}"
            + (f"  (sample: {s(self.report_lines)})" if self.report_lines else ""),
            f"- **Coverage of factual sections:** "
            f"{self.factual_sections_cited}/{self.factual_sections_total} ({self.coverage*100:.0f}%)",
            f"- **Provenance fidelity:** {rep_ok}/{len(self.report_lines)} "
            f"cited line numbers appeared in audit trail ({self.fidelity*100:.0f}%)",
            fab, "",
            f"## Verdict: **{verdict}**",
            f"(threshold: coverage ≥ {COVERAGE_THRESHOLD*100:.0f}%, "
            f"fidelity ≥ {FIDELITY_THRESHOLD*100:.0f}%)",
        ])


def grade_citations(audit_summaries: list[str], report_md: str) -> CitationReport:
    tool_lines = extract_line_numbers("\n".join(audit_summaries))
    report_lines = extract_line_numbers(report_md)

    factual_total = factual_cited = 0
    for heading, body in split_factual_sections(report_md):
        if not is_factual(heading, body):
            continue
        factual_total += 1
        if extract_line_numbers(body):
            factual_cited += 1

    fabricated = report_lines - tool_lines if tool_lines else set()
    coverage = factual_cited / factual_total if factual_total else 1.0
    fidelity = ((len(report_lines) - len(fabricated)) / len(report_lines)
                if report_lines else 1.0)
    return CitationReport(
        tool_lines=tool_lines,
        report_lines=report_lines,
        factual_sections_total=factual_total,
        factual_sections_cited=factual_cited,
        fabricated_lines=fabricated,
        coverage=coverage,
        fidelity=fidelity,
        passed=coverage >= COVERAGE_THRESHOLD and fidelity >= FIDELITY_THRESHOLD,
    )


# ---------------------------------------------------------------------------
# Self-test (offline calibration; mirrors grader_calibration.py style)
# ---------------------------------------------------------------------------

_GOOD_SUMMARIES = [
    "70 failed attempts in lines 26-95",
    "1 success at line 96 (45.123.45.67 -> root via password)",
    "12 sudo commands at lines 98-117",
    "10 items. cron.d/sysd-cron at line 1; ld.so.preload line 1",
]
_GOOD_REPORT = """\
# IR Report

## Initial Access
Brute force from 45.123.45.67 documented at auth.log:26–95 (70 attempts).
Successful login on auth.log:96 (line 96 in raw log).

## Persistence
The cron file at line 1 of /etc/cron.d/sysd-cron re-downloads the payload.
ld.so.preload (line 1) loads libprocesshider into every process.
Sudo commands cited from auth.log:98 through auth.log:117 confirm activity.

## Verdict
CONFIRMED COMPROMISE
"""
# Bad: cites lines (47, 999, 8888, 12345) the audit never offered, AND
# has a factual section with NO citation at all — both thresholds fail.
_BAD_REPORT = """\
# IR Report

## Initial Access
The attacker brute-forced SSH and gained root. No specific lines cited.
This section makes a factual claim but contains no citation at all,
which should drag the coverage metric down. The attacker IP was
45.123.45.67 — yes — but where in the log? Unsourced.

## Persistence
A cron job at line 47 was found. ld.so.preload at line 999 was modified.
The attacker also planted a key at line 12345 of authorized_keys.

## More fabrication
The systemd unit was discovered at line 8888 (also fabricated).
None of these line numbers were surfaced by any tool.
"""


def self_test() -> int:
    failed = 0
    for label, body, expect_pass in [
        ("good", _GOOD_REPORT, True),
        ("bad",  _BAD_REPORT,  False),
    ]:
        r = grade_citations(_GOOD_SUMMARIES, body)
        tag = "PASS" if r.passed else "FAIL"
        print(f"[self-test] {label} case -> {tag}")
        print(
            f"  coverage={r.coverage:.0%} fidelity={r.fidelity:.0%} "
            f"tool_lines={len(r.tool_lines)} report_lines={len(r.report_lines)} "
            f"fabricated={len(r.fabricated_lines)}"
        )
        if r.passed != expect_pass:
            print(f"  ! {label} case unexpectedly {tag}; calibration broken")
            failed += 1

    print()
    if failed:
        print(f"SELF-TEST FAILED: {failed} case(s) gave the wrong verdict")
        return 1
    print("SELF-TEST PASSED: grader correctly distinguishes good/bad reports")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    p.add_argument("--audit-log", type=Path, help="Path to logs/audit.json (JSONL)")
    p.add_argument("--report", type=Path, help="Path to the final IR report (Markdown)")
    p.add_argument("--scenario", default=None, help="Scenario id, for the report header")
    p.add_argument("--self-test", action="store_true", help="Run offline calibration only")
    args = p.parse_args()

    if args.self_test:
        return self_test()
    if not args.audit_log or not args.report:
        p.error("--audit-log and --report are required (or pass --self-test)")
    if not args.audit_log.is_file():
        print(f"audit log not found: {args.audit_log}", file=sys.stderr)
        return 2
    if not args.report.is_file():
        print(f"report not found: {args.report}", file=sys.stderr)
        return 2

    summaries = load_audit_summaries(args.audit_log)
    report_md = args.report.read_text(errors="replace")
    result = grade_citations(summaries, report_md)
    print(result.to_markdown(args.scenario))
    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
