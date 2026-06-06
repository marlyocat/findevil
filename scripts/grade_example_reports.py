#!/usr/bin/env python3
"""Compute verification scorecards for every committed example IR report.

Reads the SCENARIOS dict from `tests/harness/agent_guard.py`, runs the
same `grade()` logic against each `docs/example-reports/*.md`, and
prints a per-report scorecard. With `--inject`, writes the scorecard
into each report file (replacing any existing scorecard block).

Usage:
    python scripts/grade_example_reports.py            # dry-run, prints to stdout
    python scripts/grade_example_reports.py --inject   # write into each report

Designed to be re-runnable: detects existing scorecards via the
``<!-- scorecard:start -->`` / ``<!-- scorecard:end -->`` sentinels and
replaces them. Reports with no entry in SCENARIOS (the four adversarial
files) get a generic "no machine-graded markers" stanza instead.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Make agent_guard importable when invoked from anywhere
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "tests" / "harness"))

from agent_guard import SCENARIOS, grade  # noqa: E402


SCORECARD_START = "<!-- scorecard:start -->"
SCORECARD_END = "<!-- scorecard:end -->"


def _confidence_label(recall_pct: float, halluc_pct: float) -> str:
    """Map (recall, hallucination-resistance) to a coarse label."""
    if recall_pct == 100 and halluc_pct == 100:
        return "HIGH"
    if recall_pct >= 80 and halluc_pct >= 90:
        return "MEDIUM-HIGH"
    if recall_pct >= 50 and halluc_pct >= 80:
        return "MEDIUM"
    if halluc_pct < 80:
        return "LOW (cross-scenario pollution detected)"
    return "LOW (recall failure)"


def _pct(part: int, whole: int) -> float:
    return 100.0 * part / whole if whole else 0.0


def _build_scorecard(scenario_id: str, body: str) -> str:
    """Build a Markdown scorecard block for one scenario+body pair."""
    scenario = SCENARIOS[scenario_id]
    result = grade(scenario, body)
    required_total = len(scenario.required)
    forbidden_total = len(scenario.forbidden)
    missing = result["missing_required"]
    forbidden_present = result["forbidden_present"]
    required_found = required_total - len(missing)
    forbidden_absent = forbidden_total - len(forbidden_present)

    recall_pct = _pct(required_found, required_total)
    halluc_pct = _pct(forbidden_absent, forbidden_total)
    label = _confidence_label(recall_pct, halluc_pct)

    lines = [
        SCORECARD_START,
        "",
        "## Verification scorecard",
        "",
        "Mechanically computed by `scripts/grade_example_reports.py` against",
        f"the `agent_guard.SCENARIOS[\"{scenario_id}\"]` markers. No AI",
        "self-assessment is involved in these numbers.",
        "",
        "| Metric | Score | % |",
        "|---|---|---|",
        f"| Required markers found | {required_found}/{required_total} | **{recall_pct:.0f}%** |",
        f"| Cross-scenario markers absent | {forbidden_absent}/{forbidden_total} | **{halluc_pct:.0f}%** |",
        f"| Verdict-correctness confidence | — | **{recall_pct:.0f}%** |",
        f"| Hallucination-free confidence | — | **{halluc_pct:.0f}%** |",
        "",
        f"**Overall confidence: {label}**",
        "",
    ]
    if missing:
        lines.append(f"_Missing required markers:_ {', '.join(f'`{m}`' for m in missing)}")
        lines.append("")
    if forbidden_present:
        lines.append(
            f"_Forbidden markers detected:_ {', '.join(f'`{m}`' for m in forbidden_present)}"
        )
        lines.append("")
    lines.append(SCORECARD_END)
    return "\n".join(lines)


def _build_adversarial_scorecard() -> str:
    """For reports without machine-gradable markers (the 4 adversarial files)."""
    lines = [
        SCORECARD_START,
        "",
        "## Verification scorecard",
        "",
        "This report is part of an adversarial cross-model pair and has no",
        "entry in the agent-guard scenario catalogue, so no recall /",
        "hallucination percentages are computed mechanically. The companion",
        "ground-truth file documents the expected findings.",
        "",
        SCORECARD_END,
    ]
    return "\n".join(lines)


def _replace_or_append(text: str, scorecard: str) -> str:
    """Replace the existing scorecard block, or append if none exists."""
    pattern = re.compile(
        re.escape(SCORECARD_START) + r".*?" + re.escape(SCORECARD_END),
        re.DOTALL,
    )
    if pattern.search(text):
        return pattern.sub(scorecard, text)
    # Append with a separator
    sep = "\n\n---\n\n"
    return text.rstrip() + sep + scorecard + "\n"


def _scenario_id_from_filename(name: str) -> str | None:
    """Extract the scenario ID (e.g., '01') from agent-guard-scenario-XX.md."""
    m = re.match(r"agent-guard-scenario-(\d{2})\.md$", name)
    return m.group(1) if m else None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--inject", action="store_true", help="Write into report files")
    ap.add_argument(
        "--reports-dir",
        default=str(ROOT / "docs" / "example-reports"),
        help="Directory containing the reports",
    )
    args = ap.parse_args()

    reports_dir = Path(args.reports_dir)
    files = sorted(reports_dir.glob("*.md"))
    files = [f for f in files if f.name != "README.md"]
    print(f"# Grading {len(files)} example reports", file=sys.stderr)

    high = mid = low = unscored = 0
    for f in files:
        sid = _scenario_id_from_filename(f.name)
        body = f.read_text(errors="replace")
        if sid is None or sid not in SCENARIOS:
            scorecard = _build_adversarial_scorecard()
            unscored += 1
            print(f"  [skip-grading] {f.name}: no SCENARIOS entry", file=sys.stderr)
        else:
            scorecard = _build_scorecard(sid, body)
            # Tag for stdout summary
            if "HIGH" in scorecard.split("Overall confidence:")[1][:30]:
                high += 1
            elif "MEDIUM" in scorecard.split("Overall confidence:")[1][:30]:
                mid += 1
            else:
                low += 1
        if args.inject:
            new_body = _replace_or_append(body, scorecard)
            if new_body != body:
                f.write_text(new_body)
                print(f"  [injected] {f.name}", file=sys.stderr)
            else:
                print(f"  [unchanged] {f.name}", file=sys.stderr)
        else:
            print(f"\n=== {f.name} ===")
            print(scorecard)

    print(
        f"\n# Summary: HIGH={high} MEDIUM={mid} LOW/FAIL={low} unscored={unscored}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
