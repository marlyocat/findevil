#!/usr/bin/env python3
"""
Consistency test: run the same scenario N times, check that Claude's verdict
and findings don't drift across runs.

A deterministic agent over deterministic evidence should produce the same
high-level conclusions every time. Large variance in findings means Claude
is treating tool output as a soft prior, not as ground truth.

Scoring per scenario:
- Verdict stability: all N reports contain the required marker set
- Fabrication stability: no run contains forbidden markers from OTHER
  scenarios (cross-run hallucination check)
- Finding count variance: rough measure of consistency

Usage:
    python tests/harness/consistency_test.py [scenario] [N]
    defaults: scenario=02 (the quietest — hardest to call correctly), N=3
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from agent_guard import (
    FINDEVIL_ROOT,
    LOGS_DIR,
    MODEL,
    REPORTS_DIR,
    SCENARIOS,
    grade,
    run_claude,
)


def main() -> int:
    sid = sys.argv[1] if len(sys.argv) > 1 else "02"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    scenario = SCENARIOS.get(sid)
    if scenario is None:
        print(f"unknown scenario: {sid}", file=sys.stderr)
        return 2

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    started_at = datetime.now(timezone.utc)
    stamp = started_at.strftime("%Y%m%dT%H%M%SZ")
    print(f"[{started_at.isoformat()}] consistency test — S{sid} × {n} runs — model={MODEL}")

    run_results = []
    for i in range(n):
        run_id = f"{sid}_consistency_{stamp}_run{i + 1}"
        transcript = LOGS_DIR / f"agent_guard_{run_id}.transcript"
        print(f"\n--- run {i + 1}/{n} ---")
        meta: dict = {}
        try:
            rc, body, meta = run_claude(scenario, transcript)
        except subprocess.TimeoutExpired:
            rc = -1
            body = transcript.read_text(errors="replace") + "\n[TIMEOUT]"
        result = grade(scenario, body)
        result.update({
            "run": i + 1,
            "rc": rc,
            "transcript": str(transcript),
            # Token usage / cost — required by hackathon deliverable #8.
            "usage": meta.get("usage") or {},
            "total_cost_usd": meta.get("total_cost_usd"),
            "num_turns": meta.get("num_turns"),
            "duration_ms": meta.get("duration_ms"),
            "session_id": meta.get("session_id"),
        })
        run_results.append(result)
        print(
            f"  recall_ok={result['recall_ok']} "
            f"no_hallucination={result['no_hallucination']} "
            f"missing={result['missing_required']} "
            f"forbidden_present={result['forbidden_present']}"
        )

    # Agreement analysis
    verdicts_pass_count = sum(1 for r in run_results if r["recall_ok"])
    hallucination_free_count = sum(1 for r in run_results if r["no_hallucination"])

    # Missing / forbidden set across all runs
    all_missing = sorted({m for r in run_results for m in r["missing_required"]})
    all_forbidden = sorted({m for r in run_results for m in r["forbidden_present"]})

    summary = {
        "type": "consistency",
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "scenario": sid,
        "model": MODEL,
        "n_runs": n,
        "runs_recall_pass": verdicts_pass_count,
        "runs_hallucination_free": hallucination_free_count,
        "unique_missing_across_runs": all_missing,
        "unique_forbidden_across_runs": all_forbidden,
        "runs": run_results,
    }
    with (LOGS_DIR / "consistency_test.jsonl").open("a") as fh:
        fh.write(json.dumps(summary) + "\n")

    print()
    print("=" * 64)
    print(f"consistency test S{sid}: {verdicts_pass_count}/{n} recall, {hallucination_free_count}/{n} hallucination-free")
    if all_missing:
        print(f"  markers missing across runs: {all_missing}")
    if all_forbidden:
        print(f"  forbidden markers seen across runs: {all_forbidden}")
    return 0 if verdicts_pass_count == n and hallucination_free_count == n else 1


if __name__ == "__main__":
    sys.exit(main())
