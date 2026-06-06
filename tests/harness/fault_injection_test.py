#!/usr/bin/env python3
"""
Fault injection test: run a scenario with a percentage of MCP tool calls
returning simulated errors. Confirms that Claude:

1. Doesn't crash or hang.
2. Notices when tools fail and either retries or pivots.
3. Does NOT fabricate findings that would have required the failed tool
   to produce them.

Set FINDEVIL_FAULT_RATE in the MCP server env (see server.py _run_tool).
Default rate: 0.20 (20% of subprocess-based tool calls return a
simulated timeout fault). Only subprocess-based primitives are affected
(the Python-native scanners like find_persistence are unaffected).

Usage:
    python tests/harness/fault_injection_test.py [scenario] [rate]
    defaults: scenario=02, rate=0.20
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
    find_written_report,
    grade,
    run_claude,
)

CLAUDE_BIN = os.environ.get("CLAUDE_BIN", str(Path.home() / ".local" / "bin" / "claude"))


def main() -> int:
    sid = sys.argv[1] if len(sys.argv) > 1 else "02"
    rate = sys.argv[2] if len(sys.argv) > 2 else "0.20"
    scenario = SCENARIOS.get(sid)
    if scenario is None:
        print(f"unknown scenario: {sid}", file=sys.stderr)
        return 2

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    started_at = datetime.now(timezone.utc)
    stamp = started_at.strftime("%Y%m%dT%H%M%SZ")
    transcript = LOGS_DIR / f"fault_injection_s{sid}_{stamp}.transcript"

    print(f"[{started_at.isoformat()}] fault-injection — S{sid} — FAULT_RATE={rate}")

    # Pass FINDEVIL_FAULT_RATE to the MCP subprocess via the environment.
    # run_claude doesn't know about this, so we inject into os.environ
    # directly — the Claude subprocess inherits it, which in turn
    # forwards to the findevil stdio subprocess.
    os.environ["FINDEVIL_FAULT_RATE"] = rate

    meta: dict = {}
    try:
        rc, body, meta = run_claude(scenario, transcript)
    except subprocess.TimeoutExpired:
        rc = -1
        body = transcript.read_text(errors="replace")
    finally:
        os.environ.pop("FINDEVIL_FAULT_RATE", None)

    written_report = find_written_report(scenario, started_at)
    full_body = body + "\n" + written_report
    g = grade(scenario, full_body)

    # Graceful-degradation signal: the transcript should mention "fault",
    # "timeout", "error", or "unable" if Claude noticed something was
    # wrong. Not required for pass (Claude may not surface it), but we
    # record it for manual review.
    acknowledged_keywords = ["fault", "simulated", "timeout", "unable to", "tool error", "failed"]
    low = full_body.lower()
    acknowledged = [k for k in acknowledged_keywords if k in low]

    summary = {
        "type": "fault_injection",
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "scenario": sid,
        "fault_rate": float(rate),
        "model": MODEL,
        "claude_rc": rc,
        "recall_ok": g["recall_ok"],
        "no_hallucination": g["no_hallucination"],
        "missing_required": g["missing_required"],
        "forbidden_present": g["forbidden_present"],
        "acknowledged_faults": acknowledged,
        "transcript_file": str(transcript),
        # Token usage / cost — required by hackathon deliverable #8.
        "usage": meta.get("usage") or {},
        "total_cost_usd": meta.get("total_cost_usd"),
        "num_turns": meta.get("num_turns"),
        "duration_ms": meta.get("duration_ms"),
        "session_id": meta.get("session_id"),
    }
    with (LOGS_DIR / "fault_injection_test.jsonl").open("a") as fh:
        fh.write(json.dumps(summary) + "\n")

    print()
    print("=" * 64)
    print(f"rc={rc} recall_ok={g['recall_ok']} no_hallucination={g['no_hallucination']}")
    print(f"acknowledged_faults={acknowledged}")
    if g["forbidden_present"]:
        print(f"HALLUCINATION under fault injection: {g['forbidden_present']}")
    # The primary signal: no cross-scenario hallucination even under degraded
    # tool reliability. Missing recall markers is acceptable (tool failed);
    # fabrication is not.
    return 0 if g["no_hallucination"] else 1


if __name__ == "__main__":
    sys.exit(main())
