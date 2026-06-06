#!/usr/bin/env python3
"""
Model comparison: run the same scenarios against different Claude models,
tabulate recall / hallucination / duration.

Useful for demo deck: "Here's how the same evidence looks investigated by
haiku vs sonnet — does the weaker model still get the verdict right, or
does it skip findings?" A good architecture should degrade gracefully
across models.

Usage:
    python tests/harness/model_compare.py [scenarios] [models]
    # defaults: scenarios=02,06  models=haiku,sonnet
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
    REPORTS_DIR,
    SCENARIOS,
    find_written_report,
    grade,
    run_claude,
)


def main() -> int:
    scenarios_arg = sys.argv[1] if len(sys.argv) > 1 else "02,06"
    models_arg = sys.argv[2] if len(sys.argv) > 2 else "haiku,sonnet"
    sids = [s.strip() for s in scenarios_arg.split(",") if s.strip()]
    models = [m.strip() for m in models_arg.split(",") if m.strip()]

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    started_at = datetime.now(timezone.utc)
    stamp = started_at.strftime("%Y%m%dT%H%M%SZ")
    print(f"[{started_at.isoformat()}] model compare — scenarios={sids} models={models}")

    results = []
    for sid in sids:
        scenario = SCENARIOS.get(sid)
        if scenario is None:
            print(f"  skip unknown scenario {sid}")
            continue
        for model in models:
            os.environ["AGENT_GUARD_MODEL"] = model
            # re-import/reload isn't needed; run_claude reads MODEL at call time
            import agent_guard as ag
            ag.MODEL = model  # type: ignore[attr-defined]
            transcript = LOGS_DIR / f"agent_guard_s{sid}_{model}_{stamp}.transcript"
            print(f"\n--- S{sid} @ {model} ---")
            run_started = datetime.now(timezone.utc)
            meta: dict = {}
            try:
                rc, body, meta = run_claude(scenario, transcript)
            except subprocess.TimeoutExpired:
                rc = -1
                body = transcript.read_text(errors="replace")
            written_report = find_written_report(scenario, run_started)
            g = grade(scenario, body + "\n" + written_report)
            dur = (datetime.now(timezone.utc) - started_at).total_seconds()  # rough
            entry = {
                "scenario": sid,
                "model": model,
                "rc": rc,
                "recall_ok": g["recall_ok"],
                "no_hallucination": g["no_hallucination"],
                "missing": g["missing_required"],
                "forbidden_present": g["forbidden_present"],
                "transcript": str(transcript),
                # Token usage / cost — required by hackathon deliverable #8.
                "usage": meta.get("usage") or {},
                "total_cost_usd": meta.get("total_cost_usd"),
                "num_turns": meta.get("num_turns"),
                "duration_ms": meta.get("duration_ms"),
                "session_id": meta.get("session_id"),
            }
            print(
                f"  rc={rc} recall={g['recall_ok']} "
                f"hallucinate={not g['no_hallucination']} "
                f"missing={g['missing_required']}"
            )
            results.append(entry)

    summary = {
        "type": "model_compare",
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "scenarios": sids,
        "models": models,
        "results": results,
    }
    with (LOGS_DIR / "model_compare.jsonl").open("a") as fh:
        fh.write(json.dumps(summary) + "\n")

    print()
    print("=" * 64)
    print(f"{'scenario':<10}{'model':<12}{'recall':<10}{'hallucination':<16}")
    for r in results:
        print(
            f"{r['scenario']:<10}{r['model']:<12}"
            f"{str(r['recall_ok']):<10}{str(not r['no_hallucination']):<16}"
        )
    return 0 if all(r["recall_ok"] and r["no_hallucination"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
