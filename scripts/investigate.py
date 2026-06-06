#!/usr/bin/env python3
"""
Headless autonomous-investigation loop (starter idea #7: the persistent loop).

A single `claude -p "investigate X"` already runs findevil's self-directed
loop internally (the server's standing instructions drive orient → pivot →
assess_coverage → finalize_report). This script wraps that in an OUTER
persistent loop with a hard iteration cap so the investigation is driven to
completion fully unattended, with an iteration-over-iteration trace showing
how the agent's coverage changed each pass:

    iteration 1  → found brute force, 4 coverage gaps remain, not finalized
    iteration 2  → closed 3 gaps, pivoted on attacker IP, 1 gap remains
    iteration 3  → coverage CLEAN, finalize_report ACCEPTED → done

Termination is decided MECHANICALLY, not by trusting the agent's say-so:
after each pass we re-read the findevil audit trail (`logs/audit.json`) and
run `assess_coverage` ourselves. The loop stops when coverage is clean AND a
`finalize_report` ACCEPTED entry is present — or when --max-iterations is hit
(graceful degradation; the partial trace is preserved).

Usage
-----
    python scripts/investigate.py evidence/attack-scenario-01
    python scripts/investigate.py evidence/case --max-iterations 6 --model claude-opus-4-8
    python scripts/investigate.py --watch            # auto-triage new evidence on arrival
    python scripts/investigate.py evidence/case --dry-run   # validate the loop without an LLM

Per-iteration traces are written to logs/progress/<evidence>/iteration-NN.json.
Requires the `claude` CLI on PATH (except in --dry-run). Read-only w.r.t.
evidence; only writes under logs/.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# findevil is installed editable (pip install -e .), so these import directly.
from findevil.server import EVIDENCE_DIR, LOGS_DIR
from findevil.tools.autonomy import assess_coverage

REPO_ROOT = Path(__file__).resolve().parent.parent
PROGRESS_DIR = LOGS_DIR / "progress"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_audit() -> list[dict]:
    p = LOGS_DIR / "audit.json"
    if not p.is_file():
        return []
    out = []
    for line in p.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _coverage_state(findings_json: str = "") -> tuple[bool, str]:
    """Run assess_coverage in-process; return (is_clean, full_report)."""
    fn = getattr(assess_coverage, "fn", assess_coverage)  # unwrap FastMCP tool
    report = fn(findings_json)
    return ("COVERAGE CLEAN" in report), report


def _finalize_accepted_since(n_before: int) -> bool:
    """Was a finalize_report ACCEPTED recorded after the first n_before entries?"""
    entries = _read_audit()[n_before:]
    return any(
        e.get("tool") == "finalize_report"
        and str(e.get("result_summary", "")).startswith("ACCEPTED")
        for e in entries
    )


def _build_prompt(evidence: str, iteration: int, prior_gaps: str | None) -> str:
    if iteration == 1 or not prior_gaps:
        return (
            f"Investigate {evidence} using the findevil tools. Run the full "
            "autonomous loop: orient, investigate and pivot on every IOC, call "
            "assess_coverage until coverage is clean, then finalize_report. Do "
            "not stop until finalize_report ACCEPTS your claims."
        )
    return (
        f"Continue investigating {evidence}. A fresh assess_coverage check "
        "still reports the following gaps:\n\n"
        f"{prior_gaps}\n\n"
        "Close every gap above (pivot on any un-chased IOC, examine any "
        "un-examined artifact), re-run assess_coverage to confirm it is clean, "
        "then call finalize_report. Downgrade any CONFIRMED claim the gate "
        "rejects rather than leaving the report unfinalized."
    )


def _run_claude(
    prompt: str, model: str, claude_bin: str, max_turns: int, permission_mode: str
) -> dict:
    """Invoke `claude -p` headless; return parsed metadata (usage, cost, text).

    permission_mode is passed straight through to the claude CLI. It defaults
    to "default" (normal approval prompts). Fully unattended operation needs
    an allow-list or, on a disposable SIFT VM only, an explicit
    `--permission-mode bypassPermissions` — never the default here, so a bypass
    is always a deliberate human choice, not something this script assumes.
    """
    cmd = [
        claude_bin,
        "-p",
        prompt,
        "--permission-mode",
        permission_mode,
        "--output-format",
        "json",
        "--max-turns",
        str(max_turns),
        "--model",
        model,
    ]
    proc = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=1800,
    )
    meta: dict = {"returncode": proc.returncode}
    try:
        obj = json.loads(proc.stdout or "{}")
        meta["result_text"] = obj.get("result") or obj.get("text") or ""
        meta["usage"] = obj.get("usage", {})
        meta["num_turns"] = obj.get("num_turns")
        meta["total_cost_usd"] = obj.get("total_cost_usd")
    except json.JSONDecodeError:
        meta["result_text"] = (proc.stdout or "")[:2000]
        meta["parse_error"] = True
    if proc.stderr:
        meta["stderr"] = proc.stderr[-1000:]
    return meta


def investigate(
    evidence: str,
    *,
    max_iterations: int,
    model: str,
    claude_bin: str,
    max_turns: int,
    permission_mode: str,
    dry_run: bool,
) -> dict:
    """Drive one evidence target to completion. Returns a run summary dict."""
    name = Path(evidence).name or "evidence"
    out_dir = PROGRESS_DIR / name
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n=== Investigating {evidence}  (max {max_iterations} iterations) ===")
    history: list[dict] = []
    prior_gaps: str | None = None
    finalized = False
    clean = False

    for i in range(1, max_iterations + 1):
        n_before = len(_read_audit())
        prompt = _build_prompt(evidence, i, prior_gaps)

        if dry_run:
            # No LLM: just evaluate the current mechanical state so the loop's
            # termination logic and trace plumbing can be validated offline.
            meta = {"dry_run": True, "result_text": "(dry-run: claude not invoked)"}
        else:
            print(f"[iter {i}] launching claude ({model}, perm={permission_mode}) ...")
            meta = _run_claude(prompt, model, claude_bin, max_turns, permission_mode)

        clean, coverage_report = _coverage_state()
        finalized = _finalize_accepted_since(n_before)
        n_after = len(_read_audit())
        prior_gaps = coverage_report if not clean else None

        record = {
            "iteration": i,
            "timestamp": _now(),
            "evidence": evidence,
            "prompt": prompt,
            "tool_calls_this_iteration": n_after - n_before,
            "coverage_clean": clean,
            "finalize_accepted": finalized,
            "coverage_report": coverage_report,
            "claude": {k: v for k, v in meta.items() if k != "result_text"},
        }
        (out_dir / f"iteration-{i:02d}.json").write_text(json.dumps(record, indent=2))
        history.append(record)

        print(
            f"[iter {i}] tools(+{n_after - n_before})  "
            f"coverage={'CLEAN' if clean else 'GAPS'}  "
            f"finalized={'YES' if finalized else 'no'}"
        )

        if clean and finalized:
            print(f"[iter {i}] ✅ coverage clean and finalize_report ACCEPTED — done.")
            break
        if dry_run:
            # One pass is enough to validate plumbing; don't spin.
            print("[dry-run] stopping after one mechanical pass.")
            break
    else:
        print(f"⚠ reached --max-iterations ({max_iterations}) without clean+finalized.")

    summary = {
        "evidence": evidence,
        "iterations": len(history),
        "coverage_clean": clean,
        "finalize_accepted": finalized,
        "progress_dir": str(out_dir),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    print(
        f"--- summary: {len(history)} iteration(s), "
        f"clean={clean}, finalized={finalized}, traces in {out_dir} ---"
    )
    return summary


def watch(args) -> int:
    """Poll EVIDENCE_DIR; investigate each new top-level entry once it appears."""
    print(
        f"👁  watching {EVIDENCE_DIR} for new evidence "
        f"(poll {args.poll_interval}s). Ctrl-C to stop."
    )
    seen: set[str] = {p.name for p in EVIDENCE_DIR.iterdir()} if EVIDENCE_DIR.is_dir() else set()
    print(f"   ignoring {len(seen)} pre-existing entr(y/ies).")
    while True:
        try:
            if EVIDENCE_DIR.is_dir():
                for p in sorted(EVIDENCE_DIR.iterdir()):
                    if p.name in seen or p.name.startswith("."):
                        continue
                    seen.add(p.name)
                    print(f"\n🆕 new evidence detected: {p.name}")
                    investigate(
                        str(p),
                        max_iterations=args.max_iterations,
                        model=args.model,
                        claude_bin=args.claude_bin,
                        max_turns=args.max_turns,
                        permission_mode=args.permission_mode,
                        dry_run=args.dry_run,
                    )
            time.sleep(args.poll_interval)
        except KeyboardInterrupt:
            print("\nstopped.")
            return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("evidence", nargs="?", help="evidence path to investigate")
    ap.add_argument(
        "--max-iterations", type=int, default=5,
        help="hard cap on outer loop passes (default 5)",
    )
    ap.add_argument(
        "--max-turns", type=int, default=60, help="per-claude-run turn cap (default 60)"
    )
    ap.add_argument("--model", default="claude-opus-4-8", help="model id for claude -p")
    ap.add_argument(
        "--claude-bin", default=str(Path.home() / ".local" / "bin" / "claude"),
        help="path to claude CLI",
    )
    ap.add_argument(
        "--watch", action="store_true", help="auto-investigate new evidence as it appears"
    )
    ap.add_argument(
        "--poll-interval", type=int, default=10,
        help="watch poll interval seconds (default 10)",
    )
    ap.add_argument(
        "--permission-mode",
        default="default",
        help="claude CLI permission mode. Default keeps approval prompts. Fully "
        "unattended runs need an allow-list or, on a disposable VM only, "
        "'bypassPermissions' (must be set explicitly).",
    )
    ap.add_argument(
        "--dry-run", action="store_true",
        help="validate the loop without invoking the LLM",
    )
    args = ap.parse_args()

    if args.permission_mode == "bypassPermissions":
        print(
            "⚠  --permission-mode bypassPermissions: the agent runs with approval "
            "gates OFF. Use only on a disposable SIFT VM with read-only evidence.",
            file=sys.stderr,
        )

    if args.watch:
        return watch(args)
    if not args.evidence:
        ap.error("provide an evidence path, or use --watch")

    investigate(
        args.evidence,
        max_iterations=args.max_iterations,
        model=args.model,
        claude_bin=args.claude_bin,
        max_turns=args.max_turns,
        permission_mode=args.permission_mode,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
