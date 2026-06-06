#!/usr/bin/env python3
"""
Self-correction audit: did Claude actually use the findevil self-correction
tools (verify_finding, find_contradictions, get_audit_trail) during agent
runs that prompted for them?

Rationale: the hackathon's "Autonomous Execution Quality" criterion rewards
agents that audit themselves. S01's prompt explicitly asks Claude to call
those tools. This script parses logs/audit.json and confirms they were
invoked during each completed agent run — not just that Claude wrote "I
verified my findings" in the report without actually running the tools.

Pass criteria (per scenario that prompts for self-correction):
- verify_finding     ≥ 1 call
- find_contradictions ≥ 1 call
- get_audit_trail    ≥ 1 call

Exit 0 if all scenarios that should have self-corrected did so. Exit 1
otherwise, with details on which agent run skipped which tool.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Iterable

FINDEVIL_ROOT = Path(os.environ.get("FINDEVIL_ROOT", "/home/sansforensics/findevil")).resolve()
AUDIT_LOG = FINDEVIL_ROOT / "logs" / "audit.json"
AGENT_JSONL = FINDEVIL_ROOT / "logs" / "agent_guard.jsonl"
# get_audit_trail is deliberately NOT written to audit.json (recursion).
# A side-channel counter in self_correction.get_audit_trail() writes here.
GET_AUDIT_TRAIL_LOG = FINDEVIL_ROOT / "logs" / "get_audit_trail_invocations.jsonl"

# Scenarios whose prompts explicitly ask the agent to use self-correction.
# Keep this in sync with agent_guard.py — only S01 currently prompts for it.
SELF_CORRECTION_REQUIRED_SCENARIOS = {"01"}
SELF_CORRECTION_TOOLS = {"verify_finding", "find_contradictions", "get_audit_trail"}


def load_audit_entries() -> list[dict]:
    if not AUDIT_LOG.exists():
        return []
    entries: list[dict] = []
    with AUDIT_LOG.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def load_agent_runs() -> list[dict]:
    if not AGENT_JSONL.exists():
        return []
    runs: list[dict] = []
    with AGENT_JSONL.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                runs.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return runs


def audit_entries_in_window(
    entries: Iterable[dict], start_iso: str, end_iso: str
) -> list[dict]:
    return [e for e in entries if start_iso <= e.get("timestamp", "") <= end_iso]


def load_get_audit_trail_invocations() -> list[dict]:
    if not GET_AUDIT_TRAIL_LOG.exists():
        return []
    invocations: list[dict] = []
    with GET_AUDIT_TRAIL_LOG.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                invocations.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return invocations


def audit_run(
    run: dict,
    audit_entries: list[dict],
    get_audit_trail_invocations: list[dict],
) -> dict:
    # A malformed jsonl line could be missing any of these keys; use .get()
    # with sensible defaults so a single bad row doesn't abort the whole audit.
    scenario = run.get("scenario", "?")
    started_at = run.get("started_at", "")
    finished_at = run.get("finished_at", "")
    window = audit_entries_in_window(audit_entries, started_at, finished_at)
    tool_counts: dict[str, int] = {}
    for entry in window:
        tool = entry.get("tool")
        if not tool:
            continue
        tool_counts[tool] = tool_counts.get(tool, 0) + 1
    # get_audit_trail comes from the side-channel log, filtered to the run window.
    gat_count = sum(
        1 for i in get_audit_trail_invocations
        if started_at <= i.get("timestamp", "") <= finished_at
    )
    self_correction_counts = {
        "verify_finding": tool_counts.get("verify_finding", 0),
        "find_contradictions": tool_counts.get("find_contradictions", 0),
        "get_audit_trail": gat_count,
    }
    required = scenario in SELF_CORRECTION_REQUIRED_SCENARIOS
    missing = [t for t, c in self_correction_counts.items() if c == 0]
    passed = not required or not missing
    return {
        "scenario": scenario,
        "started_at": started_at,
        "total_tool_calls": sum(tool_counts.values()),
        "self_correction_counts": self_correction_counts,
        "required": required,
        "missing_self_correction_tools": missing if required else [],
        "passed": passed,
    }


def main() -> int:
    runs = load_agent_runs()
    if not runs:
        print("no agent runs found in agent_guard.jsonl", file=sys.stderr)
        return 2
    audit_entries = load_audit_entries()
    gat_invocations = load_get_audit_trail_invocations()

    print(
        f"inspected {len(runs)} agent runs against {len(audit_entries)} audit entries "
        f"+ {len(gat_invocations)} get_audit_trail side-channel records\n"
    )

    results = [audit_run(r, audit_entries, gat_invocations) for r in runs]
    failures = [r for r in results if not r["passed"]]

    for r in results:
        tag = "PASS" if r["passed"] else "FAIL"
        sc = r["self_correction_counts"]
        print(
            f"[{tag}] S{r['scenario']}  {r['started_at']}  "
            f"calls={r['total_tool_calls']}  "
            f"verify_finding={sc['verify_finding']} "
            f"find_contradictions={sc['find_contradictions']} "
            f"get_audit_trail={sc['get_audit_trail']}"
            + (f"  MISSING={r['missing_self_correction_tools']}" if not r["passed"] else "")
        )

    print()
    print("=" * 64)
    print(f"{len(results) - len(failures)}/{len(results)} runs passed self-correction audit")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
