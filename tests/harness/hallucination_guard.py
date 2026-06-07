#!/usr/bin/env python3
"""
FindEvil MCP hallucination guard.

Runs the findevil MCP server as a subprocess, connects as an MCP client,
invokes each tool against each of the four ground-truth scenarios, and
asserts that tool output contains required markers (recall) and does NOT
contain forbidden markers (precision / no-hallucination).

Hallucination is checked at the tool layer. The LLM's input is only as
trustworthy as the tools underneath it — if the tools ever start emitting
signals that aren't backed by the evidence, Claude's downstream reasoning
drifts. Stabilizing this layer is the single biggest hallucination lever.

Exit code: 0 if every check passed, 1 otherwise.
Results are appended to ``logs/hallucination_guard.jsonl`` (one JSON per
run) so a cron / loop driver can track trends over time.

Usage::

    python tests/harness/hallucination_guard.py
    # honors FINDEVIL_ROOT (default /home/sansforensics/findevil)
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

FINDEVIL_ROOT = Path(os.environ.get("FINDEVIL_ROOT", "/home/sansforensics/findevil")).resolve()
EVIDENCE_ROOT = FINDEVIL_ROOT / "evidence"
LOGS_DIR = FINDEVIL_ROOT / "logs"


def scenario_path(scenario: str, *parts: str) -> str:
    return str(EVIDENCE_ROOT.joinpath(scenario, *parts))


@dataclass
class Check:
    name: str
    tool: str
    args: dict
    must_contain: list[str] = field(default_factory=list)
    must_not_contain: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Ground-truth expectations, distilled from docs/accuracy-report.md §3.
# Markers are matched case-insensitively as substrings against the full
# text body the tool returns. Keep these tight enough to catch drift but
# loose enough to survive minor wording changes.
# ---------------------------------------------------------------------------

CHECKS: list[Check] = [
    # -------- Scenario 01 (loud attacker) — recall --------
    Check(
        name="s01/auth_failed_logins surfaces brute-force IP",
        tool="auth_failed_logins",
        args={"path": scenario_path("attack-scenario-01", "auth.log")},
        must_contain=["45.123.45.67"],
        must_not_contain=["No failed login attempts"],
    ),
    Check(
        name="s01/auth_successful_logins shows root login",
        tool="auth_successful_logins",
        args={"path": scenario_path("attack-scenario-01", "auth.log")},
        must_contain=["root", "45.123.45.67"],
    ),
    Check(
        name="s01/auth_user_events surfaces sysd useradd",
        tool="auth_user_events",
        args={"path": scenario_path("attack-scenario-01", "auth.log")},
        must_contain=["sysd"],
    ),
    Check(
        name="s01/auth_summary reports compromise",
        tool="auth_summary",
        args={"path": scenario_path("attack-scenario-01", "auth.log")},
        must_contain=["compromise"],
    ),
    Check(
        name="s01/find_persistence surfaces rootkit + toor + service + cron",
        tool="find_persistence",
        args={"root_path": scenario_path("attack-scenario-01", "fs")},
        must_contain=[
            "toor",
            "libprocesshider",
            "sysd-helper.service",
            "sysd-cron",
        ],
    ),
    # -------- Scenario 02 (quiet attacker) — precision --------
    Check(
        name="s02/auth_failed_logins reports ZERO (no hallucinated brute force)",
        tool="auth_failed_logins",
        args={"path": scenario_path("attack-scenario-02", "auth.log")},
        must_contain=["No failed login"],
        must_not_contain=["45.123.45.67", "brute"],
    ),
    Check(
        name="s02/auth_user_events reports NONE (no hallucinated useradd)",
        tool="auth_user_events",
        args={"path": scenario_path("attack-scenario-02", "auth.log")},
        must_contain=["No user"],
        must_not_contain=["sysd", "toor"],
    ),
    Check(
        name="s02/find_persistence surfaces beacon service, not rootkit/toor",
        tool="find_persistence",
        args={"root_path": scenario_path("attack-scenario-02", "fs")},
        must_contain=["system-updater.service"],
        must_not_contain=["libprocesshider", "toor", "ld.so.preload"],
    ),
    Check(
        name="s02/verify_finding rejects brute_force_from_ip (self-correction)",
        tool="verify_finding",
        args={
            "claim_type": "brute_force_from_ip",
            "params": json.dumps(
                {
                    "log_path": scenario_path("attack-scenario-02", "auth.log"),
                    "ip": "185.229.59.103",
                    "min_attempts": 5,
                }
            ),
        },
        must_contain=["CONTRADICTED"],
    ),
    # -------- Scenario 03 (webshell attacker) — recall --------
    Check(
        name="s03/analyze_nginx_access flags scanner + webshell chain",
        tool="analyze_nginx_access",
        args={"path": scenario_path("attack-scenario-03", "access.log")},
        must_contain=["91.121.55.44", "shell.php"],
    ),
    Check(
        name="s03/find_webshells finds shell.php",
        tool="find_webshells",
        args={"root_path": scenario_path("attack-scenario-03", "fs")},
        must_contain=["shell.php"],
        must_not_contain=["No webshell"],
    ),
    # -------- Scenario 04 (supply chain) — recall --------
    Check(
        name="s04/analyze_package_logs flags typosquat + xmrig + auditd removal",
        tool="analyze_package_logs",
        args={"root_path": scenario_path("attack-scenario-04", "fs")},
        must_contain=["requests-utils", "xmrig", "auditd"],
    ),
    Check(
        name="s04/analyze_container_artifacts flags privileged container + 2375",
        tool="analyze_container_artifacts",
        args={"root_path": scenario_path("attack-scenario-04", "fs")},
        must_contain=["Privileged", "2375", "docker.sock"],
    ),
]


def _extract_text(result) -> str:
    parts: list[str] = []
    for chunk in getattr(result, "content", []) or []:
        text = getattr(chunk, "text", None)
        if text:
            parts.append(text)
    return "\n".join(parts)


async def run_check(session: ClientSession, check: Check) -> tuple[bool, str, str]:
    try:
        result = await session.call_tool(check.tool, check.args)
    except Exception as exc:  # noqa: BLE001 - surface any client-side failure
        return False, f"tool call raised {type(exc).__name__}: {exc}", ""
    text = _extract_text(result)
    low = text.lower()
    missing = [m for m in check.must_contain if m.lower() not in low]
    forbidden = [m for m in check.must_not_contain if m.lower() in low]
    if missing and forbidden:
        return False, f"missing {missing}; forbidden present {forbidden}", text
    if missing:
        return False, f"missing required markers: {missing}", text
    if forbidden:
        return False, f"contains forbidden markers: {forbidden}", text
    return True, "ok", text


async def main() -> int:
    params = StdioServerParameters(
        command=str(FINDEVIL_ROOT / ".venv" / "bin" / "python"),
        args=["-m", "findevil"],
        env={
            **os.environ,
            "FINDEVIL_EVIDENCE_DIR": str(EVIDENCE_ROOT),
            "FINDEVIL_LOGS_DIR": str(LOGS_DIR),
            "PYTHONPATH": str(FINDEVIL_ROOT / "src"),
        },
    )

    started_at = datetime.now(timezone.utc)
    passed = 0
    failures: list[dict] = []

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            for check in CHECKS:
                ok, msg, body = await run_check(session, check)
                tag = "PASS" if ok else "FAIL"
                print(f"[{tag}] {check.name} — {msg}")
                if ok:
                    passed += 1
                else:
                    failures.append(
                        {
                            "check": check.name,
                            "tool": check.tool,
                            "args": check.args,
                            "reason": msg,
                            "body_head": body[:600],
                        }
                    )

    total = len(CHECKS)
    failed = total - passed
    finished_at = datetime.now(timezone.utc)

    summary = {
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_s": (finished_at - started_at).total_seconds(),
        "findevil_root": str(FINDEVIL_ROOT),
        "total": total,
        "passed": passed,
        "failed": failed,
        "failures": failures,
    }
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    with (LOGS_DIR / "hallucination_guard.jsonl").open("a") as fh:
        fh.write(json.dumps(summary) + "\n")

    print()
    print("=" * 64)
    print(f"{passed}/{total} checks passed  ({failed} failed)")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
