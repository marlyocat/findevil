#!/usr/bin/env python3
"""
Context-bleed test: run two scenarios in the SAME Claude session and check
that the second report doesn't reference artifacts from the first.

The regular agent_guard spawns a fresh Claude per scenario, so it can't
catch within-session context bleed. This test does: one long prompt asks
Claude to investigate S01, write a report, then investigate S02 as a
separate matter and write a second report. If S01's brute-force IP
(``45.123.45.67``) or rootkit (``libprocesshider``) shows up in the S02
report, Claude carried priors forward rather than reasoning from the
S02 evidence alone.

Usage:
    python tests/harness/context_bleed_test.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

FINDEVIL_ROOT = Path(os.environ.get("FINDEVIL_ROOT", "/home/sansforensics/findevil")).resolve()
LOGS_DIR = FINDEVIL_ROOT / "logs"
REPORTS_DIR = FINDEVIL_ROOT / "reports"
CLAUDE_BIN = os.environ.get("CLAUDE_BIN", str(Path.home() / ".local" / "bin" / "claude"))
MODEL = os.environ.get("AGENT_GUARD_MODEL", "sonnet")


COMBINED_PROMPT = (
    "You will investigate TWO SEPARATE incidents in one sitting. Treat them "
    "as unrelated cases — do not assume the attack pattern from the first "
    "investigation applies to the second.\n\n"
    "INCIDENT 1: Investigate evidence/attack-scenario-01. Produce a brief "
    "IR report (one paragraph, verdict + top 3 indicators). Write it to "
    "reports/bleed-01.md. Then STOP that investigation — forget it.\n\n"
    "INCIDENT 2: A developer's SSH key may have been stolen. Investigate "
    "whether webserver-prod-02 was compromised. The evidence is in "
    "evidence/attack-scenario-02. Reach conclusions from ONLY this "
    "evidence — do NOT reference IPs, users, files, or artifacts from "
    "INCIDENT 1. Write the final report to reports/bleed-02.md."
)

# If these appear in bleed-02.md, S01 context leaked into the S02 analysis.
S01_LEAK_MARKERS = [
    "45.123.45.67",    # S01 brute-force IP
    "185.177.124.22",  # S01 C2 IP
    "toor",             # S01 backdoor user (specific name)
    "libprocesshider",  # S01 rootkit
    "sysd-helper",      # S01 systemd unit
    "sysd-cron",        # S01 cron
    "pam_exec",         # S01 PAM
]


def main() -> int:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    started_at = datetime.now(timezone.utc)
    stamp = started_at.strftime("%Y%m%dT%H%M%SZ")
    transcript = LOGS_DIR / f"context_bleed_{stamp}.transcript"

    print(f"[{started_at.isoformat()}] context-bleed test — S01 then S02 in one session — model={MODEL}")

    env = {**os.environ, "PATH": f"{Path.home() / '.local' / 'bin'}:{os.environ.get('PATH', '')}"}
    cmd = [
        CLAUDE_BIN, "-p", COMBINED_PROMPT,
        "--permission-mode", "bypassPermissions",
        "--output-format", "text",
        "--max-turns", "120",
        "--model", MODEL,
    ]
    with transcript.open("w") as fh:
        fh.write(f"# context-bleed test\n# started {started_at.isoformat()}\n\n")
        fh.flush()
        try:
            rc = subprocess.run(
                cmd, cwd=str(FINDEVIL_ROOT), env=env,
                stdout=fh, stderr=subprocess.STDOUT, timeout=1800,
            ).returncode
        except subprocess.TimeoutExpired:
            fh.write("\n[TIMEOUT — claude -p exceeded 1800s]\n")
            rc = -1

    # Grade S02 report specifically
    report2 = REPORTS_DIR / "bleed-02.md"
    if not report2.exists():
        print("FAIL — Claude did not write reports/bleed-02.md", file=sys.stderr)
        return 1
    body = report2.read_text(errors="replace")
    low = body.lower()
    leaks = [m for m in S01_LEAK_MARKERS if m.lower() in low]

    summary = {
        "type": "context_bleed",
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "model": MODEL,
        "claude_rc": rc,
        "transcript_file": str(transcript),
        "bleed_markers_found": leaks,
        "passed": not leaks,
    }
    with (LOGS_DIR / "context_bleed_test.jsonl").open("a") as fh:
        fh.write(json.dumps(summary) + "\n")

    print()
    print("=" * 64)
    if leaks:
        print(f"FAIL — S01 context leaked into S02 report: {leaks}")
        return 1
    print("PASS — S02 report contains no S01-specific artifacts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
