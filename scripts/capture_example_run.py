"""Capture a real tool-execution audit trail for an example IR run.

The hackathon's deliverable #8 requires *structured logs showing the
full agent communication and tool execution sequence with timestamps*.
The committed agent reports under ``docs/example-reports/`` cover the
"agent communication" half (Claude's investigation prose). This script
produces the matching "tool execution sequence" half — a real, timestamped
``audit.json`` trace from the actual MCP server, exercising the same
tools an agent would call against a bundled scenario.

The script does NOT involve an LLM. It invokes the findevil tools directly
in a sequence that mirrors a typical investigation, so every entry in
the resulting audit log is a real ``_audit()`` write from the live server
code (same code path the MCP-driven agent runs through).

Usage::

    python scripts/capture_example_run.py --scenario 01 \\
        --output docs/example-reports/audit-trail-scenario-01.jsonl

Re-run any time to refresh the committed trace; the timestamps will be
new, but the tool-call sequence is deterministic for a given scenario.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = REPO_ROOT / "samples"


def _setup_env(scenario_dir: Path, logs_dir: Path) -> None:
    """Point the findevil server at the scenario's evidence and a temp log dir."""
    os.environ["FINDEVIL_EVIDENCE_DIR"] = str(scenario_dir.parent.resolve())
    os.environ["FINDEVIL_LOGS_DIR"] = str(logs_dir.resolve())
    logs_dir.mkdir(parents=True, exist_ok=True)
    # Wipe any pre-existing audit.json so the captured trace is just this run.
    audit_path = logs_dir / "audit.json"
    if audit_path.exists():
        audit_path.unlink()


def _run_scenario_01(scenario: Path) -> None:
    """Realistic investigation sequence for scenario 01 (loud SSH brute force)."""
    # Imports happen AFTER env vars are set so server.py picks them up.
    from findevil.server import file_info, hash_file, list_evidence
    from findevil.tools.linux_auth import (
        auth_failed_logins,
        auth_successful_logins,
        auth_sudo_commands,
        auth_summary,
        auth_user_events,
    )
    from findevil.tools.linux_journal import analyze_journal
    from findevil.tools.linux_persistence import (
        analyze_authorized_keys,
        analyze_sshd_config,
        analyze_systemd_unit,
        find_persistence,
    )
    from findevil.tools.linux_shell_history import (
        analyze_bash_history,
        find_shell_histories,
    )
    from findevil.tools.self_correction import (
        find_contradictions,
        get_audit_trail,
        verify_finding,
    )
    from findevil.tools.threat_intel import bulk_ioc_lookup, extract_iocs

    s = scenario
    fs = s / "fs"

    # 1. Triage — what's available?
    list_evidence(str(s))

    # 2. Auth log — full sweep
    auth_summary(str(s / "auth.log"))
    auth_failed_logins(str(s / "auth.log"))
    auth_successful_logins(str(s / "auth.log"))
    auth_sudo_commands(str(s / "auth.log"))
    auth_user_events(str(s / "auth.log"))

    # 3. Journald corroboration
    analyze_journal(str(s / "journal.jsonl"))

    # 4. Persistence sweep
    find_persistence(str(fs))
    analyze_authorized_keys(str(fs / "root/.ssh/authorized_keys"))
    analyze_systemd_unit(str(fs / "etc/systemd/system/sysd-helper.service"))
    analyze_sshd_config(str(fs / "etc/ssh/sshd_config"))

    # 5. Shell history
    find_shell_histories(str(fs))
    analyze_bash_history(str(fs / "root/.bash_history"))

    # 6. File integrity touchpoints
    file_info(str(fs / "etc/ld.so.preload"))
    hash_file(str(fs / "etc/ld.so.preload"))

    # 7. IOC extraction + lookup — both tools take a text blob (not a path)
    auth_log_content = (s / "auth.log").read_text(errors="replace")
    extract_iocs(auth_log_content)
    bulk_ioc_lookup(auth_log_content)

    # 8. Self-correction — verify the loudest claims
    verify_finding(
        "brute_force_from_ip",
        json.dumps({
            "log_path": str(s / "auth.log"),
            "ip": "45.123.45.67",
            "min_attempts": 50,
        }),
    )
    verify_finding(
        "successful_login_after_brute_force",
        json.dumps({
            "log_path": str(s / "auth.log"),
            "ip": "45.123.45.67",
            "user": "root",
        }),
    )
    verify_finding(
        "user_created",
        json.dumps({"log_path": str(s / "auth.log"), "name": "sysd"}),
    )
    verify_finding(
        "user_created",
        json.dumps({"log_path": str(s / "auth.log"), "name": "toor"}),
    )
    verify_finding(
        "persistence_mechanism_exists",
        json.dumps({"fs_root": str(fs), "category": "systemd"}),
    )

    find_contradictions(json.dumps([
        {
            "id": "c1",
            "type": "brute_force_from_ip",
            "log_path": str(s / "auth.log"),
            "ip": "45.123.45.67",
        },
        {
            "id": "c2",
            "type": "compromise_verdict",
            "verdict": "confirmed",
            "attacker_ip": "45.123.45.67",
        },
        {
            "id": "c3",
            "type": "user_created",
            "name": "sysd",
        },
    ]))

    # 9. Final introspection — confirm every claim maps to a real call
    get_audit_trail(limit=200)


_RUNNERS = {
    "01": _run_scenario_01,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario",
        default="01",
        help="Scenario number to capture (default: 01)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Destination path for the captured audit trail JSONL "
             "(default: docs/example-reports/audit-trail-scenario-N.jsonl)",
    )
    parser.add_argument(
        "--logs-dir",
        type=Path,
        default=REPO_ROOT / "logs",
        help="Where the server should write its working audit.json before "
             "we copy it to --output. Default: ./logs",
    )
    args = parser.parse_args()

    if args.scenario not in _RUNNERS:
        sys.stderr.write(
            f"No capture sequence defined for scenario {args.scenario}. "
            f"Available: {', '.join(sorted(_RUNNERS))}\n"
        )
        return 2

    scenario_dirname = {
        "01": "attack-scenario-01",
    }[args.scenario]
    scenario_dir = SAMPLES_DIR / scenario_dirname
    if not scenario_dir.is_dir():
        sys.stderr.write(f"Scenario evidence not found: {scenario_dir}\n")
        return 2

    output = args.output or (
        REPO_ROOT / "docs" / "example-reports" /
        f"audit-trail-scenario-{args.scenario}.jsonl"
    )

    _setup_env(scenario_dir, args.logs_dir)
    _RUNNERS[args.scenario](scenario_dir)

    audit_path = args.logs_dir / "audit.json"
    if not audit_path.is_file():
        sys.stderr.write(
            f"Server did not produce {audit_path}. "
            "Was findevil installed (pip install -e .)?\n"
        )
        return 1

    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(audit_path, output)

    entry_count = sum(1 for line in audit_path.read_text().splitlines() if line.strip())
    print(f"Wrote {entry_count} audit entries to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
