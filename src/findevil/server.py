"""
Findevil MCP Server

Exposes SANS SIFT Workstation forensic tools as typed, read-only MCP tools.
Designed to be used by Claude Code (or any MCP client) for autonomous IR triage.

Key design principles:
- READ-ONLY: Tools must never modify evidence (forensic integrity)
- LOGGED: Every tool invocation is logged with timestamps for audit trail
- TYPED: Structured inputs/outputs, not raw shell commands
- SAFE: All paths validated against allowed evidence directories
"""

import json
import logging
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Configuration (env-configurable so judges can point at any evidence layout)
# ---------------------------------------------------------------------------

EVIDENCE_DIR = Path(os.environ.get("FINDEVIL_EVIDENCE_DIR", "./evidence")).resolve()
LOGS_DIR = Path(os.environ.get("FINDEVIL_LOGS_DIR", "./logs")).resolve()
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Logging — every tool call is recorded for the audit trail
# ---------------------------------------------------------------------------

audit_logger = logging.getLogger("findevil.audit")
audit_logger.setLevel(logging.INFO)
audit_logger.propagate = False  # don't bubble to root logger

# Guard: server.py runs both as __main__ and as findevil.server (re-imported
# by tool modules). Without this check, the handler is registered twice and
# every audit entry gets written twice.
if not audit_logger.handlers:
    _handler = logging.FileHandler(LOGS_DIR / "audit.json")
    _handler.setFormatter(logging.Formatter("%(message)s"))
    audit_logger.addHandler(_handler)


def _audit(tool: str, params: dict, result_summary: str) -> None:
    """Write a structured audit log entry for every tool invocation."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": tool,
        "params": params,
        "result_summary": result_summary[:500],
    }
    audit_logger.info(json.dumps(entry))


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------

def _validate_evidence_path(path_str: str) -> Path:
    """Ensure the requested path is inside the evidence directory.

    Uses Path.relative_to() rather than a string-prefix check. A naive
    startswith() would accept ``/tmp/X/evidence-malicious/...`` as being
    "inside" ``/tmp/X/evidence`` because the string literally begins
    with the prefix. Tests in tests/security/test_path_validation.py
    hold this invariant in place.
    """
    requested = Path(path_str).resolve()
    evidence_resolved = EVIDENCE_DIR.resolve()
    try:
        requested.relative_to(evidence_resolved)
    except ValueError as exc:
        raise ValueError(
            f"Access denied: {path_str} is outside the evidence directory ({EVIDENCE_DIR})"
        ) from exc
    return requested


_FAULT_RATE = float(os.environ.get("FINDEVIL_FAULT_RATE", "0"))
_fault_rng = None
if _FAULT_RATE > 0:
    import random as _random
    _fault_rng = _random.Random(int(os.environ.get("FINDEVIL_FAULT_SEED", "1")))


def _run_tool(cmd: list[str], timeout: int = 120) -> str:
    """Run a SIFT tool as a subprocess, capture output, never modify evidence."""
    # Fault injection: only active when FINDEVIL_FAULT_RATE > 0. Lets
    # tests/harness/fault_injection_test.py exercise graceful degradation.
    if _fault_rng is not None and _fault_rng.random() < _FAULT_RATE:
        return (
            f"[STDERR]: simulated fault — {cmd[0]} exited 124 (timeout). "
            "FINDEVIL_FAULT_RATE is set; this is a test harness injection, "
            "not a real tool failure."
        )
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    output = result.stdout
    if result.returncode != 0:
        output += f"\n[STDERR]: {result.stderr}"
    return output


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "findevil",
    instructions=(
        "You are an autonomous incident response analyst. Use these tools to "
        "examine forensic evidence from the SANS SIFT Workstation. Always validate "
        "your findings by cross-referencing multiple tools. Flag uncertainty and "
        "distinguish confirmed findings from inferences. Never modify evidence."
    ),
)


# ---------------------------------------------------------------------------
# Tool: file_info — get metadata about a file using 'file' and 'stat'
# ---------------------------------------------------------------------------

@mcp.tool()
def file_info(path: str) -> str:
    """Get file type and metadata for a file inside the evidence directory.

    Use this as a first step to understand what kind of artifact you're looking at.
    Returns file type identification (magic bytes) and filesystem metadata.

    Args:
        path: Path to the file inside /evidence (e.g., /evidence/case01/suspicious.exe)
    """
    try:
        validated = _validate_evidence_path(path)
    except ValueError as e:
        return f"Error: {e}"
    if not validated.exists():
        return f"File not found: {path}"

    file_output = _run_tool(["file", "-b", str(validated)])
    stat_output = _run_tool(["stat", str(validated)])

    result = f"## File Type\n{file_output}\n## Stat\n{stat_output}"
    _audit("file_info", {"path": path}, result)
    return result


# ---------------------------------------------------------------------------
# Tool: hash_file — compute cryptographic hashes for evidence integrity
# ---------------------------------------------------------------------------

@mcp.tool()
def hash_file(path: str) -> str:
    """Compute MD5 and SHA256 hashes of a file for evidence integrity verification.

    Use this to verify evidence hasn't been tampered with or to look up file hashes
    in threat intelligence databases.

    Args:
        path: Path to the file inside /evidence
    """
    try:
        validated = _validate_evidence_path(path)
    except ValueError as e:
        return f"Error: {e}"
    if not validated.exists():
        return f"File not found: {path}"

    md5 = _run_tool(["md5sum", str(validated)])
    sha256 = _run_tool(["sha256sum", str(validated)])

    result = f"## MD5\n{md5}\n## SHA256\n{sha256}"
    _audit("hash_file", {"path": path}, result)
    return result


# ---------------------------------------------------------------------------
# Tool: strings_extract — extract readable strings from binary files
# ---------------------------------------------------------------------------

@mcp.tool()
def strings_extract(path: str, min_length: int = 6, encoding: str = "s") -> str:
    """Extract human-readable strings from a binary file.

    Useful for finding embedded URLs, IP addresses, commands, filenames, and other
    indicators of compromise (IOCs) inside executables or memory dumps.

    Args:
        path: Path to the file inside /evidence
        min_length: Minimum string length to extract (default: 6)
        encoding: String encoding — 's' for ASCII, 'l' for little-endian UTF-16 (default: 's')
    """
    try:
        validated = _validate_evidence_path(path)
    except ValueError as e:
        return f"Error: {e}"
    if not validated.exists():
        return f"File not found: {path}"

    if encoding not in ("s", "l", "b", "S", "B", "L"):
        return "Invalid encoding. Use: s (ASCII), l (UTF-16 LE), b (UTF-16 BE)"

    output = _run_tool(
        ["strings", f"-n{min_length}", f"-e{encoding}", str(validated)],
        timeout=60,
    )

    # Truncate if massive
    lines = output.splitlines()
    if len(lines) > 500:
        output = "\n".join(lines[:500]) + f"\n\n[TRUNCATED: {len(lines)} total lines]"

    _audit("strings_extract", {"path": path, "min_length": min_length}, f"{len(lines)} strings")
    return output


# ---------------------------------------------------------------------------
# Tool: list_evidence — list files in the evidence directory
# ---------------------------------------------------------------------------

@mcp.tool()
def list_evidence(subdir: str = "") -> str:
    """List files and directories in the evidence directory.

    Use this as your starting point to discover what evidence is available for analysis.

    Args:
        subdir: Subdirectory within /evidence to list (default: root of evidence dir)
    """
    target = EVIDENCE_DIR / subdir if subdir else EVIDENCE_DIR
    try:
        validated = _validate_evidence_path(str(target))
    except ValueError as e:
        return f"Error: {e}"

    if not validated.exists():
        return f"Directory not found: {target}"
    if not validated.is_dir():
        return f"Not a directory: {target}"

    output = _run_tool(["ls", "-lahR", str(validated)])

    lines = output.splitlines()
    if len(lines) > 300:
        output = "\n".join(lines[:300]) + f"\n\n[TRUNCATED: {len(lines)} total lines]"

    _audit("list_evidence", {"subdir": subdir}, f"{len(lines)} lines")
    return output


# ---------------------------------------------------------------------------
# Tool: log_search — search through log files for patterns
# ---------------------------------------------------------------------------

@mcp.tool()
def log_search(path: str, pattern: str, context_lines: int = 3) -> str:
    """Search log files for a regex pattern using grep.

    Use this for searching through system logs, auth logs, web server logs, etc.
    for indicators of compromise or suspicious activity.

    Args:
        path: Path to the log file inside /evidence
        pattern: Regex pattern to search for (e.g., 'Failed password', '192\\.168\\.1\\.\\d+')
        context_lines: Number of surrounding context lines (default: 3)
    """
    try:
        validated = _validate_evidence_path(path)
    except ValueError as e:
        return f"Error: {e}"
    if not validated.exists():
        return f"File not found: {path}"

    output = _run_tool(
        ["grep", "-n", "-i", f"-C{context_lines}", "-E", pattern, str(validated)],
        timeout=60,
    )

    if not output.strip():
        result = f"No matches found for pattern: {pattern}"
    else:
        lines = output.splitlines()
        if len(lines) > 300:
            output = "\n".join(lines[:300]) + f"\n\n[TRUNCATED: {len(lines)} total matches]"
        result = output

    _audit("log_search", {"path": path, "pattern": pattern}, result[:200])
    return result


# ---------------------------------------------------------------------------
# Tool: hexdump — examine raw bytes of a file
# ---------------------------------------------------------------------------

@mcp.tool()
def hexdump(path: str, offset: int = 0, length: int = 512) -> str:
    """Display a hex dump of a file region.

    Useful for examining file headers, magic bytes, or specific byte offsets
    in binary evidence.

    Args:
        path: Path to the file inside /evidence
        offset: Byte offset to start from (default: 0)
        length: Number of bytes to display (default: 512, max: 4096)
    """
    try:
        validated = _validate_evidence_path(path)
    except ValueError as e:
        return f"Error: {e}"
    if not validated.exists():
        return f"File not found: {path}"

    length = min(length, 4096)

    output = _run_tool(
        ["xxd", "-s", str(offset), "-l", str(length), str(validated)],
        timeout=30,
    )

    _audit("hexdump", {"path": path, "offset": offset, "length": length}, f"{length} bytes")
    return output


# ---------------------------------------------------------------------------
# Register domain-specific tool modules. Imports happen AFTER `mcp` is
# created above so each module can register its tools against this instance.
# ---------------------------------------------------------------------------


from findevil.tools import (  # noqa: E402
    ai_signatures,  # noqa: F401
    fim,  # noqa: F401
    linux_auth,  # noqa: F401
    linux_containers,  # noqa: F401
    linux_journal,  # noqa: F401
    linux_memory,  # noqa: F401
    linux_packages,  # noqa: F401
    linux_persistence,  # noqa: F401
    linux_shell_history,  # noqa: F401
    linux_timeline,  # noqa: F401
    linux_web,  # noqa: F401
    self_correction,  # noqa: F401
    threat_intel,  # noqa: F401
)

# Entrypoint lives in findevil/__main__.py — invoke with `python -m findevil`.
# See __main__.py for why we can't just `python -m findevil.server`.
