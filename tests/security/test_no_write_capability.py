"""
Static scan: verify no MCP tool exposes write capability on evidence paths.

findevil's Constraint Implementation claim is that there is no write
tool reachable via MCP — so prompt injection, tool-misuse, or an
adversarial client cannot make findevil modify evidence. This test
walks the src/findevil/ tree looking for disallowed write operations
(open with write mode, Path.write_*, shutil.rmtree, os.remove, etc.)
inside any file that registers @mcp.tool decorators.

The whitelist below covers places where writes are explicitly allowed:
- LOGS_DIR (audit.json, hallucination_guard.jsonl, etc.)
- get_audit_trail_invocations.jsonl (side-channel counter)
- tmpfile / tmp_path in tests

Any write-like syntax found in a file that also contains @mcp.tool and
isn't whitelisted is a policy violation worth surfacing.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

FINDEVIL_SRC = Path(__file__).parent.parent.parent / "src" / "findevil"

# Source files that register MCP tools.
def _tool_source_files() -> list[Path]:
    files = []
    for p in FINDEVIL_SRC.rglob("*.py"):
        if "@mcp.tool" in p.read_text(errors="replace"):
            files.append(p)
    return sorted(files)


# Patterns that indicate a write-to-filesystem operation.
WRITE_PATTERNS = [
    r"\bopen\([^,)]+,[^)]*['\"][rwab+xt]*[wa][rwab+xt]*['\"]",  # open(..., "w"/"a"/"x"...)
    r"\.write_text\(",
    r"\.write_bytes\(",
    r"\.write\(",
    r"\bos\.remove\(",
    r"\bos\.unlink\(",
    r"\bos\.rename\(",
    r"\bos\.mkdir\(",
    r"\bos\.rmdir\(",
    r"\bshutil\.rmtree\(",
    r"\bshutil\.copy",
    r"\bshutil\.move\(",
    r"\.mkdir\(",
]

# Per-file whitelist: {filename: [reasons why specific writes are OK]}.
# Each whitelisted write must be to LOGS_DIR or a clearly-scoped sink.
ALLOWED_WRITE_PATHS = [
    "LOGS_DIR",
    "logs/",
    "/logs/",
    "get_audit_trail_invocations",
    "FileHandler",  # stdlib logging handler
]


def _line_has_write(line: str) -> str | None:
    for pat in WRITE_PATTERNS:
        m = re.search(pat, line)
        if m:
            return m.group(0)
    return None


def _line_is_whitelisted(line: str) -> bool:
    return any(tok in line for tok in ALLOWED_WRITE_PATHS)


# Whole-file escape hatch: callouts for writes that are legitimate but
# whose path context doesn't sit on the same or adjacent line (e.g.,
# `with open(X) as f: f.write(...)` spans multiple lines). Each
# entry must name the file AND a justification.
FILE_LEVEL_WHITELIST = {
    "fim.py": (
        "baseline_create writes JSON to a user-specified path, but "
        "_resolve_output_path refuses paths inside EVIDENCE_DIR. Runtime "
        "guard is tested in test_fim_rejects_output_inside_evidence."
    ),
}


def _has_whitelist_context(lines: list[str], lineno: int, window: int = 8) -> bool:
    """Check a small window of lines above the write for a whitelist token —
    catches `with open(LOGS_DIR / x) as f:` followed by `f.write(...)`."""
    start = max(0, lineno - 1 - window)
    window_lines = lines[start : lineno]
    return any(_line_is_whitelisted(ln) for ln in window_lines)


@pytest.mark.parametrize("source_file", _tool_source_files(), ids=lambda p: p.name)
def test_no_unauthorized_writes_in_tool_source(source_file: Path):
    if source_file.name in FILE_LEVEL_WHITELIST:
        pytest.skip(FILE_LEVEL_WHITELIST[source_file.name])

    lines = source_file.read_text(errors="replace").splitlines()
    offenders: list[tuple[int, str, str]] = []
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        hit = _line_has_write(line)
        if hit is None:
            continue
        if _line_is_whitelisted(line) or _has_whitelist_context(lines, lineno):
            continue
        offenders.append((lineno, hit, stripped))

    assert not offenders, (
        f"{source_file.relative_to(source_file.parent.parent.parent)} "
        f"contains unauthorized write operations: {offenders}"
    )
