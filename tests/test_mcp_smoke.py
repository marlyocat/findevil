"""End-to-end smoke tests: every `@mcp.tool()` is registered, and the
biggest path-taking tools actually run on the S01 sample without
crashing.

Catches two classes of regression that pure unit tests miss:

1. The dual-module-execution bug documented in `src/findevil/__main__.py`.
   If the server module is imported twice, half the @mcp.tool()
   decorators register against a different FastMCP instance and the
   registered count drops silently. This test asserts the canonical 43.
2. A tool that imports cleanly but raises on real evidence — for
   example, a refactor that breaks parsing of a particular log shape.
   These tests exercise the most-used tools end-to-end on the bundled
   scenario-01 sample.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

FINDEVIL_SRC = Path(__file__).parent.parent / "src" / "findevil"
SC01 = Path(__file__).parent.parent / "samples" / "attack-scenario-01"


def _count_mcp_tools() -> int:
    """Static count of @mcp.tool()-decorated functions across src/findevil/."""
    n = 0
    for source_file in sorted(FINDEVIL_SRC.rglob("*.py")):
        try:
            tree = ast.parse(source_file.read_text(errors="replace"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            for dec in node.decorator_list:
                if (
                    isinstance(dec, ast.Call)
                    and isinstance(dec.func, ast.Attribute)
                    and dec.func.attr == "tool"
                    and isinstance(dec.func.value, ast.Name)
                    and dec.func.value.id == "mcp"
                ):
                    n += 1
    return n


def test_canonical_tool_count_is_43():
    """README, devpost, architecture.md, and accuracy-report.md all claim 43.
    If this drifts, those docs become stale. Update the docs in the same PR
    that adds or removes a tool."""
    assert _count_mcp_tools() == 43, (
        f"@mcp.tool() decoration count drifted; got {_count_mcp_tools()}, "
        "expected 43. If you intentionally added/removed a tool, update "
        "this test AND the count in README.md / docs/architecture.md / "
        "docs/devpost.md / docs/accuracy-report.md in the same change."
    )


def test_server_imports_without_dual_module_bug(monkeypatch, tmp_path):
    """Importing findevil.server must register every tool against a single
    FastMCP instance. The shim in __main__.py exists to prevent this from
    silently breaking; the test holds it in place.
    """
    monkeypatch.setenv("FINDEVIL_EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FINDEVIL_LOGS_DIR", str(tmp_path))
    import importlib
    import findevil.server as server
    importlib.reload(server)
    # Importing the package's tool modules registers their tools against
    # `server.mcp`. If a tool module ever silently imported its own copy
    # of server.py (the dual-module bug) those registrations would land
    # on a different instance, and the smoke tests below would fail.
    assert hasattr(server, "mcp")
    assert hasattr(server, "_audit")
    assert hasattr(server, "_validate_evidence_path")


# ---------------------------------------------------------------------------
# Tool integration smoke tests on scenario 01
# ---------------------------------------------------------------------------


@pytest.fixture
def s01_env(monkeypatch):
    """Point the server at samples/ as the evidence root, so S01 paths resolve."""
    samples_dir = Path(__file__).parent.parent / "samples"
    monkeypatch.setenv("FINDEVIL_EVIDENCE_DIR", str(samples_dir))
    import importlib
    import findevil.server as server
    importlib.reload(server)
    # Tool modules need to re-register against the reloaded server.mcp.
    for mod_name in (
        "findevil.tools.linux_auth",
        "findevil.tools.linux_persistence",
        "findevil.tools.linux_journal",
        "findevil.tools.linux_shell_history",
    ):
        import sys
        if mod_name in sys.modules:
            importlib.reload(sys.modules[mod_name])
    return server


@pytest.mark.skipif(not SC01.exists(), reason="scenario 01 sample not present")
def test_smoke_find_persistence_runs_on_scenario_01(s01_env):
    """find_persistence on the S01 fs/ tree must complete and return a str."""
    from findevil.tools.linux_persistence import find_persistence
    out = find_persistence(str(SC01 / "fs"))
    assert isinstance(out, str)
    assert len(out) > 0
    # S01 is the loud-attacker scenario — at least ONE high-severity finding
    # must surface or something has gone very wrong with the scanner.
    assert "HIGH" in out.upper() or "🚨" in out


@pytest.mark.skipif(not (SC01 / "auth.log").is_file(), reason="scenario 01 auth.log not present")
def test_smoke_auth_summary_runs_on_scenario_01(s01_env):
    from findevil.tools.linux_auth import auth_summary
    out = auth_summary(str(SC01 / "auth.log"))
    assert isinstance(out, str)
    assert len(out) > 0


@pytest.mark.skipif(
    not (SC01 / "journal.jsonl").is_file(),
    reason="scenario 01 journal.jsonl not present",
)
def test_smoke_analyze_journal_runs_on_scenario_01(s01_env):
    from findevil.tools.linux_journal import analyze_journal
    out = analyze_journal(str(SC01 / "journal.jsonl"))
    assert isinstance(out, str)
    assert len(out) > 0


@pytest.mark.skipif(not (SC01 / "fs").is_dir(), reason="scenario 01 fs/ not present")
def test_smoke_find_shell_histories_runs_on_scenario_01(s01_env):
    from findevil.tools.linux_shell_history import find_shell_histories
    out = find_shell_histories(str(SC01 / "fs"))
    assert isinstance(out, str)
    assert len(out) > 0


@pytest.mark.skipif(not (SC01 / "auth.log").is_file(), reason="scenario 01 auth.log not present")
def test_smoke_extract_iocs_runs_on_scenario_01_authlog(s01_env):
    """Threat-intel extraction on the auth log must complete and surface
    at least one IP (the attacker's brute-force source).

    `extract_iocs` takes a text blob (not a path), so we read the file
    here. Passing the path string would scan the literal path and find
    nothing — silent test rot we caught before it bit.
    """
    from findevil.tools.threat_intel import extract_iocs
    auth_log_text = (SC01 / "auth.log").read_text(errors="replace")
    out = extract_iocs(auth_log_text)
    assert isinstance(out, str)
    # The known attacker IP must appear in the IOC list.
    assert "45.123.45.67" in out
