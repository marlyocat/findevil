"""
Static scan: verify every @mcp.tool function calls _audit().

findevil's architectural claim (docs/architecture.md §Security-boundaries-2
and accuracy-report.md §5) is that every tool invocation is recorded in
audit.json. If a tool skips the _audit() call, a claim in an IR report
could reference that tool without any traceable provenance — breaking
the auditability guarantee.

Exception: ``get_audit_trail`` is deliberately not in audit.json (see
§6.3 — would recurse and bloat the log). It has a side-channel counter
instead; that's verified elsewhere.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

FINDEVIL_SRC = Path(__file__).parent.parent.parent / "src" / "findevil"

# Functions that are allowed to skip _audit() because they are themselves
# part of the audit machinery. If this list grows, add a comment
# justifying each addition.
AUDIT_EXEMPT = {
    "get_audit_trail",  # deliberately unaudited to avoid recursion
}


def _iter_mcp_tool_functions():
    """Yield (file, function_name, function_node) for every function
    registered with @mcp.tool() in the findevil source tree."""
    for source_file in sorted(FINDEVIL_SRC.rglob("*.py")):
        try:
            tree = ast.parse(source_file.read_text(errors="replace"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            for dec in node.decorator_list:
                # Look for @mcp.tool(...)
                if (
                    isinstance(dec, ast.Call)
                    and isinstance(dec.func, ast.Attribute)
                    and dec.func.attr == "tool"
                    and isinstance(dec.func.value, ast.Name)
                    and dec.func.value.id == "mcp"
                ):
                    yield source_file, node.name, node


def _function_calls_audit(func_node: ast.FunctionDef) -> bool:
    """Does this function body contain a top-level call to _audit(...)?"""
    for inner in ast.walk(func_node):
        if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name):
            if inner.func.id == "_audit":
                return True
    return False


@pytest.mark.parametrize(
    "source_file,func_name,func_node",
    list(_iter_mcp_tool_functions()),
    ids=lambda x: x.name if isinstance(x, Path) else (x if isinstance(x, str) else "node"),
)
def test_every_mcp_tool_calls_audit(
    source_file: Path, func_name: str, func_node: ast.FunctionDef
):
    if func_name in AUDIT_EXEMPT:
        pytest.skip(f"{func_name} is deliberately exempt from audit.json")
    assert _function_calls_audit(func_node), (
        f"MCP tool {func_name!r} in "
        f"{source_file.relative_to(source_file.parent.parent.parent)} "
        f"does not call _audit() — every tool invocation must be recorded."
    )


def test_there_are_mcp_tools_to_check():
    """Sanity: if the collector finds zero tools, the parametrization
    is broken and the test above silently becomes a no-op. Guard that."""
    count = sum(1 for _ in _iter_mcp_tool_functions())
    assert count >= 20, f"expected at least 20 MCP tools, found {count}"
