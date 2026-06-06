"""Runtime MCP-protocol-level tests.

`tests/test_mcp_smoke.py` does a static count of `@mcp.tool()`
decorations via AST and confirms key tools run on bundled evidence.
This file complements that by exercising the **runtime** protocol
surface — i.e., the same view a real MCP client (Claude Code) sees
when it calls `tools/list`.

Catches regressions where:
- A tool is decorated but never imported, so the AST counts it but the
  protocol layer doesn't expose it.
- A tool is registered against a different FastMCP instance (the
  dual-module-execution bug).
- A tool's input schema is malformed (e.g., a non-JSON-serialisable
  default value silently drops the tool from the registry).
"""

from __future__ import annotations

import asyncio
import importlib

import pytest


def _list_tools_runtime() -> list:
    """Return the live list of registered tools from the FastMCP instance.

    FastMCP's public async API is `await mcp.list_tools()`. We use
    asyncio.run() to call it from sync test code. If the API surface
    moves under us across mcp-package versions, fall back to the
    internal `_tool_manager._tools` dict.
    """
    import findevil.server as server
    importlib.reload(server)
    # Re-import all tool modules so they register against the freshly
    # reloaded mcp instance (otherwise reload leaves us with zero tools).
    import sys
    for mod_name in list(sys.modules):
        if mod_name.startswith("findevil.tools."):
            importlib.reload(sys.modules[mod_name])

    mcp = server.mcp

    # Public async API
    try:
        tools = asyncio.run(mcp.list_tools())
        return list(tools)
    except (AttributeError, RuntimeError):
        pass

    # Fallback: internal tool manager dict
    manager = getattr(mcp, "_tool_manager", None)
    if manager is not None:
        tools_dict = getattr(manager, "_tools", None)
        if tools_dict is not None:
            return list(tools_dict.values())

    pytest.skip("FastMCP version exposes no tool-listing API we recognise")
    return []  # unreachable, satisfies type checker


# ---------------------------------------------------------------------------
# Tool count visible via the runtime registry
# ---------------------------------------------------------------------------


def test_runtime_tool_registry_exposes_45_tools():
    """The protocol-level view must match the AST count. If they diverge,
    a tool exists in source but isn't actually registered (a real bug
    that broke the project once already, hence the __main__.py shim).
    """
    tools = _list_tools_runtime()
    names = {_tool_name(t) for t in tools}
    assert len(names) == 45, (
        f"FastMCP exposes {len(names)} tools, expected 45. "
        f"Names: {sorted(names)}"
    )


def _tool_name(tool) -> str:
    """Extract a name from whatever shape `list_tools()` returned."""
    # Async list_tools returns Tool dataclass-ish objects with a .name
    if hasattr(tool, "name"):
        return tool.name
    # Fallback dict shape
    if isinstance(tool, dict) and "name" in tool:
        return tool["name"]
    # Last resort
    return str(tool)


# ---------------------------------------------------------------------------
# Specific tool presence
# ---------------------------------------------------------------------------


# Selected tools we want explicit "is registered" coverage for. If any of
# these disappears from the live registry, the README's tool inventory and
# the integration tests will drift silently — this test catches it first.
_REQUIRED_TOOLS = {
    # Generic primitives
    "file_info", "hash_file", "strings_extract", "hexdump",
    "list_evidence", "log_search",
    # Auth
    "auth_summary", "auth_failed_logins", "auth_successful_logins",
    "auth_sudo_commands", "auth_user_events", "analyze_journal",
    # Persistence
    "find_persistence", "analyze_systemd_unit", "analyze_authorized_keys",
    "analyze_sshd_config", "analyze_sudoers",
    # Self-correction (the hackathon tiebreaker tools)
    "verify_finding", "find_contradictions", "get_audit_trail",
    # Memory family
    "analyze_memory_summary", "analyze_memory_processes",
    "analyze_memory_network", "analyze_memory_modules",
    "analyze_memory_bash_history", "analyze_memory_malfind",
    "correlate_memory_and_disk",
    # Threat intel + AI signatures
    "extract_iocs", "bulk_ioc_lookup", "find_ai_signatures",
    # Package integrity (added today)
    "verify_package_integrity",
}


def test_runtime_registry_contains_required_tools():
    tools = _list_tools_runtime()
    names = {_tool_name(t) for t in tools}
    missing = _REQUIRED_TOOLS - names
    assert not missing, f"required tools missing from runtime registry: {missing}"


# ---------------------------------------------------------------------------
# No deprecated tool names leaked back in
# ---------------------------------------------------------------------------


_DEPRECATED_TOOLS = {
    "lookup_ip_reputation",
    "lookup_domain_reputation",
    "lookup_hash_reputation",
}


def test_runtime_registry_does_not_expose_deprecated_tools():
    """The reputation-lookup tools were collapsed into `extract_iocs` +
    `bulk_ioc_lookup` in commit e7960b4. If any of them reappear in the
    runtime registry, an old @mcp.tool decoration was reintroduced.
    """
    tools = _list_tools_runtime()
    names = {_tool_name(t) for t in tools}
    leaked = _DEPRECATED_TOOLS & names
    assert not leaked, (
        f"deprecated tool names re-registered: {leaked}. "
        f"Use extract_iocs + bulk_ioc_lookup instead."
    )
