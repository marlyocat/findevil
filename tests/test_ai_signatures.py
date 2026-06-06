"""Tests for the AI/agent-driven adversary signature scanner."""

from __future__ import annotations

import json
from pathlib import Path

from findevil.tools.ai_signatures import (
    scan_agent_paths,
    scan_all_ai,
    scan_llm_api_references,
    scan_machine_speed_history,
    scan_polished_scripts,
    scan_tool_call_jsonl,
)


# ---------------------------------------------------------------------------
# LLM API destinations + key declarations
# ---------------------------------------------------------------------------


def test_scan_llm_api_finds_anthropic_in_env_file(tmp_path):
    sysconfig = tmp_path / "etc/sysconfig"
    sysconfig.mkdir(parents=True)
    (sysconfig / "agent-env").write_text(
        "ANTHROPIC_API_KEY=sk-ant-api03-PLACEHOLDER\n"
        "ANTHROPIC_API_URL=https://api.anthropic.com\n"
    )
    findings = scan_llm_api_references(tmp_path)
    cats = {f.category for f in findings}
    assert "llm_api_dest" in cats
    assert "api_key" in cats


def test_scan_llm_api_finds_openai_cron(tmp_path):
    cron = tmp_path / "etc/cron.d"
    cron.mkdir(parents=True)
    (cron / "openai-poll").write_text(
        '*/5 * * * * root curl -sS https://api.openai.com/v1/messages -H "Auth: $K"\n'
    )
    findings = scan_llm_api_references(tmp_path)
    assert any("api.openai.com" in f.summary or "api.openai.com" in f.sample for f in findings)


def test_scan_llm_api_clean_etc_returns_empty(tmp_path):
    etc = tmp_path / "etc/sysconfig"
    etc.mkdir(parents=True)
    (etc / "rsyslog").write_text("# rsyslog default\nMODLOAD imuxsock\n")
    findings = scan_llm_api_references(tmp_path)
    assert findings == []


def test_scan_llm_api_ignores_placeholder_value(tmp_path):
    """All-words placeholder strings must NOT register as an API key.

    Regression: the original regex's ``[A-Za-z0-9_-]{20,}`` fallback fired
    on any 20+ char string assigned to one of the listed env vars,
    flagging filler like ``DELETED-FOR-COMMIT-PLEASE-REGENERATE``.
    """
    sysconfig = tmp_path / "etc/sysconfig"
    sysconfig.mkdir(parents=True)
    (sysconfig / "agent-env").write_text(
        # No host reference, only a placeholder. We expect zero findings.
        "OPENAI_API_KEY=DELETED-FOR-COMMIT-PLEASE-REGENERATE\n"
        "ANTHROPIC_API_KEY=please-set-this-properly-soon\n"
    )
    findings = scan_llm_api_references(tmp_path)
    api_key_findings = [f for f in findings if f.category == "api_key"]
    assert api_key_findings == [], (
        "all-words placeholder values must not be matched as API keys"
    )


def test_scan_llm_api_matches_realistic_anthropic_key(tmp_path):
    """A realistic-shaped Anthropic key must still match."""
    sysconfig = tmp_path / "etc/sysconfig"
    sysconfig.mkdir(parents=True)
    (sysconfig / "agent-env").write_text(
        "ANTHROPIC_API_KEY=sk-ant-api03-aB3xYz9_kLmNoPqRsTuVwXyZ1234567890abcdef-AbCd\n"
    )
    findings = scan_llm_api_references(tmp_path)
    assert any(f.category == "api_key" for f in findings)


def test_scan_llm_api_matches_generic_high_entropy_key(tmp_path):
    """A 32+ char mixed-case-and-digit string still registers (Mistral/Together shape)."""
    sysconfig = tmp_path / "etc/sysconfig"
    sysconfig.mkdir(parents=True)
    (sysconfig / "agent-env").write_text(
        "MISTRAL_API_KEY=AbC1dEf2GhI3jKl4MnO5pQr6StU7vWx8YzZ\n"
    )
    findings = scan_llm_api_references(tmp_path)
    assert any(f.category == "api_key" for f in findings)


# ---------------------------------------------------------------------------
# Agent runtime artifacts
# ---------------------------------------------------------------------------


def test_scan_agent_paths_flags_tmp_agent_cache(tmp_path):
    cache = tmp_path / "tmp/.agent_cache"
    cache.mkdir(parents=True)
    (cache / "tools.json").write_text('{"tools":["bash","find"]}')
    findings = scan_agent_paths(tmp_path)
    assert findings, ".agent_cache directory should be flagged"
    assert any(".agent_cache" in f.path for f in findings)


def test_scan_agent_paths_flags_claude_projects(tmp_path):
    p = tmp_path / "root/.claude/projects/-tmp-target/sessions/abc-123"
    p.mkdir(parents=True)
    findings = scan_agent_paths(tmp_path)
    assert any(".claude" in f.path for f in findings)


def test_scan_agent_paths_flags_var_log_agent_tasks(tmp_path):
    var_log = tmp_path / "var/log"
    var_log.mkdir(parents=True)
    (var_log / "agent_tasks.jsonl").write_text(
        json.dumps({"id": "task-001", "phase": "recon", "tool_calls": 12}) + "\n"
    )
    findings = scan_agent_paths(tmp_path)
    assert any("agent_tasks" in f.path for f in findings)


# ---------------------------------------------------------------------------
# Tool-call JSONL detection
# ---------------------------------------------------------------------------


def test_scan_tool_call_jsonl_detects_tool_use_schema(tmp_path):
    var_log = tmp_path / "var/log"
    var_log.mkdir(parents=True)
    p = var_log / "session.jsonl"
    p.write_text(
        json.dumps({"role": "user", "content": "find SUID"}) + "\n"
        + json.dumps({"role": "assistant", "tool_use": "bash",
                      "input": {"command": "find / -perm -4000"}}) + "\n"
        + json.dumps({"role": "tool_result", "content": "/usr/bin/sudo"}) + "\n"
    )
    findings = scan_tool_call_jsonl(tmp_path)
    assert findings, "tool_use schema should be detected"
    assert findings[0].category == "tool_call_jsonl"


def test_scan_tool_call_jsonl_ignores_unrelated_jsonl(tmp_path):
    var_log = tmp_path / "var/log"
    var_log.mkdir(parents=True)
    p = var_log / "metrics.jsonl"
    p.write_text(
        json.dumps({"ts": "2026-04-30T00:00:00Z", "metric": "cpu", "value": 42}) + "\n"
        + json.dumps({"ts": "2026-04-30T00:01:00Z", "metric": "cpu", "value": 43}) + "\n"
    )
    findings = scan_tool_call_jsonl(tmp_path)
    assert not findings, "unrelated JSONL should not match"


# ---------------------------------------------------------------------------
# Polished-script idiom combination
# ---------------------------------------------------------------------------


def test_scan_polished_scripts_flags_three_idiom_combo(tmp_path):
    bin_dir = tmp_path / "usr/local/bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "k8s-recon.sh").write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "readonly TARGET_CIDR=\"10.0.0.0/16\"\n"
        "probe() { echo $1; }\n"
        "export -f probe\n"
        "echo done | xargs -n1 -P200 -I{} bash -c 'probe \"$@\"' _ {}\n"
    )
    findings = scan_polished_scripts(tmp_path)
    assert findings, "AI-style script combo should fire"
    assert findings[0].category == "polished_script"


def test_scan_polished_scripts_ignores_simple_script(tmp_path):
    bin_dir = tmp_path / "usr/local/bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "simple.sh").write_text("#!/bin/sh\necho hi\n")
    findings = scan_polished_scripts(tmp_path)
    assert not findings


# ---------------------------------------------------------------------------
# Machine-speed bash history
# ---------------------------------------------------------------------------


def test_scan_machine_speed_history_fires_on_sub_2s_bursts(tmp_path):
    home = tmp_path / "home/deploy"
    home.mkdir(parents=True)
    base = 1714435200
    lines = []
    for i, cmd in enumerate([
        "find / -perm -4000 -type f",
        "ls /etc/sudoers.d/",
        "cat /etc/passwd",
        "cat /etc/sudoers",
        "ss -tlnp",
        "ps -eo pid,user,comm",
        "systemctl list-unit-files",
    ]):
        lines.append(f"#{base + i}")  # 1-second apart
        lines.append(cmd)
    (home / ".bash_history").write_text("\n".join(lines) + "\n")
    findings = scan_machine_speed_history(tmp_path)
    assert findings
    assert findings[0].category == "machine_speed_history"


def test_scan_machine_speed_history_ignores_human_paced_history(tmp_path):
    home = tmp_path / "home/alice"
    home.mkdir(parents=True)
    base = 1714435200
    lines = []
    # 30+ second gaps — typical interactive use
    for i, cmd in enumerate(["ls", "cd /etc", "cat passwd", "exit"]):
        lines.append(f"#{base + i * 60}")
        lines.append(cmd)
    (home / ".bash_history").write_text("\n".join(lines) + "\n")
    findings = scan_machine_speed_history(tmp_path)
    assert not findings


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------


def test_scan_all_ai_aggregates_categories(tmp_path):
    # Plant artifacts in two distinct categories
    sysconfig = tmp_path / "etc/sysconfig"
    sysconfig.mkdir(parents=True)
    (sysconfig / "agent-env").write_text("ANTHROPIC_API_URL=https://api.anthropic.com\n")
    cache = tmp_path / "tmp/.agent_cache"
    cache.mkdir(parents=True)
    (cache / "tools.json").write_text('{"tools":["bash"]}')
    findings = scan_all_ai(tmp_path)
    cats = {f.category for f in findings}
    assert "llm_api_dest" in cats
    assert "agent_path" in cats
