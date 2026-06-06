"""Tests for sshd_config + sudoers scanners.

Recall (scenario 01):
- sshd_config flags PermitRootLogin yes + PasswordAuthentication yes
- sudoers.d/deploy has ONLY specific commands with NOPASSWD → scanner must NOT flag

Recall (scenario 02):
- sshd_config is hardened → no findings
- sudoers.d/deploy has bare `systemctl` NOPASSWD → scanner MUST flag

Precision: neither scenario should produce sudoers findings on the main
/etc/sudoers file (both have stock contents).
"""

from pathlib import Path

import pytest

from findevil.tools.linux_persistence import (
    _parse_sshd_config,
    _parse_sudoers_line,
    scan_ssh_config,
    scan_sudoers,
)

SCENARIO_01_FS = Path(__file__).parent.parent / "samples" / "attack-scenario-01" / "fs"
SCENARIO_02_FS = Path(__file__).parent.parent / "samples" / "attack-scenario-02" / "fs"


# ---------------------------------------------------------------------------
# Parser unit tests
# ---------------------------------------------------------------------------


def test_parse_sshd_config_handles_comments_and_last_wins():
    content = (
        "# comment line\n"
        "PermitRootLogin no\n"
        "PasswordAuthentication yes\n"
        "PermitRootLogin yes  # override later in file\n"
    )
    settings = _parse_sshd_config(content)
    assert settings["PermitRootLogin"] == "yes"  # last occurrence wins
    assert settings["PasswordAuthentication"] == "yes"


def test_parse_sudoers_line_user_rule():
    result = _parse_sudoers_line("deploy  ALL=(root) NOPASSWD: /usr/bin/systemctl")
    assert result is not None
    who, runas, spec = result
    assert who == "deploy"
    assert "systemctl" in spec


def test_parse_sudoers_line_skips_defaults():
    assert _parse_sudoers_line("Defaults    env_reset") is None
    assert _parse_sudoers_line("# comment") is None
    assert _parse_sudoers_line("") is None


# ---------------------------------------------------------------------------
# Scenario 01: vulnerable sshd, safe sudoers (specific-command NOPASSWD)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SCENARIO_01_FS.exists(), reason="scenario 01 FS not present")
def test_scenario01_sshd_flags_root_and_password_auth():
    findings = scan_ssh_config(SCENARIO_01_FS)
    assert findings, "expected sshd_config to be flagged in scenario 01"
    reasons = " ".join(r for f in findings for r in f.reasons)
    assert "PermitRootLogin" in reasons
    assert "Password" in reasons


@pytest.mark.skipif(not SCENARIO_01_FS.exists(), reason="scenario 01 FS not present")
def test_scenario01_sudoers_clean_specific_commands_not_flagged():
    """Scenario 01's deploy sudoers file has only specific-command NOPASSWD
    (systemctl restart nginx, etc.) — these are argv-constrained and must
    NOT be flagged as a privesc vector."""
    findings = scan_sudoers(SCENARIO_01_FS)
    # Filter to findings about the deploy file specifically
    deploy_findings = [f for f in findings if "deploy" in f.path]
    assert deploy_findings == [], (
        f"specific-command NOPASSWD should NOT be flagged; got {deploy_findings}"
    )


# ---------------------------------------------------------------------------
# Scenario 02: hardened sshd, dangerous sudoers
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SCENARIO_02_FS.exists(), reason="scenario 02 FS not present")
def test_scenario02_sshd_is_clean():
    findings = scan_ssh_config(SCENARIO_02_FS)
    assert findings == [], f"hardened sshd should not be flagged; got {findings}"


@pytest.mark.skipif(not SCENARIO_02_FS.exists(), reason="scenario 02 FS not present")
def test_scenario02_sudoers_flags_bare_systemctl():
    """Scenario 02 has `deploy ALL=(root) NOPASSWD: /usr/bin/systemctl` —
    bare binary with no fixed args, so any argv is allowed → privesc vector."""
    findings = scan_sudoers(SCENARIO_02_FS)
    assert findings, "bare systemctl NOPASSWD should be flagged"
    reasons = " ".join(r for f in findings for r in f.reasons)
    assert "systemctl" in reasons
    assert "bare" in reasons.lower() or "any-argv" in reasons.lower()
