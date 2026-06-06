"""
Precision tests against scenario 02 (subtle compromise).

Scenario 02 is deliberately quiet: no brute force, no rootkit, no new users,
no /tmp/ payloads, no logging tampering. Only ONE real persistence artifact
(the beacon systemd unit) and TWO SSH keys in a developer account.

These tests validate that our tools:
1. DO flag the one real artifact (recall).
2. Do NOT false-positive on the clean categories (precision).

If either side of that contract breaks, something regressed.
"""

from pathlib import Path

import pytest

from findevil.tools.linux_auth import parse_auth_log
from findevil.tools.linux_persistence import (
    scan_all,
    scan_authorized_keys,
    scan_cron,
    scan_library_preload,
    scan_shell_init,
    scan_systemd,
    scan_users,
)

SCENARIO_02_FS = Path(__file__).parent.parent / "samples" / "attack-scenario-02" / "fs"
SCENARIO_02_LOG = Path(__file__).parent.parent / "samples" / "attack-scenario-02" / "auth.log"


# ---------------------------------------------------------------------------
# Recall: the ONE malicious systemd unit must be flagged
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SCENARIO_02_FS.exists(), reason="scenario 02 FS not present")
def test_scenario02_systemd_unit_is_flagged_high():
    findings = scan_systemd(SCENARIO_02_FS)
    high = [f for f in findings if f.severity == "high"]
    assert high, "scenario 02's beacon unit must be flagged"
    # Exactly one system-level unit file exists in the sample
    assert len(high) == 1, f"expected exactly one high finding, got {len(high)}"
    assert "system-updater.service" in high[0].path
    reasons = " ".join(high[0].reasons)
    # At minimum we expect outbound download OR non-RFC1918 IP
    assert "download" in reasons.lower() or "non-rfc1918" in reasons.lower()


# ---------------------------------------------------------------------------
# Precision: clean categories must stay clean
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SCENARIO_02_FS.exists(), reason="scenario 02 FS not present")
def test_scenario02_users_has_no_findings():
    """No backdoor users, no empty passwords, no UID 0 extras."""
    findings = scan_users(SCENARIO_02_FS)
    assert findings == [], f"user scan should be empty; got {findings}"


@pytest.mark.skipif(not SCENARIO_02_FS.exists(), reason="scenario 02 FS not present")
def test_scenario02_library_preload_empty():
    """No ld.so.preload file, no LD_PRELOAD in environment."""
    findings = scan_library_preload(SCENARIO_02_FS)
    assert findings == [], f"library preload should be clean; got {findings}"


@pytest.mark.skipif(not SCENARIO_02_FS.exists(), reason="scenario 02 FS not present")
def test_scenario02_cron_empty():
    """No cron persistence."""
    findings = scan_cron(SCENARIO_02_FS)
    high = [f for f in findings if f.severity == "high"]
    assert high == [], f"cron scan should have no high findings; got {high}"


@pytest.mark.skipif(not SCENARIO_02_FS.exists(), reason="scenario 02 FS not present")
def test_scenario02_shell_init_empty():
    """Developer and admin bashrc are both clean."""
    findings = scan_shell_init(SCENARIO_02_FS)
    high = [f for f in findings if f.severity == "high"]
    assert high == [], f"no shell init should be flagged high; got {high}"


@pytest.mark.skipif(not SCENARIO_02_FS.exists(), reason="scenario 02 FS not present")
def test_scenario02_authorized_keys_not_high():
    """Deploy has 2 keys, both with plausible comments. Neither should be
    flagged individually — the agent has to use judgment on 'why are there two'."""
    findings = scan_authorized_keys(SCENARIO_02_FS)
    high = [f for f in findings if f.severity == "high"]
    assert high == [], f"plausibly-commented keys should not be 'high'; got {high}"


# ---------------------------------------------------------------------------
# Auth log precision: scenario 02 has no brute force
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SCENARIO_02_LOG.exists(), reason="scenario 02 log not present")
def test_scenario02_zero_failed_logins():
    content = SCENARIO_02_LOG.read_text()
    events = parse_auth_log(content)
    failed = [e for e in events if e.kind in ("login_failed", "invalid_user")]
    assert failed == [], f"scenario 02 must have zero failed logins; got {len(failed)}"


@pytest.mark.skipif(not SCENARIO_02_LOG.exists(), reason="scenario 02 log not present")
def test_scenario02_deploy_login_from_new_ip():
    """The attack session uses deploy's key but from a non-10.x.x.x source."""
    content = SCENARIO_02_LOG.read_text()
    events = parse_auth_log(content)
    accepted = [e for e in events if e.kind == "login_accepted"]
    ips = {e.fields.get("ip") for e in accepted}
    # At least one internal IP and the one attacker IP must be present
    assert "10.0.1.50" in ips, "expected legitimate deploy IP in log"
    assert "185.229.59.103" in ips, "expected attacker IP in log"


# ---------------------------------------------------------------------------
# End-to-end: scan_all gives exactly one high-severity category
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SCENARIO_02_FS.exists(), reason="scenario 02 FS not present")
def test_scenario02_scan_all_only_systemd_and_sudoers():
    """Scenario 02's real attack surface is two things the agent needs to
    surface: the rogue systemd unit (what the attacker planted) AND the
    bare-binary sudoers NOPASSWD on /usr/bin/systemctl (what enabled it).

    Every other category — users, cron, ld.so.preload, shell init, PAM,
    kernel modules, sshd_config — must remain clean. That is the
    precision contract for the whole scanner.
    """
    findings = scan_all(SCENARIO_02_FS)
    high = [f for f in findings if f.severity == "high"]
    high_categories = {f.category for f in high}
    assert high_categories == {"systemd", "sudoers"}, (
        f"expected high findings only in systemd + sudoers; got {high_categories}"
    )
