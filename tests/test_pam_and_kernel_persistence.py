"""Tests for the PAM and kernel-module persistence scanners."""

from pathlib import Path

import pytest

from findevil.tools.linux_persistence import (
    scan_all,
    scan_kernel_modules,
    scan_pam,
)

SCENARIO_01_FS = Path(__file__).parent.parent / "samples" / "attack-scenario-01" / "fs"
SCENARIO_02_FS = Path(__file__).parent.parent / "samples" / "attack-scenario-02" / "fs"


# ---------------------------------------------------------------------------
# PAM scanner — recall
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SCENARIO_01_FS.exists(), reason="scenario 01 FS not present")
def test_scenario01_pam_flags_pam_exec_tmp():
    findings = scan_pam(SCENARIO_01_FS)
    assert findings, "expected PAM tampering in scenario 01"
    reasons = " ".join(r for f in findings for r in f.reasons)
    assert "pam_exec" in reasons.lower()
    assert "/tmp/" in reasons or "world-writable" in reasons.lower()


# ---------------------------------------------------------------------------
# PAM scanner — precision
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SCENARIO_02_FS.exists(), reason="scenario 02 FS not present")
def test_scenario02_pam_empty():
    """Scenario 02 has no /etc/pam.d tampering."""
    findings = scan_pam(SCENARIO_02_FS)
    assert findings == [], f"unexpected PAM findings: {findings}"


# ---------------------------------------------------------------------------
# Kernel module scanner — recall
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SCENARIO_01_FS.exists(), reason="scenario 01 FS not present")
def test_scenario01_kernel_modules_flags_unknown_entry():
    findings = scan_kernel_modules(SCENARIO_01_FS)
    assert findings, "expected /etc/modules tampering in scenario 01"
    # At least one finding should reference the attacker's module name
    all_reasons = " ".join(r for f in findings for r in f.reasons)
    assert "sysd_helper_km" in all_reasons


@pytest.mark.skipif(not SCENARIO_01_FS.exists(), reason="scenario 01 FS not present")
def test_scenario01_modprobe_flags_security_blacklist():
    findings = scan_kernel_modules(SCENARIO_01_FS)
    # At least one finding should flag the blacklist audit OR the install directive
    all_reasons = " ".join(r for f in findings for r in f.reasons)
    assert ("blacklist" in all_reasons.lower() and "audit" in all_reasons.lower()) or (
        "install" in all_reasons.lower()
    )


# ---------------------------------------------------------------------------
# Kernel module scanner — precision
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SCENARIO_02_FS.exists(), reason="scenario 02 FS not present")
def test_scenario02_kernel_modules_empty():
    """Scenario 02 has no kernel-module persistence."""
    findings = scan_kernel_modules(SCENARIO_02_FS)
    assert findings == [], f"unexpected kernel module findings: {findings}"


# ---------------------------------------------------------------------------
# scan_all now covers 9 categories
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SCENARIO_01_FS.exists(), reason="scenario 01 FS not present")
def test_scan_all_covers_pam_and_kernel_in_scenario01():
    findings = scan_all(SCENARIO_01_FS)
    high = [f for f in findings if f.severity == "high"]
    high_categories = {f.category for f in high}
    assert "pam" in high_categories
    assert "kernel_module" in high_categories
