"""Tests for the autonomy layer: assess_coverage (gap finder) and
finalize_report (the self-correction gate).

These lock in the two behaviours that make findevil's self-correction
*architectural* rather than advisory:

- finalize_report REFUSES to pass a CONFIRMED claim that fails an
  independent re-check or contradicts another claim, but accepts the
  same claim once it is downgraded or properly cited.
- assess_coverage reports gaps derived from the mechanical audit trail —
  an artifact present but unexamined, an IOC flagged but un-pivoted, a
  CONFIRMED claim with no verification on record.
"""

import json
from pathlib import Path

import pytest

from findevil.tools import autonomy
from findevil.tools.autonomy import assess_coverage, finalize_report

SAMPLES_DIR = Path(__file__).parent.parent / "samples"
SC01 = SAMPLES_DIR / "attack-scenario-01"


# ---------------------------------------------------------------------------
# finalize_report — the gate
# ---------------------------------------------------------------------------


def test_finalize_rejects_unverified_confirmed(monkeypatch):
    """A CONFIRMED brute-force claim with the wrong IP must be rejected."""
    import findevil.server as srv

    monkeypatch.setattr(srv, "EVIDENCE_DIR", SAMPLES_DIR.resolve())
    claims = [
        {
            "id": "c1",
            "type": "brute_force_from_ip",
            "confidence": "confirmed",
            "log_path": str(SC01 / "auth.log"),
            "ip": "203.0.113.255",  # not the attacker IP
            "min_attempts": 10,
            "statement": "brute force from 203.0.113.255",
        }
    ]
    out = finalize_report(json.dumps(claims))
    assert "REJECTED" in out
    assert "c1" in out
    assert "CONTRADICTED" in out


def test_finalize_rejects_confirmed_unverifiable_without_citation():
    claims = [
        {
            "id": "c1",
            "type": "rootkit_present",  # not a machine-verifiable type
            "confidence": "confirmed",
            "statement": "rootkit installed",
        }
    ]
    out = finalize_report(json.dumps(claims))
    assert "REJECTED" in out
    assert "citation" in out.lower()


def test_finalize_rejects_invalid_confidence():
    claims = [{"id": "c1", "type": "x", "confidence": "definitely", "statement": "s"}]
    out = finalize_report(json.dumps(claims))
    assert "REJECTED" in out
    assert "confidence" in out.lower()


def test_finalize_rejects_contradiction(monkeypatch):
    """Two claims that contradict are rejected even at inference confidence
    (the contradiction check runs over all claims)."""
    import findevil.server as srv

    monkeypatch.setattr(srv, "EVIDENCE_DIR", SAMPLES_DIR.resolve())
    log = str(SC01 / "auth.log")
    claims = [
        {"id": "c1", "type": "brute_force_from_ip", "confidence": "inference",
         "log_path": log, "ip": "45.123.45.67", "statement": "bf"},
        {"id": "c2", "type": "no_failed_logins", "confidence": "inference",
         "log_path": log, "statement": "no failures"},
    ]
    out = finalize_report(json.dumps(claims))
    assert "REJECTED" in out
    assert "Contradiction" in out


@pytest.mark.skipif(not SC01.exists(), reason="scenario 01 missing")
def test_finalize_accepts_supported_confirmed(monkeypatch):
    """A CONFIRMED claim that verifies against real evidence passes."""
    import findevil.server as srv

    monkeypatch.setattr(srv, "EVIDENCE_DIR", SAMPLES_DIR.resolve())
    claims = [
        {
            "id": "c1",
            "type": "brute_force_from_ip",
            "confidence": "confirmed",
            "log_path": str(SC01 / "auth.log"),
            "ip": "45.123.45.67",
            "min_attempts": 50,
            "statement": "brute force from 45.123.45.67",
        }
    ]
    out = finalize_report(json.dumps(claims))
    assert "ACCEPTED" in out
    assert "verified" in out.lower()


def test_finalize_accepts_when_downgraded_or_cited():
    """The same unsound claims pass once downgraded / cited."""
    claims = [
        {"id": "c1", "type": "brute_force_from_ip", "confidence": "inference",
         "statement": "possible brute force (unverified)"},
        {"id": "c2", "type": "rootkit_present", "confidence": "confirmed",
         "statement": "rootkit installed", "evidence": "fs/etc/ld.so.preload:1"},
    ]
    out = finalize_report(json.dumps(claims))
    assert "ACCEPTED" in out
    assert "c1" in out and "c2" in out


def test_finalize_rejects_empty_and_invalid_json():
    assert "REJECTED" in finalize_report("[]")
    assert "REJECTED" in finalize_report("{not json")


# ---------------------------------------------------------------------------
# assess_coverage — the gap finder
# ---------------------------------------------------------------------------


def _write_audit(logs_dir: Path, tools: list[str]) -> None:
    """Craft an audit.json with one entry per named tool."""
    lines = []
    for t in tools:
        lines.append(json.dumps({
            "timestamp": "2026-06-06T00:00:00+00:00",
            "tool": t,
            "params": {},
            "result_summary": "x",
        }))
    (logs_dir / "audit.json").write_text("\n".join(lines) + ("\n" if lines else ""))


@pytest.fixture
def staged(tmp_path, monkeypatch):
    """A tiny evidence tree + an isolated logs dir, wired into the autonomy module."""
    ev = tmp_path / "evidence"
    (ev / "fs" / "etc" / "ssh").mkdir(parents=True)
    (ev / "auth.log").write_text("Jun 6 00:00:00 h sshd[1]: Failed password\n")
    (ev / "fs" / "etc" / "ssh" / "sshd_config").write_text("PermitRootLogin yes\n")
    logs = tmp_path / "logs"
    logs.mkdir()
    # assess_coverage reads these names from the autonomy module namespace.
    monkeypatch.setattr(autonomy, "EVIDENCE_DIR", ev)
    monkeypatch.setattr(autonomy, "LOGS_DIR", logs)
    return ev, logs


def test_assess_coverage_flags_unexamined_artifacts(staged):
    ev, logs = staged
    _write_audit(logs, ["auth_summary"])  # auth examined; sshd_config + fsroot not
    out = assess_coverage()
    assert "GAP" in out
    assert "sshd_config" in out
    assert "filesystem root" in out
    assert "auth log" in out and "examined" in out


def test_assess_coverage_clean_when_all_examined(staged):
    ev, logs = staged
    _write_audit(logs, ["auth_summary", "analyze_sshd_config", "find_persistence"])
    out = assess_coverage()
    assert "COVERAGE CLEAN" in out


def test_assess_coverage_flags_unpivoted_ioc_and_unverified_confirmed(staged):
    ev, logs = staged
    # Everything examined so artifact coverage is clean; the gaps come from the
    # findings: a public IP never run through bulk_ioc_lookup, and a CONFIRMED
    # claim with no verify_finding on record.
    _write_audit(logs, ["auth_summary", "analyze_sshd_config", "find_persistence"])
    findings = [
        {"id": "c1", "confidence": "confirmed",
         "statement": "C2 beacon to 185.220.101.45", "ip": "185.220.101.45"},
    ]
    out = assess_coverage(json.dumps(findings))
    assert "bulk_ioc_lookup" in out
    assert "CONFIRMED claim" in out
    assert "GAP" in out
