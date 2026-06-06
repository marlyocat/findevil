"""Tests for the self-correction framework."""

import json
from pathlib import Path

import pytest

from findevil.tools.self_correction import (
    _find_contradiction_patterns,
    _parse_claims,
    find_contradictions,
    verify_finding,
)

SAMPLES_DIR = Path(__file__).parent.parent / "samples"
SC01 = SAMPLES_DIR / "attack-scenario-01"
SC02_LOG = SAMPLES_DIR / "attack-scenario-02" / "auth.log"
SC03_LOG = SAMPLES_DIR / "attack-scenario-03" / "access.log"
SC04_FS = SAMPLES_DIR / "attack-scenario-04" / "fs"


# ---------------------------------------------------------------------------
# verify_finding — SUPPORTED cases
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SC01.exists(), reason="scenario 01 missing")
def test_verify_brute_force_supported(monkeypatch):
    import findevil.server as srv
    monkeypatch.setattr(srv, "EVIDENCE_DIR", SAMPLES_DIR.resolve())
    out = verify_finding(
        "brute_force_from_ip",
        json.dumps({
            "log_path": str(SC01 / "auth.log"),
            "ip": "45.123.45.67",
            "min_attempts": 50,
        }),
    )
    assert "SUPPORTED" in out
    assert "45.123.45.67" in out


@pytest.mark.skipif(not SC01.exists(), reason="scenario 01 missing")
def test_verify_login_after_brute_force_supported(monkeypatch):
    import findevil.server as srv
    monkeypatch.setattr(srv, "EVIDENCE_DIR", SAMPLES_DIR.resolve())
    out = verify_finding(
        "successful_login_after_brute_force",
        json.dumps({"log_path": str(SC01 / "auth.log"), "ip": "45.123.45.67"}),
    )
    assert "SUPPORTED" in out


@pytest.mark.skipif(not SC01.exists(), reason="scenario 01 missing")
def test_verify_user_created_supported(monkeypatch):
    import findevil.server as srv
    monkeypatch.setattr(srv, "EVIDENCE_DIR", SAMPLES_DIR.resolve())
    out = verify_finding(
        "user_created",
        json.dumps({"log_path": str(SC01 / "auth.log"), "name": "sysd"}),
    )
    assert "SUPPORTED" in out


@pytest.mark.skipif(not SC04_FS.exists(), reason="scenario 04 missing")
def test_verify_package_installed_supported(monkeypatch):
    import findevil.server as srv
    monkeypatch.setattr(srv, "EVIDENCE_DIR", SAMPLES_DIR.resolve())
    out = verify_finding(
        "package_installed",
        json.dumps({"fs_root": str(SC04_FS), "name": "xmrig"}),
    )
    assert "SUPPORTED" in out


@pytest.mark.skipif(not SC03_LOG.exists(), reason="scenario 03 missing")
def test_verify_webshell_upload_chain_supported(monkeypatch):
    import findevil.server as srv
    monkeypatch.setattr(srv, "EVIDENCE_DIR", SAMPLES_DIR.resolve())
    out = verify_finding(
        "webshell_upload_chain",
        json.dumps({"log_path": str(SC03_LOG), "ip": "91.121.55.44"}),
    )
    assert "SUPPORTED" in out
    assert "shell.php" in out


# ---------------------------------------------------------------------------
# verify_finding — CONTRADICTED cases
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SC02_LOG.exists(), reason="scenario 02 missing")
def test_verify_brute_force_contradicted_on_scenario02(monkeypatch):
    """Scenario 02 has zero failed logins — claiming a brute force must
    be CONTRADICTED."""
    import findevil.server as srv
    monkeypatch.setattr(srv, "EVIDENCE_DIR", SAMPLES_DIR.resolve())
    out = verify_finding(
        "brute_force_from_ip",
        json.dumps({
            "log_path": str(SC02_LOG),
            "ip": "185.229.59.103",
            "min_attempts": 10,
        }),
    )
    assert "CONTRADICTED" in out


@pytest.mark.skipif(not SC01.exists(), reason="scenario 01 missing")
def test_verify_user_created_contradicted_for_toor(monkeypatch):
    """The toor account exists in /etc/passwd but was not added via useradd,
    so it should NOT appear in auth.log — verification must flag this."""
    import findevil.server as srv
    monkeypatch.setattr(srv, "EVIDENCE_DIR", SAMPLES_DIR.resolve())
    out = verify_finding(
        "user_created",
        json.dumps({"log_path": str(SC01 / "auth.log"), "name": "toor"}),
    )
    assert "CONTRADICTED" in out
    # The message must hint that direct file edit is the explanation
    assert "directly" in out or "/etc/passwd" in out


def test_verify_finding_invalid_claim_type():
    out = verify_finding("nonsense_claim", json.dumps({}))
    assert "INVALID" in out


def test_verify_finding_bad_params_json():
    out = verify_finding("brute_force_from_ip", "not valid json")
    assert "INVALID" in out


# ---------------------------------------------------------------------------
# find_contradictions
# ---------------------------------------------------------------------------


def test_find_contradictions_brute_force_vs_zero_failures():
    claims = json.dumps([
        {"id": "a", "type": "brute_force_from_ip", "ip": "1.2.3.4", "log_path": "/x/auth.log"},
        {"id": "b", "type": "no_failed_logins", "log_path": "/x/auth.log"},
    ])
    parsed, err = _parse_claims(claims)
    assert err is None
    issues = _find_contradiction_patterns(parsed)
    assert any("brute force" in i.lower() and "zero" in i.lower() for i in issues)


def test_find_contradictions_verdict_vs_no_success():
    claims = json.dumps([
        {
            "id": "v",
            "type": "compromise_verdict",
            "verdict": "confirmed",
            "attacker_ip": "1.2.3.4",
        },
        {"id": "n", "type": "no_successful_login_from_ip", "ip": "1.2.3.4"},
    ])
    out = find_contradictions(claims)
    assert "contradiction" in out.lower()


def test_find_contradictions_persistence_conflict():
    claims = json.dumps([
        {"id": "p", "type": "persistence_mechanism_exists", "category": "systemd"},
        {"id": "e", "type": "persistence_empty", "category": "systemd"},
    ])
    out = find_contradictions(claims)
    assert "contradiction" in out.lower()
    assert "systemd" in out


def test_find_contradictions_multiple_initial_vectors():
    claims = json.dumps([
        {"id": "i1", "type": "initial_access_vector", "vector": "ssh_brute_force"},
        {"id": "i2", "type": "initial_access_vector", "vector": "webshell_upload"},
    ])
    out = find_contradictions(claims)
    assert "contradiction" in out.lower()


def test_find_contradictions_returns_none_when_clean():
    claims = json.dumps([
        {"id": "a", "type": "brute_force_from_ip", "ip": "1.2.3.4", "log_path": "/x/auth.log"},
        {"id": "b", "type": "user_created", "name": "sysd"},
    ])
    out = find_contradictions(claims)
    assert "No contradictions" in out


def test_find_contradictions_rejects_bad_json():
    out = find_contradictions("definitely not json")
    assert "INVALID" in out


def test_find_contradictions_rejects_non_array():
    out = find_contradictions(json.dumps({"not": "an array"}))
    assert "INVALID" in out


# ---------------------------------------------------------------------------
# get_audit_trail — smoke test on an isolated log
# ---------------------------------------------------------------------------


def test_get_audit_trail_reads_from_configured_path(tmp_path: Path, monkeypatch):
    """Redirect LOGS_DIR to tmp, write a synthetic audit log, read it back."""
    from findevil.tools import self_correction as sc

    audit_file = tmp_path / "audit.json"
    audit_file.write_text(
        '{"timestamp": "2026-04-19T12:00:00+00:00", "tool": "foo", "params": {}, "result_summary": "ok"}\n'
        '{"timestamp": "2026-04-19T12:00:05+00:00", "tool": "bar", "params": {"x": 1}, "result_summary": "fine"}\n'
    )
    monkeypatch.setattr(sc, "LOGS_DIR", tmp_path)

    out = sc.get_audit_trail()
    assert "foo" in out
    assert "bar" in out

    out_filtered = sc.get_audit_trail(filter_tool="foo")
    assert "foo" in out_filtered
    # The bar entry should still not appear in the entries section
    assert out_filtered.count("bar") == 0
