"""
Runtime test: ``fim.baseline_create`` must refuse to write its baseline
JSON to a path inside the evidence directory.

Without this guard, a prompt-injected or adversarial caller could pass
``output_file=evidence/attack-scenario-01/auth.log`` and overwrite
actual evidence with the baseline JSON. That would destroy evidence
integrity — the core architectural claim findevil makes.
"""

from __future__ import annotations

import importlib

import pytest


@pytest.fixture
def isolated_env(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "fake.log").write_text("precious evidence")
    logs = tmp_path / "logs"
    logs.mkdir()
    monkeypatch.setenv("FINDEVIL_EVIDENCE_DIR", str(evidence))
    monkeypatch.setenv("FINDEVIL_LOGS_DIR", str(logs))

    import findevil.server as server
    importlib.reload(server)
    import findevil.tools.fim as fim
    importlib.reload(fim)
    return fim, evidence, logs


def test_baseline_output_inside_evidence_is_refused(isolated_env):
    fim, evidence, _ = isolated_env
    attempted_path = str(evidence / "overwritten-evidence.log")
    with pytest.raises(ValueError, match="inside the evidence directory"):
        fim._resolve_output_path(attempted_path)


def test_baseline_output_outside_evidence_is_allowed(isolated_env, tmp_path):
    fim, _evidence, _ = isolated_env
    safe_path = str(tmp_path / "away_from_evidence" / "baseline.json")
    result = fim._resolve_output_path(safe_path)
    assert str(result).endswith("baseline.json")


def test_default_baseline_goes_to_logs_dir(isolated_env):
    fim, _evidence, logs = isolated_env
    result = fim._resolve_output_path("")
    assert str(result).startswith(str(logs.resolve()))
    assert result.name == "baseline.json"


def test_baseline_create_returns_error_string_for_evidence_output_path(isolated_env):
    """Regression: ``baseline_create`` must catch the ``_resolve_output_path``
    ValueError and surface it as a readable error string. Letting the
    exception bubble up would crash the MCP tool call."""
    fim, evidence, _ = isolated_env
    attempted = str(evidence / "overwritten-evidence.log")
    out = fim.baseline_create(str(evidence), attempted)
    assert isinstance(out, str)
    assert "inside the evidence directory" in out
