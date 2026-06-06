"""
Symlink-safety tests for _validate_evidence_path.

An attacker who can write inside evidence/ shouldn't be able to plant
a symlink that points outside evidence/ and then have findevil read
through it. Path.resolve() follows symlinks, so after resolution the
target path should land outside evidence/ and the validator must
reject. These tests verify that invariant.
"""

from __future__ import annotations

import importlib
import os

import pytest


@pytest.fixture
def isolated_evidence_dir(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "real.txt").write_text("legit evidence")
    monkeypatch.setenv("FINDEVIL_EVIDENCE_DIR", str(evidence))
    monkeypatch.setenv("FINDEVIL_LOGS_DIR", str(tmp_path / "logs"))
    import findevil.server as server
    importlib.reload(server)
    return server, evidence, tmp_path


def test_rejects_symlink_to_system_file(isolated_evidence_dir, tmp_path):
    server, evidence, _ = isolated_evidence_dir
    secret = tmp_path / "target-outside-evidence"
    secret.write_text("should not be reachable through a symlink")
    link = evidence / "sneaky_link"
    os.symlink(secret, link)

    with pytest.raises(ValueError, match="Access denied"):
        server._validate_evidence_path(str(link))


def test_rejects_symlink_chain_escaping(isolated_evidence_dir, tmp_path):
    server, evidence, _ = isolated_evidence_dir
    outside_target = tmp_path / "final_target"
    outside_target.write_text("end of chain, outside evidence")
    mid = tmp_path / "hop"
    os.symlink(outside_target, mid)
    entry = evidence / "chain_start"
    os.symlink(mid, entry)

    with pytest.raises(ValueError, match="Access denied"):
        server._validate_evidence_path(str(entry))


def test_accepts_symlink_that_stays_inside(isolated_evidence_dir):
    """A symlink inside evidence/ that points to another file inside
    evidence/ is legitimate. Validator must NOT over-reject it."""
    server, evidence, _ = isolated_evidence_dir
    link = evidence / "valid_alias"
    os.symlink(evidence / "real.txt", link)
    result = server._validate_evidence_path(str(link))
    assert result == (evidence / "real.txt").resolve()


def test_rejects_relative_symlink_escaping(isolated_evidence_dir, tmp_path):
    """Symlink target expressed as a relative ../../ path. After
    Path.resolve() this lands at an absolute path outside evidence."""
    server, evidence, _ = isolated_evidence_dir
    link = evidence / "dotdot_link"
    os.symlink("../target_outside", link)
    (tmp_path / "target_outside").write_text("should not be reachable")

    with pytest.raises(ValueError, match="Access denied"):
        server._validate_evidence_path(str(link))
