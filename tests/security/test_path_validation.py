"""
Security tests for findevil's evidence-path validator.

findevil's Constraint Implementation claim is "no MCP tool can access
files outside the evidence directory." That guarantee lives in one
function — ``_validate_evidence_path`` in ``src/findevil/server.py`` —
so it deserves direct adversarial coverage. These tests try to make
it accept paths that escape the evidence root.

If any of these pass (meaning: the validator failed to reject), the
architectural claim in docs/architecture.md §Security-boundaries-1 is
broken and needs fixing before the demo.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture
def isolated_evidence_dir(tmp_path, monkeypatch):
    """Give each test its own evidence root so we can test prefix bugs safely."""
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "real.txt").write_text("legit evidence file")
    monkeypatch.setenv("FINDEVIL_EVIDENCE_DIR", str(evidence))
    monkeypatch.setenv("FINDEVIL_LOGS_DIR", str(tmp_path / "logs"))
    # Import late so the env vars take effect.
    import importlib

    import findevil.server as server
    importlib.reload(server)
    return server, evidence, tmp_path


def test_rejects_parent_directory_traversal(isolated_evidence_dir):
    server, evidence, _ = isolated_evidence_dir
    with pytest.raises(ValueError, match="Access denied"):
        server._validate_evidence_path(str(evidence / ".." / ".." / "etc" / "passwd"))


def test_rejects_absolute_path_outside(isolated_evidence_dir):
    server, _evidence, _ = isolated_evidence_dir
    with pytest.raises(ValueError, match="Access denied"):
        server._validate_evidence_path("/etc/passwd")


def test_rejects_null_byte_smuggle(isolated_evidence_dir):
    """Python's pathlib raises on null bytes; we want a clean rejection either way."""
    server, evidence, _ = isolated_evidence_dir
    with pytest.raises((ValueError, OSError)):
        server._validate_evidence_path(str(evidence) + "\x00/../../etc/passwd")


def test_url_encoded_segments_are_literal_directories(isolated_evidence_dir):
    """Python's Path does NOT decode URL encoding. "%2E%2E" is just a
    literal directory name inside evidence — this is the safe behavior,
    NOT a bypass. Test locks that behavior in."""
    server, evidence, _ = isolated_evidence_dir
    (evidence / "%2E%2E").mkdir()
    target = evidence / "%2E%2E" / "file.txt"
    target.write_text("literal subdirectory, not traversal")
    result = server._validate_evidence_path(str(target))
    assert result == target.resolve()


def test_accepts_real_file_inside(isolated_evidence_dir):
    """Baseline: legitimate path must pass. If this fails, the validator is over-strict."""
    server, evidence, _ = isolated_evidence_dir
    result = server._validate_evidence_path(str(evidence / "real.txt"))
    assert result == (evidence / "real.txt").resolve()


# ---------------------------------------------------------------------------
# KNOWN BUG: sibling-directory string-prefix attack
#
# The validator does str(requested).startswith(str(evidence_resolved)).
# If EVIDENCE_DIR is "/tmp/X/evidence" and requested is
# "/tmp/X/evidence-malicious/file", the startswith check passes because
# the string literally starts with the evidence path — there's no
# separator check after the prefix.
#
# A proper implementation uses Path.is_relative_to(), or appends
# os.sep to the prefix before the startswith check.
# ---------------------------------------------------------------------------


def test_rejects_sibling_prefix_escape(isolated_evidence_dir):
    """Sibling directory that happens to share the evidence path as a string prefix.

    Expected: rejected. If this test FAILS, the validator has a
    real prefix-confusion vulnerability — a file in evidence-malicious/
    (sibling of evidence/) would be treated as if it were inside evidence/.
    """
    server, evidence, tmp_path = isolated_evidence_dir
    sibling = tmp_path / (evidence.name + "-malicious")
    sibling.mkdir()
    leaked = sibling / "secret.txt"
    leaked.write_text("this should NOT be reachable")

    with pytest.raises(ValueError, match="Access denied"):
        server._validate_evidence_path(str(leaked))


def test_rejects_parent_with_matching_prefix(isolated_evidence_dir):
    """Like above but the attacker-owned path is a longer name sharing the prefix.

    Expected: rejected. Variant of the prefix-confusion class.
    """
    server, evidence, tmp_path = isolated_evidence_dir
    impostor = tmp_path / (evidence.name + "_backup")
    impostor.mkdir()
    fake = impostor / "steal_me"
    fake.write_text("should never be read")

    with pytest.raises(ValueError, match="Access denied"):
        server._validate_evidence_path(str(fake))
