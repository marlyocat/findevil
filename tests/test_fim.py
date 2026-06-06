"""Tests for the FIM (file integrity monitoring) tools.

Covers:
- Baseline creation on a synthetic 'clean' filesystem
- Hash stability (same content -> same baseline)
- Detection of added critical files
- Detection of modified critical files
- Detection of removed critical files
- Severity classification
- Scenario-01 as a real-case integration test: baseline created from a
  synthetic CLEAN version of the scenario-01 FS (without the attacker's
  additions) should, when diffed against the real compromised FS,
  surface the attacker's persistence changes as critical diffs.
"""

import json
import shutil
from pathlib import Path

import pytest

from findevil.tools.fim import (
    _build_baseline,
    _diff_baselines,
    _expand_tracked_paths,
    _hash_file,
    baseline_create,
    baseline_diff,
)

SC01_FS = Path(__file__).parent.parent / "samples" / "attack-scenario-01" / "fs"
SC02_FS = Path(__file__).parent.parent / "samples" / "attack-scenario-02" / "fs"


def _build_clean_tree(root: Path) -> None:
    """Create a minimal 'clean' tree with the files the tracker cares about.
    Works whether or not `root` already exists."""

    def write(rel: str, content: str) -> None:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)

    # Ensure these dirs exist even if we never populate them (so the
    # tracker's dir-level lookups don't skip them silently)
    root.mkdir(parents=True, exist_ok=True)
    for d in (
        "etc/systemd/system",
        "etc/cron.d",
        "etc/modprobe.d",
    ):
        (root / d).mkdir(parents=True, exist_ok=True)

    write("etc/passwd",
          "root:x:0:0:root:/root:/bin/bash\n"
          "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n")
    write("etc/shadow", "root:$6$hashed$...:19823:0:99999:7:::\n")
    write("etc/sudoers",
          "Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n")
    write("etc/ssh/sshd_config",
          "Port 22\nPermitRootLogin no\nPasswordAuthentication no\n")
    write("etc/pam.d/sshd", "@include common-auth\n")
    write("root/.ssh/authorized_keys",
          "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... admin@bastion\n")
    write("root/.bashrc", "alias ls='ls --color=auto'\n")
    write("home/alice/.bashrc", "alias ll='ls -alF'\nalias la='ls -A'\n")


# ---------------------------------------------------------------------------
# Unit-level helpers
# ---------------------------------------------------------------------------


def test_hash_file_stable(tmp_path: Path):
    p = tmp_path / "x"
    p.write_text("hello world")
    a = _hash_file(p)
    b = _hash_file(p)
    assert a == b
    assert a == (
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    )


def test_hash_file_detects_change(tmp_path: Path):
    p = tmp_path / "x"
    p.write_text("v1")
    h1 = _hash_file(p)
    p.write_text("v2")
    h2 = _hash_file(p)
    assert h1 != h2


def test_expand_tracked_paths_walks_expected_dirs(tmp_path: Path):
    _build_clean_tree(tmp_path)
    entries = _expand_tracked_paths(tmp_path)
    paths = {str(p[0].relative_to(tmp_path)) for p in entries}
    # Must include the critical individual files
    assert "etc/passwd" in paths
    assert "etc/shadow" in paths
    assert "etc/ssh/sshd_config" in paths
    # Must include per-user dotfiles
    assert "root/.ssh/authorized_keys" in paths
    assert "root/.bashrc" in paths
    assert "home/alice/.bashrc" in paths
    # Must include entries from tracked directories
    assert "etc/pam.d/sshd" in paths


# ---------------------------------------------------------------------------
# Build + diff on a tmp tree
# ---------------------------------------------------------------------------


def test_baseline_captures_entries(tmp_path: Path):
    _build_clean_tree(tmp_path)
    baseline = _build_baseline(tmp_path)
    assert "_metadata" in baseline
    assert baseline["_metadata"]["entry_count"] == len(baseline["entries"])
    assert baseline["_metadata"]["entry_count"] >= 5


def test_diff_detects_modified_critical_file(tmp_path: Path):
    _build_clean_tree(tmp_path)
    baseline = _build_baseline(tmp_path)
    # Modify /etc/passwd — add a UID-0 backdoor
    (tmp_path / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
        "toor:x:0:0:admin backup:/root:/bin/bash\n"
    )
    current = _build_baseline(tmp_path)
    added, removed, modified = _diff_baselines(baseline["entries"], current["entries"])
    assert added == []
    assert removed == []
    assert any(e.path == "etc/passwd" and e.severity == "critical" for e in modified)


def test_diff_detects_added_systemd_unit(tmp_path: Path):
    _build_clean_tree(tmp_path)
    baseline = _build_baseline(tmp_path)
    # Attacker plants a rogue systemd service
    (tmp_path / "etc" / "systemd" / "system" / "sysd-helper.service").write_text(
        "[Service]\nExecStart=/bin/bash /tmp/.x\n[Install]\nWantedBy=multi-user.target\n"
    )
    current = _build_baseline(tmp_path)
    added, removed, modified = _diff_baselines(baseline["entries"], current["entries"])
    assert any(
        e.path == "etc/systemd/system/sysd-helper.service" and e.severity == "critical"
        for e in added
    )


def test_diff_detects_removed_file(tmp_path: Path):
    _build_clean_tree(tmp_path)
    baseline = _build_baseline(tmp_path)
    (tmp_path / "etc" / "passwd").unlink()
    current = _build_baseline(tmp_path)
    _, removed, _ = _diff_baselines(baseline["entries"], current["entries"])
    assert any(e.path == "etc/passwd" and e.severity == "critical" for e in removed)


def test_diff_ignores_mtime_only_changes(tmp_path: Path):
    _build_clean_tree(tmp_path)
    baseline = _build_baseline(tmp_path)
    # Touch /etc/passwd — update mtime but keep content identical
    import os, time
    p = tmp_path / "etc" / "passwd"
    future = time.time() + 3600
    os.utime(p, (future, future))
    current = _build_baseline(tmp_path)
    _, _, modified = _diff_baselines(baseline["entries"], current["entries"])
    # mtime-only changes do NOT count as modifications in our diff
    assert not any(e.path == "etc/passwd" for e in modified)


def test_diff_clean_tree_has_zero_changes(tmp_path: Path):
    _build_clean_tree(tmp_path)
    baseline = _build_baseline(tmp_path)
    current = _build_baseline(tmp_path)
    added, removed, modified = _diff_baselines(baseline["entries"], current["entries"])
    assert added == []
    assert removed == []
    assert modified == []


# ---------------------------------------------------------------------------
# MCP-tool surface tests using monkeypatched EVIDENCE_DIR
# ---------------------------------------------------------------------------


def test_baseline_create_writes_json(tmp_path: Path, monkeypatch):
    import findevil.server as srv
    _build_clean_tree(tmp_path / "ev")
    monkeypatch.setattr(srv, "EVIDENCE_DIR", (tmp_path / "ev").resolve())
    monkeypatch.setattr(srv, "LOGS_DIR", (tmp_path / "logs").resolve())
    (tmp_path / "logs").mkdir()

    out = baseline_create(str(tmp_path / "ev"))
    assert "baseline created" in out.lower()
    # Default baseline file should exist
    base_file = (tmp_path / "logs" / "baseline.json").resolve()
    assert base_file.is_file()
    data = json.loads(base_file.read_text())
    assert data["_metadata"]["entry_count"] == len(data["entries"])


def test_baseline_diff_detects_compromise(tmp_path: Path, monkeypatch):
    import findevil.server as srv
    ev = tmp_path / "ev"
    _build_clean_tree(ev)
    monkeypatch.setattr(srv, "EVIDENCE_DIR", ev.resolve())
    monkeypatch.setattr(srv, "LOGS_DIR", (tmp_path / "logs").resolve())
    (tmp_path / "logs").mkdir()

    baseline_create(str(ev))

    # Simulate a compromise: add backdoor user and rogue systemd unit
    (ev / "etc" / "passwd").write_text(
        (ev / "etc" / "passwd").read_text()
        + "toor:x:0:0:admin backup:/root:/bin/bash\n"
    )
    (ev / "etc" / "systemd" / "system" / "rogue.service").write_text(
        "[Service]\nExecStart=/tmp/.x\n"
    )

    out = baseline_diff(str(ev), str(tmp_path / "logs" / "baseline.json"))
    assert "LIKELY COMPROMISE" in out
    assert "etc/passwd" in out
    assert "rogue.service" in out


# ---------------------------------------------------------------------------
# Real-case integration: scenario 01 should surface the persistence files
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SC01_FS.exists(), reason="scenario 01 FS not present")
def test_scenario01_fim_surfaces_all_persistence(tmp_path: Path, monkeypatch):
    """Build a baseline from scenario-02's clean FS (the 'known good'
    proxy), then diff against scenario-01's compromised FS. Every
    persistence file from scenario 01 should appear as an 'added'
    critical finding (or 'modified' for files that also exist in SC02).

    This exercises the *real* detection use case: baseline from a
    clean golden-image host, diff against a suspect host, see
    unexplained changes.
    """
    if not SC02_FS.exists():
        pytest.skip("scenario 02 FS (clean baseline proxy) not present")

    import findevil.server as srv

    # Clean up any leftover logs/ dir from previous runs
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    monkeypatch.setattr(srv, "LOGS_DIR", logs_dir.resolve())

    # Put a copy of SC02's FS under evidence, build baseline from it
    ev_root = tmp_path / "evidence"
    ev_root.mkdir()
    clean_copy = ev_root / "clean"
    shutil.copytree(SC02_FS, clean_copy)
    monkeypatch.setattr(srv, "EVIDENCE_DIR", ev_root.resolve())

    baseline_create(str(clean_copy))
    base_path = logs_dir / "baseline.json"
    assert base_path.is_file()

    # Now put SC01's FS in evidence and diff against the SC02 baseline
    suspect_copy = ev_root / "suspect"
    shutil.copytree(SC01_FS, suspect_copy)

    out = baseline_diff(str(suspect_copy), str(base_path))

    # Critical findings expected from scenario-01 artifacts that are
    # NOT in the scenario-02 clean baseline:
    for expected in (
        "etc/ld.so.preload",
        "etc/systemd/system/sysd-helper.service",
        "etc/cron.d/sysd-cron",
        "etc/modprobe.d/sysd.conf",
        "home/sysd/.bashrc",
    ):
        assert expected in out, f"FIM did NOT surface {expected}"
    # Must surface that critical changes were detected
    assert "LIKELY COMPROMISE" in out
