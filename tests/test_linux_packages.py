"""Tests for analyze_package_logs and verify_package_integrity."""

import hashlib
import importlib
from pathlib import Path

import pytest

from findevil.tools.linux_packages import (
    parse_apt_history,
    parse_dpkg_log,
    parse_pip_log,
)

SC04_FS = Path(__file__).parent.parent / "samples" / "attack-scenario-04" / "fs"


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------


def test_parse_apt_history_install_block():
    content = (
        "Start-Date: 2026-04-15 02:47:33\n"
        "Commandline: dpkg -i /tmp/xmrig_6.20.0_amd64.deb\n"
        "Requested-By: mlops (1100)\n"
        "Install: xmrig:amd64 (6.20.0)\n"
        "End-Date: 2026-04-15 02:47:42\n"
    )
    events = parse_apt_history(content)
    assert len(events) == 1
    assert events[0].action == "install"
    assert events[0].name == "xmrig"
    # Should flag local .deb installation AND known-bad package name
    assert any("known-bad" in f for f in events[0].flags)
    assert any(".deb" in f or "local" in f for f in events[0].flags)


def test_parse_apt_history_remove_block_flags_security_tool():
    content = (
        "Start-Date: 2026-04-15 02:48:10\n"
        "Commandline: apt remove auditd\n"
        "Requested-By: mlops (1100)\n"
        "Remove: auditd:amd64 (3.0.7-1build1)\n"
        "End-Date: 2026-04-15 02:48:22\n"
    )
    events = parse_apt_history(content)
    assert len(events) == 1
    assert events[0].action == "remove"
    assert events[0].name == "auditd"
    assert any("security tooling" in f for f in events[0].flags)


def test_parse_dpkg_log_extracts_installs():
    content = (
        "2026-04-15 02:47:34 install xmrig:amd64 <none> 6.20.0\n"
        "2026-04-14 10:30:04 install iotop:amd64 <none> 0.6-24-g733f3f8-1.1\n"
    )
    events = parse_dpkg_log(content)
    assert len(events) == 2
    names = {e.name for e in events}
    assert "xmrig" in names
    assert "iotop" in names


def test_parse_pip_log_detects_typosquat():
    content = "2026-04-15 02:45:11 pip install requests-utils==0.1.0\n"
    events = parse_pip_log(content)
    assert len(events) == 1
    assert events[0].name == "requests-utils"
    assert any("typosquat" in f for f in events[0].flags)


def test_parse_pip_log_clean_install_not_flagged():
    content = "2026-04-13 09:15:22 pip install requests==2.31.0\n"
    events = parse_pip_log(content)
    assert len(events) == 1
    assert events[0].flags == []


# ---------------------------------------------------------------------------
# Scenario 04 end-to-end
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SC04_FS.exists(), reason="scenario 04 FS not present")
def test_scenario04_apt_log_flags_local_deb_and_miner():
    content = (SC04_FS / "var/log/apt/history.log").read_text()
    events = parse_apt_history(content)
    flagged = [e for e in events if e.flags]
    # xmrig install + auditd removal must both be flagged
    names = {e.name for e in flagged}
    assert "xmrig" in names
    assert "auditd" in names


@pytest.mark.skipif(not SC04_FS.exists(), reason="scenario 04 FS not present")
def test_scenario04_pip_log_flags_typosquat():
    content = (SC04_FS / "root/.pip/pip.log").read_text()
    events = parse_pip_log(content)
    flagged = [e for e in events if e.flags]
    names = {e.name for e in flagged}
    assert "requests-utils" in names
    # Legitimate installs should NOT be flagged
    legit = [e for e in events if e.name in {"requests", "pandas", "numpy", "flask"}]
    assert all(e.flags == [] for e in legit)


# ---------------------------------------------------------------------------
# verify_package_integrity — closes the S24 timestomp class
# ---------------------------------------------------------------------------


def _setup_dpkg_evidence(tmp_path: Path, files: dict) -> Path:
    """Build a fake dpkg-managed filesystem under tmp_path.

    `files` is a dict mapping {pkg_name: [(rel_path, content_on_disk, content_dpkg_recorded)]}.
    Creates the on-disk file at `rel_path` with content_on_disk, and writes a
    `.md5sums` file in /var/lib/dpkg/info/ that records the MD5 of
    content_dpkg_recorded. If the two contents differ the integrity check
    must flag the file.
    """
    info = tmp_path / "var/lib/dpkg/info"
    info.mkdir(parents=True)
    for pkg, entries in files.items():
        md5sums_lines = []
        for rel, on_disk, recorded in entries:
            target = tmp_path / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(on_disk)
            md5 = hashlib.md5(recorded).hexdigest()  # noqa: S324
            md5sums_lines.append(f"{md5}  {rel}")
        (info / f"{pkg}.md5sums").write_text("\n".join(md5sums_lines) + "\n")
    return tmp_path


@pytest.fixture
def server_env(tmp_path, monkeypatch):
    monkeypatch.setenv("FINDEVIL_EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FINDEVIL_LOGS_DIR", str(tmp_path / "logs"))
    (tmp_path / "logs").mkdir()
    import findevil.server as server
    importlib.reload(server)
    import findevil.tools.linux_packages as pkgs
    importlib.reload(pkgs)
    return pkgs


def test_verify_package_integrity_flags_modified_sshd(server_env, tmp_path):
    """The S24 case: /usr/sbin/sshd content differs from what dpkg recorded.
    The tool must surface it as a critical-severity modification."""
    pkgs = server_env
    _setup_dpkg_evidence(tmp_path, {
        "openssh-server": [
            # On disk: backdoored content. dpkg recorded: original.
            ("usr/sbin/sshd", b"BACKDOORED-BINARY-CONTENT", b"original sshd content"),
        ],
    })
    out = pkgs.verify_package_integrity(str(tmp_path))
    assert isinstance(out, str)
    assert "Modified files:** 1" in out or "Modified files:** **1**" in out
    assert "usr/sbin/sshd" in out
    # System-binary classification fires
    assert "CRITICAL" in out
    assert "system binary" in out.lower()


def test_verify_package_integrity_clean_filesystem(server_env, tmp_path):
    """When every recorded MD5 matches the on-disk file, no findings."""
    pkgs = server_env
    content = b"unchanged file content"
    _setup_dpkg_evidence(tmp_path, {
        "coreutils": [
            ("bin/ls", content, content),
            ("bin/cat", content, content),
        ],
    })
    out = pkgs.verify_package_integrity(str(tmp_path))
    assert "Modified files:** 0" in out
    assert "No package-file integrity violations" in out


def test_verify_package_integrity_no_dpkg_dir(server_env, tmp_path):
    """RPM-only or non-package-managed filesystems: tool returns a graceful
    'no dpkg metadata' response rather than crashing."""
    pkgs = server_env
    out = pkgs.verify_package_integrity(str(tmp_path))
    assert isinstance(out, str)
    assert "No `/var/lib/dpkg/info/`" in out


def test_verify_package_integrity_rejects_outside_evidence(server_env, tmp_path):
    """Path validation must reject paths outside the evidence root."""
    pkgs = server_env
    # Try a path one level above the evidence dir
    out = pkgs.verify_package_integrity(str(tmp_path.parent))
    assert "Access denied" in out or "outside" in out.lower() or "Error" in out


def test_verify_package_integrity_skips_missing_files(server_env, tmp_path):
    """A file recorded in dpkg metadata but not present on disk should be
    counted as missing, not crash, not get flagged as a mismatch."""
    pkgs = server_env
    _setup_dpkg_evidence(tmp_path, {
        "ghost-package": [
            # dpkg recorded a file that doesn't exist on disk
            ("usr/bin/ghost-binary", b"present-on-disk-but-untouched", b"recorded-by-dpkg"),
        ],
    })
    # Now delete the on-disk version to simulate a removed file
    (tmp_path / "usr/bin/ghost-binary").unlink()
    out = pkgs.verify_package_integrity(str(tmp_path))
    assert "Missing files (recorded by dpkg, not on disk):** 1" in out
    assert "Modified files:** 0" in out
