"""Tests for the Linux memory-forensics module.

Volatility 3 is wrapped at the subprocess level; these tests mock
subprocess.run to feed canned plugin output and assert correct parsing,
classification, and graceful degradation on missing kernel symbols.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from findevil.tools.linux_memory import (
    _classify_network,
    _classify_processes,
    _diff_modules,
    _is_rfc1918,
    _looks_like_no_symbols,
)


# ---------------------------------------------------------------------------
# Pure-function classifier tests (no Volatility needed)
# ---------------------------------------------------------------------------


def test_diff_modules_finds_hidden_module():
    lsmod = [{"Name": "ip_tables"}, {"Name": "nf_nat"}, {"Name": "virtio_net"}]
    check = [{"Name": "ip_tables"}, {"Name": "nf_nat"}, {"Name": "virtio_net"},
             {"Name": "diamorphine"}]
    diff = _diff_modules(lsmod, check)
    assert diff["hidden_modules"] == ["diamorphine"]
    assert "diamorphine" not in diff["both"]


def test_diff_modules_no_hidden_when_aligned():
    lsmod = [{"Name": "a"}, {"Name": "b"}]
    check = [{"Name": "a"}, {"Name": "b"}]
    diff = _diff_modules(lsmod, check)
    assert diff["hidden_modules"] == []


def test_classify_processes_flags_known_bad_name():
    rows = [
        {"PID": 1, "PPID": 0, "COMM": "systemd"},
        {"PID": 1234, "PPID": 1, "COMM": "kdevtmpfsi"},
        {"PID": 5678, "PPID": 1, "COMM": "sshd"},
    ]
    procs, anomalies = _classify_processes(rows)
    assert len(procs) == 3
    assert any("kdevtmpfsi" in a for a in anomalies)


def test_classify_processes_flags_orphan_parent():
    rows = [
        {"PID": 1, "PPID": 0, "COMM": "systemd"},
        {"PID": 1234, "PPID": 9999, "COMM": "sshd"},  # ppid 9999 not present
    ]
    procs, anomalies = _classify_processes(rows)
    assert any("PPID=9999" in a for a in anomalies)


def test_classify_processes_clean_returns_no_anomalies():
    rows = [
        {"PID": 1, "PPID": 0, "COMM": "systemd"},
        {"PID": 1234, "PPID": 1, "COMM": "sshd"},
        {"PID": 5678, "PPID": 1234, "COMM": "bash"},
    ]
    procs, anomalies = _classify_processes(rows)
    assert anomalies == []


def test_classify_network_flags_revshell_listener():
    # Mix of legacy and modern Vol3 field shapes — both must be accepted.
    rows = [
        {"Protocol": "TCP", "Family": "AF_INET", "Local IP": "0.0.0.0",
         "Local Port": 22, "State": "LISTEN"},
        {"Proto": "TCP", "Family": "AF_INET", "Source Addr": "0.0.0.0",
         "Source Port": "4444", "State": "LISTEN"},  # sockstat shape
    ]
    findings = _classify_network(rows)
    assert any("4444" in f for f in findings)
    assert not any("22 " in f or ":22" in f for f in findings)


def test_classify_network_flags_outbound_external():
    rows = [
        {"Proto": "TCP", "Family": "AF_INET", "Source Addr": "10.0.0.5",
         "Destination Addr": "203.0.113.99", "Destination Port": "443",
         "State": "ESTABLISHED"},
        {"Proto": "TCP", "Family": "AF_INET", "Source Addr": "10.0.0.5",
         "Destination Addr": "10.0.0.1", "Destination Port": "443",
         "State": "ESTABLISHED"},  # internal — must not flag
    ]
    findings = _classify_network(rows)
    flagged = [f for f in findings if "203.0.113.99" in f]
    assert flagged
    not_flagged = [f for f in findings if "10.0.0.1" in f]
    assert not not_flagged


def test_classify_network_skips_netlink_unix_sockets():
    """Vol3 sockstat returns netlink/unix sockets too. Don't false-positive
    on those — they have no inet ports."""
    rows = [
        {"Family": "AF_NETLINK", "Source Addr": "group:0x00000000",
         "Source Port": "0", "Destination Addr": "group:0x00000000",
         "Destination Port": "0", "State": "?", "Proto": "NETLINK_KOBJECT_UEVENT"},
        {"Family": "AF_UNIX", "Source Addr": "@/tmp/dbus-x",
         "Destination Addr": "-", "State": "ESTABLISHED", "Proto": "STREAM"},
    ]
    findings = _classify_network(rows)
    assert findings == []


def test_is_rfc1918_classification():
    assert _is_rfc1918("10.0.0.5")
    assert _is_rfc1918("172.16.0.1")
    assert _is_rfc1918("192.168.1.1")
    assert _is_rfc1918("127.0.0.1")
    assert not _is_rfc1918("203.0.113.99")
    assert not _is_rfc1918("198.51.100.1")
    assert not _is_rfc1918("not-an-ip")


def test_looks_like_no_symbols_detects_common_messages():
    assert _looks_like_no_symbols("Could not find a suitable kernel symbol table")
    assert _looks_like_no_symbols("Unable to validate the plugin requirements")
    assert _looks_like_no_symbols("No available symbol table for this kernel")
    assert not _looks_like_no_symbols("Permission denied")
    assert not _looks_like_no_symbols("")


# ---------------------------------------------------------------------------
# MCP tool tests with mocked subprocess
# ---------------------------------------------------------------------------


@pytest.fixture
def evidence_dump(tmp_path, monkeypatch):
    """Create a fake memory dump inside a fake EVIDENCE_DIR and patch the
    server's evidence root to point at it."""
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    dump = evidence / "case01.lime"
    dump.write_bytes(b"\x00" * 1024)  # placeholder
    from findevil import server
    monkeypatch.setattr(server, "EVIDENCE_DIR", evidence)
    return dump


def _mock_vol_response(plugin_to_rows: dict) -> object:
    """Build a side_effect for subprocess.run that returns canned JSON per plugin."""
    def _run(cmd, *args, **kwargs):
        # cmd is a list; the plugin name is the last non-flag element after -r json
        plugin = None
        for i, c in enumerate(cmd):
            if c.startswith("linux.") or c.startswith("banners."):
                plugin = c
                break
        rows = plugin_to_rows.get(plugin, [])
        # vol --help probe — return rc=0 to satisfy availability check
        if "--help" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="usage: ...", stderr="")
        return subprocess.CompletedProcess(
            cmd, 0,
            stdout=json.dumps(rows),
            stderr="",
        )
    return _run


def test_analyze_memory_modules_surfaces_hidden_module(evidence_dump):
    plugin_data = {
        "linux.lsmod": [{"Name": "ip_tables"}, {"Name": "nf_nat"}],
        "linux.check_modules": [{"Name": "ip_tables"}, {"Name": "nf_nat"},
                                {"Name": "diamorphine"}],
    }
    with patch("findevil.tools.linux_memory.subprocess.run", side_effect=_mock_vol_response(plugin_data)):
        from findevil.tools.linux_memory import analyze_memory_modules
        out = analyze_memory_modules(str(evidence_dump))
    assert "Hidden kernel modules" in out
    assert "diamorphine" in out
    assert "LIKELY KERNEL ROOTKIT" in out


def test_analyze_memory_modules_clean(evidence_dump):
    plugin_data = {
        "linux.lsmod": [{"Name": "ip_tables"}, {"Name": "nf_nat"}],
        "linux.check_modules": [{"Name": "ip_tables"}, {"Name": "nf_nat"}],
    }
    with patch("findevil.tools.linux_memory.subprocess.run", side_effect=_mock_vol_response(plugin_data)):
        from findevil.tools.linux_memory import analyze_memory_modules
        out = analyze_memory_modules(str(evidence_dump))
    assert "No hidden modules detected" in out


def test_analyze_memory_processes_flags_known_bad(evidence_dump):
    plugin_data = {
        "linux.pslist": [
            {"PID": 1, "PPID": 0, "COMM": "systemd"},
            {"PID": 1234, "PPID": 1, "COMM": "kdevtmpfsi"},
        ],
    }
    with patch("findevil.tools.linux_memory.subprocess.run", side_effect=_mock_vol_response(plugin_data)):
        from findevil.tools.linux_memory import analyze_memory_processes
        out = analyze_memory_processes(str(evidence_dump))
    assert "kdevtmpfsi" in out
    assert "Anomalies" in out


def test_analyze_memory_network_flags_revshell_port(evidence_dump):
    plugin_data = {
        "linux.sockstat.Sockstat": [
            {"Protocol": "TCP", "Local IP": "0.0.0.0", "Local Port": 4444,
             "Foreign IP": "-", "State": "LISTEN"},
        ],
    }
    with patch("findevil.tools.linux_memory.subprocess.run", side_effect=_mock_vol_response(plugin_data)):
        from findevil.tools.linux_memory import analyze_memory_network
        out = analyze_memory_network(str(evidence_dump))
    assert "4444" in out
    assert "Flagged" in out


def test_analyze_memory_bash_history_renders_recovered_commands(evidence_dump):
    plugin_data = {
        "linux.bash": [
            {"PID": 1234, "Process": "bash", "CommandTime": "2026-04-30 02:14:01",
             "Command": "find / -perm -4000"},
            {"PID": 1234, "Process": "bash", "CommandTime": "2026-04-30 02:14:03",
             "Command": "history -c"},
        ],
    }
    with patch("findevil.tools.linux_memory.subprocess.run", side_effect=_mock_vol_response(plugin_data)):
        from findevil.tools.linux_memory import analyze_memory_bash_history
        out = analyze_memory_bash_history(str(evidence_dump))
    assert "find / -perm -4000" in out
    assert "history -c" in out
    assert "Commands recovered:** 2" in out


def test_analyze_memory_summary_aggregates_signals(evidence_dump):
    plugin_data = {
        "banners.Banners": [{"Banner": "Linux version 6.0.0-generic"}],
        "linux.pslist": [
            {"PID": 1, "PPID": 0, "COMM": "systemd"},
            {"PID": 1234, "PPID": 1, "COMM": "kthrotlds"},
        ],
        "linux.sockstat.Sockstat": [
            {"Protocol": "TCP", "Local IP": "0.0.0.0", "Local Port": 4444, "State": "LISTEN"},
        ],
        "linux.lsmod": [{"Name": "ip_tables"}],
        "linux.check_modules": [{"Name": "ip_tables"}, {"Name": "diamorphine"}],
        "linux.malware.malfind.Malfind": [
            {"PID": 1234, "Process": "kthrotlds",
             "Start Address": "0x7f", "End Address": "0x80",
             "Protection": "RWX"},
        ],
    }
    with patch("findevil.tools.linux_memory.subprocess.run", side_effect=_mock_vol_response(plugin_data)):
        from findevil.tools.linux_memory import analyze_memory_summary
        out = analyze_memory_summary(str(evidence_dump))
    assert "diamorphine" in out
    assert "kthrotlds" in out
    assert "4444" in out
    assert "LIKELY MEMORY-RESIDENT COMPROMISE" in out


def test_analyze_memory_summary_clean_dump(evidence_dump):
    plugin_data = {
        "banners.Banners": [{"Banner": "Linux version 6.0.0-generic"}],
        "linux.pslist": [
            {"PID": 1, "PPID": 0, "COMM": "systemd"},
            {"PID": 1234, "PPID": 1, "COMM": "sshd"},
        ],
        "linux.sockstat.Sockstat": [
            {"Protocol": "TCP", "Local IP": "0.0.0.0", "Local Port": 22, "State": "LISTEN"},
        ],
        "linux.lsmod": [{"Name": "ip_tables"}, {"Name": "nf_nat"}],
        "linux.check_modules": [{"Name": "ip_tables"}, {"Name": "nf_nat"}],
        "linux.malware.malfind.Malfind": [],
    }
    with patch("findevil.tools.linux_memory.subprocess.run", side_effect=_mock_vol_response(plugin_data)):
        from findevil.tools.linux_memory import analyze_memory_summary
        out = analyze_memory_summary(str(evidence_dump))
    assert "No strong memory-resident compromise indicators" in out


# ---------------------------------------------------------------------------
# Graceful degradation when kernel symbols missing
# ---------------------------------------------------------------------------


def test_no_symbols_returns_actionable_message(evidence_dump):
    def _run_no_sym(cmd, *args, **kwargs):
        if "--help" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")
        if "banners.Banners" in cmd:
            return subprocess.CompletedProcess(
                cmd, 0,
                stdout=json.dumps([{"Banner": "Linux version 6.99-customkernel"}]),
                stderr="",
            )
        return subprocess.CompletedProcess(
            cmd, 1, stdout="",
            stderr="volatility3.framework.exceptions.UnsatisfiedException: "
                   "Could not find a suitable kernel symbol table",
        )
    with patch("findevil.tools.linux_memory.subprocess.run", side_effect=_run_no_sym):
        from findevil.tools.linux_memory import analyze_memory_summary
        out = analyze_memory_summary(str(evidence_dump))
    assert "Kernel symbols required" in out
    assert "ISF" in out
    assert "Linux version 6.99-customkernel" in out


# ---------------------------------------------------------------------------
# Path validation
# ---------------------------------------------------------------------------


def test_rejects_path_outside_evidence_dir(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    outside = tmp_path / "stolen.lime"
    outside.write_bytes(b"\x00")
    from findevil import server
    monkeypatch.setattr(server, "EVIDENCE_DIR", evidence)
    from findevil.tools.linux_memory import analyze_memory_summary
    out = analyze_memory_summary(str(outside))
    assert "Error" in out
    assert "outside the evidence directory" in out


def test_missing_dump_file_returns_friendly_error(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    from findevil import server
    monkeypatch.setattr(server, "EVIDENCE_DIR", evidence)
    from findevil.tools.linux_memory import analyze_memory_summary
    out = analyze_memory_summary(str(evidence / "nonexistent.lime"))
    assert "not found" in out


# ---------------------------------------------------------------------------
# Additional edge cases
# ---------------------------------------------------------------------------


def test_vol_not_installed_returns_clear_message(evidence_dump):
    """When the vol binary is absent, plugin runs return a clean rc=127 +
    'volatility3 not installed' rather than crashing."""
    def _which_returns_nothing(*args, **kwargs):
        return None
    # Force _vol_available to return False by patching the resolved path AND shutil.which
    with patch("findevil.tools.linux_memory.shutil.which", _which_returns_nothing), \
         patch("findevil.tools.linux_memory._VOL_BIN", "/nonexistent/vol"):
        # Also patch subprocess.run so the --help probe fails
        def _fail(*args, **kwargs):
            raise OSError("No such file or directory")
        with patch("findevil.tools.linux_memory.subprocess.run", side_effect=_fail):
            from findevil.tools.linux_memory import analyze_memory_processes
            out = analyze_memory_processes(str(evidence_dump))
    assert "vol" in out.lower() or "not installed" in out.lower() or "failed" in out.lower()


def test_plugin_timeout_propagates_clean_error(evidence_dump):
    """Vol3 sometimes hangs on broken dumps. The wrapper must return a
    clear 'timed out' message rather than raise to the caller."""
    def _timeout(*args, **kwargs):
        if "--help" in args[0]:
            return subprocess.CompletedProcess(args[0], 0, stdout="", stderr="")
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=600)
    with patch("findevil.tools.linux_memory.subprocess.run", side_effect=_timeout):
        from findevil.tools.linux_memory import analyze_memory_modules
        out = analyze_memory_modules(str(evidence_dump))
    assert "timed out" in out.lower() or "vol" in out.lower()


def test_malformed_json_output_does_not_crash(evidence_dump):
    """Vol3 occasionally emits warnings before the JSON. Recovery path
    extracts the JSON via regex; full garbage falls through to rc-fail."""
    def _garbage(cmd, *args, **kwargs):
        if "--help" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(
            cmd, 0,
            stdout="this is not JSON at all, just text",
            stderr="",
        )
    with patch("findevil.tools.linux_memory.subprocess.run", side_effect=_garbage):
        from findevil.tools.linux_memory import analyze_memory_processes
        out = analyze_memory_processes(str(evidence_dump))
    # No crash. Tool returns either zero processes or a parse-fail message.
    assert "processes" in out.lower() or "failed" in out.lower()


def test_recoverable_json_with_warning_prefix(evidence_dump):
    """Vol3 sometimes prints a warning line before the JSON array. The
    fallback regex-extracts the array out of mixed stdout."""
    def _mixed(cmd, *args, **kwargs):
        if "--help" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(
            cmd, 0,
            stdout='WARNING: deprecated flag used\n[{"PID": 1, "PPID": 0, "COMM": "systemd"}]',
            stderr="",
        )
    with patch("findevil.tools.linux_memory.subprocess.run", side_effect=_mixed):
        from findevil.tools.linux_memory import analyze_memory_processes
        out = analyze_memory_processes(str(evidence_dump))
    assert "systemd" in out


def test_empty_plugin_result_renders_clean(evidence_dump):
    """A successful plugin invocation with no rows (e.g. clean malfind)
    should render a 'No suspicious regions detected' message."""
    plugin_data = {"linux.malfind": []}
    with patch("findevil.tools.linux_memory.subprocess.run", side_effect=_mock_vol_response(plugin_data)):
        from findevil.tools.linux_memory import analyze_memory_malfind
        out = analyze_memory_malfind(str(evidence_dump))
    assert "No suspicious memory regions detected" in out


def test_processes_only_known_bad_returns_specific_anomaly(evidence_dump):
    """Multiple known-bad process names should each produce a separate anomaly entry."""
    plugin_data = {
        "linux.pslist": [
            {"PID": 1, "PPID": 0, "COMM": "systemd"},
            {"PID": 100, "PPID": 1, "COMM": "kdevtmpfsi"},
            {"PID": 101, "PPID": 1, "COMM": "kinsing"},
            {"PID": 102, "PPID": 1, "COMM": "kthrotlds"},
        ],
    }
    with patch("findevil.tools.linux_memory.subprocess.run", side_effect=_mock_vol_response(plugin_data)):
        from findevil.tools.linux_memory import analyze_memory_processes
        out = analyze_memory_processes(str(evidence_dump))
    assert "kdevtmpfsi" in out
    assert "kinsing" in out
    assert "kthrotlds" in out


def test_summary_with_only_proc_anomaly_returns_moderate_verdict(evidence_dump):
    """If only proc anomalies fire (no hidden modules, no malfind), verdict
    should be 'moderate signals' not 'LIKELY' compromise."""
    plugin_data = {
        "banners.Banners": [{"Banner": "Linux 6.0.0"}],
        "linux.pslist": [
            {"PID": 1, "PPID": 0, "COMM": "systemd"},
            {"PID": 100, "PPID": 9999, "COMM": "sshd"},  # orphaned ppid only
        ],
        "linux.sockstat.Sockstat": [],
        "linux.lsmod": [{"Name": "ip_tables"}],
        "linux.check_modules": [{"Name": "ip_tables"}],
        "linux.malware.malfind.Malfind": [],
    }
    with patch("findevil.tools.linux_memory.subprocess.run", side_effect=_mock_vol_response(plugin_data)):
        from findevil.tools.linux_memory import analyze_memory_summary
        out = analyze_memory_summary(str(evidence_dump))
    assert "Moderate signals" in out or "moderate" in out.lower()
    assert "LIKELY MEMORY-RESIDENT COMPROMISE" not in out


# ---------------------------------------------------------------------------
# correlate_memory_and_disk — the new MCP tool
# ---------------------------------------------------------------------------


def test_correlate_confirms_rootkit_when_disk_and_memory_agree(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    fs_root = evidence / "case01" / "fs"
    fs_root.mkdir(parents=True)
    # Disk: /etc/modules lists diamorphine
    (fs_root / "etc").mkdir()
    (fs_root / "etc/modules").write_text("# /etc/modules\ndiamorphine\n")
    dump = evidence / "case01.lime"
    dump.write_bytes(b"\x00" * 1024)
    from findevil import server
    monkeypatch.setattr(server, "EVIDENCE_DIR", evidence)

    # Memory: lsmod missing diamorphine, check_modules has it (hidden)
    plugin_data = {
        "linux.lsmod": [{"Name": "ip_tables"}],
        "linux.check_modules": [{"Name": "ip_tables"}, {"Name": "diamorphine"}],
    }
    with patch("findevil.tools.linux_memory.subprocess.run", side_effect=_mock_vol_response(plugin_data)):
        from findevil.tools.linux_memory import correlate_memory_and_disk
        out = correlate_memory_and_disk(str(dump), str(fs_root))

    assert "CONFIRMED KERNEL ROOTKIT" in out
    assert "diamorphine" in out


def test_correlate_flags_memory_only_rootkit(tmp_path, monkeypatch):
    """Hidden in memory, no disk reference — memory-resident rootkit."""
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    fs_root = evidence / "case01" / "fs"
    (fs_root / "etc").mkdir(parents=True)
    (fs_root / "etc/modules").write_text("# stock\n")
    dump = evidence / "case01.lime"
    dump.write_bytes(b"\x00" * 1024)
    from findevil import server
    monkeypatch.setattr(server, "EVIDENCE_DIR", evidence)
    plugin_data = {
        "linux.lsmod": [{"Name": "ip_tables"}],
        "linux.check_modules": [{"Name": "ip_tables"}, {"Name": "stealthkit"}],
    }
    with patch("findevil.tools.linux_memory.subprocess.run", side_effect=_mock_vol_response(plugin_data)):
        from findevil.tools.linux_memory import correlate_memory_and_disk
        out = correlate_memory_and_disk(str(dump), str(fs_root))
    assert "MEMORY-RESIDENT ROOTKIT" in out
    assert "stealthkit" in out


def test_correlate_clean_case_returns_no_findings(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    fs_root = evidence / "case01" / "fs"
    (fs_root / "etc").mkdir(parents=True)
    (fs_root / "etc/modules").write_text("# stock\n")
    dump = evidence / "case01.lime"
    dump.write_bytes(b"\x00" * 1024)
    from findevil import server
    monkeypatch.setattr(server, "EVIDENCE_DIR", evidence)
    plugin_data = {
        "linux.lsmod": [{"Name": "ip_tables"}, {"Name": "nf_nat"}],
        "linux.check_modules": [{"Name": "ip_tables"}, {"Name": "nf_nat"}],
    }
    with patch("findevil.tools.linux_memory.subprocess.run", side_effect=_mock_vol_response(plugin_data)):
        from findevil.tools.linux_memory import correlate_memory_and_disk
        out = correlate_memory_and_disk(str(dump), str(fs_root))
    assert "Memory and disk agree" in out or "No correlation-based compromise" in out


def test_correlate_invalid_fs_root_returns_error(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    dump = evidence / "case.lime"
    dump.write_bytes(b"\x00")
    outside = tmp_path / "outside_fs"
    outside.mkdir()
    from findevil import server
    monkeypatch.setattr(server, "EVIDENCE_DIR", evidence)
    from findevil.tools.linux_memory import correlate_memory_and_disk
    out = correlate_memory_and_disk(str(dump), str(outside))
    assert "Error" in out
    assert "outside the evidence directory" in out
