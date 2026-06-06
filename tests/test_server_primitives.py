"""Tests for the six generic primitives in `src/findevil/server.py`.

These are the first tools a user touches — `file_info`, `hash_file`,
`strings_extract`, `hexdump`, `list_evidence`, `log_search` — and they
were not covered by any other test module.

Path-validation and argument-validation paths run on any platform.
Happy-path tests that depend on Linux subprocesses (``file``, ``stat``,
``md5sum``, ``sha256sum``, ``strings``, ``ls``, ``grep``, ``xxd``) are
skipped on Windows.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

LINUX_ONLY = pytest.mark.skipif(
    sys.platform == "win32",
    reason="primitive depends on a POSIX subprocess (file/stat/md5sum/strings/ls/grep/xxd)",
)


@pytest.fixture
def isolated_server(tmp_path, monkeypatch):
    """Reload the server module against a tmp evidence dir.

    Each test gets its own evidence root so paths can't leak.
    """
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    logs = tmp_path / "logs"
    logs.mkdir()
    monkeypatch.setenv("FINDEVIL_EVIDENCE_DIR", str(evidence))
    monkeypatch.setenv("FINDEVIL_LOGS_DIR", str(logs))
    import findevil.server as server
    importlib.reload(server)
    return server, evidence


# ---------------------------------------------------------------------------
# file_info
# ---------------------------------------------------------------------------


def test_file_info_rejects_path_outside_evidence(isolated_server, tmp_path):
    server, _evidence = isolated_server
    outside = tmp_path / "outside.txt"
    outside.write_text("anything")
    out = server.file_info(str(outside))
    assert "Access denied" in out or "outside" in out.lower()


def test_file_info_returns_not_found_for_missing(isolated_server):
    server, evidence = isolated_server
    out = server.file_info(str(evidence / "does-not-exist.bin"))
    assert "not found" in out.lower()


@LINUX_ONLY
def test_file_info_happy_path_returns_metadata(isolated_server):
    server, evidence = isolated_server
    sample = evidence / "hello.txt"
    sample.write_text("hello world\n")
    out = server.file_info(str(sample))
    assert "## File Type" in out
    assert "## Stat" in out
    # `file` should classify a UTF-8 text file as such
    assert "ASCII" in out or "text" in out.lower()


# ---------------------------------------------------------------------------
# hash_file
# ---------------------------------------------------------------------------


def test_hash_file_rejects_path_outside_evidence(isolated_server, tmp_path):
    server, _ = isolated_server
    outside = tmp_path / "outside.bin"
    outside.write_text("nope")
    out = server.hash_file(str(outside))
    assert "Access denied" in out or "outside" in out.lower()


@LINUX_ONLY
def test_hash_file_returns_md5_and_sha256(isolated_server):
    server, evidence = isolated_server
    sample = evidence / "h.txt"
    sample.write_text("findevil")
    out = server.hash_file(str(sample))
    assert "## MD5" in out
    assert "## SHA256" in out


# ---------------------------------------------------------------------------
# strings_extract
# ---------------------------------------------------------------------------


def test_strings_extract_rejects_invalid_encoding(isolated_server):
    server, evidence = isolated_server
    sample = evidence / "x.bin"
    sample.write_bytes(b"\x00" * 32)
    out = server.strings_extract(str(sample), min_length=6, encoding="ZZ")
    assert "Invalid encoding" in out


def test_strings_extract_path_outside_evidence(isolated_server, tmp_path):
    server, _ = isolated_server
    outside = tmp_path / "elf.bin"
    outside.write_bytes(b"\x7fELFanother-string")
    out = server.strings_extract(str(outside))
    assert "Access denied" in out or "outside" in out.lower()


@LINUX_ONLY
def test_strings_extract_finds_known_string(isolated_server):
    server, evidence = isolated_server
    sample = evidence / "embedded.bin"
    sample.write_bytes(b"\x00\x00\x00findevil-marker-string\x00\x00\x00")
    out = server.strings_extract(str(sample), min_length=10)
    assert "findevil-marker-string" in out


# ---------------------------------------------------------------------------
# hexdump — length cap is platform-independent
# ---------------------------------------------------------------------------


def test_hexdump_path_outside_evidence(isolated_server, tmp_path):
    server, _ = isolated_server
    outside = tmp_path / "x.bin"
    outside.write_bytes(b"\x00")
    out = server.hexdump(str(outside))
    assert "Access denied" in out or "outside" in out.lower()


@LINUX_ONLY
def test_hexdump_returns_xxd_format(isolated_server):
    server, evidence = isolated_server
    sample = evidence / "x.bin"
    sample.write_bytes(bytes(range(64)))
    out = server.hexdump(str(sample), offset=0, length=32)
    # xxd output begins with `00000000:` style offset
    assert "00000000:" in out


@LINUX_ONLY
def test_hexdump_caps_length_at_4096(isolated_server, monkeypatch):
    """The tool documents `length` is capped to 4096; this test confirms the
    cap is applied (caller cannot read more than 4 KiB in one call).
    """
    server, evidence = isolated_server
    sample = evidence / "big.bin"
    sample.write_bytes(b"A" * 8192)
    captured: dict = {}
    real_run_tool = server._run_tool

    def spy(cmd, timeout=120):
        captured["cmd"] = cmd
        return real_run_tool(cmd, timeout)

    monkeypatch.setattr(server, "_run_tool", spy)
    server.hexdump(str(sample), offset=0, length=99999)
    # The xxd command must carry `-l 4096` not the user-supplied 99999
    assert "-l" in captured["cmd"]
    cap_arg = captured["cmd"][captured["cmd"].index("-l") + 1]
    assert cap_arg == "4096", f"length cap not applied; saw -l {cap_arg}"


# ---------------------------------------------------------------------------
# list_evidence
# ---------------------------------------------------------------------------


def test_list_evidence_rejects_subdir_outside_evidence(isolated_server, tmp_path):
    server, _ = isolated_server
    # A sub-path that escapes via ..
    out = server.list_evidence("../../etc")
    assert "Access denied" in out or "outside" in out.lower()


@LINUX_ONLY
def test_list_evidence_lists_subdirectories(isolated_server):
    server, evidence = isolated_server
    (evidence / "case01").mkdir()
    (evidence / "case01" / "auth.log").write_text("entry\n")
    (evidence / "case02").mkdir()
    out = server.list_evidence("")
    # ls -lahR includes both subdir names
    assert "case01" in out
    assert "case02" in out


# ---------------------------------------------------------------------------
# log_search
# ---------------------------------------------------------------------------


def test_log_search_rejects_path_outside_evidence(isolated_server, tmp_path):
    server, _ = isolated_server
    outside = tmp_path / "auth.log"
    outside.write_text("Failed password for root")
    out = server.log_search(str(outside), "Failed password")
    assert "Access denied" in out or "outside" in out.lower()


@LINUX_ONLY
def test_log_search_finds_matching_pattern(isolated_server):
    server, evidence = isolated_server
    log = evidence / "auth.log"
    log.write_text(
        "Apr 12 14:30:01 web sshd[100]: Accepted publickey for deploy\n"
        "Apr 12 14:30:05 web sshd[101]: Failed password for root\n"
        "Apr 12 14:30:09 web sshd[102]: Failed password for root\n"
    )
    out = server.log_search(str(log), "Failed password", context_lines=0)
    assert "Failed password for root" in out


@LINUX_ONLY
def test_log_search_no_match_returns_explicit_message(isolated_server):
    server, evidence = isolated_server
    log = evidence / "boring.log"
    log.write_text("nothing of note here\n")
    out = server.log_search(str(log), "definitely-not-present")
    assert "No matches" in out
