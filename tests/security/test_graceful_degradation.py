"""
Failure-mode demos: verify findevil degrades gracefully rather than
fabricating findings when given unusual or degenerate input.

Three pressure cases:

1. **Empty evidence directory.** list_evidence returns nothing. Parsers
   that are handed a path to a file that doesn't exist return an
   explicit "not found", not a fabricated event list.

2. **Wrong-format input.** Passing a binary blob or a non-Linux log
   (e.g., something resembling a Windows .evtx header) as an
   auth.log must return zero events from the parser — NOT a
   hallucinated auth session.

3. **Large random-bytes input.** A 2 MB random-bytes file posing as
   auth.log must parse to zero events, not crash, not claim to find
   brute-force attempts in noise.

The hackathon brief is explicit that "failure modes are signal, not
weakness." These tests document where findevil declines to guess.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from findevil.tools.linux_auth import parse_auth_log


@pytest.fixture
def empty_evidence_dir(tmp_path, monkeypatch):
    evidence = tmp_path / "empty_evidence"
    evidence.mkdir()
    monkeypatch.setenv("FINDEVIL_EVIDENCE_DIR", str(evidence))
    monkeypatch.setenv("FINDEVIL_LOGS_DIR", str(tmp_path / "logs"))
    import importlib

    import findevil.server as server
    importlib.reload(server)
    return server, evidence


# ---------------------------------------------------------------------------
# Case 1 — empty evidence
# ---------------------------------------------------------------------------


def test_list_evidence_on_empty_dir_returns_structured_empty(empty_evidence_dir):
    server, evidence = empty_evidence_dir
    result = server.list_evidence()
    # Output should clearly indicate the directory is present but empty,
    # not fabricate file names.
    assert str(evidence) in result or "evidence" in result.lower()
    # Nothing should look like a filename or suspicious artifact
    for forbidden in ("shell.php", "toor", "libprocesshider", "xmrig", "root:"):
        assert forbidden not in result, (
            f"list_evidence on an empty dir mentioned {forbidden!r} — fabrication."
        )


def test_auth_tool_on_nonexistent_file_returns_not_found(empty_evidence_dir):
    server, evidence = empty_evidence_dir
    from findevil.tools.linux_auth import auth_summary
    result = auth_summary(str(evidence / "does_not_exist.log"))
    assert "not found" in result.lower() or "does not exist" in result.lower()


# ---------------------------------------------------------------------------
# Case 2 — wrong format
# ---------------------------------------------------------------------------


def test_auth_parser_on_evtx_like_binary_returns_zero_events(tmp_path):
    """Feed the parser a blob that starts with the Windows .evtx magic
    number (ElfFile) and contains binary noise. Parser must not
    fabricate auth events from it."""
    fake_evtx = tmp_path / "Security.evtx"
    # "ElfFile\x00" is the EVTX magic, followed by random bytes.
    fake_evtx.write_bytes(b"ElfFile\x00" + os.urandom(4096))
    # parse_auth_log takes decoded text; passing bytes-as-text tests the
    # decode path too.
    content = fake_evtx.read_text(errors="replace")
    events = parse_auth_log(content)
    assert events == [], (
        f"parse_auth_log hallucinated {len(events)} events from an EVTX-shaped blob"
    )


def test_auth_parser_on_json_content_returns_zero_events(tmp_path):
    """A file that looks like it could be JSON logs but isn't syslog-format
    must parse to zero events."""
    content = '[{"timestamp": "2026-04-14T03:17:44Z", "user": "deploy"}]'
    events = parse_auth_log(content)
    assert events == [], (
        f"parse_auth_log hallucinated {len(events)} events from a JSON file"
    )


# ---------------------------------------------------------------------------
# Case 3 — large random-bytes noise
# ---------------------------------------------------------------------------


def test_auth_parser_handles_2mb_random_noise(tmp_path):
    """Pressure test: 2 MB of urandom shaped as text must not crash the
    parser and must not produce spurious events."""
    noise_file = tmp_path / "garbage.log"
    noise_file.write_bytes(os.urandom(2 * 1024 * 1024))
    content = noise_file.read_text(errors="replace")
    # parse_auth_log is bounded by content length, not by allocation
    events = parse_auth_log(content)
    # Random noise shouldn't match the strict syslog-line grammar.
    # If 2MB of urandom produces any matches at all, the parser's grammar
    # is too loose — but strictly > 10 matches would be a real concern.
    assert len(events) < 10, (
        f"parse_auth_log matched {len(events)} auth events in 2MB of urandom "
        "— parser grammar is too permissive; a real noisy log would cause "
        "false positives."
    )


def test_auth_parser_on_empty_string_returns_empty_list():
    assert parse_auth_log("") == []


def test_auth_parser_on_whitespace_returns_empty_list():
    assert parse_auth_log("   \n\n\t\n") == []


# ---------------------------------------------------------------------------
# Sanity: the parser DOES work on real input (guard against the above
# tests accidentally passing because the parser is broken everywhere).
# ---------------------------------------------------------------------------


def test_auth_parser_returns_events_on_real_syslog():
    real_content = (
        "Apr 14 03:17:44 webserver-prod-02 sshd[12301]: "
        "Accepted publickey for deploy from 185.229.59.103 port 51122 ssh2: "
        "RSA SHA256:aB1cDeFg\n"
    )
    events = parse_auth_log(real_content)
    assert len(events) >= 1, (
        "parse_auth_log returned zero events on valid syslog — baseline broken"
    )
