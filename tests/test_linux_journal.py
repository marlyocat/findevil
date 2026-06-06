"""Tests for the systemd journal analyzer."""

from pathlib import Path

import pytest

from findevil.tools.linux_journal import (
    _auth_event_kind,
    parse_journal,
)

SCENARIO_01_JOURNAL = (
    Path(__file__).parent.parent / "samples" / "attack-scenario-01" / "journal.jsonl"
)


def test_parse_journal_handles_jsonl():
    content = (
        '{"__REALTIME_TIMESTAMP":"1744465234000000","SYSLOG_IDENTIFIER":"sshd",'
        '"_SYSTEMD_UNIT":"ssh.service","MESSAGE":"Failed password for root from 1.2.3.4 port 22 ssh2",'
        '"PRIORITY":"6"}\n'
        '{"__REALTIME_TIMESTAMP":"1744465237000000","SYSLOG_IDENTIFIER":"sshd",'
        '"_SYSTEMD_UNIT":"ssh.service","MESSAGE":"Accepted publickey for deploy from 10.0.1.5 port 22 ssh2",'
        '"PRIORITY":"6"}\n'
    )
    entries = parse_journal(content)
    assert len(entries) == 2
    assert entries[0].identifier == "sshd"
    assert "Failed password" in entries[0].message
    # Timestamp must convert to ISO 8601
    assert entries[0].timestamp.startswith("2025-") or entries[0].timestamp.startswith("2026-")


def test_parse_journal_ignores_malformed_lines():
    content = (
        '{"__REALTIME_TIMESTAMP":"1744465234000000","MESSAGE":"ok"}\n'
        'this is not json at all\n'
        '{"__REALTIME_TIMESTAMP":"1744465237000000","MESSAGE":"ok2"}\n'
    )
    entries = parse_journal(content)
    assert len(entries) == 2


def test_classify_sshd_failed():
    from findevil.tools.linux_journal import JournalEntry

    entry = JournalEntry(
        line_number=1,
        timestamp="",
        unit="ssh.service",
        identifier="sshd",
        priority=6,
        message="Failed password for root from 45.123.45.67 port 51132 ssh2",
        uid=None,
        pid=None,
        raw={},
    )
    kind = _auth_event_kind(entry)
    assert kind is not None
    assert kind[0] == "login_failed"
    assert kind[1]["ip"] == "45.123.45.67"
    assert kind[1]["user"] == "root"


def test_classify_sudo():
    from findevil.tools.linux_journal import JournalEntry

    entry = JournalEntry(
        line_number=1,
        timestamp="",
        unit="sudo.service",
        identifier="sudo",
        priority=5,
        message="   root : TTY=pts/2 ; PWD=/root ; USER=root ; COMMAND=/bin/cat /etc/shadow",
        uid=None,
        pid=None,
        raw={},
    )
    kind = _auth_event_kind(entry)
    assert kind is not None
    assert kind[0] == "sudo"
    assert kind[1]["command"] == "/bin/cat /etc/shadow"


def test_classify_does_not_match_fake_sshd_unit():
    """Regression: a unit name that *contains* "sshd" but isn't an SSH unit
    must not be classified as sshd-auth. Substring match would do that."""
    from findevil.tools.linux_journal import JournalEntry

    entry = JournalEntry(
        line_number=1,
        timestamp="",
        unit="not-real-sshd.service",  # contains "sshd" but isn't ssh
        identifier="not-real-sshd",
        priority=6,
        message="Failed password for root from 1.2.3.4 port 22 ssh2",
        uid=None,
        pid=None,
        raw={},
    )
    kind = _auth_event_kind(entry)
    # Substring-match would classify this as login_failed; path-component
    # match must not.
    assert kind is None, f"expected None for fake-sshd unit; got {kind}"


def test_classify_matches_canonical_sshd_unit_names():
    """Regression: ssh.service, sshd.service, sshd@1234.service must still
    be recognised as ssh-auth units."""
    from findevil.tools.linux_journal import JournalEntry

    for unit in ("ssh.service", "sshd.service", "sshd@1234.service"):
        entry = JournalEntry(
            line_number=1, timestamp="", unit=unit, identifier="sshd",
            priority=6,
            message="Failed password for root from 45.123.45.67 port 51132 ssh2",
            uid=None, pid=None, raw={},
        )
        kind = _auth_event_kind(entry)
        assert kind is not None and kind[0] == "login_failed", (
            f"unit {unit!r} should classify as login_failed; got {kind}"
        )


@pytest.mark.skipif(not SCENARIO_01_JOURNAL.exists(), reason="scenario 01 journal not present")
def test_scenario01_journal_counts():
    content = SCENARIO_01_JOURNAL.read_text()
    entries = parse_journal(content)
    # The bundled export has 21 entries
    assert len(entries) >= 18
    # At least one sshd accepted event
    accepted = [e for e in entries if "Accepted" in e.message]
    assert len(accepted) >= 2  # legitimate deploy + attacker root
    # At least one kernel-module message
    kernel = [e for e in entries if e.identifier == "kernel"]
    assert len(kernel) >= 1
