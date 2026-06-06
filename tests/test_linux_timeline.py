"""Tests for timeline and filesystem metadata tools."""

import os
import time
from pathlib import Path

import pytest

from findevil.tools.linux_timeline import (
    TimelineEvent,
    _events_from_access_log,
    _events_from_auth_log,
    _events_from_apt,
    _events_from_bash_history,
    _normalize_nginx_ts,
    _normalize_syslog_ts,
)

SC01 = Path(__file__).parent.parent / "samples" / "attack-scenario-01"
SC04_FS = Path(__file__).parent.parent / "samples" / "attack-scenario-04" / "fs"


# ---------------------------------------------------------------------------
# Timestamp normalisation
# ---------------------------------------------------------------------------


def test_normalize_syslog_ts_basic():
    out = _normalize_syslog_ts("Apr 12 14:30:04", 2026)
    assert out == "2026-04-12T14:30:04+00:00"


def test_normalize_syslog_ts_handles_single_digit_day():
    out = _normalize_syslog_ts("Jan  3 01:02:03", 2026)
    assert out == "2026-01-03T01:02:03+00:00"


def test_normalize_syslog_ts_bad_input_returns_raw():
    out = _normalize_syslog_ts("not a timestamp", 2026)
    assert out == "not a timestamp"


def test_normalize_nginx_ts():
    out = _normalize_nginx_ts("14/Apr/2026:15:03:11")
    assert out == "2026-04-14T15:03:11+00:00"


# ---------------------------------------------------------------------------
# Event extractors — check they produce TimelineEvent with expected fields
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SC01.exists(), reason="scenario 01 missing")
def test_events_from_auth_log_covers_compromise():
    log = SC01 / "auth.log"
    events = _events_from_auth_log(log, 2026)
    assert events
    # There must be a login_accepted for root from the attacker IP
    accepted = [e for e in events if e.action == "login_accepted" and "45.123.45.67" in e.actor]
    assert accepted, "expected successful root login from attacker IP"
    # At least one sudo showing /etc/shadow read
    shadow_sudos = [e for e in events if e.action == "sudo" and "shadow" in e.detail]
    assert shadow_sudos
    # At least one user_added for sysd
    user_adds = [e for e in events if e.action == "user_added" and "sysd" in e.detail]
    assert user_adds


@pytest.mark.skipif(not SC04_FS.exists(), reason="scenario 04 missing")
def test_events_from_apt_includes_xmrig_and_auditd():
    apt = SC04_FS / "var/log/apt/history.log"
    events = _events_from_apt(apt)
    actions = [(e.action, e.detail) for e in events]
    assert any("package_install" == a and "xmrig" in d for a, d in actions)
    assert any("package_remove" == a and "auditd" in d for a, d in actions)


def test_events_from_access_log_drops_unparseable_timestamps(tmp_path: Path):
    """Regression: access-log entries whose timestamp can't be normalised must
    not be emitted with empty `ts`. Previously they sorted to the top of
    timelines, scrambling chronological ordering for valid events.
    """
    log = tmp_path / "access.log"
    # Two entries: one with a valid nginx timestamp, one with garbage
    log.write_text(
        '1.2.3.4 - - [14/Apr/2026:15:03:11 +0000] "GET /a HTTP/1.1" 200 0 "-" "-"\n'
        '5.6.7.8 - - [definitely-not-a-timestamp] "GET /b HTTP/1.1" 200 0 "-" "-"\n'
    )
    events = _events_from_access_log(log)
    timestamps = [e.timestamp for e in events]
    # No empty-string timestamps may leak through.
    assert "" not in timestamps, (
        "events with unparseable timestamps must be dropped, not emitted with ts=''"
    )
    # The single valid entry must still come through.
    assert any(t.startswith("2026-04-14") for t in timestamps)


def test_events_from_bash_history_skips_untimestamped(tmp_path: Path):
    # Plain history without HISTTIMEFORMAT — should produce NO timeline events
    hist = tmp_path / "home" / "u1" / ".bash_history"
    hist.parent.mkdir(parents=True)
    hist.write_text("ls\ncd /tmp\npwd\n")
    events = _events_from_bash_history(hist)
    assert events == []


def test_events_from_bash_history_timestamped(tmp_path: Path):
    hist = tmp_path / "home" / "u1" / ".bash_history"
    hist.parent.mkdir(parents=True)
    hist.write_text(
        "#1744465234\n"
        "ls -la\n"
        "#1744465240\n"
        "cat /etc/passwd\n"
    )
    events = _events_from_bash_history(hist)
    assert len(events) == 2
    assert events[0].action == "shell_command"
    assert events[0].actor == "u1"
    assert "2025-" in events[0].timestamp or "2026-" in events[0].timestamp


# ---------------------------------------------------------------------------
# stat_file behaviour — indirect via find_timestamp_anomalies unit
# ---------------------------------------------------------------------------


def test_find_timestamp_anomalies_detects_timestomping(tmp_path: Path, monkeypatch):
    """Create a file, then manually backdate its mtime — mtime > ctime can
    only be simulated the other way on a temp fs: create, then bump mtime
    far past ctime."""
    from findevil.tools.linux_timeline import find_timestamp_anomalies
    # Point EVIDENCE_DIR at tmp for the duration of this test
    import findevil.server as srv
    monkeypatch.setattr(srv, "EVIDENCE_DIR", tmp_path.resolve())

    clean = tmp_path / "clean.txt"
    clean.write_text("hello")

    tampered = tmp_path / "tampered.txt"
    tampered.write_text("hello")
    # Set mtime to one hour in the future
    future_ts = time.time() + 3600
    os.utime(tampered, (future_ts, future_ts))

    out = find_timestamp_anomalies(str(tmp_path))
    # Must surface tampered.txt in the future-mtime section at minimum
    assert "tampered.txt" in out


def test_stat_file_returns_metadata(tmp_path: Path, monkeypatch):
    from findevil.tools.linux_timeline import stat_file
    import findevil.server as srv
    monkeypatch.setattr(srv, "EVIDENCE_DIR", tmp_path.resolve())

    f = tmp_path / "x.txt"
    f.write_text("abc")
    out = stat_file(str(f))
    assert "File metadata" in out
    assert "Size:** 3 bytes" in out
    assert "mtime:" in out


# ---------------------------------------------------------------------------
# build_timeline end-to-end
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SC01.exists(), reason="scenario 01 missing")
def test_build_timeline_scenario01_sources(monkeypatch):
    """On scenario 01 the timeline should include auth.log + journal events
    and span the attack window (08:15 baseline → 15:00 session close)."""
    from findevil.tools.linux_timeline import build_timeline
    import findevil.server as srv

    evidence_dir = SC01.parent.parent / "samples"
    monkeypatch.setattr(srv, "EVIDENCE_DIR", evidence_dir.resolve())

    out = build_timeline(str(SC01))
    assert "auth.log" in out
    # journal export exists for scenario 01 too
    assert "journal" in out
    # The attacker IP must show up at least once
    assert "45.123.45.67" in out


@pytest.mark.skipif(not SC04_FS.exists(), reason="scenario 04 missing")
def test_build_timeline_scenario04_fuses_apt_dpkg_pip(monkeypatch):
    """Scenario 04 has no auth.log — but apt, dpkg, and pip timelines
    should all fuse together."""
    from findevil.tools.linux_timeline import build_timeline
    import findevil.server as srv

    evidence_dir = SC04_FS.parent.parent.parent / "samples"
    monkeypatch.setattr(srv, "EVIDENCE_DIR", evidence_dir.resolve())

    out = build_timeline(str(SC04_FS.parent))
    assert "apt" in out
    assert "dpkg" in out
    assert "pip" in out
    # Must include the suspicious artifacts
    assert "xmrig" in out
    assert "requests-utils" in out
