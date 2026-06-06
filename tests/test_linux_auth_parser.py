"""Tests for the auth.log parser. These can run on any machine — no SIFT needed."""

from findevil.tools.linux_auth import parse_auth_line, parse_auth_log


def test_parse_failed_password():
    line = (
        "Apr 12 14:30:34 webserver sshd[22011]: Failed password for root from "
        "45.123.45.67 port 51132 ssh2"
    )
    ev = parse_auth_line(line, 1)
    assert ev is not None
    assert ev.kind == "login_failed"
    assert ev.service == "sshd"
    assert ev.pid == 22011
    assert ev.fields["user"] == "root"
    assert ev.fields["ip"] == "45.123.45.67"
    assert ev.fields["method"] == "password"


def test_parse_invalid_user():
    line = "Apr 12 14:30:04 webserver sshd[22001]: Invalid user admin from 45.123.45.67 port 51112"
    ev = parse_auth_line(line, 1)
    assert ev is not None
    assert ev.kind == "invalid_user"
    assert ev.fields["user"] == "admin"
    assert ev.fields["ip"] == "45.123.45.67"


def test_parse_accepted_publickey():
    line = (
        "Apr 12 08:15:42 webserver sshd[21100]: Accepted publickey for deploy "
        "from 10.0.1.50 port 45678 ssh2: RSA SHA256:abcd"
    )
    ev = parse_auth_line(line, 1)
    assert ev is not None
    assert ev.kind == "login_accepted"
    assert ev.fields["user"] == "deploy"
    assert ev.fields["ip"] == "10.0.1.50"
    assert ev.fields["method"] == "publickey"


def test_parse_sudo_command():
    line = (
        "Apr 12 14:45:33 webserver sudo:    root : TTY=pts/2 ; PWD=/root ; "
        "USER=root ; COMMAND=/bin/cat /etc/shadow"
    )
    ev = parse_auth_line(line, 1)
    assert ev is not None
    assert ev.kind == "sudo"
    assert ev.fields["user"] == "root"
    assert ev.fields["target"] == "root"
    assert ev.fields["command"] == "/bin/cat /etc/shadow"


def test_parse_useradd():
    line = (
        "Apr 12 14:46:02 webserver useradd[22215]: new user: name=sysd, UID=1050, "
        "GID=1050, home=/home/sysd, shell=/bin/bash"
    )
    ev = parse_auth_line(line, 1)
    assert ev is not None
    assert ev.kind == "user_added"
    assert ev.fields["name"] == "sysd"
    assert ev.fields["uid"] == "1050"


def test_parse_malformed_line_returns_none():
    assert parse_auth_line("this is not a syslog line", 1) is None
    assert parse_auth_line("", 1) is None


def test_parse_auth_log_preserves_line_numbers():
    content = "\n".join([
        "Apr 12 14:30:34 host sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2",
        "this is garbage",
        "Apr 12 14:30:37 host sshd[2]: Failed password for root from 1.2.3.4 port 23 ssh2",
    ])
    events = parse_auth_log(content)
    assert len(events) == 2
    assert events[0].line_number == 1
    assert events[1].line_number == 3


def test_full_attack_scenario_counts():
    """Smoke test against the bundled attack-scenario-01 sample."""
    from pathlib import Path

    sample = (
        Path(__file__).parent.parent / "samples" / "attack-scenario-01" / "auth.log"
    )
    if not sample.exists():
        return  # sample file optional in some test envs
    content = sample.read_text()
    events = parse_auth_log(content)

    kinds = {}
    for e in events:
        kinds[e.kind] = kinds.get(e.kind, 0) + 1

    # The scenario must contain all the signals our tools look for
    assert kinds.get("login_failed", 0) >= 50  # brute force component
    assert kinds.get("invalid_user", 0) >= 10  # username enumeration
    assert kinds.get("login_accepted", 0) >= 5  # legit + compromised
    assert kinds.get("sudo", 0) >= 15  # pre- and post-compromise sudo
    assert kinds.get("user_added", 0) == 1  # the backdoor 'sysd' account
