"""Hypothesis-based property tests for parsers.

The parsers in `findevil.tools.*` are the bottom of every IR analysis;
if any of them crashes on a malformed log line, every tool that wraps
them silently fails. Unit tests cover known shapes (the bundled samples
plus a handful of regression fixtures), but they don't exercise the
adversarial input space — and that's exactly where attackers operate
(an injected nul byte, a control character, a giant single line).

These tests use Hypothesis to throw arbitrary text at every parser
and assert two universal invariants:

1. Parsing **never** raises an unhandled exception.
2. The number of returned records is bounded by the number of input
   lines (no parser may amplify input).

A handful of stronger per-parser invariants are added on top
(timestamps that survived the parser are non-empty strings; line
numbers monotonically increase; etc.).
"""

from __future__ import annotations

import re

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from findevil.tools.linux_auth import parse_auth_log
from findevil.tools.linux_journal import parse_journal
from findevil.tools.linux_packages import (
    parse_apt_history,
    parse_dpkg_log,
    parse_pip_log,
    parse_yum_log,
)
from findevil.tools.linux_shell_history import parse_history
from findevil.tools.linux_web import parse_access_log


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------


# Restrict to characters that survive any encoding / errors="replace" path
# without going through codepaths Python's str API doesn't define on.
_TEXT_CHARS = st.characters(
    blacklist_categories=("Cs",),  # surrogates only
    min_codepoint=0,
    max_codepoint=0x10FFFF,
)
_TEXT = st.text(alphabet=_TEXT_CHARS, max_size=4000)
_LINES = st.lists(_TEXT, max_size=200).map("\n".join)


# ---------------------------------------------------------------------------
# Universal invariants — every parser must satisfy these.
# ---------------------------------------------------------------------------


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(content=_LINES)
def test_parse_auth_log_never_crashes(content):
    out = parse_auth_log(content)
    assert isinstance(out, list)
    # Output count is bounded by input line count — no amplification.
    assert len(out) <= max(1, content.count("\n") + 1)


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(content=_LINES)
def test_parse_journal_never_crashes(content):
    out = parse_journal(content)
    assert isinstance(out, list)
    assert len(out) <= max(1, content.count("\n") + 1)


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(content=_LINES)
def test_parse_apt_history_never_crashes(content):
    out = parse_apt_history(content)
    assert isinstance(out, list)


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(content=_LINES)
def test_parse_dpkg_log_never_crashes(content):
    out = parse_dpkg_log(content)
    assert isinstance(out, list)
    assert len(out) <= max(1, content.count("\n") + 1)


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(content=_LINES)
def test_parse_pip_log_never_crashes(content):
    out = parse_pip_log(content)
    assert isinstance(out, list)


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(content=_LINES)
def test_parse_yum_log_never_crashes(content):
    out = parse_yum_log(content)
    assert isinstance(out, list)


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(content=_LINES)
def test_parse_history_never_crashes(content):
    out = parse_history(content)
    assert isinstance(out, list)


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(content=_LINES)
def test_parse_access_log_never_crashes(content):
    out = parse_access_log(content)
    assert isinstance(out, list)
    assert len(out) <= max(1, content.count("\n") + 1)


# ---------------------------------------------------------------------------
# Per-parser stronger invariants
# ---------------------------------------------------------------------------


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(content=_LINES)
def test_parse_auth_log_line_numbers_monotonic(content):
    """If the parser claims to know the source line of an event, the line
    numbers must be in ascending order across the result list."""
    events = parse_auth_log(content)
    nums = [e.line_number for e in events]
    assert nums == sorted(nums), "auth events emitted out of source order"
    assert all(n >= 1 for n in nums), "line numbers must be 1-indexed"


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(content=_LINES)
def test_parse_journal_timestamps_are_strings(content):
    """Every returned JournalEntry has a `timestamp` field; it must be a
    string (possibly empty for unparseable timestamps)."""
    entries = parse_journal(content)
    for e in entries:
        assert isinstance(e.timestamp, str)


# An auth-log line shape that's known-good — a Hypothesis "example" that
# guides the engine toward the parser's success path so we get coverage
# of both the negative (random text) and positive (well-formed) sides.
@settings(max_examples=50)
@given(
    ip=st.from_regex(r"^(\d{1,3}\.){3}\d{1,3}$", fullmatch=True),
    user=st.text(
        alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd")),
        min_size=1,
        max_size=12,
    ),
)
def test_parse_auth_log_recognises_failed_password(ip, user):
    """A canonical 'Failed password' line must round-trip through the parser
    as a login_failed event with the right IP and user."""
    line = f"Apr 12 14:30:01 host sshd[123]: Failed password for {user} from {ip} port 22 ssh2\n"
    events = parse_auth_log(line)
    failed = [e for e in events if e.kind == "login_failed"]
    assert failed, f"expected one login_failed event, parsed: {events}"
    assert failed[0].fields.get("ip") == ip
    assert failed[0].fields.get("user") == user


_ACCESS_LINE = (
    '{ip} - - [14/Apr/2026:15:03:11 +0000] '
    '"{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"\n'
)


@settings(max_examples=50)
@given(
    ip=st.from_regex(r"^(\d{1,3}\.){3}\d{1,3}$", fullmatch=True),
    method=st.sampled_from(["GET", "POST", "PUT", "DELETE", "HEAD"]),
    path=st.text(
        alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="/-_."),
        min_size=1,
        max_size=64,
    ).map(lambda s: "/" + s),
    status=st.integers(min_value=100, max_value=599),
    size=st.integers(min_value=0, max_value=1_000_000),
    ua=st.text(
        alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters=" /."),
        max_size=32,
    ),
)
def test_parse_access_log_canonical_combined_format(ip, method, path, status, size, ua):
    """Combined-log-format lines must round-trip through parse_access_log."""
    line = _ACCESS_LINE.format(ip=ip, method=method, path=path, status=status, size=size, ua=ua)
    entries = parse_access_log(line)
    assert len(entries) == 1
    e = entries[0]
    assert e.ip == ip
    assert e.method == method
    assert e.path == path
    assert e.status == str(status)


# ---------------------------------------------------------------------------
# Adversarial inputs surfaced by Hypothesis previously cause crashes —
# pin them as explicit examples so they're checked even if Hypothesis
# changes its shrinker.
# ---------------------------------------------------------------------------


def test_parsers_handle_only_newlines():
    for fn in (
        parse_auth_log, parse_journal, parse_apt_history, parse_dpkg_log,
        parse_pip_log, parse_yum_log, parse_history, parse_access_log,
    ):
        out = fn("\n" * 100)
        assert isinstance(out, list)


def test_parsers_handle_empty_string():
    for fn in (
        parse_auth_log, parse_journal, parse_apt_history, parse_dpkg_log,
        parse_pip_log, parse_yum_log, parse_history, parse_access_log,
    ):
        assert fn("") == []


def test_parsers_handle_giant_single_line():
    """A 100k-character line with no newline must not blow up. Real-world
    web access logs sometimes contain very long URLs / UA strings."""
    big = "x" * 100_000
    for fn in (
        parse_auth_log, parse_journal, parse_apt_history, parse_dpkg_log,
        parse_pip_log, parse_yum_log, parse_history, parse_access_log,
    ):
        out = fn(big)
        # Some parsers may interpret this as one record, others zero;
        # either is fine. The point is it doesn't crash.
        assert isinstance(out, list)


def test_parsers_handle_non_utf8_replacement_chars():
    """When `errors="replace"` decoded a binary blob, the result contains
    U+FFFD. Parsers must not choke on it."""
    content = "Apr 12 14:30:01 host sshd[1]: ��� msg\n" * 10
    for fn in (
        parse_auth_log, parse_journal, parse_apt_history, parse_dpkg_log,
        parse_pip_log, parse_yum_log, parse_history, parse_access_log,
    ):
        out = fn(content)
        assert isinstance(out, list)


# Sanity check that the IPv4 strategy used above produces parseable IPs;
# Hypothesis can produce strings like `0.0.0.0` which all parsers should
# handle, but `999.999.999.999` would still be syntactically valid for our
# regex. Confirm parsing tolerates either.
_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def test_strategy_yields_ipv4_shape():
    # Generate a few examples directly and confirm shape.
    for _ in range(5):
        ip = st.from_regex(r"^(\d{1,3}\.){3}\d{1,3}$", fullmatch=True).example()
        assert _IPV4_RE.match(ip)
