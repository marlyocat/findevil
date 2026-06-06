"""
Linux auth.log / secure log analysis tools.

Parses the standard Linux authentication log format (Ubuntu/Debian auth.log,
RHEL/CentOS /var/log/secure) into structured events, and exposes focused
MCP tools for common IR queries:

- Failed SSH login attempts (brute force detection)
- Successful logins (authentication method, source IP, user)
- Sudo command execution (privilege escalation audit)
- User/group management events (persistence via new accounts)

Tools return structured Markdown with confidence scoring and provenance —
each finding includes a pointer to the raw log line that produced it.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from findevil._table import emit_table
from findevil.server import _audit, _validate_evidence_path, mcp

# ---------------------------------------------------------------------------
# Parsing — pure functions, no I/O, fully testable
# ---------------------------------------------------------------------------

# Standard syslog prefix: "Apr 15 14:23:05 hostname service[pid]: message"
_SYSLOG_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>[^\[\]:]+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

# Event-specific patterns inside the message field
_SSHD_FAILED = re.compile(
    r"Failed (?P<method>password|publickey|none) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
_SSHD_ACCEPTED = re.compile(
    r"Accepted (?P<method>password|publickey|none|keyboard-interactive) "
    r"for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_SSHD_INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\S+)(?: port (?P<port>\d+))?"
)
_SUDO_EVENT = re.compile(
    r"^\s*(?P<user>\S+)\s*:.*?USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<command>.+)$"
)
_USERADD = re.compile(
    r"new user:\s*name=(?P<name>\S+?),\s*UID=(?P<uid>\d+)"
)
_USERDEL = re.compile(
    r"delete user '(?P<name>\S+?)'"
)
_GROUPADD = re.compile(
    r"new group:\s*name=(?P<name>\S+?),\s*GID=(?P<gid>\d+)"
)


@dataclass
class AuthEvent:
    """A single parsed auth.log event."""

    timestamp: str
    host: str
    service: str
    pid: int | None
    kind: Literal[
        "login_failed",
        "login_accepted",
        "invalid_user",
        "sudo",
        "user_added",
        "user_deleted",
        "group_added",
        "other",
    ]
    fields: dict[str, str]
    raw: str
    line_number: int


def parse_auth_line(line: str, line_number: int) -> AuthEvent | None:
    """Parse a single auth.log line. Returns None if the line is malformed."""
    line = line.rstrip("\n")
    m = _SYSLOG_RE.match(line)
    if not m:
        return None

    message = m.group("message")
    service = m.group("service")
    pid = int(m.group("pid")) if m.group("pid") else None

    # Determine event kind and extract structured fields
    kind: str = "other"
    fields: dict[str, str] = {}

    if service.startswith("sshd"):
        if sm := _SSHD_FAILED.search(message):
            kind = "login_failed"
            fields = sm.groupdict()
        elif sm := _SSHD_ACCEPTED.search(message):
            kind = "login_accepted"
            fields = sm.groupdict()
        elif sm := _SSHD_INVALID_USER.search(message):
            kind = "invalid_user"
            fields = sm.groupdict()
    elif service == "sudo":
        if sm := _SUDO_EVENT.match(message):
            kind = "sudo"
            fields = sm.groupdict()
    elif service.startswith("useradd"):
        if sm := _USERADD.search(message):
            kind = "user_added"
            fields = sm.groupdict()
    elif service.startswith("userdel"):
        if sm := _USERDEL.search(message):
            kind = "user_deleted"
            fields = sm.groupdict()
    elif service.startswith("groupadd"):
        if sm := _GROUPADD.search(message):
            kind = "group_added"
            fields = sm.groupdict()

    return AuthEvent(
        timestamp=m.group("timestamp"),
        host=m.group("host"),
        service=service,
        pid=pid,
        kind=kind,  # type: ignore[arg-type]
        fields=fields,
        raw=line,
        line_number=line_number,
    )


def parse_auth_log(content: str) -> list[AuthEvent]:
    """Parse an entire auth.log file into structured events."""
    events = []
    for i, line in enumerate(content.splitlines(), start=1):
        if not line.strip():
            continue
        ev = parse_auth_line(line, i)
        if ev is not None:
            events.append(ev)
    return events


def _read_auth_log(path: str) -> tuple[Path, list[AuthEvent]]:
    """Validate path, read file, parse events. Raises if path is unsafe."""
    validated = _validate_evidence_path(path)
    if not validated.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not validated.is_file():
        raise ValueError(f"Not a file: {path}")

    content = validated.read_text(errors="replace")
    return validated, parse_auth_log(content)


# ---------------------------------------------------------------------------
# MCP Tool: auth_failed_logins
# ---------------------------------------------------------------------------

@mcp.tool()
def auth_failed_logins(path: str, top_n: int = 20) -> str:
    """Analyze failed SSH login attempts for brute force indicators.

    Parses the auth log and groups failed login attempts by source IP. Surfaces
    brute force patterns (high attempt counts from a single IP), user enumeration
    (many distinct usernames from one IP), and password spraying (one user from
    many IPs). Each finding includes the log line number for audit provenance.

    Args:
        path: Path to an auth.log-format file inside the evidence directory
        top_n: Return the top N source IPs by attempt count (default: 20)

    Returns:
        Markdown report with attacker IPs, targeted users, and confidence scoring.
    """
    try:
        _, events = _read_auth_log(path)
    except (FileNotFoundError, ValueError) as e:
        return f"Error: {e}"

    failed = [e for e in events if e.kind in ("login_failed", "invalid_user")]

    if not failed:
        result = "No failed login attempts found in the log."
        _audit("auth_failed_logins", {"path": path, "top_n": top_n}, "0 failed")
        return result

    # Group by source IP
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for ev in failed:
        ip = ev.fields.get("ip", "unknown")
        by_ip[ip].append(ev)

    # Rank by attempt count
    ranked = sorted(by_ip.items(), key=lambda kv: len(kv[1]), reverse=True)[:top_n]

    lines = [
        f"# Failed Login Analysis — {len(failed)} total attempts from {len(by_ip)} unique IPs",
        "",
    ]

    for ip, ip_events in ranked:
        users = Counter(e.fields.get("user", "?") for e in ip_events)
        methods = Counter(e.fields.get("method", "?") for e in ip_events)
        first_line = min(e.line_number for e in ip_events)
        last_line = max(e.line_number for e in ip_events)

        # Confidence scoring
        attempt_count = len(ip_events)
        distinct_users = len(users)
        if attempt_count >= 50 or distinct_users >= 10:
            confidence = "high"
            verdict = "Brute force / user enumeration — high confidence"
        elif attempt_count >= 10:
            confidence = "medium"
            verdict = "Suspicious — repeated failures from same source"
        else:
            confidence = "low"
            verdict = "Possible typos or legitimate failures"

        lines.append(f"## Source IP: `{ip}`")
        lines.append(f"- **Attempts:** {attempt_count}")
        lines.append(f"- **Distinct users targeted:** {distinct_users}")
        lines.append(f"- **Top users:** {', '.join(f'{u} ({c})' for u, c in users.most_common(5))}")
        lines.append(f"- **Methods:** {', '.join(f'{m} ({c})' for m, c in methods.items())}")
        lines.append(f"- **First seen line:** {first_line}  |  **Last seen line:** {last_line}")
        lines.append(f"- **Confidence:** {confidence} — {verdict}")
        lines.append("")

    result = "\n".join(lines)
    _audit(
        "auth_failed_logins",
        {"path": path, "top_n": top_n},
        f"{len(failed)} failed attempts from {len(by_ip)} IPs",
    )
    return result


# ---------------------------------------------------------------------------
# MCP Tool: auth_successful_logins
# ---------------------------------------------------------------------------

@mcp.tool()
def auth_successful_logins(path: str, top_n: int = 200) -> str:
    """List successful authentication events (SSH, console) with provenance.

    Each login includes user, source IP, auth method (password / publickey /
    keyboard-interactive), and the raw log line number. Useful for spotting
    suspicious successful access after a brute force attempt, or identifying
    which accounts were compromised.

    Args:
        path: Path to an auth.log-format file inside the evidence directory
        top_n: Maximum number of login rows to render in the table
            (default: 200). Extra rows are summarised in a footer line so
            the response stays inside the LLM context window on busy hosts.

    Returns:
        Markdown table of successful logins (capped at ``top_n``), sorted
        chronologically.
    """
    try:
        _, events = _read_auth_log(path)
    except (FileNotFoundError, ValueError) as e:
        return f"Error: {e}"

    accepted = [e for e in events if e.kind == "login_accepted"]

    if not accepted:
        result = "No successful login events found in the log."
        _audit("auth_successful_logins", {"path": path, "top_n": top_n}, "0 successes")
        return result

    # Identify IPs that ALSO had failed attempts — correlation signal
    failed_ips = {
        e.fields.get("ip") for e in events if e.kind in ("login_failed", "invalid_user")
    }

    rows: list[list[str]] = []
    for e in accepted:
        ip = e.fields.get("ip", "?")
        user = e.fields.get("user", "?")
        method = e.fields.get("method", "?")
        flag = "⚠ brute-force-preceded" if ip in failed_ips else ""
        rows.append([str(e.line_number), e.timestamp, user, ip, method, flag])

    # Count suspicious successful logins
    suspicious = sum(1 for e in accepted if e.fields.get("ip") in failed_ips)
    footer_note = ""
    if suspicious:
        footer_note = (
            f"\n**⚠ {suspicious} of {len(accepted)} successful logins came from an IP "
            "that also had failed attempts** — investigate for post-brute-force compromise."
        )

    table = emit_table(
        ["Line", "Timestamp", "User", "Source IP", "Method", "Flag"],
        rows,
        top_n=top_n,
        footer_note=footer_note,
    )

    result = "\n".join([
        f"# Successful Logins — {len(accepted)} total",
        "",
        table,
    ])
    _audit(
        "auth_successful_logins",
        {"path": path, "top_n": top_n},
        f"{len(accepted)} successes, {suspicious} post-brute-force",
    )
    return result


# ---------------------------------------------------------------------------
# MCP Tool: auth_sudo_commands
# ---------------------------------------------------------------------------

@mcp.tool()
def auth_sudo_commands(path: str, user_filter: str = "", top_n: int = 200) -> str:
    """List sudo commands executed — critical privilege escalation audit trail.

    Returns every sudo invocation with user, target (usually root), and the
    full command. Looks for suspicious patterns: reading /etc/shadow, modifying
    SSH keys, installing packages, disabling logging, etc.

    Args:
        path: Path to an auth.log-format file inside the evidence directory
        user_filter: If set, only return sudo commands by this user (default: all)
        top_n: Maximum number of sudo rows to render in the table
            (default: 200). Extra rows are summarised in a footer line so
            the response stays inside the LLM context window on busy hosts.

    Returns:
        Markdown table of sudo events (capped at ``top_n``) with flagged
        suspicious commands.
    """
    try:
        _, events = _read_auth_log(path)
    except (FileNotFoundError, ValueError) as e:
        return f"Error: {e}"

    sudos = [e for e in events if e.kind == "sudo"]
    if user_filter:
        sudos = [e for e in sudos if e.fields.get("user") == user_filter]

    if not sudos:
        result = "No sudo commands found" + (
            f" for user '{user_filter}'" if user_filter else ""
        )
        _audit(
            "auth_sudo_commands",
            {"path": path, "user_filter": user_filter, "top_n": top_n},
            "0 sudos",
        )
        return result

    # Patterns that should raise flags
    suspicious_patterns = [
        (re.compile(r"/etc/(shadow|passwd|sudoers)", re.I), "credential/config access"),
        (re.compile(r"authorized_keys", re.I), "SSH key modification"),
        (re.compile(r"\b(nc|netcat|ncat|socat)\b", re.I), "network tool execution"),
        (re.compile(r"\b(wget|curl)\s+https?://", re.I), "outbound download"),
        (re.compile(r"\b(chattr|setfattr)\b", re.I), "file attribute manipulation"),
        (re.compile(r"\bhistory\s*-c\b|\b>\s*\.bash_history\b"), "history tampering"),
        (re.compile(r"iptables.*-F|ufw.*disable|systemctl.*stop.*(firewall|ufw)", re.I), "firewall tampering"),
        (re.compile(r"systemctl.*(stop|disable).*(auditd|rsyslog|syslog)", re.I), "logging tampering"),
        (re.compile(r"\b(crontab|systemctl enable)\b", re.I), "persistence mechanism"),
        (re.compile(r"/etc/systemd/system/", re.I), "systemd unit modification"),
    ]

    flag_counts: Counter = Counter()
    rows: list[list[str]] = []
    for e in sudos:
        user = e.fields.get("user", "?")
        target = e.fields.get("target", "?")
        command = e.fields.get("command", "?")
        matched = [label for pat, label in suspicious_patterns if pat.search(command)]
        for m in matched:
            flag_counts[m] += 1
        flags_str = "; ".join(f"⚠ {m}" for m in matched) if matched else ""
        rows.append([str(e.line_number), e.timestamp, user, target, command, flags_str])

    summary_lines: list[str] = []
    if flag_counts:
        summary_lines.append("")
        summary_lines.append("## Summary of flagged patterns")
        for label, count in flag_counts.most_common():
            summary_lines.append(f"- **{label}**: {count} occurrences")
    footer_note = "\n".join(summary_lines)

    table = emit_table(
        ["Line", "Timestamp", "User", "Target", "Command", "Flags"],
        rows,
        top_n=top_n,
        footer_note=footer_note,
    )

    header = (
        f"# Sudo Command Log — {len(sudos)} events"
        + (f" (filtered to user '{user_filter}')" if user_filter else "")
    )
    result = "\n".join([header, "", table])
    _audit(
        "auth_sudo_commands",
        {"path": path, "user_filter": user_filter, "top_n": top_n},
        f"{len(sudos)} sudos, {sum(flag_counts.values())} flagged",
    )
    return result


# ---------------------------------------------------------------------------
# MCP Tool: auth_user_events
# ---------------------------------------------------------------------------

@mcp.tool()
def auth_user_events(path: str) -> str:
    """List user and group management events (account creation/deletion).

    New user accounts are a classic Linux persistence mechanism — attackers
    create backdoor accounts after gaining root access. This tool surfaces
    every useradd/userdel/groupadd event with full provenance.

    Args:
        path: Path to an auth.log-format file inside the evidence directory

    Returns:
        Markdown report of user/group lifecycle events.
    """
    try:
        _, events = _read_auth_log(path)
    except (FileNotFoundError, ValueError) as e:
        return f"Error: {e}"

    user_events = [
        e for e in events if e.kind in ("user_added", "user_deleted", "group_added")
    ]

    if not user_events:
        result = "No user or group management events found."
        _audit("auth_user_events", {"path": path}, "0 events")
        return result

    lines = [f"# User / Group Lifecycle Events — {len(user_events)} total", ""]

    for e in user_events:
        name = e.fields.get("name", "?")
        ident = e.fields.get("uid") or e.fields.get("gid", "?")
        label = {
            "user_added": "USER ADDED",
            "user_deleted": "USER DELETED",
            "group_added": "GROUP ADDED",
        }[e.kind]
        lines.append(
            f"- **Line {e.line_number}** — {e.timestamp} — **{label}**: "
            f"`{name}` (id={ident})"
        )

    # Flag new accounts as potential persistence
    added = [e for e in user_events if e.kind == "user_added"]
    if added:
        lines.append("")
        lines.append(
            f"⚠ **{len(added)} new user account(s) created.** This is a common "
            "persistence mechanism. Correlate with successful root logins and "
            "sudo activity to identify if an attacker added these accounts."
        )

    result = "\n".join(lines)
    _audit("auth_user_events", {"path": path}, f"{len(user_events)} lifecycle events")
    return result


# ---------------------------------------------------------------------------
# MCP Tool: auth_summary — one-call overview of the whole log
# ---------------------------------------------------------------------------

@mcp.tool()
def auth_summary(path: str) -> str:
    """High-level overview of an auth log — call this first for triage.

    Returns counts of each event type, top source IPs, and a verdict on
    whether the log shows signs of compromise. Use this as the entry point
    before drilling into specific tools (failed logins, sudo, etc).

    Args:
        path: Path to an auth.log-format file inside the evidence directory

    Returns:
        Markdown summary with triage verdict.
    """
    try:
        validated, events = _read_auth_log(path)
    except (FileNotFoundError, ValueError) as e:
        return f"Error: {e}"

    if not events:
        result = "Log file contains no recognizable auth events."
        _audit("auth_summary", {"path": path}, "0 events parsed")
        return result

    counts = Counter(e.kind for e in events)
    failed_ips = Counter(
        e.fields.get("ip", "?")
        for e in events
        if e.kind in ("login_failed", "invalid_user")
    )
    successful_ips = {
        e.fields.get("ip") for e in events if e.kind == "login_accepted"
    }

    # Correlation: successful logins from IPs that also had failures
    compromised_ips = [
        ip for ip in successful_ips if ip and failed_ips.get(ip, 0) >= 5
    ]

    lines = [
        f"# Auth Log Summary — `{validated.name}`",
        "",
        f"- **Total events:** {len(events)}",
        f"- **Failed logins:** {counts.get('login_failed', 0) + counts.get('invalid_user', 0)}",
        f"- **Successful logins:** {counts.get('login_accepted', 0)}",
        f"- **Sudo commands:** {counts.get('sudo', 0)}",
        f"- **User accounts added:** {counts.get('user_added', 0)}",
        f"- **User accounts deleted:** {counts.get('user_deleted', 0)}",
        f"- **Groups added:** {counts.get('group_added', 0)}",
        "",
    ]

    if failed_ips:
        lines.append("## Top failed-login sources")
        for ip, c in failed_ips.most_common(5):
            lines.append(f"- `{ip}`: {c} attempts")
        lines.append("")

    lines.append("## Triage verdict")
    if compromised_ips:
        lines.append(
            f"⚠⚠ **LIKELY COMPROMISE** — {len(compromised_ips)} IP(s) successfully "
            f"authenticated AFTER failed attempts: {', '.join(f'`{ip}`' for ip in compromised_ips)}"
        )
        lines.append("Recommended next steps:")
        lines.append("- Call `auth_successful_logins` to see which accounts were breached")
        lines.append("- Call `auth_sudo_commands` to see post-compromise activity")
        lines.append("- Call `auth_user_events` to check for backdoor account creation")
    elif counts.get("login_failed", 0) > 20:
        lines.append(
            "⚠ **BRUTE FORCE ACTIVITY** detected but no correlated successful logins. "
            "Attackers may still be probing. Review `auth_failed_logins` for full detail."
        )
    else:
        lines.append(
            "No obvious compromise indicators from auth log alone. "
            "Continue investigation with other artifacts (bash history, persistence, filesystem)."
        )

    result = "\n".join(lines)
    _audit("auth_summary", {"path": path}, f"verdict: {len(compromised_ips)} suspect IPs")
    return result
