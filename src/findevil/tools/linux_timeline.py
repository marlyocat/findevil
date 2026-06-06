"""
Timeline and filesystem metadata analysis.

Phase 4 addresses the limitation the agent itself identified: individual
domain tools produce findings that are chronologically disconnected. To
reason about "what happened when", the agent needs:

1. `stat_file(path)` — structured file metadata (mtime, ctime, atime,
   mode, owner, size) so the agent can reason about specific artifacts.
2. `find_recent_changes(root, since, until)` — enumerate files modified
   in a time window, revealing what the attacker touched.
3. `find_timestamp_anomalies(root)` — detect timestomping patterns:
   mtime newer than ctime, batch-modified files, future timestamps.
4. `build_timeline(evidence_root, ...)` — fuse events from auth.log,
   systemd journal, apt/dpkg history, nginx access logs, shell history,
   and filesystem mtimes into ONE chronologically-sorted view.

Events are unified into a common schema:
    {timestamp, source, actor, action, detail, line_number|None}

This is what lets the agent reason: "the package install at 02:47:33
matches the xmrig.service creation at 02:47:38, both preceded by the
pip install at 02:45:11 — cohesive attack chain."
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from findevil.server import _audit, _validate_evidence_path, mcp

# Parsers from sibling modules are imported lazily inside the extractor
# functions that use them. Top-level cross-module imports cause a circular
# dependency because server.py triggers linux_timeline to load while
# other tool modules (which this one depends on) are still being
# initialised.


# ---------------------------------------------------------------------------
# Unified event model
# ---------------------------------------------------------------------------


@dataclass
class TimelineEvent:
    timestamp: str  # ISO 8601 (UTC where possible)
    source: str  # "auth.log", "journal", "apt", "dpkg", "pip", "nginx", "bash_history", "filesystem"
    actor: str  # user / IP / subject or "?"
    action: str  # short verb: "login", "sudo", "install", "fs_modify", etc.
    detail: str  # human-readable specifics
    provenance: str  # file path and line number for traceback


_MONTH_TO_NUM = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

_SYSLOG_TS_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$")
_NGINX_TS_RE = re.compile(r"^(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2})")


def _normalize_syslog_ts(raw: str, fallback_year: int) -> str:
    """Convert `Apr 12 14:30:04` -> ISO 8601 UTC. fallback_year required
    because syslog lines don't carry a year."""
    m = _SYSLOG_TS_RE.match(raw.strip())
    if not m:
        return raw
    month, day, h, mn, s = m.groups()
    try:
        dt = datetime(
            fallback_year, _MONTH_TO_NUM[month], int(day),
            int(h), int(mn), int(s), tzinfo=timezone.utc,
        )
        return dt.isoformat()
    except (KeyError, ValueError):
        return raw


def _normalize_nginx_ts(raw: str) -> str:
    m = _NGINX_TS_RE.match(raw)
    if not m:
        return raw
    day, month, year, h, mn, s = m.groups()
    try:
        dt = datetime(
            int(year), _MONTH_TO_NUM[month], int(day),
            int(h), int(mn), int(s), tzinfo=timezone.utc,
        )
        return dt.isoformat()
    except (KeyError, ValueError):
        return raw


# ---------------------------------------------------------------------------
# stat_file
# ---------------------------------------------------------------------------


@mcp.tool()
def stat_file(path: str) -> str:
    """Return structured filesystem metadata for a single file.

    Provides the agent with typed access to timestamps (mtime, ctime, atime),
    mode / permissions, owner (uid/gid), size, and file type. Use this when
    reasoning about WHEN an artifact was created or modified — typically
    after another tool has surfaced a path of interest.

    Args:
        path: Path inside the evidence directory

    Returns:
        Markdown-formatted metadata block.
    """
    try:
        validated = _validate_evidence_path(path)
    except ValueError as e:
        return f"Error: {e}"
    if not validated.exists():
        return f"Path not found: {path}"

    st = validated.stat()
    mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
    ctime = datetime.fromtimestamp(st.st_ctime, tz=timezone.utc).isoformat()
    atime = datetime.fromtimestamp(st.st_atime, tz=timezone.utc).isoformat()
    ftype = (
        "symlink" if validated.is_symlink()
        else "dir" if validated.is_dir()
        else "file"
    )
    mode = oct(st.st_mode)[-4:]

    flags = []
    if st.st_mode & 0o4000:
        flags.append("SETUID")
    if st.st_mode & 0o2000:
        flags.append("SETGID")
    if st.st_mode & 0o1000:
        flags.append("STICKY")
    if mtime > ctime:
        flags.append("⚠ mtime>ctime (possible timestomping)")
    if mtime > datetime.now(tz=timezone.utc).isoformat():
        flags.append("⚠ future mtime")

    lines = [f"# File metadata — `{path}`", ""]
    lines.append(f"- **Type:** {ftype}")
    lines.append(f"- **Size:** {st.st_size} bytes")
    lines.append(f"- **Mode:** {mode}")
    lines.append(f"- **UID/GID:** {st.st_uid}/{st.st_gid}")
    lines.append(f"- **mtime:** {mtime}")
    lines.append(f"- **ctime:** {ctime}")
    lines.append(f"- **atime:** {atime}")
    if flags:
        lines.append(f"- **Flags:** {', '.join(flags)}")

    result = "\n".join(lines)
    _audit("stat_file", {"path": path}, f"{ftype} {st.st_size}B mode={mode}")
    return result


# ---------------------------------------------------------------------------
# find_recent_changes
# ---------------------------------------------------------------------------


@mcp.tool()
def find_recent_changes(
    root_path: str, since_iso: str, until_iso: str, limit: int = 200
) -> str:
    """List files modified within a time window under a filesystem root.

    Critical for reasoning about attack windows: "between 14:45 (successful
    login) and 15:00 (session end), what did the attacker modify?"

    Args:
        root_path: Filesystem root to walk
        since_iso: Lower bound (ISO 8601, e.g. "2026-04-12T14:45:00+00:00")
        until_iso: Upper bound (ISO 8601)
        limit: Cap the returned file list (default 200)

    Returns:
        Markdown listing of files with mtime in the window, sorted
        chronologically.
    """
    try:
        validated = _validate_evidence_path(root_path)
    except ValueError as e:
        return f"Error: {e}"
    if not validated.is_dir():
        return f"Not a directory: {root_path}"

    try:
        since_dt = datetime.fromisoformat(since_iso.replace("Z", "+00:00"))
        until_dt = datetime.fromisoformat(until_iso.replace("Z", "+00:00"))
    except ValueError as e:
        return f"Invalid ISO timestamp: {e}"

    since_ts = since_dt.timestamp()
    until_ts = until_dt.timestamp()

    matches: list[tuple[float, Path]] = []
    for p in validated.rglob("*"):
        try:
            if not p.is_file():
                continue
            mt = p.stat().st_mtime
            if since_ts <= mt <= until_ts:
                matches.append((mt, p))
        except (OSError, PermissionError):
            continue

    matches.sort()

    lines = [
        f"# Recent changes — `{root_path}`",
        "",
        f"- **Window:** {since_dt.isoformat()} → {until_dt.isoformat()}",
        f"- **Files matched:** {len(matches)}",
        "",
    ]
    if matches:
        lines.append("| mtime | size | path |")
        lines.append("|-------|------|------|")
        for mt, p in matches[:limit]:
            iso = datetime.fromtimestamp(mt, tz=timezone.utc).isoformat()
            size = p.stat().st_size
            rel = str(p.relative_to(validated))
            lines.append(f"| {iso} | {size} | `{rel}` |")
        if len(matches) > limit:
            lines.append(f"\n... {len(matches) - limit} more matches truncated ...")

    result = "\n".join(lines)
    _audit(
        "find_recent_changes",
        {"root_path": root_path, "since": since_iso, "until": until_iso},
        f"{len(matches)} files",
    )
    return result


# ---------------------------------------------------------------------------
# find_timestamp_anomalies
# ---------------------------------------------------------------------------


@mcp.tool()
def find_timestamp_anomalies(root_path: str, limit: int = 100) -> str:
    """Detect classic timestomping patterns across a filesystem tree.

    Surfaces:
    - Files where mtime > ctime (mtime can be set by the user; ctime
      cannot be backdated without root+kernel tricks — so this often
      indicates a deliberate mtime reset).
    - Files with mtime in the future.
    - Clusters of files with identical mtime+ctime to the second
      (possible batch-touched artifacts).

    Args:
        root_path: Filesystem root to scan
        limit: Cap each category of findings (default 100)

    Returns:
        Markdown report grouped by anomaly type.
    """
    try:
        validated = _validate_evidence_path(root_path)
    except ValueError as e:
        return f"Error: {e}"
    if not validated.is_dir():
        return f"Not a directory: {root_path}"

    now = datetime.now(tz=timezone.utc).timestamp()
    mt_gt_ct: list[Path] = []
    future_mt: list[Path] = []
    ts_groups: dict[tuple[int, int], list[Path]] = {}

    for p in validated.rglob("*"):
        try:
            if not p.is_file():
                continue
            st = p.stat()
        except (OSError, PermissionError):
            continue
        if st.st_mtime > st.st_ctime + 1:  # +1 second tolerance
            mt_gt_ct.append(p)
        if st.st_mtime > now + 60:  # more than a minute in future
            future_mt.append(p)
        key = (int(st.st_mtime), int(st.st_ctime))
        ts_groups.setdefault(key, []).append(p)

    # Batch groups: more than 3 files with identical second-level mtime+ctime
    batch_groups = {k: v for k, v in ts_groups.items() if len(v) >= 4}

    lines = [f"# Timestamp anomalies — `{root_path}`", ""]
    lines.append(f"- **mtime > ctime:** {len(mt_gt_ct)}")
    lines.append(f"- **future mtime:** {len(future_mt)}")
    lines.append(f"- **identical-timestamp groups (≥4 files):** {len(batch_groups)}")
    lines.append("")

    if mt_gt_ct:
        lines.append("## Files with mtime newer than ctime")
        for p in mt_gt_ct[:limit]:
            st = p.stat()
            mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
            ctime = datetime.fromtimestamp(st.st_ctime, tz=timezone.utc).isoformat()
            rel = str(p.relative_to(validated))
            lines.append(f"- `{rel}` — mtime={mtime} ctime={ctime}")
        lines.append("")

    if future_mt:
        lines.append("## Files with future mtime")
        for p in future_mt[:limit]:
            st = p.stat()
            mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
            rel = str(p.relative_to(validated))
            lines.append(f"- `{rel}` — mtime={mtime}")
        lines.append("")

    if batch_groups:
        lines.append("## Identical-timestamp batches")
        for (mt, ct), paths in list(batch_groups.items())[:10]:
            ts_iso = datetime.fromtimestamp(mt, tz=timezone.utc).isoformat()
            lines.append(f"- **{ts_iso}** ({len(paths)} files):")
            for p in paths[:10]:
                lines.append(f"  - `{p.relative_to(validated)}`")
        lines.append("")

    if not (mt_gt_ct or future_mt or batch_groups):
        lines.append("No timestamp anomalies detected.")

    result = "\n".join(lines)
    _audit(
        "find_timestamp_anomalies",
        {"root_path": root_path},
        f"{len(mt_gt_ct)} mt>ct, {len(future_mt)} future, {len(batch_groups)} batches",
    )
    return result


# ---------------------------------------------------------------------------
# build_timeline — the main Phase 4 event
# ---------------------------------------------------------------------------


def _events_from_auth_log(path: Path, fallback_year: int) -> list[TimelineEvent]:
    from findevil.tools.linux_auth import parse_auth_log
    out: list[TimelineEvent] = []
    content = path.read_text(errors="replace")
    for e in parse_auth_log(content):
        ts = _normalize_syslog_ts(e.timestamp, fallback_year)
        if e.kind == "login_accepted":
            out.append(TimelineEvent(
                ts, "auth.log",
                actor=f"{e.fields.get('user', '?')}@{e.fields.get('ip', '?')}",
                action="login_accepted",
                detail=f"method={e.fields.get('method', '?')}",
                provenance=f"{path.name}:{e.line_number}",
            ))
        elif e.kind in ("login_failed", "invalid_user"):
            out.append(TimelineEvent(
                ts, "auth.log",
                actor=f"{e.fields.get('user', '?')}@{e.fields.get('ip', '?')}",
                action="login_failed",
                detail=f"method={e.fields.get('method', '?')}",
                provenance=f"{path.name}:{e.line_number}",
            ))
        elif e.kind == "sudo":
            out.append(TimelineEvent(
                ts, "auth.log",
                actor=e.fields.get("user", "?"),
                action="sudo",
                detail=e.fields.get("command", "?")[:200],
                provenance=f"{path.name}:{e.line_number}",
            ))
        elif e.kind == "user_added":
            out.append(TimelineEvent(
                ts, "auth.log",
                actor="root",
                action="user_added",
                detail=f"name={e.fields.get('name', '?')} uid={e.fields.get('uid', '?')}",
                provenance=f"{path.name}:{e.line_number}",
            ))
    return out


def _events_from_journal(path: Path) -> list[TimelineEvent]:
    from findevil.tools.linux_journal import parse_journal
    out: list[TimelineEvent] = []
    content = path.read_text(errors="replace")
    for e in parse_journal(content):
        # Only pull the informative ones to keep the timeline lean
        if e.identifier not in {"sshd", "sudo", "useradd", "kernel", "systemd"}:
            continue
        out.append(TimelineEvent(
            e.timestamp, "journal",
            actor=e.identifier,
            action=e.identifier,
            detail=e.message[:200],
            provenance=f"{path.name}:{e.line_number}",
        ))
    return out


def _events_from_apt(apt_log: Path) -> list[TimelineEvent]:
    from findevil.tools.linux_packages import parse_apt_history
    out: list[TimelineEvent] = []
    content = apt_log.read_text(errors="replace")
    for e in parse_apt_history(content):
        flag_note = f" ⚠ {'; '.join(e.flags)}" if e.flags else ""
        out.append(TimelineEvent(
            e.timestamp, "apt",
            actor="apt",
            action=f"package_{e.action}",
            detail=f"{e.name}={e.version}{flag_note}",
            provenance=f"{apt_log.name}:{e.source_line}",
        ))
    return out


def _events_from_dpkg(dpkg_log: Path) -> list[TimelineEvent]:
    from findevil.tools.linux_packages import parse_dpkg_log
    out: list[TimelineEvent] = []
    content = dpkg_log.read_text(errors="replace")
    for e in parse_dpkg_log(content):
        out.append(TimelineEvent(
            e.timestamp, "dpkg",
            actor="dpkg",
            action=f"package_{e.action}",
            detail=f"{e.name}={e.version}",
            provenance=f"{dpkg_log.name}:{e.source_line}",
        ))
    return out


def _events_from_pip(pip_log: Path) -> list[TimelineEvent]:
    from findevil.tools.linux_packages import parse_pip_log
    out: list[TimelineEvent] = []
    content = pip_log.read_text(errors="replace")
    for e in parse_pip_log(content):
        flag_note = f" ⚠ {'; '.join(e.flags)}" if e.flags else ""
        out.append(TimelineEvent(
            e.timestamp, "pip",
            actor="pip",
            action=f"pip_{e.action}",
            detail=f"{e.name}={e.version}{flag_note}",
            provenance=f"{pip_log.name}:{e.source_line}",
        ))
    return out


def _events_from_access_log(path: Path) -> list[TimelineEvent]:
    from findevil.tools.linux_web import parse_access_log
    out: list[TimelineEvent] = []
    content = path.read_text(errors="replace")
    for e in parse_access_log(content):
        ts_raw = e.time.split()[0] if e.time else ""
        ts = _normalize_nginx_ts(ts_raw)
        # Drop events whose timestamp couldn't be normalised. Two failure
        # modes: empty time string (ts == "") and unparseable nginx format
        # (`_normalize_nginx_ts` returns the raw input unchanged on regex
        # non-match — detect that by comparing against the input).
        if not ts or ts == ts_raw:
            continue
        out.append(TimelineEvent(
            ts, "nginx",
            actor=e.ip,
            action=f"http_{e.method.lower()}",
            detail=f"{e.status} {e.path[:180]}",
            provenance=f"{path.name}:{e.line_number}",
        ))
    return out


def _events_from_bash_history(path: Path) -> list[TimelineEvent]:
    from findevil.tools.linux_shell_history import parse_history
    out: list[TimelineEvent] = []
    content = path.read_text(errors="replace")
    user = "?"
    if "home" in path.parts:
        try:
            user = path.parts[path.parts.index("home") + 1]
        except (ValueError, IndexError):
            pass
    elif "root" in path.parts:
        user = "root"
    for entry in parse_history(content):
        if not entry.timestamp:
            continue  # skip entries without HISTTIMEFORMAT timestamps
        out.append(TimelineEvent(
            entry.timestamp, "bash_history",
            actor=user,
            action="shell_command",
            detail=entry.command[:200],
            provenance=f"{path.name}:{entry.line_number}",
        ))
    return out


def _events_from_filesystem(
    fs_root: Path, since_ts: float, until_ts: float, max_files: int = 500
) -> list[TimelineEvent]:
    out: list[TimelineEvent] = []
    count = 0
    for p in fs_root.rglob("*"):
        try:
            if not p.is_file():
                continue
            mt = p.stat().st_mtime
            if since_ts <= mt <= until_ts:
                iso = datetime.fromtimestamp(mt, tz=timezone.utc).isoformat()
                out.append(TimelineEvent(
                    iso, "filesystem",
                    actor="?",
                    action="fs_modify",
                    detail=f"mtime modified: {p.relative_to(fs_root)}",
                    provenance=f"fs:{p.relative_to(fs_root)}",
                ))
                count += 1
                if count >= max_files:
                    break
        except (OSError, PermissionError):
            continue
    return out


@mcp.tool()
def build_timeline(
    evidence_root: str,
    fs_subpath: str = "fs",
    since_iso: str = "",
    until_iso: str = "",
    fallback_year: int = 2026,
    max_events: int = 500,
) -> str:
    """Fuse events from every available artifact into one unified timeline.

    Automatically discovers and parses: auth.log, journal.jsonl,
    var/log/apt/history.log, var/log/dpkg.log, root/.pip/pip.log, any
    access.log, and any .bash_history with HISTTIMEFORMAT timestamps —
    wherever they exist under the evidence root. Optionally folds in
    filesystem mtime events if a time window is provided.

    Every event carries: timestamp, source, actor, action, short detail,
    and provenance (file:line). The result is a chronologically sorted
    markdown table the agent can use to reason about attack sequence,
    correlate cross-source events, and spot gaps.

    Args:
        evidence_root: Root directory of the evidence case (under the
            evidence dir)
        fs_subpath: Subpath inside evidence_root for the filesystem
            snapshot (default "fs")
        since_iso: Optional ISO 8601 lower bound to include filesystem
            mtime events
        until_iso: Optional ISO 8601 upper bound
        fallback_year: Year to attribute to syslog-style timestamps that
            don't carry a year (default 2026)
        max_events: Cap the timeline to keep output manageable

    Returns:
        Markdown table of unified events sorted by timestamp.
    """
    try:
        validated = _validate_evidence_path(evidence_root)
    except ValueError as e:
        return f"Error: {e}"
    if not validated.is_dir():
        return f"Not a directory: {evidence_root}"

    fs_root = validated / fs_subpath
    events: list[TimelineEvent] = []

    # Text auth.log
    for name in ("auth.log", "secure.log", "secure"):
        p = validated / name
        if p.is_file():
            events.extend(_events_from_auth_log(p, fallback_year))

    # systemd journal export
    for name in ("journal.jsonl", "journal.json"):
        p = validated / name
        if p.is_file():
            events.extend(_events_from_journal(p))

    # apt, dpkg, pip — look in fs subtree
    apt_hist = fs_root / "var/log/apt/history.log"
    if apt_hist.is_file():
        events.extend(_events_from_apt(apt_hist))
    dpkg_log = fs_root / "var/log/dpkg.log"
    if dpkg_log.is_file():
        events.extend(_events_from_dpkg(dpkg_log))
    pip_log = fs_root / "root/.pip/pip.log"
    if pip_log.is_file():
        events.extend(_events_from_pip(pip_log))

    # nginx access.log in evidence root
    for name in ("access.log", "access_log"):
        p = validated / name
        if p.is_file():
            events.extend(_events_from_access_log(p))

    # Bash histories inside fs/
    if fs_root.is_dir():
        bash_histories = [fs_root / "root/.bash_history"]
        bash_histories.extend((fs_root / "home").glob("*/.bash_history"))
        for bh in bash_histories:
            if bh.is_file():
                events.extend(_events_from_bash_history(bh))

    # Filesystem mtime events (only if window given — otherwise flood risk)
    if since_iso and until_iso and fs_root.is_dir():
        try:
            since_ts = datetime.fromisoformat(
                since_iso.replace("Z", "+00:00")
            ).timestamp()
            until_ts = datetime.fromisoformat(
                until_iso.replace("Z", "+00:00")
            ).timestamp()
            events.extend(_events_from_filesystem(fs_root, since_ts, until_ts))
        except ValueError:
            pass

    if not events:
        result = f"No timeline events could be extracted from `{evidence_root}`."
        _audit("build_timeline", {"evidence_root": evidence_root}, "0 events")
        return result

    events.sort(key=lambda e: (e.timestamp, e.source))

    lines = [
        f"# Unified timeline — `{evidence_root}`",
        "",
        f"- **Events:** {len(events)}",
        f"- **Sources:** {', '.join(sorted({e.source for e in events}))}",
        "",
        "| Timestamp | Source | Actor | Action | Detail | Provenance |",
        "|-----------|--------|-------|--------|--------|------------|",
    ]
    for e in events[:max_events]:
        safe_detail = e.detail.replace("|", "\\|")[:200]
        lines.append(
            f"| {e.timestamp} | {e.source} | `{e.actor[:40]}` | {e.action} | {safe_detail} | {e.provenance} |"
        )
    if len(events) > max_events:
        lines.append(f"\n... {len(events) - max_events} more events truncated ...")

    result = "\n".join(lines)
    _audit(
        "build_timeline",
        {"evidence_root": evidence_root, "since": since_iso, "until": until_iso},
        f"{len(events)} events from {len({e.source for e in events})} sources",
    )
    return result
