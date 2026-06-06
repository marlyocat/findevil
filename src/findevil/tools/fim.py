"""
File integrity monitoring (FIM).

Detection-side counterpart to the rest of Findevil's IR tools. Takes a
content-addressed snapshot of every forensic-critical file (hash + mode
+ owner + size + mtime), writes it to a JSON baseline, and later
compares the current state against that baseline to surface any
unauthorized changes.

Analogous to AIDE / Tripwire / Samhain — the open-source FIM tools that
are mandated by PCI-DSS, HIPAA, SOX, and similar compliance regimes.
Difference: designed to work through the same MCP server as our IR
tools, so detection and investigation live in one audit trail.

Two tools:

- `baseline_create(root_path, output_file?)` — walks the tracked-path
  list under `root_path` and writes a JSON baseline. Run once, on a
  known-clean host. (The classic caveat: a baseline taken from an
  already-compromised host bakes the attacker's changes into "normal"
  and subsequent diffs will miss them. Take baselines from golden
  images or freshly-provisioned hosts.)

- `baseline_diff(root_path, baseline_file)` — compares the current
  state under `root_path` to the baseline. Classifies changes by
  severity (`critical` for files like `/etc/passwd`, `/etc/sudoers`,
  `sshd_config`, `authorized_keys`; `warn` for host/network configs)
  and by kind (added / removed / modified).

Tracked paths cover the same surface as `find_persistence`, so any
persistence attempt our other tools would surface also shows up as an
unexplained change here. Running `baseline_diff` on a schedule
(cron / systemd timer) gives continuous compromise detection without
requiring a SIEM.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from findevil.server import _audit, _validate_evidence_path, mcp

# NOTE: we deliberately don't `from findevil.server import LOGS_DIR` at module
# load time because tests monkeypatch `srv.LOGS_DIR` and a captured import
# would hold the old value. `_resolve_output_path` does a late import so the
# tests see what they expect.


# ---------------------------------------------------------------------------
# Tracked-path catalogue
# ---------------------------------------------------------------------------
#
# Intentionally conservative. Every path here is one we'd want to be
# alerted about on a production host. We prefer false-negatives (missing
# a rare persistence vector) over false-positives (flagging rotating
# log files or package-manager caches every run).

# Individual files tracked by exact path (relative to root)
_TRACKED_FILES: dict[str, str] = {
    # Account and privilege config — any change is critical
    "etc/passwd": "critical",
    "etc/shadow": "critical",
    "etc/group": "warn",
    "etc/gshadow": "warn",
    "etc/sudoers": "critical",
    # SSH daemon config
    "etc/ssh/sshd_config": "critical",
    "etc/ssh/ssh_config": "warn",
    # Library preload (ld.so.preload rootkit vector)
    "etc/ld.so.preload": "critical",
    # Startup / init
    "etc/rc.local": "critical",
    # Kernel module persistence
    "etc/modules": "critical",
    # Cron root
    "etc/crontab": "critical",
    # Hosts / DNS / basic net config
    "etc/hosts": "warn",
    "etc/hostname": "warn",
    "etc/resolv.conf": "warn",
    "etc/nsswitch.conf": "warn",
    # Global shell init
    "etc/profile": "warn",
    "etc/bash.bashrc": "warn",
}

# Directories whose ENTIRE contents (non-recursive unless noted) are
# tracked at the given severity. Additions / removals / modifications
# of any file in these directories are reported.
_TRACKED_DIRS: dict[str, dict] = {
    "etc/sudoers.d": {"severity": "critical", "recursive": False},
    "etc/pam.d": {"severity": "critical", "recursive": False},
    "etc/modprobe.d": {"severity": "critical", "recursive": False},
    "etc/cron.d": {"severity": "critical", "recursive": False},
    "etc/cron.daily": {"severity": "critical", "recursive": False},
    "etc/cron.hourly": {"severity": "critical", "recursive": False},
    "etc/cron.weekly": {"severity": "critical", "recursive": False},
    "etc/cron.monthly": {"severity": "critical", "recursive": False},
    "etc/systemd/system": {
        "severity": "critical",
        "recursive": True,
        "filter": ("*.service", "*.timer", "*.socket", "*.path"),
    },
    "etc/init.d": {"severity": "critical", "recursive": False},
    "etc/profile.d": {"severity": "warn", "recursive": False},
    "var/spool/cron": {"severity": "critical", "recursive": True},
}

# Files to track inside each user's home directory (root + /home/*)
_USER_DOTFILES: dict[str, str] = {
    ".ssh/authorized_keys": "critical",
    ".ssh/known_hosts": "warn",
    ".bashrc": "critical",
    ".bash_profile": "critical",
    ".bash_login": "critical",
    ".profile": "critical",
    ".zshrc": "critical",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class FileEntry:
    path: str  # relative to scan root
    sha256: str
    size: int
    mode: str  # octal, last 4 digits e.g. "0644"
    uid: int
    gid: int
    mtime: str  # ISO 8601 UTC
    severity: str  # "critical" | "warn"


@dataclass
class DiffEntry:
    kind: str  # "added" | "removed" | "modified"
    path: str
    severity: str
    details: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hash_file(path: Path, chunk_size: int = 65536) -> str:
    """Compute SHA256 streaming. Returns empty string on permission error."""
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
    except (OSError, PermissionError):
        return ""
    return h.hexdigest()


def _stat_entry(root: Path, path: Path, severity: str) -> FileEntry | None:
    """Build a FileEntry from a real file. Returns None if unreadable."""
    try:
        st = path.stat()
    except (OSError, PermissionError):
        return None
    sha = _hash_file(path)
    if not sha:
        return None
    rel = str(path.relative_to(root))
    return FileEntry(
        path=rel,
        sha256=sha,
        size=st.st_size,
        mode=oct(st.st_mode)[-4:],
        uid=st.st_uid,
        gid=st.st_gid,
        mtime=datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
        severity=severity,
    )


def _expand_tracked_paths(root: Path) -> list[tuple[Path, str]]:
    """Return (absolute_path, severity) pairs for every file we track."""
    out: list[tuple[Path, str]] = []

    for rel, severity in _TRACKED_FILES.items():
        p = root / rel
        if p.is_file():
            out.append((p, severity))

    for rel, spec in _TRACKED_DIRS.items():
        d = root / rel
        if not d.is_dir():
            continue
        severity = spec["severity"]
        recursive = spec["recursive"]
        walker = d.rglob("*") if recursive else d.iterdir()
        filter_globs = spec.get("filter")
        for p in walker:
            if not p.is_file():
                continue
            if filter_globs and not any(
                fnmatch.fnmatch(p.name, g) for g in filter_globs
            ):
                continue
            out.append((p, severity))

    # Per-user dotfiles — iterate root/, home/*, and also every /home/<user>
    user_homes: list[Path] = []
    root_home = root / "root"
    if root_home.is_dir():
        user_homes.append(root_home)
    home_parent = root / "home"
    if home_parent.is_dir():
        for sub in home_parent.iterdir():
            if sub.is_dir():
                user_homes.append(sub)

    for home in user_homes:
        for rel, severity in _USER_DOTFILES.items():
            p = home / rel
            if p.is_file():
                out.append((p, severity))

    # Dedupe while preserving severity of the first match
    seen: dict[Path, str] = {}
    for p, s in out:
        if p not in seen:
            seen[p] = s
    return [(p, s) for p, s in seen.items()]


# ---------------------------------------------------------------------------
# Baseline creation
# ---------------------------------------------------------------------------


def _build_baseline(root: Path) -> dict:
    entries: list[FileEntry] = []
    for path, severity in _expand_tracked_paths(root):
        entry = _stat_entry(root, path, severity)
        if entry is not None:
            entries.append(entry)

    return {
        "_metadata": {
            "created_at": datetime.now(tz=timezone.utc).isoformat(),
            "root_path": str(root),
            "tool_version": "findevil-fim-1",
            "entry_count": len(entries),
        },
        "entries": [asdict(e) for e in entries],
    }


def _resolve_output_path(output_file: str) -> Path:
    """Pick the baseline output path. Default is LOGS_DIR/baseline.json.

    Late import of `server` is intentional — tests monkeypatch
    `server.LOGS_DIR` and we want to see the current value, not a
    captured-at-import-time copy.

    Security: refuses output paths inside EVIDENCE_DIR. Without this,
    a user (or prompt-injected tool arg) could tell baseline_create to
    write its JSON output over an evidence file, violating the
    "no-write-to-evidence" architectural guarantee.
    """
    from findevil import server

    if not output_file:
        return server.LOGS_DIR / "baseline.json"
    p = Path(output_file)
    if not p.is_absolute():
        p = Path.cwd() / p
    resolved = p.resolve()
    evidence_resolved = server.EVIDENCE_DIR.resolve()
    try:
        resolved.relative_to(evidence_resolved)
    except ValueError:
        return resolved  # not inside evidence — allowed
    raise ValueError(
        f"baseline output path {output_file} resolves inside the evidence "
        f"directory ({server.EVIDENCE_DIR}); refusing to write over evidence."
    )


@mcp.tool()
def baseline_create(root_path: str, output_file: str = "") -> str:
    """Create a file-integrity baseline snapshot.

    Walks the tracked-path catalogue under `root_path` (which must be
    inside the evidence directory) and produces a JSON snapshot of
    every critical file's SHA256, size, mode, owner, and mtime.

    CRITICAL workflow note: take baselines from a KNOWN-CLEAN state
    (a golden image, or a freshly-provisioned host). A baseline taken
    from an already-compromised host bakes the backdoors in as
    "normal" and subsequent diffs will miss them.

    Args:
        root_path: Filesystem root to snapshot (must be inside
            FINDEVIL_EVIDENCE_DIR — for live-host monitoring, point
            FINDEVIL_EVIDENCE_DIR at a read-only mount of `/`)
        output_file: Where to write the baseline JSON. Defaults to
            `<FINDEVIL_LOGS_DIR>/baseline.json`.

    Returns:
        Markdown summary of what was captured.
    """
    try:
        validated = _validate_evidence_path(root_path)
    except ValueError as e:
        return f"Error: {e}"
    if not validated.is_dir():
        return f"Not a directory: {root_path}"

    try:
        out_path = _resolve_output_path(output_file)
    except ValueError as e:
        # Refuses output paths inside the evidence directory; surface a
        # readable error rather than letting the exception bubble.
        return f"Error: {e}"
    baseline = _build_baseline(validated)

    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(baseline, indent=2))
    except (OSError, PermissionError) as e:
        return f"Error writing baseline: {e}"

    entries = baseline["entries"]
    by_severity: dict[str, int] = {}
    for e in entries:
        by_severity[e["severity"]] = by_severity.get(e["severity"], 0) + 1

    lines = [
        f"# FIM baseline created — `{validated}`",
        "",
        f"- **Entries:** {len(entries)}",
        f"- **Output:** `{out_path}`",
        f"- **Created at (UTC):** {baseline['_metadata']['created_at']}",
        "",
        "## Entries by severity",
    ]
    for sev in ("critical", "warn", "info"):
        if sev in by_severity:
            lines.append(f"- `{sev}`: {by_severity[sev]}")

    # Quick category breakdown
    categories = {
        "Account/privilege configs": [
            e for e in entries if e["path"].startswith(("etc/passwd", "etc/shadow", "etc/group", "etc/sudoers"))
        ],
        "SSH configuration": [
            e for e in entries if "etc/ssh/" in e["path"]
        ],
        "PAM modules": [
            e for e in entries if e["path"].startswith("etc/pam.d/")
        ],
        "Systemd units": [
            e for e in entries if e["path"].startswith("etc/systemd/")
        ],
        "Cron entries": [
            e for e in entries if "cron" in e["path"]
        ],
        "Kernel module config": [
            e for e in entries if e["path"].startswith(("etc/modules", "etc/modprobe.d/"))
        ],
        "Library preload": [
            e for e in entries if e["path"] == "etc/ld.so.preload"
        ],
        "User dotfiles (root + home)": [
            e for e in entries
            if e["path"].startswith(("root/.", "home/"))
        ],
    }
    lines.append("")
    lines.append("## Coverage")
    for cat, items in categories.items():
        if items:
            lines.append(f"- **{cat}:** {len(items)} file(s)")

    _audit(
        "baseline_create",
        {"root_path": root_path, "output_file": str(out_path)},
        f"{len(entries)} entries written to {out_path.name}",
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Baseline diff
# ---------------------------------------------------------------------------


def _diff_baselines(
    baseline_entries: list[dict], current_entries: list[dict]
) -> tuple[list[DiffEntry], list[DiffEntry], list[DiffEntry]]:
    """Return (added, removed, modified) diff entries."""
    base_map = {e["path"]: e for e in baseline_entries}
    curr_map = {e["path"]: e for e in current_entries}

    added_paths = set(curr_map) - set(base_map)
    removed_paths = set(base_map) - set(curr_map)
    common_paths = set(base_map) & set(curr_map)

    added = [
        DiffEntry(
            kind="added",
            path=p,
            severity=curr_map[p].get("severity", "info"),
            details=[
                f"New file (not in baseline)",
                f"SHA256: {curr_map[p]['sha256']}",
                f"Size: {curr_map[p]['size']} bytes",
                f"Mode: {curr_map[p]['mode']}",
                f"UID/GID: {curr_map[p]['uid']}/{curr_map[p]['gid']}",
            ],
        )
        for p in sorted(added_paths)
    ]

    removed = [
        DiffEntry(
            kind="removed",
            path=p,
            severity=base_map[p].get("severity", "info"),
            details=[
                f"File present in baseline but missing now",
                f"Baseline SHA256: {base_map[p]['sha256']}",
                f"Baseline size: {base_map[p]['size']} bytes",
            ],
        )
        for p in sorted(removed_paths)
    ]

    modified: list[DiffEntry] = []
    for p in sorted(common_paths):
        b = base_map[p]
        c = curr_map[p]
        changes: list[str] = []
        if b["sha256"] != c["sha256"]:
            changes.append(f"SHA256: {b['sha256']} -> {c['sha256']}")
        if b["size"] != c["size"]:
            changes.append(f"Size: {b['size']} -> {c['size']} bytes")
        if b["mode"] != c["mode"]:
            changes.append(f"Mode: {b['mode']} -> {c['mode']}")
        if b["uid"] != c["uid"] or b["gid"] != c["gid"]:
            changes.append(f"Owner: {b['uid']}/{b['gid']} -> {c['uid']}/{c['gid']}")
        if not changes:
            continue  # mtime only — not reported as modification
        modified.append(
            DiffEntry(
                kind="modified",
                path=p,
                severity=c.get("severity", b.get("severity", "info")),
                details=changes,
            )
        )

    return added, removed, modified


_SEVERITY_ORDER = {"critical": 0, "warn": 1, "info": 2}
_SEVERITY_ICON = {"critical": "🚨", "warn": "⚠", "info": "·"}


def _format_diff(
    baseline_meta: dict,
    added: list[DiffEntry],
    removed: list[DiffEntry],
    modified: list[DiffEntry],
    root: Path,
) -> str:
    total_critical = sum(
        1 for e in (*added, *removed, *modified) if e.severity == "critical"
    )
    total_warn = sum(
        1 for e in (*added, *removed, *modified) if e.severity == "warn"
    )

    lines = [
        f"# FIM diff — `{root}`",
        "",
        f"- **Baseline created:** {baseline_meta.get('created_at', '?')}",
        f"- **Baseline root:** `{baseline_meta.get('root_path', '?')}`",
        f"- **Changes detected:** {len(added) + len(removed) + len(modified)} "
        f"({total_critical} critical, {total_warn} warn)",
        f"  - Added: {len(added)}",
        f"  - Removed: {len(removed)}",
        f"  - Modified: {len(modified)}",
        "",
    ]

    # Triage verdict
    lines.append("## Triage verdict")
    if total_critical > 0:
        lines.append(
            f"🚨 **LIKELY COMPROMISE** — {total_critical} critical file(s) "
            "changed since baseline. Investigate every entry below."
        )
    elif total_warn > 0:
        lines.append(
            f"⚠ {total_warn} warn-severity change(s). Review to confirm "
            "legitimacy (patch day, config update, etc.)."
        )
    elif (len(added) + len(removed) + len(modified)) == 0:
        lines.append("✓ No changes detected. Baseline state intact.")
    else:
        lines.append(
            "No critical or warn changes. Info-level changes only — review "
            "for completeness."
        )
    lines.append("")

    # Group by severity for details
    all_changes = [*added, *removed, *modified]
    all_changes.sort(
        key=lambda e: (_SEVERITY_ORDER.get(e.severity, 9), e.kind, e.path)
    )

    current_sev = None
    for e in all_changes:
        if e.severity != current_sev:
            lines.append(f"## {_SEVERITY_ICON.get(e.severity, '·')} {e.severity.upper()} changes")
            lines.append("")
            current_sev = e.severity
        lines.append(f"### `{e.path}` — {e.kind}")
        for d in e.details:
            lines.append(f"- {d}")
        lines.append("")

    return "\n".join(lines)


@mcp.tool()
def baseline_diff(root_path: str, baseline_file: str) -> str:
    """Compare the current filesystem state against a FIM baseline.

    Re-walks the tracked-path catalogue under `root_path` and diffs
    against the baseline at `baseline_file`. Every added / removed /
    modified file is reported, grouped by severity. Any critical-
    severity change is surfaced as "LIKELY COMPROMISE" in the triage
    verdict — these are paths (like `etc/passwd`, `etc/sudoers`,
    `sshd_config`, `authorized_keys`, cron/systemd/PAM entries) that
    should never change outside of explicit admin activity.

    Args:
        root_path: Filesystem root to inspect (must be inside
            FINDEVIL_EVIDENCE_DIR)
        baseline_file: Path to a baseline JSON produced by
            `baseline_create` (does NOT need to be inside evidence —
            baselines are analyst artifacts, not evidence)

    Returns:
        Markdown diff report grouped by severity, with a triage
        verdict at the top.
    """
    try:
        validated_root = _validate_evidence_path(root_path)
    except ValueError as e:
        return f"Error: {e}"
    if not validated_root.is_dir():
        return f"Not a directory: {root_path}"

    baseline_path = Path(baseline_file)
    if not baseline_path.is_absolute():
        baseline_path = (Path.cwd() / baseline_path).resolve()
    if not baseline_path.is_file():
        return f"Baseline file not found: {baseline_path}"

    try:
        baseline = json.loads(baseline_path.read_text())
    except (OSError, PermissionError, json.JSONDecodeError) as e:
        return f"Error reading baseline: {e}"

    baseline_entries = baseline.get("entries", [])
    baseline_meta = baseline.get("_metadata", {})

    current = _build_baseline(validated_root)
    current_entries = current["entries"]

    added, removed, modified = _diff_baselines(baseline_entries, current_entries)

    result = _format_diff(baseline_meta, added, removed, modified, validated_root)

    total = len(added) + len(removed) + len(modified)
    critical = sum(
        1 for e in (*added, *removed, *modified) if e.severity == "critical"
    )
    _audit(
        "baseline_diff",
        {"root_path": root_path, "baseline_file": str(baseline_path)},
        f"{total} changes ({critical} critical)",
    )
    return result
