"""
Shell history analysis (bash, zsh, sh).

The sudo trail in `auth.log` only captures privileged commands. Non-sudo
commands — reconnaissance (`whoami`, `id`, `netstat`), downloads (`curl`,
`wget`), script execution (`bash /tmp/x`), and the clearing itself —
only appear in shell history. Missing or empty history is itself a signal:
attackers routinely run `history -c` or `>~/.bash_history`.

Tools:
- `analyze_bash_history(path)` — parse one history file, flag suspicious
  commands and evidence of tampering.
- `find_shell_histories(root_path)` — enumerate all .bash_history / .zsh_history
  / .sh_history / .ash_history files under a filesystem root, with per-file
  size and a suspiciousness hint.

The parser understands BOTH formats:
- Plain history (one command per line)
- Extended history (HISTTIMEFORMAT set) — `#1713065234\\n<command>\\n...`
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from findevil.server import _audit, _validate_evidence_path, mcp

# ---------------------------------------------------------------------------
# Suspicious command heuristics specific to shell history context
# Overlaps deliberately with linux_persistence to keep the two tools independent.
# ---------------------------------------------------------------------------

_SUSPICIOUS_HISTORY_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Reverse shells (classic patterns)
    (re.compile(r"bash\s+-[ic]\s+.*>&?\s*/dev/tcp/"), "bash reverse shell"),
    (re.compile(r"\bnc\b.*\s-[el]\w*\s"), "nc with -e/-l flag (reverse/bind shell)"),
    (re.compile(r"python3?\s+-c.*socket", re.I), "python reverse shell one-liner"),
    (re.compile(r"perl\s+-e.*socket", re.I), "perl reverse shell one-liner"),
    (re.compile(r"\b/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+"), "bash /dev/tcp socket reference"),
    # Download tools
    (re.compile(r"\b(curl|wget)\b.*?https?://", re.I), "outbound download"),
    # Credential access
    (re.compile(r"cat\s+.*/etc/(shadow|passwd|sudoers)"), "credential/config file access"),
    (re.compile(r"cat\s+.*\.ssh/(id_rsa|id_ed25519|id_ecdsa)"), "SSH private key access"),
    (re.compile(r"\bsudo\s+-l\b"), "sudo privilege enumeration"),
    # Recon
    (re.compile(r"\b(whoami|id|uname\s+-a|hostname)\b"), "system recon"),
    (re.compile(r"\b(netstat\s+-|ss\s+-|lsof\s+-i)"), "network state enumeration"),
    (re.compile(r"\b(find|locate)\s+.*-perm\s+-?[ug]\s*=\s*s"), "SUID binary search"),
    # Anti-forensics / tampering
    (re.compile(r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b"), "history clearing"),
    (re.compile(r">\s*~?/?\.?bash_history\b|>\s*\.zsh_history\b"), "history file truncation"),
    (re.compile(r"\brm\s+.*\.(bash|zsh|sh|ash)_history"), "history file removal"),
    (re.compile(r"\bchattr\s+[+-]i\b"), "chattr immutable toggle"),
    # Obfuscation
    (re.compile(r"\b(base64\s+-d|xxd\s+-r|openssl\s+enc\b.*-d)"), "obfuscated payload decode"),
    (re.compile(r"\beval\s+\$\("), "eval of subshell command"),
    # Firewall/service tampering
    (re.compile(r"\biptables\s+.*-F\b|\bufw\s+disable\b"), "firewall tampering"),
    (re.compile(r"systemctl\s+(stop|disable).*(auditd|rsyslog|syslog)"), "logging service tampering"),
    # Persistence-adjacent (overlaps with linux_persistence but useful here)
    (re.compile(r"\bcrontab\s+-e\b|\bcrontab\s+-l\b"), "crontab inspection/edit"),
    (re.compile(r"/etc/systemd/system/"), "systemd unit path reference"),
    (re.compile(r"~?/?\.ssh/authorized_keys"), "authorized_keys reference"),
    # World-writable exec
    (re.compile(r"(?:^|\s|/)(/tmp/|/var/tmp/|/dev/shm/)\S"), "exec/file in world-writable dir"),
    # Container escape / dangerous configs
    (re.compile(r"\bdocker\s+run\s+.*--privileged"), "privileged container run"),
    (re.compile(r"--cap-add\s+SYS_ADMIN"), "capability addition"),
]


@dataclass
class HistoryEntry:
    line_number: int
    command: str
    timestamp: str | None  # ISO format if HISTTIMEFORMAT was in use


@dataclass
class HistoryFinding:
    path: str
    suspicious_entries: list[tuple[HistoryEntry, list[str]]]
    tampering: list[str]  # "empty_file", "suspiciously_short", "missing_timestamps"
    total_entries: int
    timestamped_entries: int
    file_size: int
    earliest_ts: str | None
    latest_ts: str | None


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


_TS_RE = re.compile(r"^#(\d{9,11})$")


def parse_history(content: str) -> list[HistoryEntry]:
    """Parse both plain and extended (HISTTIMEFORMAT) shell histories."""
    entries: list[HistoryEntry] = []
    pending_ts: str | None = None

    for lineno, raw in enumerate(content.splitlines(), 1):
        if not raw.strip():
            continue
        m = _TS_RE.match(raw.strip())
        if m:
            try:
                pending_ts = datetime.fromtimestamp(
                    int(m.group(1)), tz=timezone.utc
                ).isoformat()
            except (ValueError, OSError):
                pending_ts = None
            continue
        entries.append(HistoryEntry(line_number=lineno, command=raw, timestamp=pending_ts))
        pending_ts = None

    return entries


def analyze_entries(entries: list[HistoryEntry]) -> list[tuple[HistoryEntry, list[str]]]:
    out = []
    for e in entries:
        reasons = []
        for pat, label in _SUSPICIOUS_HISTORY_PATTERNS:
            if pat.search(e.command):
                reasons.append(label)
        if reasons:
            out.append((e, reasons))
    return out


# ---------------------------------------------------------------------------
# Single-file analysis
# ---------------------------------------------------------------------------


def _analyze(path: Path) -> HistoryFinding:
    try:
        raw_bytes = path.read_bytes()
    except (OSError, PermissionError) as e:
        return HistoryFinding(
            path=str(path),
            suspicious_entries=[],
            tampering=[f"unreadable: {e}"],
            total_entries=0,
            timestamped_entries=0,
            file_size=0,
            earliest_ts=None,
            latest_ts=None,
        )

    size = len(raw_bytes)
    content = raw_bytes.decode(errors="replace")
    entries = parse_history(content)
    suspicious = analyze_entries(entries)

    tampering: list[str] = []
    if size == 0:
        tampering.append("file is empty (0 bytes) — classic evidence of `history -c` or truncation")
    elif len(entries) == 0 and size > 0:
        tampering.append("file has non-zero size but zero parseable commands — unusual")
    elif len(entries) <= 2 and size < 128:
        tampering.append(
            f"only {len(entries)} entries in {size}-byte file — truncation is plausible"
        )

    timestamped = sum(1 for e in entries if e.timestamp)
    earliest = min((e.timestamp for e in entries if e.timestamp), default=None)
    latest = max((e.timestamp for e in entries if e.timestamp), default=None)

    if entries and timestamped == 0:
        # No timestamps — not evidence of tampering on its own (HISTTIMEFORMAT
        # is off by default in most distros) but worth noting for the agent.
        pass

    return HistoryFinding(
        path=str(path),
        suspicious_entries=suspicious,
        tampering=tampering,
        total_entries=len(entries),
        timestamped_entries=timestamped,
        file_size=size,
        earliest_ts=earliest,
        latest_ts=latest,
    )


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------


_HISTORY_NAMES = [".bash_history", ".zsh_history", ".sh_history", ".ash_history"]


@mcp.tool()
def find_shell_histories(root_path: str) -> str:
    """Enumerate shell history files under a filesystem root.

    Lists `.bash_history`, `.zsh_history`, `.sh_history`, `.ash_history` for
    root and every home directory. Call this first to see which accounts
    have usable shell history, then drill in with `analyze_bash_history`.
    An empty or missing history for an active account is itself a signal.

    Args:
        root_path: Filesystem root to search (must be inside evidence directory)

    Returns:
        Markdown table of history files with size and a brief suspiciousness hint.
    """
    try:
        validated = _validate_evidence_path(root_path)
    except ValueError as e:
        return f"Error: {e}"
    if not validated.is_dir():
        return f"Not a directory: {root_path}"

    candidates: list[Path] = []
    for name in _HISTORY_NAMES:
        candidates.append(validated / "root" / name)
        candidates.extend((validated / "home").glob(f"*/{name}"))

    rows = []
    for p in candidates:
        if not p.exists():
            continue
        size = p.stat().st_size
        owner = _infer_owner(p, validated)
        hint = _size_hint(size, p.name)
        rows.append((str(p.relative_to(validated)), owner, size, hint))

    if not rows:
        result = f"No shell history files found under `{root_path}`."
        _audit("find_shell_histories", {"root_path": root_path}, "0 files")
        return result

    lines = [
        f"# Shell history files under `{root_path}`",
        "",
        f"Found **{len(rows)}** history file(s):",
        "",
        "| Path | Owner | Size | Hint |",
        "|------|-------|------|------|",
    ]
    for path, owner, size, hint in rows:
        lines.append(f"| `{path}` | {owner} | {size} bytes | {hint} |")

    result = "\n".join(lines)
    _audit("find_shell_histories", {"root_path": root_path}, f"{len(rows)} files")
    return result


def _infer_owner(path: Path, root: Path) -> str:
    parts = path.relative_to(root).parts
    if parts[0] == "root":
        return "root"
    if len(parts) >= 2 and parts[0] == "home":
        return parts[1]
    return "unknown"


def _size_hint(size: int, name: str) -> str:
    if size == 0:
        return "⚠ empty — possible tampering"
    if size < 128:
        return "⚠ very short"
    if size < 1024:
        return "short"
    return "normal"


@mcp.tool()
def analyze_bash_history(path: str) -> str:
    """Parse a shell history file and flag suspicious commands or tampering.

    Detects:
    - Reverse shells (bash/nc/python one-liners)
    - Credential access (cat /etc/shadow, ~/.ssh/id_rsa)
    - Recon (whoami, id, netstat, find -perm -u=s)
    - Anti-forensics (history -c, history file truncation, chattr)
    - Obfuscated payloads (base64 -d, eval $(...))
    - Firewall/logging service tampering
    - References to world-writable dirs and persistence paths
    - Tampering signals: empty file, suspiciously short content

    Args:
        path: Path to a shell history file inside the evidence directory

    Returns:
        Markdown report with flagged entries, timestamps (if present), and
        tampering indicators.
    """
    try:
        validated = _validate_evidence_path(path)
    except ValueError as e:
        return f"Error: {e}"
    if not validated.exists():
        return f"File not found: {path}"
    if not validated.is_file():
        return f"Not a file: {path}"

    finding = _analyze(validated)

    lines = [f"# Shell history — `{path}`", ""]
    lines.append(
        f"- **Size:** {finding.file_size} bytes  |  "
        f"**Commands:** {finding.total_entries}  |  "
        f"**Timestamped:** {finding.timestamped_entries}"
    )
    if finding.earliest_ts and finding.latest_ts:
        lines.append(f"- **Time range:** {finding.earliest_ts}  →  {finding.latest_ts}")
    lines.append("")

    if finding.tampering:
        lines.append("## ⚠ Tampering indicators")
        for t in finding.tampering:
            lines.append(f"- {t}")
        lines.append("")

    if finding.suspicious_entries:
        lines.append(f"## Suspicious commands ({len(finding.suspicious_entries)})")
        lines.append("")
        lines.append("| Line | Timestamp | Command | Flags |")
        lines.append("|------|-----------|---------|-------|")
        for entry, reasons in finding.suspicious_entries:
            ts = entry.timestamp or "—"
            safe_cmd = entry.command.replace("|", "\\|")
            lines.append(
                f"| {entry.line_number} | {ts} | `{safe_cmd}` | {'; '.join(reasons)} |"
            )
    elif finding.total_entries > 0:
        lines.append("No suspicious commands detected in this history.")
    else:
        lines.append("History file is empty — no commands to analyze.")

    result = "\n".join(lines)
    _audit(
        "analyze_bash_history",
        {"path": path},
        f"{len(finding.suspicious_entries)} suspicious / {finding.total_entries} total / {len(finding.tampering)} tampering signals",
    )
    return result
