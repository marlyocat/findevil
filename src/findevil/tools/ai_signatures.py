"""
LLM-driven adversary detection (GTG-1002 / Symbiote-of-the-attacker class).

Anthropic's November 2025 GTG-1002 disclosure documented an agentic
intrusion campaign where an LLM (Claude Code, in that case) drove
~90% of the offensive operation autonomously. That class of intrusion
leaves forensic signatures human attackers don't:

- Outbound calls to LLM API endpoints (api.anthropic.com, api.openai.com,
  api.deepseek.com, claude.ai) baked into env files, scripts, cron entries
- LLM API key shapes (sk-ant-..., sk-...) in /etc and ~/.config trees
- Leftover agent cache/session directories (.claude/projects/, .agent_cache/,
  llm_session_*.jsonl, agent_tasks.jsonl)
- JSONL files matching the tool-call schema (`tool_use`, `tool_result`)
- Bash scripts with the agent's idiomatic style: `set -euo pipefail` plus
  `readonly` constants plus parallel-execution primitives (`xargs -P`,
  GNU parallel, `export -f`) — too clean for human ad-hoc work
- Bash history with sub-2-second gaps between distinct commands

This module exposes one MCP tool, `find_ai_signatures`, that scans the
filesystem for those patterns and returns a markdown report. Findings
do not by themselves prove compromise — legitimate AI tooling exists —
but combined with other persistence/anomaly findings they explain the
*tradecraft style* of the attacker.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from findevil.server import _audit, _validate_evidence_path, mcp


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------


_LLM_HOST_RE = re.compile(
    r"\b(?:api\.anthropic\.com|api\.openai\.com|api\.deepseek\.com|"
    r"api\.mistral\.ai|api\.together\.xyz|claude\.ai|"
    r"generativelanguage\.googleapis\.com)\b",
    re.I,
)

# API key shapes — keyed off the env-var name AND the value shape.
#
# The fallback used to be a flat ``[A-Za-z0-9_-]{20,}``, which fired on
# any 20+ char base64-ish blob assigned to one of the listed env vars.
# That false-positives on placeholder values like
# ``OPENAI_API_KEY=DELETED-FOR-COMMIT-PLEASE-REGENERATE``. We now match
# either a known provider prefix (sk-/gsk_/AIzaSy) or a generic
# high-entropy value that requires both a digit AND a letter — rejecting
# all-words filler that has no key-like structure.
_LLM_KEY_RE = re.compile(
    r"\b(?:ANTHROPIC_API_KEY|OPENAI_API_KEY|DEEPSEEK_API_KEY|GROQ_API_KEY|"
    r"MISTRAL_API_KEY|TOGETHER_API_KEY|GOOGLE_API_KEY)\b\s*=\s*[\"']?"
    r"(?:"
    # Anthropic: sk-ant-api03-... (or future api{NN}- prefixes)
    r"sk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{8,}"
    # OpenAI / DeepSeek: sk-..., sk-proj-..., sk-svcacct-...
    r"|sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{16,}"
    # Groq
    r"|gsk_[A-Za-z0-9]{16,}"
    # Google AI Studio / Generative Language API
    r"|AIzaSy[A-Za-z0-9_-]{16,}"
    # Generic high-entropy fallback for providers without a distinctive
    # prefix (Mistral, Together): require 32+ chars AND at least one
    # digit AND at least one letter.
    r"|(?=[A-Za-z0-9_-]*\d)(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9_-]{32,}"
    r")",
    re.I,
)

_TOOL_CALL_KEYS = ("tool_use", "tool_result", "tool_calls", "tool_call_id",
                   "anthropic", "claude-sonnet", "claude-haiku", "claude-opus",
                   "session_id", "messages")

_AGENT_PATH_HINTS = [
    ".claude/projects",
    ".claude/sessions",
    ".agent_cache",
    "agent_tasks.jsonl",
    "agent-env",
    "llm_session",
    "agent-session",
    "openai-poll",
]

# AI-style script idioms — looking for the *combination*, not any one
_AI_SCRIPT_IDIOMS = [
    re.compile(r"set\s+-euo\s+pipefail"),
    re.compile(r"^\s*readonly\s+[A-Z_]+\s*=", re.M),
    re.compile(r"\bxargs\s+-[a-zA-Z]*P\s*\d+"),  # xargs -P N
    re.compile(r"\bexport\s+-f\b"),
    re.compile(r"\bparallel\s+[-:]"),
    re.compile(r"\btrap\s+'[^']*'\s+EXIT"),
]


# Common script roots to scan
_SCRIPT_ROOTS = [
    "usr/local/bin",
    "usr/local/sbin",
    "tmp",
    "var/tmp",
    "opt",
    "root",
    "home",
]


@dataclass
class AISignatureFinding:
    severity: str           # "high" | "medium" | "low"
    category: str           # "llm_api_dest" | "api_key" | "agent_path" |
                            # "tool_call_jsonl" | "polished_script" | "machine_speed_history"
    path: str
    summary: str
    reasons: list[str] = field(default_factory=list)
    sample: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_safe(path: Path, max_bytes: int = 65536) -> str:
    try:
        with path.open("rb") as f:
            data = f.read(max_bytes)
        return data.decode(errors="replace")
    except (OSError, PermissionError):
        return ""


def _rel(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


# ---------------------------------------------------------------------------
# Per-class scanners
# ---------------------------------------------------------------------------


def _scan_text_file_for_api_refs(path: Path, root: Path) -> list[AISignatureFinding]:
    """Look in a config/script/log file for LLM API hosts and keys."""
    findings: list[AISignatureFinding] = []
    content = _read_safe(path, max_bytes=131072)
    if not content:
        return findings
    hosts = sorted(set(_LLM_HOST_RE.findall(content)))
    keys = _LLM_KEY_RE.findall(content)
    if hosts:
        findings.append(
            AISignatureFinding(
                severity="high",
                category="llm_api_dest",
                path=_rel(root, path),
                summary=f"LLM API destination(s) referenced: {', '.join(hosts)}",
                reasons=[f"matches: {h}" for h in hosts[:5]],
                sample=content[:400].rstrip(),
            )
        )
    if keys:
        findings.append(
            AISignatureFinding(
                severity="high",
                category="api_key",
                path=_rel(root, path),
                summary=f"LLM API key declaration ({len(keys)} match(es))",
                reasons=[
                    "API key environment variable assignment present —"
                    " unusual on a host that doesn't legitimately use LLM tooling",
                ],
                sample=content[:400].rstrip(),
            )
        )
    return findings


def scan_llm_api_references(root: Path) -> list[AISignatureFinding]:
    """Walk script/config/env/cron/log paths for LLM API endpoints + key declarations."""
    findings: list[AISignatureFinding] = []

    # Specific known config paths first
    direct_targets = [
        root / "etc/environment",
        root / "etc/sysconfig",
        root / "etc/profile",
        root / "etc/profile.d",
        root / "etc/cron.d",
        root / "etc/cron.daily",
        root / "etc/cron.hourly",
        root / "etc/systemd/system",
        root / "var/log",
    ]
    visited: set[Path] = set()
    for t in direct_targets:
        if not t.exists():
            continue
        if t.is_file():
            findings.extend(_scan_text_file_for_api_refs(t, root))
            visited.add(t)
        else:
            for p in t.rglob("*"):
                if not p.is_file():
                    continue
                if p in visited:
                    continue
                # Skip very large or binary files
                try:
                    if p.stat().st_size > 1_048_576:
                        continue
                except OSError:
                    continue
                findings.extend(_scan_text_file_for_api_refs(p, root))
                visited.add(p)

    # User dotfiles
    for home_glob in ((root / "home").glob("*"), (root,) if (root / "root").is_dir() else ()):
        for h in home_glob:
            base = h if h.name == "root" else h
            for sub in (".bashrc", ".profile", ".zshrc", ".env", ".envrc"):
                p = base / sub
                if p.is_file() and p not in visited:
                    findings.extend(_scan_text_file_for_api_refs(p, root))
                    visited.add(p)

    return findings


def scan_agent_paths(root: Path) -> list[AISignatureFinding]:
    """Walk for distinctive agent-cache/session directory and file naming."""
    findings: list[AISignatureFinding] = []

    candidates: list[Path] = []
    # Hidden /tmp dirs that signal agent caches
    if (root / "tmp").is_dir():
        for p in (root / "tmp").iterdir():
            if p.name.startswith(".agent_cache") or p.name.startswith("agent-"):
                candidates.append(p)
        for p in (root / "tmp").glob("llm_session*"):
            candidates.append(p)
        for p in (root / "tmp").glob("agent_session*"):
            candidates.append(p)

    # Per-user .claude/.openai/.anthropic dirs and project caches
    for home_dir in [root / "root"] + list((root / "home").glob("*")):
        if not home_dir.is_dir():
            continue
        for sub in (".claude", ".anthropic", ".openai"):
            p = home_dir / sub
            if p.exists():
                candidates.append(p)

    # /var/log agent task logs
    if (root / "var/log").is_dir():
        for p in (root / "var/log").glob("agent_*"):
            if p.is_file():
                candidates.append(p)
        for p in (root / "var/log").glob("llm_*"):
            if p.is_file():
                candidates.append(p)

    # /etc/sysconfig agent env files
    if (root / "etc/sysconfig").is_dir():
        for p in (root / "etc/sysconfig").iterdir():
            if any(hint in p.name for hint in ("agent", "openai", "anthropic", "claude", "deepseek")):
                candidates.append(p)

    for p in candidates:
        try:
            kind = "directory" if p.is_dir() else "file"
        except OSError:
            continue
        # Quick content sample for files
        sample = ""
        if p.is_file():
            sample = _read_safe(p, 1024)[:300]
        findings.append(
            AISignatureFinding(
                severity="high",
                category="agent_path",
                path=_rel(root, p),
                summary=f"Agent/LLM-tooling {kind}: {p.name}",
                reasons=[
                    "distinctive naming for LLM/agent runtime artifacts —"
                    " inspect contents for tool-call schemas, session IDs, API keys",
                ],
                sample=sample.rstrip(),
            )
        )

    return findings


def _looks_like_tool_call_jsonl(path: Path) -> tuple[bool, list[str]]:
    """Inspect first few lines of a .jsonl file for tool-call schema markers."""
    try:
        with path.open("rb") as f:
            head = f.read(8192)
    except (OSError, PermissionError):
        return False, []
    text = head.decode(errors="replace")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()][:10]
    matched: list[str] = []
    for ln in lines:
        try:
            obj = json.loads(ln)
        except json.JSONDecodeError:
            continue
        flat = json.dumps(obj).lower()
        for k in _TOOL_CALL_KEYS:
            if k.lower() in flat:
                matched.append(k)
    matched = list(dict.fromkeys(matched))
    # Need at least one strong tool-call indicator
    strong = {"tool_use", "tool_result", "tool_calls", "tool_call_id"}
    has_strong = any(m.lower() in strong for m in matched)
    return has_strong, matched


def scan_tool_call_jsonl(root: Path) -> list[AISignatureFinding]:
    """Find .jsonl files that match the LLM tool-call schema."""
    findings: list[AISignatureFinding] = []
    search_dirs = [
        root / "tmp",
        root / "var/log",
        root / "var/lib",
        root / "root",
        root / "home",
        root / "etc/sysconfig",
        root / "opt",
    ]
    seen: set[Path] = set()
    for d in search_dirs:
        if not d.is_dir():
            continue
        for p in d.rglob("*.jsonl"):
            if p in seen or not p.is_file():
                continue
            seen.add(p)
            try:
                if p.stat().st_size > 5_000_000:
                    continue
            except OSError:
                continue
            ok, matched = _looks_like_tool_call_jsonl(p)
            if ok:
                findings.append(
                    AISignatureFinding(
                        severity="high",
                        category="tool_call_jsonl",
                        path=_rel(root, p),
                        summary="JSONL with LLM tool-call schema",
                        reasons=[f"contains keys: {', '.join(matched[:6])}"],
                        sample=_read_safe(p, 500),
                    )
                )
    return findings


def scan_polished_scripts(root: Path) -> list[AISignatureFinding]:
    """Find scripts with the agent-idiomatic combo of polish markers."""
    findings: list[AISignatureFinding] = []
    visited: set[Path] = set()
    for rel in _SCRIPT_ROOTS:
        d = root / rel
        if not d.is_dir():
            continue
        for p in d.rglob("*"):
            if not p.is_file() or p in visited:
                continue
            visited.add(p)
            if p.suffix not in ("", ".sh", ".bash") and p.name not in ("run", "main"):
                continue
            content = _read_safe(p, 32768)
            if not content or not content.startswith(("#!", "#!/")):
                continue
            matches = [pat.search(content) for pat in _AI_SCRIPT_IDIOMS]
            hit_count = sum(1 for m in matches if m)
            if hit_count >= 3:
                hit_names = []
                for pat, m in zip(_AI_SCRIPT_IDIOMS, matches):
                    if m:
                        hit_names.append(pat.pattern[:40])
                findings.append(
                    AISignatureFinding(
                        severity="medium",
                        category="polished_script",
                        path=_rel(root, p),
                        summary=f"AI-style polished script ({hit_count} idioms)",
                        reasons=[
                            "combination of strict-mode + readonly + parallelism is"
                            " agent-typical; humans rarely write all three in ad-hoc work",
                            *[f"matched: {n}" for n in hit_names[:5]],
                        ],
                        sample=content[:400].rstrip(),
                    )
                )
    return findings


_HISTTIMEFORMAT_TS = re.compile(r"^#(\d{9,11})$")


def scan_machine_speed_history(root: Path) -> list[AISignatureFinding]:
    """Detect bash history blocks where consecutive commands fired <2s apart.

    Humans take longer than 2s to type even short independent commands. A
    history with extended timestamps where >50% of consecutive deltas are
    sub-2s indicates an agent or scripted execution.
    """
    findings: list[AISignatureFinding] = []
    candidates: list[Path] = []
    for h in [root / "root"] + list((root / "home").glob("*")):
        if not h.is_dir():
            continue
        for name in (".bash_history", ".zsh_history"):
            p = h / name
            if p.is_file() and p.stat().st_size > 0:
                candidates.append(p)

    for p in candidates:
        content = _read_safe(p, 65536)
        timestamps: list[int] = []
        for line in content.splitlines():
            m = _HISTTIMEFORMAT_TS.match(line.strip())
            if m:
                try:
                    timestamps.append(int(m.group(1)))
                except ValueError:
                    continue
        if len(timestamps) < 5:
            continue
        deltas = [b - a for a, b in zip(timestamps, timestamps[1:])]
        # consider only positive deltas (history may include resets)
        deltas = [d for d in deltas if 0 < d < 86400]
        if not deltas:
            continue
        sub2 = sum(1 for d in deltas if d < 2)
        ratio = sub2 / len(deltas)
        if ratio >= 0.5 and len(deltas) >= 5:
            findings.append(
                AISignatureFinding(
                    severity="high",
                    category="machine_speed_history",
                    path=_rel(root, p),
                    summary=f"machine-speed bash history ({sub2}/{len(deltas)} deltas under 2s, {ratio:.0%})",
                    reasons=[
                        "consecutive commands fired faster than human typing rate",
                        "consistent with agent/automated execution, not interactive use",
                    ],
                    sample=content[:400].rstrip(),
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Aggregator + MCP tool
# ---------------------------------------------------------------------------


def scan_all_ai(root: Path) -> list[AISignatureFinding]:
    findings: list[AISignatureFinding] = []
    findings.extend(scan_llm_api_references(root))
    findings.extend(scan_agent_paths(root))
    findings.extend(scan_tool_call_jsonl(root))
    findings.extend(scan_polished_scripts(root))
    findings.extend(scan_machine_speed_history(root))
    return findings


_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
_SEVERITY_ICON = {"high": "🚨", "medium": "⚠", "low": "·"}


def _format_findings(findings: list[AISignatureFinding], root: Path) -> str:
    if not findings:
        return f"No AI/agent-driven adversary signatures found under `{root}`."
    sorted_findings = sorted(findings, key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.category, f.path))
    counts: dict[str, int] = {}
    for f in sorted_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    lines = [
        f"# AI / agent-driven adversary signatures — `{root}`",
        "",
        "## Summary",
        "",
        *[f"- **{sev}**: {counts[sev]} finding(s)" for sev in ("high", "medium", "low") if sev in counts],
        "",
    ]
    current_sev: str | None = None
    for f in sorted_findings:
        if f.severity != current_sev:
            lines.append(f"## {_SEVERITY_ICON.get(f.severity, '·')} {f.severity.upper()} findings")
            lines.append("")
            current_sev = f.severity
        lines.append(f"### `{f.path}` — {f.summary}")
        lines.append(f"- **Category:** {f.category}")
        if f.reasons:
            lines.append("- **Reasons:**")
            for r in f.reasons:
                lines.append(f"  - {r}")
        if f.sample:
            lines.append("")
            lines.append("```")
            lines.append(f.sample)
            lines.append("```")
        lines.append("")
    return "\n".join(lines)


@mcp.tool()
def find_ai_signatures(root_path: str) -> str:
    """Scan a Linux filesystem root for forensic signatures of LLM-driven adversaries.

    Detects six classes of artifact distinctive of agentic/AI-driven intrusions:

    1. **LLM API destinations** — references to `api.anthropic.com`,
       `api.openai.com`, `api.deepseek.com`, `claude.ai`, etc. in env files,
       configs, cron entries, scripts, or systemd units.
    2. **LLM API key declarations** — `ANTHROPIC_API_KEY=`, `OPENAI_API_KEY=`,
       and similar environment-variable assignments.
    3. **Agent runtime artifacts** — `.claude/projects/`, `.agent_cache/`,
       `agent_tasks.jsonl`, `llm_session_*` files, `~/.config/claude` etc.
    4. **Tool-call schema JSONL** — `.jsonl` files containing
       `tool_use`/`tool_result`/`tool_calls` keys characteristic of LLM
       agent transcripts.
    5. **AI-polished scripts** — bash scripts that combine `set -euo pipefail`,
       `readonly` constants, and parallel-execution primitives (xargs -P,
       GNU parallel, export -f, EXIT traps). Three or more idioms together
       is more polish than humans typically apply to ad-hoc scripts.
    6. **Machine-speed bash history** — extended-history blocks where
       consecutive command timestamps differ by less than 2 seconds for
       a majority of entries. Humans take longer to type independent commands.

    A finding here is a *tradecraft signal*, not direct proof of compromise.
    Combine with persistence/auth findings to confirm an intrusion and
    classify it as agent-operated. False positives are possible on hosts
    that legitimately run AI tooling (developer workstations, MLOps boxes).

    Args:
        root_path: Filesystem root to scan (must be inside the evidence directory)

    Returns:
        Markdown report grouped by severity and category.
    """
    try:
        validated = _validate_evidence_path(root_path)
    except ValueError as e:
        return f"Error: {e}"
    if not validated.is_dir():
        return f"Not a directory: {root_path}"

    findings = scan_all_ai(validated)
    result = _format_findings(findings, validated)

    high = sum(1 for f in findings if f.severity == "high")
    _audit(
        "find_ai_signatures",
        {"root_path": root_path},
        f"{len(findings)} findings ({high} high)",
    )
    return result
