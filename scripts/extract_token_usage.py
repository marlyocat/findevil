#!/usr/bin/env python3
"""Extract per-tool token usage from a Claude Code session transcript.

Why this lives at the agent layer, not in the MCP server
---------------------------------------------------------
Token usage is an LLM-side concept. The findevil MCP server only ever sees
tool *calls* — it has no visibility into how many tokens Claude spent
deciding to make them or digesting their results. So the mechanical tool
trail (``logs/audit.json``) records *what was executed and when*, and this
script recovers *what it cost* from Claude Code's own session transcript,
then correlates the two.

The hackathon's Component 8 asks single-agent submissions for "tool
execution logs with timestamps and token usage [...] trace any finding back
to the specific tool execution that produced it." Together,
``audit.json`` (timestamps + params + result summary, per tool call) and
``token_usage.jsonl`` (token usage of the turn each tool call belonged to)
provide exactly that.

Claude Code writes one JSONL transcript per session under
``~/.claude/projects/<slugified-cwd>/<session-uuid>.jsonl``. Each assistant
turn carries a ``message.usage`` block (input/output/cache token counts) and
``message.content`` ``tool_use`` blocks naming the tools invoked that turn.

Usage
-----
    python scripts/extract_token_usage.py                 # auto-pick session
    python scripts/extract_token_usage.py --session UUID  # specific session
    python scripts/extract_token_usage.py --transcript /path/to/file.jsonl
    python scripts/extract_token_usage.py --all           # every session, merged

Outputs (under FINDEVIL_LOGS_DIR, default ./logs):
    token_usage.jsonl          one record per assistant turn that called >=1
                               findevil tool: timestamp, model, tools, usage
    token_usage_summary.md     grand totals + per-tool call counts

Dependency-free (stdlib only), read-only, never touches evidence.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

TOOL_PREFIX = "mcp__findevil__"


def _default_project_dir() -> Path:
    """Claude Code slugifies the cwd by replacing each '/' with '-'."""
    cwd = Path.cwd().resolve()
    slug = str(cwd).replace("/", "-")
    return Path.home() / ".claude" / "projects" / slug


def _findevil_calls(line_obj: dict) -> list[dict]:
    """Return the findevil tool_use blocks in an assistant message, if any."""
    msg = line_obj.get("message")
    if not isinstance(msg, dict):
        return []
    calls = []
    for block in msg.get("content") or []:
        if (
            isinstance(block, dict)
            and block.get("type") == "tool_use"
            and str(block.get("name", "")).startswith(TOOL_PREFIX)
        ):
            calls.append(
                {
                    "name": block["name"][len(TOOL_PREFIX) :],
                    "params": block.get("input", {}),
                    "tool_use_id": block.get("id"),
                }
            )
    return calls


def _usage(line_obj: dict) -> dict:
    msg = line_obj.get("message")
    if not isinstance(msg, dict):
        return {}
    u = msg.get("usage")
    if not isinstance(u, dict):
        return {}
    inp = int(u.get("input_tokens", 0) or 0)
    out = int(u.get("output_tokens", 0) or 0)
    cache_read = int(u.get("cache_read_input_tokens", 0) or 0)
    cache_creation = int(u.get("cache_creation_input_tokens", 0) or 0)
    return {
        "input_tokens": inp,
        "output_tokens": out,
        "cache_read_input_tokens": cache_read,
        "cache_creation_input_tokens": cache_creation,
        # full context billed for this turn = fresh input + both cache classes
        "total_input_tokens": inp + cache_read + cache_creation,
        "total_tokens": inp + cache_read + cache_creation + out,
    }


def _model(line_obj: dict) -> str:
    msg = line_obj.get("message")
    return msg.get("model", "") if isinstance(msg, dict) else ""


def process_transcript(path: Path) -> list[dict]:
    """Yield one record per assistant turn that invoked >=1 findevil tool."""
    records = []
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("type") != "assistant":
                continue
            calls = _findevil_calls(obj)
            if not calls:
                continue
            records.append(
                {
                    "timestamp": obj.get("timestamp"),
                    "session": obj.get("sessionId"),
                    "request_id": obj.get("requestId"),
                    "model": _model(obj),
                    "tools": calls,
                    "tool_count": len(calls),
                    "usage": _usage(obj),
                }
            )
    return records


def discover_transcripts(args) -> list[Path]:
    if args.transcript:
        return [Path(args.transcript)]
    project_dir = Path(args.project_dir) if args.project_dir else _default_project_dir()
    if not project_dir.is_dir():
        sys.exit(f"No Claude Code project dir found at {project_dir}")
    if args.session:
        p = project_dir / f"{args.session}.jsonl"
        if not p.is_file():
            sys.exit(f"Session transcript not found: {p}")
        return [p]
    all_t = sorted(project_dir.glob("*.jsonl"))
    if not all_t:
        sys.exit(f"No transcripts under {project_dir}")
    if args.all:
        return all_t
    # Default: the single transcript with the most findevil tool calls
    # (i.e. the real investigation session, not a chat about the project).
    best, best_n = None, -1
    for t in all_t:
        n = sum(r["tool_count"] for r in process_transcript(t))
        if n > best_n:
            best, best_n = t, n
    if best_n <= 0:
        sys.exit(
            "No findevil tool calls found in any transcript under "
            f"{project_dir}. Run an investigation first, or pass --session."
        )
    return [best]


def write_outputs(records: list[dict], logs_dir: Path) -> dict:
    logs_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = logs_dir / "token_usage.jsonl"
    with jsonl_path.open("w") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")

    # Aggregate
    per_tool: dict[str, int] = {}
    totals = {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_input_tokens": 0,
        "cache_creation_input_tokens": 0,
        "total_tokens": 0,
    }
    for rec in records:
        for c in rec["tools"]:
            per_tool[c["name"]] = per_tool.get(c["name"], 0) + 1
        for k in totals:
            totals[k] += rec["usage"].get(k, 0)
    total_calls = sum(per_tool.values())

    lines = [
        "# Agent token-usage trail",
        "",
        "Generated by `scripts/extract_token_usage.py` from the Claude Code",
        "session transcript. Token usage is an agent-layer quantity (the MCP",
        "server cannot observe it); this report correlates it with the",
        "mechanical tool trail in `audit.json`. See `logs/README.md`.",
        "",
        "## Totals",
        "",
        f"- Assistant turns invoking findevil tools: **{len(records)}**",
        f"- findevil tool executions: **{total_calls}**",
        f"- Output tokens (generation): **{totals['output_tokens']:,}**",
        f"- Fresh input tokens: **{totals['input_tokens']:,}**",
        f"- Cache-read input tokens: **{totals['cache_read_input_tokens']:,}**",
        f"- Cache-creation input tokens: **{totals['cache_creation_input_tokens']:,}**",
        f"- Total tokens (input+cache+output): **{totals['total_tokens']:,}**",
        "",
        "## Tool executions by tool",
        "",
        "| Tool | Calls |",
        "|------|-------|",
    ]
    for name, n in sorted(per_tool.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"| `{name}` | {n} |")
    lines.append("")
    summary_path = logs_dir / "token_usage_summary.md"
    summary_path.write_text("\n".join(lines))

    return {
        "jsonl": jsonl_path,
        "summary": summary_path,
        "turns": len(records),
        "calls": total_calls,
        "totals": totals,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--session", help="session UUID (filename stem) to parse")
    ap.add_argument("--transcript", help="explicit path to a .jsonl transcript")
    ap.add_argument("--project-dir", help="override the Claude Code project dir")
    ap.add_argument("--all", action="store_true", help="merge every session")
    args = ap.parse_args()

    transcripts = discover_transcripts(args)
    records: list[dict] = []
    for t in transcripts:
        records.extend(process_transcript(t))
    records.sort(key=lambda r: r.get("timestamp") or "")

    logs_dir = Path(os.environ.get("FINDEVIL_LOGS_DIR", "./logs")).resolve()
    out = write_outputs(records, logs_dir)

    print(f"Parsed {len(transcripts)} transcript(s):")
    for t in transcripts:
        print(f"  - {t}")
    print(f"Wrote {out['jsonl']}  ({out['turns']} turns, {out['calls']} tool calls)")
    print(f"Wrote {out['summary']}")
    print(
        f"Total tokens: {out['totals']['total_tokens']:,} "
        f"(output {out['totals']['output_tokens']:,})"
    )


if __name__ == "__main__":
    main()
