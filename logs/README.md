# Agent execution logs

FindEvil is a **single-agent** submission (Claude Code + a custom MCP
server). Per the hackathon's Component 8, this directory provides "tool
execution logs with timestamps and token usage" and lets a judge "trace
any finding back to the specific tool execution that produced it."

Because token usage is an LLM-side quantity that the MCP server cannot
observe, the trail is split across two complementary, layered files:

| File | Layer | Written by | Contains |
|------|-------|------------|----------|
| `audit.json` | MCP server (mechanical) | every tool call, automatically via `_audit()` in `src/findevil/server.py` | ISO-8601 `timestamp`, `tool`, `params`, `result_summary` — one line per tool execution |
| `token_usage.jsonl` | Claude Code agent | `scripts/extract_token_usage.py` (post-hoc, from the session transcript) | per assistant turn: `timestamp`, `model`, findevil `tools` invoked (+ params + `tool_use_id`), and the turn's `usage` (input / output / cache-read / cache-creation / totals) |
| `token_usage_summary.md` | Claude Code agent | same script | grand totals + per-tool call counts |

## Why two files instead of one

The MCP server sees *what was executed and when* but never *what it
cost* — tokens are spent by Claude Code deciding to call a tool and
digesting its result, entirely outside the server process. Rather than
fabricate a token estimate inside the server, `audit.json` records the
mechanical truth and `token_usage.jsonl` recovers the real token counts
from Claude Code's own session transcript
(`~/.claude/projects/<slug>/<session>.jsonl`). This keeps each layer
honest about what it can actually measure.

## Tracing a finding back to its tool execution

1. A finding in the IR report cites a tool + evidence line number.
2. `audit.json` has the matching entry: exact `timestamp`, `tool`, and
   `params` used.
3. `token_usage.jsonl` has the assistant turn at that timestamp: the
   `tool_use_id`, the model, and the token usage that turn cost.

`get_audit_trail` (an MCP tool) lets the agent introspect `audit.json`
live during an investigation; this directory is the same trail on disk.

## Regenerating the token trail

```bash
# Auto-selects the session transcript with the most findevil tool calls
python scripts/extract_token_usage.py

# Or target a specific session / transcript / merge all sessions
python scripts/extract_token_usage.py --session <uuid>
python scripts/extract_token_usage.py --transcript /path/to/file.jsonl
python scripts/extract_token_usage.py --all
```

The script is read-only and stdlib-only. It honors `FINDEVIL_LOGS_DIR`
for its output location, matching the server.
