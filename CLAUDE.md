# FindEvil

Autonomous AI agent for **Linux incident response forensics**, built for the FIND EVIL! hackathon (SANS Institute).

## What this is

An MCP (Model Context Protocol) server that wraps Linux forensic tools as typed, read-only, audited functions. Claude Code connects to this server and uses the tools to autonomously triage Linux systems compromised by attackers.

## Why Linux-focused

Most DFIR tooling targets Windows workstations. But the systems attackers actually target in practice — web servers, Kubernetes clusters, cloud VMs — run Linux. FindEvil fills that gap, built from an SRE's perspective on what's normal vs anomalous in a production Linux environment.

## Scope

**In scope:**
- Linux log analysis (auth.log, syslog, journalctl, audit logs)
- Persistence mechanisms (cron, systemd, bashrc, authorized_keys, LD_PRELOAD)
- Process and network forensics (if live system or memory dump)
- Container artifacts (Docker, containerd, Kubernetes audit logs)
- Rootkit detection (modified binaries, hidden processes, kernel modules)
- Bash/shell history analysis
- Package manager logs (apt, dpkg, yum)
- Filesystem artifacts on ext4/xfs

**Out of scope:**
- Windows artifacts (event logs, registry, prefetch, MFT)
- Memory forensics on Windows (Volatility Windows plugins)
- Network packet capture analysis
- Mobile/cloud-provider-specific forensics (except container and k8s artifacts)

## Architecture

- **MCP Server** (`src/findevil/server.py`): Exposes forensic tools as MCP tools
- **Tools** (`src/findevil/tools/`): Individual tool modules grouped by forensic domain
- **Evidence** (`evidence/`): Mount point for forensic images — NEVER committed to git
- **Logs** (`logs/`): Audit trail of all tool invocations — JSON format with timestamps

## Key rules

- **READ-ONLY**: Tools must NEVER modify evidence files. This is non-negotiable for forensic integrity.
- **Path validation**: All file access must go through `_validate_evidence_path()` to prevent path traversal.
- **Audit everything**: Every tool invocation must call `_audit()` with tool name, parameters, and result summary.
- **Structured output**: Tools return formatted strings, not raw subprocess output. Include section headers.
- **Timeout**: All subprocess calls must have a timeout. Default 120s, adjust per tool.

## Autonomous investigation SOP

When investigating evidence, work the case end to end on your own — do
not wait for step-by-step instructions, and do not wait to be told to
check yourself. Run this loop until it terminates:

1. **Orient** — `list_evidence` to inventory what's available.
2. **Investigate** — form a hypothesis and run the relevant typed tools.
   Treat every finding as a lead: when a tool surfaces an IOC (IP, user,
   hash, path, domain), **pivot before moving on** — `extract_iocs` /
   `bulk_ioc_lookup` it and search it across the other evidence.
3. **Assess** — call `assess_coverage` (pass findings so far as
   `findings_json`). It reports gaps grounded in the audit trail:
   unexamined artifacts, un-pivoted IOCs, unverified CONFIRMED claims. If
   gaps remain, go back to step 2. Repeat until it returns COVERAGE CLEAN.
4. **Finalize** — assemble findings as structured claims and call
   `finalize_report`. It is the ONLY sanctioned way to emit conclusions
   and it will **reject** any CONFIRMED claim that fails independent
   verification or contradicts another. When rejected, re-investigate to
   support the claim OR downgrade its confidence to `inference` /
   `uncertain`, then call `finalize_report` again. Only a claim that
   survives the gate may be stated as CONFIRMED in the report.

Prefer "cannot determine from available evidence" over speculation. You
are not done until `assess_coverage` is clean and `finalize_report` has
ACCEPTED your claims. For unattended runs, `scripts/investigate.py`
drives this same loop headlessly with a hard `--max-iterations` cap.

## Development

```bash
# Install dependencies
pip install -e ".[dev]"

# Run MCP server (stdio transport for Claude Code)
python -m findevil.server

# Run tests
pytest tests/

# Lint
ruff check src/ tests/
```

## SIFT tools we wrap (Linux-focused)

The server runs inside a SANS SIFT Workstation VM. Tools we'll use:

**Core Linux utilities:**
- `grep`, `find`, `awk`, `sed`, `sort`, `uniq` — log searching and parsing
- `file`, `stat`, `strings`, `xxd`, `md5sum`, `sha256sum` — file analysis
- `journalctl`, `last`, `lastb` — log inspection
- `auditctl`, `ausearch` — audit log parsing
- `lsof`, `ss`, `netstat`, `ps` — runtime state (if live system)

**Forensic tools on SIFT:**
- `sleuthkit` (fls, icat, mmls, fsstat) — ext4/xfs filesystem analysis
- `bulk_extractor` — extract IOCs (emails, IPs, URLs) from any blob
- `yara` — pattern matching for Linux malware signatures
- `plaso`/`log2timeline` — timeline generation across Linux artifacts
- `chkrootkit`, `rkhunter` — rootkit detection

**Common Linux IR artifacts:**
- `/var/log/*` — auth, syslog, kern, dpkg, apt, nginx, apache, etc.
- `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d/` — accounts
- `~/.ssh/authorized_keys`, `/root/.ssh/authorized_keys` — SSH access
- `~/.bash_history`, `~/.zsh_history` — command history
- `/etc/cron*`, `/var/spool/cron/*` — scheduled tasks
- `/etc/systemd/system/`, `~/.config/systemd/user/` — persistence via services
- `/etc/rc.local`, `/etc/init.d/` — legacy init persistence
- `/etc/ld.so.preload` — library preload persistence
- `/proc/*` (live only) — process state, network connections, loaded modules

## Adding a new tool

1. Create a function in the appropriate module under `src/findevil/tools/`
2. Decorate with `@mcp.tool()`
3. Validate paths with `_validate_evidence_path()`
4. Log with `_audit()`
5. Write a test in `tests/`
