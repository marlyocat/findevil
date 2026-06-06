"""
Linux memory-capture forensics via Volatility 3.

The hackathon brief lists memory captures as a first-class data type
alongside disk images, log files, and network captures. The most
sophisticated Linux malware (Symbiote, BPFDoor, Drovorub-style LKM
rootkits, in-memory ELF loaders) leaves its *primary* indicators in
RAM, not on disk — meaning a disk-only investigation can miss the
attack entirely.

This module wraps the Volatility 3 Linux plugin family as typed MCP
tools so the agent can correlate memory state with the on-disk
findings produced by `find_persistence` and friends. Seven tools:

- `analyze_memory_summary(dump)` — high-level triage. Identifies the
  kernel from `banners.Banners`, then runs the four most useful
  plugins in sequence and produces a verdict.
- `analyze_memory_processes(dump)` — process list (linux.pslist),
  parent/child relationships, processes with no parent or unusual
  comm names.
- `analyze_memory_network(dump)` — open network connections at
  capture time (linux.netstat). Surfaces listening services not in
  the disk image's systemd state and outbound connections to
  non-RFC1918 destinations.
- `analyze_memory_modules(dump)` — `linux.lsmod` AND `linux.check_modules`
  side-by-side. If a module shows in `check_modules` but not `lsmod`,
  it's a hidden module — a high-confidence rootkit indicator.
- `analyze_memory_bash_history(dump)` — `linux.bash`. Recovers shell
  history fragments from process heap even when `~/.bash_history`
  was wiped on disk.
- `analyze_memory_malfind(dump)` — `linux.malfind`. Detects code
  injection / shellcode in process memory regions (RWX maps without
  a backing file, suspicious entropy patterns).
- `correlate_memory_and_disk(dump, fs_root)` — cross-checks live
  memory state against the disk-side persistence findings; surfaces
  discrepancies (e.g., a module listed in /etc/modules but absent
  from the running kernel, or a running process with no on-disk
  binary backing).

Volatility 3 needs a kernel symbol table matched to the captured
kernel version. We surface that requirement clearly when missing and
do not crash. Symbol tables can be acquired via:
  - downloading from the Volatility 3 ISF cache (banners → symbols)
  - building locally with `dwarf2json` from the kernel's debug symbols
  - shipping with the dump as part of a forensic evidence bundle
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from findevil.server import _audit, _validate_evidence_path, mcp

# ---------------------------------------------------------------------------
# Configuration + helpers
# ---------------------------------------------------------------------------


def _resolve_vol_bin() -> str:
    """Find the Volatility 3 entrypoint.

    Order of preference:
      1. FINDEVIL_VOL env var (explicit override)
      2. `vol` / `vol.py` on $PATH
      3. The findevil venv's own bin/ (so installs into the project venv work
         even when the venv is not activated by the calling shell)
      4. Fall back to "vol" so the no-such-binary error message is clean
    """
    override = os.environ.get("FINDEVIL_VOL")
    if override and Path(override).is_file():
        return override
    for name in ("vol", "vol.py"):
        found = shutil.which(name)
        if found:
            return found
    # Note: do NOT call .resolve() here — venv pythons are typically
    # symlinks to the system interpreter, and resolving that symlink
    # leaks back to the system bin dir where `vol` likely isn't.
    venv_bin = Path(sys.executable).parent
    for name in ("vol", "vol.py"):
        cand = venv_bin / name
        if cand.is_file():
            return str(cand)
    return "vol"


_VOL_BIN = _resolve_vol_bin()
_VOL_TIMEOUT_S = 600  # 10 minutes — memory analysis can be slow on large dumps
_VOL_NO_SYMBOLS_HINT = (
    "Volatility could not find a kernel symbol table for this dump. "
    "Populate `~/.cache/volatility3/symbols/linux/` with the matching "
    "ISF (Intermediate Symbol Format) JSON, or build one from the "
    "kernel debug symbols via `dwarf2json linux --elf <vmlinux> "
    "> ~/.cache/volatility3/symbols/linux/<name>.json`. Note: Vol3 "
    "uses `~/.cache/`, not `~/.local/share/`, despite some older "
    "documentation. Without symbols, no plugin can resolve kernel "
    "structures."
)


@dataclass
class VolResult:
    """Outcome of one `vol -f <dump> <plugin>` invocation."""

    plugin: str
    rc: int
    stdout: str
    stderr: str
    rows: list[dict]  # parsed JSON if --output=json succeeded; else []
    no_symbols: bool  # True if vol failed for symbol-table reasons


def _vol_available() -> bool:
    if not _VOL_BIN:
        return False
    try:
        proc = subprocess.run(
            [_VOL_BIN, "--help"],
            capture_output=True, text=True, timeout=10,
        )
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _looks_like_no_symbols(stderr: str) -> bool:
    """Recognise the 'no kernel symbols' family of vol3 error messages."""
    s = stderr.lower()
    return (
        "could not find a suitable kernel symbol" in s
        or "unable to validate the plugin requirements" in s
        or "no available symbol table" in s
        or "symbols requirement" in s
    )


def _run_vol_plugin(
    dump_path: Path, plugin: str, *extra_args: str, json_output: bool = True
) -> VolResult:
    """Run one Volatility 3 plugin against a memory dump.

    Returns a VolResult that distinguishes plugin success, plugin failure,
    and the specific 'no kernel symbols' failure (which the agent should
    surface clearly to the operator rather than treat as 'memory clean').
    """
    if not _vol_available():
        return VolResult(
            plugin=plugin, rc=127,
            stdout="", stderr="volatility3 (`vol`) not installed on PATH",
            rows=[], no_symbols=False,
        )

    cmd = [_VOL_BIN, "-q", "-f", str(dump_path)]
    if json_output:
        cmd += ["-r", "json"]
    cmd += [plugin, *extra_args]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=_VOL_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return VolResult(
            plugin=plugin, rc=124,
            stdout="", stderr=f"vol {plugin} timed out after {_VOL_TIMEOUT_S}s",
            rows=[], no_symbols=False,
        )
    except OSError as e:
        return VolResult(
            plugin=plugin, rc=126,
            stdout="", stderr=f"vol invocation failed: {e}",
            rows=[], no_symbols=False,
        )

    rows: list[dict] = []
    if json_output and proc.returncode == 0 and proc.stdout.strip():
        try:
            parsed = json.loads(proc.stdout)
            if isinstance(parsed, list):
                rows = [r for r in parsed if isinstance(r, dict)]
        except json.JSONDecodeError:
            # vol3 occasionally emits warnings before the JSON; try recovery
            m = re.search(r"^\s*(\[.*\])\s*$", proc.stdout, re.S | re.M)
            if m:
                try:
                    parsed = json.loads(m.group(1))
                    if isinstance(parsed, list):
                        rows = [r for r in parsed if isinstance(r, dict)]
                except json.JSONDecodeError:
                    pass

    return VolResult(
        plugin=plugin,
        rc=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        rows=rows,
        no_symbols=proc.returncode != 0 and _looks_like_no_symbols(proc.stderr),
    )


def _validate_dump(memory_dump_path: str) -> tuple[Path | None, str | None]:
    """Validate the dump path is inside the evidence directory and exists."""
    try:
        validated = _validate_evidence_path(memory_dump_path)
    except ValueError as e:
        return None, f"Error: {e}"
    if not validated.is_file():
        return None, f"Memory dump file not found: {memory_dump_path}"
    return validated, None


# ---------------------------------------------------------------------------
# Kernel banner identification
# ---------------------------------------------------------------------------


def _identify_kernel(dump: Path) -> tuple[str, list[str]]:
    """Run banners.Banners and return (best_banner, all_banners).

    The kernel banner determines which symbol table Volatility needs.
    Returning the banner gives the agent something to act on if symbols
    are missing.
    """
    res = _run_vol_plugin(dump, "banners.Banners", json_output=True)
    banners: list[str] = []
    for row in res.rows:
        b = row.get("Banner") or row.get("banner")
        if isinstance(b, str) and b.strip():
            banners.append(b.strip())
    # Prefer the longest Linux banner (kernel header banner is usually verbose)
    linux_banners = [b for b in banners if "Linux version" in b]
    best = max(linux_banners, key=len) if linux_banners else (banners[0] if banners else "")
    return best, banners


# ---------------------------------------------------------------------------
# Per-plugin classification
# ---------------------------------------------------------------------------


_SUSPICIOUS_PROCESS_NAMES = {
    # Common malware-named processes (case-insensitive)
    "kdevtmpfsi", "kinsing", "xmrig", "cpuminer", "cryptonight", "ccminer",
    "kthrotlds", "kdmtmpflush", "haldrund", "watchdog-init",
    ".x", ".update", ".busybox", ".libhide.so",
}


def _classify_processes(rows: list[dict]) -> tuple[list[dict], list[str]]:
    """Return (processes, anomalies)."""
    procs = []
    anomalies = []
    seen_pids: set[int] = set()
    for row in rows:
        pid = row.get("PID") or row.get("Pid")
        ppid = row.get("PPID") or row.get("Ppid")
        comm = row.get("COMM") or row.get("Comm") or row.get("Process") or "?"
        try:
            pid_i = int(pid) if pid is not None else None
            ppid_i = int(ppid) if ppid is not None else None
        except (TypeError, ValueError):
            pid_i = ppid_i = None
        proc_obj = {"pid": pid_i, "ppid": ppid_i, "comm": str(comm)}
        procs.append(proc_obj)
        if pid_i is not None:
            seen_pids.add(pid_i)
        if isinstance(comm, str) and comm.lower() in _SUSPICIOUS_PROCESS_NAMES:
            anomalies.append(f"PID {pid_i}: known-bad process name `{comm}`")

    # Process whose parent is missing from the snapshot (orphaned by a parent kill)
    for p in procs:
        if p["ppid"] is not None and p["ppid"] != 0 and p["ppid"] not in seen_pids:
            anomalies.append(
                f"PID {p['pid']} (`{p['comm']}`) has PPID={p['ppid']} not present in snapshot"
            )

    return procs, anomalies


def _classify_network(rows: list[dict]) -> list[str]:
    """Return human-readable findings for suspicious network state.

    Vol3 v2.28's `linux.sockstat.Sockstat` uses Source/Destination naming:
        `Source Addr`, `Source Port`, `Destination Addr`, `Destination Port`,
        `Family`, `Proto`, `Process Name`, `State`.
    The older `linux.netstat` used Local/Foreign naming:
        `Local IP`, `Local Port`, `Foreign IP`, `Foreign Port`,
        `Protocol`, `State`.
    Both shapes are accepted.
    """
    findings = []
    for row in rows:
        # Filter to inet sockets only — netlink/unix sockets don't have IP ports
        family = str(row.get("Family", "")).upper()
        if family and not family.startswith("AF_INET"):
            continue

        local_port_raw = row.get("Source Port") or row.get("Local Port") or row.get("LocalPort")
        remote = (row.get("Destination Addr") or row.get("Foreign IP")
                  or row.get("ForeignAddr") or row.get("Remote IP") or "")
        remote_port = (row.get("Destination Port") or row.get("Foreign Port")
                       or row.get("RemotePort") or row.get("Remote Port"))
        state = row.get("State", "?")
        proto = row.get("Proto") or row.get("Protocol") or "?"

        # Coerce ports to int — sockstat returns them as strings, netstat as ints
        try:
            local_port = int(local_port_raw) if local_port_raw not in (None, "") else None
        except (ValueError, TypeError):
            local_port = None

        # Listeners on unusual ports
        if state == "LISTEN" and isinstance(local_port, int):
            if local_port in (4444, 4445, 1337, 31337, 8888, 9001, 6666, 13337):
                findings.append(
                    f"⚠ {proto} listener on unusual port {local_port} "
                    "(often used by reverse-shell handlers)"
                )

        # Outbound to non-RFC1918 with suspicious state
        if state in ("ESTABLISHED", "SYN_SENT") and isinstance(remote, str) and remote:
            if not _is_rfc1918(remote) and remote not in ("127.0.0.1", "::1", "0.0.0.0"):
                rport_text = f":{remote_port}" if remote_port else ""
                findings.append(
                    f"⚠ outbound {proto} to {remote}{rport_text} (non-RFC1918, state={state})"
                )
    return findings


def _is_rfc1918(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        o = [int(p) for p in parts]
    except ValueError:
        return False
    if o[0] == 10:
        return True
    if o[0] == 172 and 16 <= o[1] <= 31:
        return True
    if o[0] == 192 and o[1] == 168:
        return True
    if o[0] == 127:
        return True
    return False


def _diff_modules(lsmod_rows: list[dict], check_rows: list[dict]) -> dict:
    """Compare linux.lsmod and linux.check_modules to find hidden modules.

    A module that appears in `check_modules` (which walks kernel structures
    directly) but NOT in `lsmod` (which uses the canonical loaded-modules
    list a rootkit can hide from) is the classic hidden-LKM signature.

    Vol3 v2.28 uses "Module Name" (with a space) for linux.lsmod output.
    Older variants use "Name" or "Module". We accept all three.
    """
    def _mod_name(row: dict) -> str:
        n = row.get("Module Name") or row.get("Name") or row.get("Module")
        return str(n) if n else ""

    lsmod_names = {_mod_name(r).lower() for r in lsmod_rows if _mod_name(r)}
    check_names = {_mod_name(r).lower() for r in check_rows if _mod_name(r)}

    only_in_check = sorted(check_names - lsmod_names)
    only_in_lsmod = sorted(lsmod_names - check_names)
    both = sorted(check_names & lsmod_names)

    return {
        "loaded_modules": sorted(lsmod_names),
        "check_modules": sorted(check_names),
        "hidden_modules": only_in_check,
        "only_in_lsmod": only_in_lsmod,
        "both": both,
    }


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------


def _format_no_symbols_block(banner: str) -> str:
    parts = [
        "## ⚠ Kernel symbols required",
        "",
        _VOL_NO_SYMBOLS_HINT,
        "",
    ]
    if banner:
        parts.append(f"**Kernel banner detected:** `{banner[:200]}`")
    return "\n".join(parts)


@mcp.tool()
def analyze_memory_processes(memory_dump_path: str) -> str:
    """List processes recovered from a Linux memory dump.

    Wraps Volatility 3's `linux.pslist`. Surfaces every process the kernel
    had at capture time, the PID/PPID parent-child relationship, command
    name, and flags two anomalies:

    - Processes whose parent PID is not present in the snapshot (orphaned
      by a parent that was killed before capture — sometimes a sign of a
      detached daemon or a process that hid its parent).
    - Process command names matching a small known-bad list (Kinsing's
      `kdevtmpfsi`, TeamTNT's `kthrotlds`, BPFDoor's `kdmtmpflush`, etc.).

    Args:
        memory_dump_path: Path to a Linux memory dump (.lime / .raw / .vmem)
            inside the evidence directory.

    Returns:
        Markdown report listing processes, PID hierarchy, and anomalies.
    """
    dump, err = _validate_dump(memory_dump_path)
    if err:
        return err
    res = _run_vol_plugin(dump, "linux.pslist")
    if res.no_symbols:
        banner, _ = _identify_kernel(dump)
        out = _format_no_symbols_block(banner)
        _audit("analyze_memory_processes", {"path": memory_dump_path}, "no symbols")
        return out
    if res.rc != 0:
        _audit("analyze_memory_processes", {"path": memory_dump_path}, f"rc={res.rc}")
        return (
            f"# Memory processes — `{memory_dump_path}`\n\n"
            f"vol failed (rc={res.rc}):\n```\n{res.stderr[:500]}\n```"
        )

    procs, anomalies = _classify_processes(res.rows)
    lines = [
        f"# Memory processes — `{memory_dump_path}`",
        "",
        f"- **Total processes:** {len(procs)}",
        f"- **Anomalies:** {len(anomalies)}",
        "",
    ]
    if anomalies:
        lines.append("## ⚠ Anomalies")
        for a in anomalies:
            lines.append(f"- {a}")
        lines.append("")

    lines.append("## Process list (first 60)")
    lines.append("| PID | PPID | COMM |")
    lines.append("|-----|------|------|")
    for p in procs[:60]:
        lines.append(f"| {p['pid']} | {p['ppid']} | `{p['comm']}` |")
    if len(procs) > 60:
        lines.append(f"\n*({len(procs) - 60} more processes truncated)*")

    _audit(
        "analyze_memory_processes", {"path": memory_dump_path},
        f"{len(procs)} procs, {len(anomalies)} anomalies",
    )
    return "\n".join(lines)


@mcp.tool()
def analyze_memory_network(memory_dump_path: str) -> str:
    """List network connections recovered from a Linux memory dump.

    Wraps `linux.netstat`. Surfaces every TCP/UDP/UNIX socket the kernel
    knew about at capture time. Flags listeners on common reverse-shell
    handler ports (4444, 4445, 1337, 31337, 8888, 9001, 6666, 13337)
    and outbound connections to non-RFC1918 destinations, since live
    network state is often the only place to see a rootkit's C2.

    Args:
        memory_dump_path: Path to a Linux memory dump inside the evidence
            directory.

    Returns:
        Markdown report listing sockets and flagged connections.
    """
    dump, err = _validate_dump(memory_dump_path)
    if err:
        return err
    # Vol3 v2.28 renamed linux.netstat -> linux.sockstat.Sockstat. Try
    # the new name first; fall back to the old name for older Vol3 builds.
    res = _run_vol_plugin(dump, "linux.sockstat.Sockstat")
    if res.rc != 0 and "invalid choice" in res.stderr.lower():
        res = _run_vol_plugin(dump, "linux.netstat")
    if res.no_symbols:
        banner, _ = _identify_kernel(dump)
        out = _format_no_symbols_block(banner)
        _audit("analyze_memory_network", {"path": memory_dump_path}, "no symbols")
        return out
    if res.rc != 0:
        _audit("analyze_memory_network", {"path": memory_dump_path}, f"rc={res.rc}")
        return (
            f"# Memory network — `{memory_dump_path}`\n\n"
            f"vol failed (rc={res.rc}):\n```\n{res.stderr[:500]}\n```"
        )

    findings = _classify_network(res.rows)
    lines = [
        f"# Memory network state — `{memory_dump_path}`",
        "",
        f"- **Sockets observed:** {len(res.rows)}",
        f"- **Flagged connections:** {len(findings)}",
        "",
    ]
    if findings:
        lines.append("## ⚠ Flagged")
        for f in findings:
            lines.append(f"- {f}")
        lines.append("")

    lines.append("## All sockets (first 50)")
    lines.append("| Family | Proto | Local | Remote | State | Process |")
    lines.append("|--------|-------|-------|--------|-------|---------|")
    for row in res.rows[:50]:
        family = row.get("Family", "?")
        proto = row.get("Proto") or row.get("Protocol") or "?"
        lip = row.get("Source Addr") or row.get("Local IP") or row.get("LocalAddr") or "-"
        lp = row.get("Source Port") or row.get("Local Port") or row.get("LocalPort") or ""
        rip = (row.get("Destination Addr") or row.get("Foreign IP")
               or row.get("ForeignAddr") or row.get("Remote IP") or "-")
        rp = (row.get("Destination Port") or row.get("Foreign Port")
              or row.get("RemotePort") or row.get("Remote Port") or "")
        st = row.get("State", "?")
        proc = row.get("Process Name") or "-"
        lines.append(f"| {family} | {proto} | {lip}:{lp} | {rip}:{rp} | {st} | `{proc}` |")

    _audit(
        "analyze_memory_network", {"path": memory_dump_path},
        f"{len(res.rows)} sockets, {len(findings)} flagged",
    )
    return "\n".join(lines)


@mcp.tool()
def analyze_memory_modules(memory_dump_path: str) -> str:
    """Compare linux.lsmod and linux.check_modules to surface hidden LKMs.

    A module that appears in `linux.check_modules` (which walks kernel
    data structures directly) but NOT in `linux.lsmod` (which uses the
    canonical loaded-modules list that rootkits like Diamorphine, Drovorub,
    and many real-world Linux rootkits hide themselves from) is the
    classic hidden-module signature.

    This is one of the strongest single signals available in memory
    forensics — a hidden module is almost always a rootkit, and there is
    no equivalent disk-only check.

    Args:
        memory_dump_path: Path to a Linux memory dump inside the evidence
            directory.

    Returns:
        Markdown report with loaded modules, hidden modules, and a
        triage verdict.
    """
    dump, err = _validate_dump(memory_dump_path)
    if err:
        return err
    lsmod = _run_vol_plugin(dump, "linux.lsmod")
    check = _run_vol_plugin(dump, "linux.check_modules")
    if lsmod.no_symbols or check.no_symbols:
        banner, _ = _identify_kernel(dump)
        out = _format_no_symbols_block(banner)
        _audit("analyze_memory_modules", {"path": memory_dump_path}, "no symbols")
        return out
    if lsmod.rc != 0:
        out = (
            f"# Memory modules — vol linux.lsmod failed (rc={lsmod.rc})\n"
            f"```\n{lsmod.stderr[:400]}\n```"
        )
        _audit("analyze_memory_modules", {"path": memory_dump_path}, f"lsmod rc={lsmod.rc}")
        return out
    if check.rc != 0:
        out = (
            f"# Memory modules — vol linux.check_modules failed (rc={check.rc})\n"
            f"```\n{check.stderr[:400]}\n```"
        )
        _audit("analyze_memory_modules", {"path": memory_dump_path}, f"check_modules rc={check.rc}")
        return out

    diff = _diff_modules(lsmod.rows, check.rows)
    hidden = diff["hidden_modules"]
    lines = [
        f"# Memory kernel modules — `{memory_dump_path}`",
        "",
        f"- **lsmod count:** {len(diff['loaded_modules'])}",
        f"- **check_modules count:** {len(diff['check_modules'])}",
        f"- **Hidden modules (in check_modules but NOT lsmod):** {len(hidden)}",
        "",
    ]
    if hidden:
        lines.append("## 🚨 Hidden kernel modules — high-confidence rootkit indicator")
        for m in hidden:
            lines.append(f"- `{m}` — present in kernel structures but hidden from `lsmod`")
        lines.append("")
        lines.append("**Triage verdict: LIKELY KERNEL ROOTKIT.** A module hidden from")
        lines.append("`lsmod` is the canonical signature of LKM rootkits like Diamorphine.")
        lines.append("Cross-reference with `find_persistence` for disk-side `etc/modules`")
        lines.append("or `lib/modules/*/extra/*.ko` artefacts that may have planted it.")
    else:
        lines.append("No hidden modules detected.")

    if diff["only_in_lsmod"]:
        lines.append("")
        lines.append(f"## Modules in lsmod only (likely benign — {len(diff['only_in_lsmod'])})")
        for m in diff["only_in_lsmod"][:20]:
            lines.append(f"- `{m}`")

    _audit(
        "analyze_memory_modules", {"path": memory_dump_path},
        f"{len(diff['loaded_modules'])} lsmod / {len(hidden)} hidden",
    )
    return "\n".join(lines)


@mcp.tool()
def analyze_memory_bash_history(memory_dump_path: str) -> str:
    """Recover bash command history from process heap memory.

    Wraps `linux.bash`. Crucial when an attacker ran `history -c` or
    truncated `~/.bash_history` — the in-memory history of a still-running
    bash process is unaffected by the on-disk file deletion.

    Args:
        memory_dump_path: Path to a Linux memory dump inside the evidence
            directory.

    Returns:
        Markdown listing of recovered commands with PID, process name,
        and timestamp.
    """
    dump, err = _validate_dump(memory_dump_path)
    if err:
        return err
    res = _run_vol_plugin(dump, "linux.bash")
    if res.no_symbols:
        banner, _ = _identify_kernel(dump)
        out = _format_no_symbols_block(banner)
        _audit("analyze_memory_bash_history", {"path": memory_dump_path}, "no symbols")
        return out
    if res.rc != 0:
        out = f"# Memory bash history — vol failed (rc={res.rc})\n```\n{res.stderr[:400]}\n```"
        _audit("analyze_memory_bash_history", {"path": memory_dump_path}, f"rc={res.rc}")
        return out

    lines = [
        f"# Memory bash history — `{memory_dump_path}`",
        "",
        f"- **Commands recovered:** {len(res.rows)}",
        "",
    ]
    if res.rows:
        lines.append("| Time | PID | Process | Command |")
        lines.append("|------|-----|---------|---------|")
        for row in res.rows[:200]:
            ts = row.get("CommandTime") or row.get("Time") or "-"
            pid = row.get("PID") or row.get("Pid") or "-"
            comm = row.get("Process") or row.get("Comm") or "-"
            cmd = row.get("Command") or "-"
            safe_cmd = str(cmd).replace("|", "\\|")[:200]
            lines.append(f"| {ts} | {pid} | `{comm}` | `{safe_cmd}` |")
        if len(res.rows) > 200:
            lines.append(f"\n*({len(res.rows) - 200} more commands truncated)*")
    else:
        lines.append("No bash history recovered. Either no bash process was active,")
        lines.append("or the heap pages containing history were swapped out / overwritten.")

    _audit(
        "analyze_memory_bash_history", {"path": memory_dump_path},
        f"{len(res.rows)} commands",
    )
    return "\n".join(lines)


@mcp.tool()
def analyze_memory_malfind(memory_dump_path: str) -> str:
    """Detect injected code / shellcode in process memory (linux.malfind).

    `linux.malfind` finds RWX memory regions without a backing file, and
    regions whose entropy or magic-byte patterns suggest shellcode or
    reflective ELF loading. This catches in-memory-only malware that
    leaves nothing on disk.

    Args:
        memory_dump_path: Path to a Linux memory dump inside the evidence
            directory.

    Returns:
        Markdown listing of suspicious memory regions per process.
    """
    dump, err = _validate_dump(memory_dump_path)
    if err:
        return err
    # Vol3 v2.28 deprecated linux.malfind in favour of linux.malware.malfind.Malfind.
    # Try the new name first; fall back to the old for older Vol3 builds.
    res = _run_vol_plugin(dump, "linux.malware.malfind.Malfind")
    if res.rc != 0 and "invalid choice" in res.stderr.lower():
        res = _run_vol_plugin(dump, "linux.malfind")
    if res.no_symbols:
        banner, _ = _identify_kernel(dump)
        out = _format_no_symbols_block(banner)
        _audit("analyze_memory_malfind", {"path": memory_dump_path}, "no symbols")
        return out
    if res.rc != 0:
        out = f"# Memory malfind — vol failed (rc={res.rc})\n```\n{res.stderr[:400]}\n```"
        _audit("analyze_memory_malfind", {"path": memory_dump_path}, f"rc={res.rc}")
        return out

    lines = [
        f"# Memory injection scan (malfind) — `{memory_dump_path}`",
        "",
        f"- **Suspicious regions:** {len(res.rows)}",
        "",
    ]
    if res.rows:
        lines.append("## ⚠ Findings")
        for row in res.rows[:30]:
            pid = row.get("PID") or row.get("Pid") or "?"
            proc = row.get("Process") or "?"
            start = row.get("Start Address") or row.get("Start") or "?"
            end = row.get("End Address") or row.get("End") or "?"
            prot = row.get("Protection") or row.get("Permissions") or "?"
            note = row.get("Note") or row.get("Notes") or ""
            lines.append(
                f"- PID {pid} `{proc}` — region `{start}` → `{end}` "
                f"prot=`{prot}` {note}"
            )
        if len(res.rows) > 30:
            lines.append(f"\n*({len(res.rows) - 30} more regions truncated)*")
        lines.append("")
        lines.append("**Note:** RWX regions without a backing file are the canonical")
        lines.append("shape of shellcode injection or reflective ELF loading. Cross-")
        lines.append("reference flagged PIDs against the process list to identify")
        lines.append("which service or session was hijacked.")
    else:
        lines.append("No suspicious memory regions detected.")

    _audit(
        "analyze_memory_malfind", {"path": memory_dump_path},
        f"{len(res.rows)} regions",
    )
    return "\n".join(lines)


@mcp.tool()
def correlate_memory_and_disk(memory_dump_path: str, fs_root: str) -> str:
    """Cross-reference memory state against on-disk persistence findings.

    The strongest forensic verdict comes from memory + disk *agreement*.
    This tool runs `analyze_memory_modules` and `find_persistence`'s
    kernel-module + container scanners against the same case and
    reports the four-quadrant correlation:

    | memory says | disk says | interpretation |
    |---|---|---|
    | hidden module X | /etc/modules lists X | confirmed kernel rootkit |
    | hidden module X | disk has nothing | memory-resident rootkit |
    | no hidden modules | /etc/modules has X | stale config, possibly rolled back |
    | no hidden modules | disk clean | memory + disk agree: no LKM compromise |

    Both arguments must resolve inside the evidence directory.

    Args:
        memory_dump_path: Path to a Linux memory dump
        fs_root: Filesystem root (e.g. evidence/case01/fs) for find_persistence

    Returns:
        Markdown report with the correlation matrix and a unified verdict.
    """
    dump, err = _validate_dump(memory_dump_path)
    if err:
        return err
    try:
        fs_validated = _validate_evidence_path(fs_root)
    except ValueError as e:
        return f"Error validating fs_root: {e}"
    if not fs_validated.is_dir():
        return f"fs_root is not a directory: {fs_root}"

    # Memory side
    lsmod = _run_vol_plugin(dump, "linux.lsmod")
    check = _run_vol_plugin(dump, "linux.check_modules")
    if lsmod.no_symbols or check.no_symbols:
        banner, _ = _identify_kernel(dump)
        body = _format_no_symbols_block(banner)
        _audit(
            "correlate_memory_and_disk",
            {"dump": memory_dump_path, "fs_root": fs_root},
            "no symbols",
        )
        return f"# Memory-disk correlation — `{memory_dump_path}` × `{fs_root}`\n\n{body}"
    if lsmod.rc != 0 or check.rc != 0:
        out = (
            f"# Memory-disk correlation\n\n"
            f"vol plugin failed: lsmod rc={lsmod.rc}, check rc={check.rc}\n"
            f"```\n{lsmod.stderr[:200]}\n{check.stderr[:200]}\n```"
        )
        _audit(
            "correlate_memory_and_disk",
            {"dump": memory_dump_path, "fs_root": fs_root},
            f"vol plugin rc lsmod={lsmod.rc} check={check.rc}",
        )
        return out
    mem_diff = _diff_modules(lsmod.rows, check.rows)
    hidden = mem_diff["hidden_modules"]
    loaded = mem_diff["loaded_modules"]

    # Disk side — reuse the persistence scanner
    from findevil.tools.linux_persistence import scan_kernel_modules

    disk_findings = scan_kernel_modules(fs_validated)
    disk_module_names: set[str] = set()
    for f in disk_findings:
        # scan_kernel_modules surfaces modules-by-name in reasons
        for r in f.reasons:
            m = re.search(r"`([A-Za-z0-9_]+)`", r)
            if m:
                disk_module_names.add(m.group(1).lower())

    # Four-quadrant analysis
    hidden_set = set(hidden)
    loaded_set = set(loaded)
    overlap_disk_hidden = hidden_set & disk_module_names
    disk_only = disk_module_names - hidden_set - loaded_set
    hidden_no_disk = hidden_set - disk_module_names

    lines = [
        f"# Memory-disk correlation — `{memory_dump_path}` × `{fs_root}`",
        "",
        "## Headline counts",
        f"- Memory: {len(loaded)} loaded, {len(hidden)} hidden",
        f"- Disk: {len(disk_module_names)} module name(s) in /etc/modules or modprobe.d/",
        "",
    ]

    if overlap_disk_hidden:
        lines.append("## 🚨 CONFIRMED KERNEL ROOTKIT")
        for m in sorted(overlap_disk_hidden):
            lines.append(
                f"- `{m}` — present on disk (etc/modules or modprobe.d) AND loaded but"
                f" hidden in memory. Plant + load + active hide. Highest-confidence verdict."
            )
        lines.append("")

    if hidden_no_disk:
        lines.append("## 🚨 MEMORY-RESIDENT ROOTKIT (on-disk traces removed or never written)")
        for m in sorted(hidden_no_disk):
            lines.append(
                f"- `{m}` — loaded but hidden in memory; no matching disk artefact."
                f" Either attacker scrubbed the disk after planting, or the module was"
                f" loaded directly via insmod from a since-deleted file."
            )
        lines.append("")

    if disk_only:
        lines.append("## ⚠ Disk-only references (possibly stale / rolled back)")
        for m in sorted(disk_only):
            lines.append(
                f"- `{m}` — listed in /etc/modules or modprobe.d but neither loaded"
                f" nor hidden in memory. Could be a rolled-back rootkit, a typo, or"
                f" a planned-but-not-yet-loaded module."
            )
        lines.append("")

    if not (overlap_disk_hidden or hidden_no_disk or disk_only):
        lines.append("## ✓ Memory and disk agree")
        lines.append(
            f"No memory-resident rootkit signals. Disk-side kernel-module config "
            f"({len(disk_module_names)} modules tracked) is consistent with the loaded "
            f"set in memory ({len(loaded)} loaded). No compromise indicators from this "
            f"correlation."
        )
        lines.append("")

    lines.append("## Triage verdict")
    if overlap_disk_hidden:
        lines.append(
            "🚨 **CONFIRMED KERNEL ROOTKIT.** Memory + disk agreement on hidden module(s). "
            "Quarantine the host; this is the highest-confidence rootkit verdict findevil produces."
        )
    elif hidden_no_disk:
        lines.append(
            "🚨 **MEMORY-RESIDENT ROOTKIT.** Hidden in memory with no matching disk trace. "
            "Likely insmod-from-deleted-file or post-load disk scrub. Capture the live system "
            "before reboot — a reboot loses the only evidence."
        )
    elif disk_only:
        lines.append(
            "⚠ Disk-only references suggest stale config or rolled-back attack. Inspect "
            "the specific files for context (timestamps, surrounding entries) before "
            "drawing conclusions."
        )
    else:
        lines.append(
            "No correlation-based compromise signals. Memory and disk module state agree. "
            "Continue investigation with other artefacts (auth logs, persistence categories beyond "
            "kernel modules, FIM diff)."
        )

    _audit(
        "correlate_memory_and_disk",
        {"dump": memory_dump_path, "fs_root": fs_root},
        f"hidden={len(hidden)} disk={len(disk_module_names)} confirmed={len(overlap_disk_hidden)}",
    )
    return "\n".join(lines)


@mcp.tool()
def analyze_memory_summary(memory_dump_path: str) -> str:
    """Triage a Linux memory dump — high-level verdict in one tool call.

    Identifies the kernel via `banners.Banners`, then runs `linux.pslist`,
    `linux.netstat`, `linux.lsmod` + `linux.check_modules` (compared for
    hidden modules), and `linux.malfind`. Returns a unified report with
    a single triage verdict.

    Use this first when you receive a memory dump. Drill into the specific
    `analyze_memory_*` tools afterward for full per-plugin output.

    Args:
        memory_dump_path: Path to a Linux memory dump (.lime / .raw / .vmem)
            inside the evidence directory.

    Returns:
        Markdown report with kernel banner, headline counts, hidden
        modules, suspicious processes, suspicious network state, code
        injection findings, and a triage verdict.
    """
    dump, err = _validate_dump(memory_dump_path)
    if err:
        return err

    banner, all_banners = _identify_kernel(dump)
    pslist = _run_vol_plugin(dump, "linux.pslist")
    netstat = _run_vol_plugin(dump, "linux.sockstat.Sockstat")
    if netstat.rc != 0 and "invalid choice" in netstat.stderr.lower():
        netstat = _run_vol_plugin(dump, "linux.netstat")
    lsmod = _run_vol_plugin(dump, "linux.lsmod")
    check_modules = _run_vol_plugin(dump, "linux.check_modules")
    malfind = _run_vol_plugin(dump, "linux.malware.malfind.Malfind")
    if malfind.rc != 0 and "invalid choice" in malfind.stderr.lower():
        malfind = _run_vol_plugin(dump, "linux.malfind")

    no_sym = any(r.no_symbols for r in (pslist, netstat, lsmod, check_modules, malfind))
    if no_sym:
        out = [
            f"# Memory triage — `{memory_dump_path}`",
            "",
            _format_no_symbols_block(banner),
        ]
        _audit("analyze_memory_summary", {"path": memory_dump_path}, "no symbols")
        return "\n".join(out)

    # Aggregate findings
    if pslist.rc == 0:
        procs, proc_anomalies = _classify_processes(pslist.rows)
    else:
        procs, proc_anomalies = [], []
    net_findings = _classify_network(netstat.rows) if netstat.rc == 0 else []
    if lsmod.rc == 0 and check_modules.rc == 0:
        mod_diff = _diff_modules(lsmod.rows, check_modules.rows)
    else:
        mod_diff = {"hidden_modules": [], "loaded_modules": [], "check_modules": []}
    hidden = mod_diff["hidden_modules"]
    inj_count = len(malfind.rows) if malfind.rc == 0 else 0

    # Verdict
    verdict_strong_signals = []
    if hidden:
        verdict_strong_signals.append(f"hidden kernel module(s): {', '.join(hidden)}")
    if inj_count > 0:
        verdict_strong_signals.append(f"{inj_count} suspicious memory region(s) (malfind)")
    if proc_anomalies:
        verdict_strong_signals.append(f"{len(proc_anomalies)} process anomaly/anomalies")
    if net_findings:
        verdict_strong_signals.append(f"{len(net_findings)} flagged network connection(s)")

    lines = [
        f"# Memory triage — `{memory_dump_path}`",
        "",
        "## Kernel",
        f"- Banner: `{banner[:200]}`" if banner else "- Banner: not detected",
        "",
        "## Headlines",
        f"- Processes: {len(procs)} ({len(proc_anomalies)} anomalies)",
        f"- Sockets: {len(netstat.rows)} ({len(net_findings)} flagged)",
        f"- Loaded modules: {len(mod_diff['loaded_modules'])}",
        f"- Hidden modules (lsmod-vs-check_modules): **{len(hidden)}**",
        f"- Code-injection regions (malfind): **{inj_count}**",
        "",
    ]

    if hidden:
        lines.append("## 🚨 Hidden kernel modules")
        for m in hidden:
            lines.append(f"- `{m}` (in check_modules but NOT lsmod — kernel rootkit signature)")
        lines.append("")

    if proc_anomalies:
        lines.append("## ⚠ Process anomalies")
        for a in proc_anomalies[:10]:
            lines.append(f"- {a}")
        lines.append("")

    if net_findings:
        lines.append("## ⚠ Flagged network connections")
        for f in net_findings[:10]:
            lines.append(f"- {f}")
        lines.append("")

    lines.append("## Triage verdict")
    if hidden or inj_count > 0:
        lines.append(
            f"🚨 **LIKELY MEMORY-RESIDENT COMPROMISE** — {'; '.join(verdict_strong_signals)}. "
            "Drill into `analyze_memory_modules` and `analyze_memory_malfind` for full detail. "
            "Cross-reference with `find_persistence` to see whether the rootkit also planted "
            "disk-side persistence (often it does — e.g., `/etc/modules` or "
            "`/lib/modules/*/extra/*.ko`)."
        )
    elif proc_anomalies or net_findings:
        lines.append(
            f"⚠ Moderate signals: {'; '.join(verdict_strong_signals)}. "
            "Not conclusive on its own — correlate with disk findings."
        )
    else:
        lines.append(
            "No strong memory-resident compromise indicators. The dump is internally "
            "consistent (lsmod ↔ check_modules align, no malfind hits, no orphan-parent "
            "processes). A clean memory verdict does not rule out disk-side persistence; "
            "run `find_persistence` separately."
        )

    _audit(
        "analyze_memory_summary", {"path": memory_dump_path},
        f"hidden={len(hidden)} malfind={inj_count} proc_anomalies={len(proc_anomalies)}",
    )
    return "\n".join(lines)
