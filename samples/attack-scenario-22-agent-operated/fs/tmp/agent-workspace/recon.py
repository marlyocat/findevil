#!/usr/bin/env python3
"""Host reconnaissance helper. Collects SUID binaries, writable
directories, listening sockets, and outbound network state. Results
are written as structured JSON to stdout for downstream consumption.
"""

import json
import subprocess
from pathlib import Path


def run(cmd: list[str]) -> str:
    """Run a command; return combined stdout, empty string on failure."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30, check=False,
        )
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def collect_suid() -> list[str]:
    raw = run(["find", "/", "-perm", "-4000", "-type", "f"])
    return [line for line in raw.splitlines() if line]


def collect_writable_dirs() -> list[str]:
    raw = run(["find", "/", "-writable", "-type", "d"])
    excluded_prefixes = ("/proc", "/sys", "/tmp", "/dev", "/run")
    return [
        line for line in raw.splitlines()
        if line and not any(line.startswith(p) for p in excluded_prefixes)
    ]


def collect_listening_sockets() -> list[str]:
    return run(["ss", "-tunlp"]).splitlines()[1:]


def collect_outbound_routes() -> list[str]:
    return run(["ip", "route"]).splitlines()


def collect_passwd_users() -> list[dict]:
    users = []
    passwd = Path("/etc/passwd").read_text(errors="replace")
    for line in passwd.splitlines():
        fields = line.split(":")
        if len(fields) >= 7:
            users.append({
                "user": fields[0],
                "uid": int(fields[2]) if fields[2].isdigit() else -1,
                "shell": fields[6],
            })
    return users


def main() -> None:
    report = {
        "suid_binaries": collect_suid(),
        "writable_directories": collect_writable_dirs(),
        "listening_sockets": collect_listening_sockets(),
        "outbound_routes": collect_outbound_routes(),
        "passwd_users": collect_passwd_users(),
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
