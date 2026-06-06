"""
Web server (nginx/apache) forensic analysis.

Web applications are the #1 initial-access vector for Linux compromises.
This module parses nginx-style Combined Log Format access logs and scans
web roots for webshells. Tools:

- `analyze_nginx_access(path)` — parse access log; flag SQLi / RCE / LFI /
  path-traversal / webshell-access / scanner-UA patterns; surface IPs by
  attack-signal count and flag post-webshell-upload GET activity.
- `find_webshells(root_path)` — scan common web roots for PHP/JSP/ASP/CGI
  files containing classic backdoor primitives (eval/system on user input,
  assert on request data, preg_replace /e, WScript.Shell, etc.).

Combined Log Format (nginx default, apache standard):
    $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"

Example:
    91.121.55.44 - - [14/Apr/2026:02:03:11 +0000] "POST /uploads/shell.php HTTP/1.1" 200 34 "-" "curl/7.74.0"
"""

from __future__ import annotations

import re
import urllib.parse
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from findevil.server import _audit, _validate_evidence_path, mcp

# ---------------------------------------------------------------------------
# Access log parsing
# ---------------------------------------------------------------------------


_ACCESS_LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d+)\s+'
    r'(?P<size>\S+)\s+'
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<ua>[^"]*)"'
)


@dataclass
class AccessLogEntry:
    line_number: int
    ip: str
    time: str
    method: str
    path: str
    status: int
    size: str
    referer: str
    user_agent: str
    raw: str


def parse_access_log(content: str) -> list[AccessLogEntry]:
    entries: list[AccessLogEntry] = []
    for lineno, raw in enumerate(content.splitlines(), 1):
        if not raw.strip():
            continue
        m = _ACCESS_LOG_RE.match(raw)
        if not m:
            continue
        try:
            status = int(m.group("status"))
        except ValueError:
            status = 0
        entries.append(
            AccessLogEntry(
                line_number=lineno,
                ip=m.group("ip"),
                time=m.group("time"),
                method=m.group("method"),
                path=m.group("path"),
                status=status,
                size=m.group("size"),
                referer=m.group("referer"),
                user_agent=m.group("ua"),
                raw=raw,
            )
        )
    return entries


# ---------------------------------------------------------------------------
# Attack-pattern heuristics
# ---------------------------------------------------------------------------


_ATTACK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # SQL Injection
    (re.compile(r"(\bUNION\b.*\bSELECT\b)|(\bOR\b\s*\d+\s*=\s*\d+)", re.I), "sql_injection"),
    (re.compile(r"(?i)(sleep\s*\(|benchmark\s*\(|xp_cmdshell|pg_sleep)"), "sql_injection"),
    # LFI / Path traversal
    (re.compile(r"\.\./|%2e%2e%2f|%2e%2e/|\.\.\\"), "path_traversal"),
    (re.compile(r"/etc/passwd|/etc/shadow|/proc/self/environ|/proc/self/cmdline"), "lfi_target"),
    # RCE / command injection
    (re.compile(r"(?i)[;|`]\s*(cat|ls|id|whoami|uname|pwd|ps|ifconfig|netstat)(\s|$)"), "shell_injection"),
    (re.compile(r"(?i)(?:bash|sh|nc|ncat|wget|curl|python|perl)\s+-"), "shell_cmd_arg"),
    (re.compile(r"\$\(.+\)|`[^`]+`"), "command_substitution"),
    # PHP-specific RCE
    (re.compile(r"(?i)php://(filter|input|expect)"), "php_stream_wrapper"),
    (re.compile(r"(?i)data:\s*text/plain"), "data_uri_execution"),
    # Base64 payload in query
    (re.compile(r"(?:^|[?&=])[A-Za-z0-9+/]{40,}={0,2}(?:&|$)"), "base64_payload"),
    # Webshell-access indicators
    (re.compile(r"\?(c|cmd|exec|execute|run|do|x|e)="), "webshell_cmd_param"),
    (re.compile(r"/(c99|r57|wso|b374k|ws0|marijuana|indoxploit|mini|xattacker)\.(php|asp|jsp)", re.I), "known_webshell_name"),
    # Serialised payloads
    (re.compile(r"O:\d+:\"[A-Za-z0-9_]+\":\d+:{"), "php_serialised_object"),
]


_SCANNER_UA_PATTERNS = re.compile(
    r"(?i)(nmap|nikto|sqlmap|burp|zgrab|masscan|dirbuster|gobuster|wfuzz|"
    r"hydra|acunetix|nessus|qualys|metasploit|fuzzer|w3af|skipfish|arachni)"
)


_SUSPICIOUS_STATIC_POST_RE = re.compile(r"\.(png|jpg|jpeg|gif|ico|css|js|woff2?|svg|ttf)$", re.I)


def classify_attacks(entry: AccessLogEntry) -> list[str]:
    """Return every attack label that matches this request."""
    labels: list[str] = []
    # Try URL-decoded and raw path+query together — many encoders hide in raw
    combined = entry.path + " " + entry.user_agent + " " + entry.referer
    try:
        decoded = urllib.parse.unquote(combined)
    except Exception:
        decoded = combined
    haystack = combined + "\n" + decoded

    for pat, label in _ATTACK_PATTERNS:
        if pat.search(haystack):
            labels.append(label)

    if _SCANNER_UA_PATTERNS.search(entry.user_agent):
        labels.append("scanner_user_agent")

    if entry.method == "POST" and _SUSPICIOUS_STATIC_POST_RE.search(entry.path):
        labels.append("post_to_static_file")

    if entry.method in ("PUT", "DELETE", "PROPFIND", "MKCOL"):
        labels.append(f"unusual_method_{entry.method.lower()}")

    return list(dict.fromkeys(labels))  # dedupe, preserve order


# ---------------------------------------------------------------------------
# Webshell-upload correlation
# ---------------------------------------------------------------------------


_UPLOAD_PATH_RE = re.compile(
    r"/(uploads?|upload_files|files|media|images?|tmp|public/uploads?)/",
    re.I,
)
_EXEC_EXT_RE = re.compile(r"\.(php[347]?|phtml|asp|aspx|jsp|jspx|cgi|pl|py)(\?|$)", re.I)


def detect_webshell_upload_chain(entries: list[AccessLogEntry]) -> list[dict]:
    """Find POST uploads to executable extensions, paired with later GETs
    that invoke them. Classic webshell-upload-then-exec behaviour."""
    chains = []
    uploaded: dict[str, AccessLogEntry] = {}  # path -> POST entry
    for e in entries:
        if (
            e.method == "POST"
            and _UPLOAD_PATH_RE.search(e.path)
            and _EXEC_EXT_RE.search(e.path)
            and 200 <= e.status < 400
        ):
            # normalise path — strip query
            key = e.path.split("?")[0]
            uploaded[key] = e
    for e in entries:
        if e.method == "GET" and _EXEC_EXT_RE.search(e.path):
            key = e.path.split("?")[0]
            if key in uploaded:
                chains.append(
                    {
                        "upload_line": uploaded[key].line_number,
                        "upload_time": uploaded[key].time,
                        "upload_ip": uploaded[key].ip,
                        "exec_line": e.line_number,
                        "exec_time": e.time,
                        "exec_ip": e.ip,
                        "path": key,
                        "query": e.path.split("?", 1)[1] if "?" in e.path else "",
                    }
                )
    return chains


# ---------------------------------------------------------------------------
# MCP tool: analyze_nginx_access
# ---------------------------------------------------------------------------


@mcp.tool()
def analyze_nginx_access(path: str, top_n_ips: int = 10) -> str:
    """Analyze an nginx/apache access log (Combined Log Format) for web attacks.

    Detects: SQLi, LFI/path traversal, RCE / command injection, PHP stream
    wrappers, base64-encoded payloads, known webshell filenames, scanner
    user-agents, unusual HTTP methods, and POST-to-static-file patterns.
    Correlates file uploads to executable extensions with subsequent GETs
    that invoke them — the classic webshell-upload-then-execute chain.

    Args:
        path: Path to an access log inside the evidence directory
        top_n_ips: Cap the per-IP attack summary (default 10)

    Returns:
        Markdown report with per-finding line numbers, top offending IPs,
        webshell-upload chains, and a triage verdict.
    """
    try:
        validated = _validate_evidence_path(path)
    except ValueError as e:
        return f"Error: {e}"
    if not validated.is_file():
        return f"Not a file: {path}"

    content = validated.read_text(errors="replace")
    entries = parse_access_log(content)

    if not entries:
        result = f"No parseable Combined-Log-Format entries in `{path}`."
        _audit("analyze_nginx_access", {"path": path}, "0 entries")
        return result

    # Attack classification per entry
    by_ip_labels: dict[str, Counter] = defaultdict(Counter)
    by_ip_entries: dict[str, list[AccessLogEntry]] = defaultdict(list)
    error_bursts: dict[str, int] = defaultdict(int)
    total_attacks = 0
    flagged_entries: list[tuple[AccessLogEntry, list[str]]] = []

    for e in entries:
        labels = classify_attacks(e)
        by_ip_entries[e.ip].append(e)
        if labels:
            total_attacks += 1
            for lbl in labels:
                by_ip_labels[e.ip][lbl] += 1
            flagged_entries.append((e, labels))
        if 400 <= e.status < 500:
            error_bursts[e.ip] += 1

    chains = detect_webshell_upload_chain(entries)

    # Build report
    lines = [
        f"# nginx access log — `{path}`",
        "",
        f"- **Total requests parsed:** {len(entries)}",
        f"- **Requests with attack signals:** {total_attacks}",
        f"- **Unique client IPs:** {len(by_ip_entries)}",
        f"- **Webshell upload-then-exec chains detected:** {len(chains)}",
        "",
    ]

    if by_ip_labels:
        ranked = sorted(
            by_ip_labels.items(), key=lambda kv: sum(kv[1].values()), reverse=True
        )[:top_n_ips]
        lines.append("## Top attacker IPs (by attack-signal count)")
        lines.append("| IP | Attack signals | Labels | 4xx count |")
        lines.append("|----|----------------|--------|-----------|")
        for ip, cnt in ranked:
            label_summary = ", ".join(f"{lbl}:{c}" for lbl, c in cnt.most_common(5))
            lines.append(f"| `{ip}` | {sum(cnt.values())} | {label_summary} | {error_bursts.get(ip, 0)} |")
        lines.append("")

    if chains:
        lines.append("## ⚠ Webshell upload chains")
        lines.append("(POST that uploads to an executable extension, followed by GET that invokes it)")
        lines.append("")
        lines.append("| Upload line | Upload time | Upload IP | Exec line | Exec IP | Path | Query |")
        lines.append("|-------------|-------------|-----------|-----------|---------|------|-------|")
        for c in chains[:20]:
            safe_q = (c["query"] or "")[:80].replace("|", "\\|")
            lines.append(
                f"| {c['upload_line']} | {c['upload_time']} | `{c['upload_ip']}` | "
                f"{c['exec_line']} | `{c['exec_ip']}` | `{c['path']}` | `{safe_q}` |"
            )
        lines.append("")

    if flagged_entries:
        lines.append(f"## Flagged requests (first 30 of {len(flagged_entries)})")
        lines.append("| Line | IP | Method | Status | Path | Labels |")
        lines.append("|------|----|----|--------|------|--------|")
        for e, labels in flagged_entries[:30]:
            safe_path = e.path.replace("|", "\\|")[:140]
            lines.append(
                f"| {e.line_number} | `{e.ip}` | {e.method} | {e.status} | `{safe_path}` | {', '.join(labels)} |"
            )
        lines.append("")

    # Triage verdict
    lines.append("## Triage verdict")
    if chains:
        lines.append("⚠⚠ **LIKELY WEBSHELL COMPROMISE** — file upload followed by execution of the uploaded file. Investigate what commands the webshell ran.")
    elif total_attacks > 20:
        lines.append(f"⚠ **ACTIVE SCANNING / EXPLOIT ATTEMPTS** — {total_attacks} flagged requests across {len(by_ip_labels)} IP(s). Most may be automated scanning without a successful exploit; correlate with `find_webshells` and application error logs.")
    elif total_attacks > 0:
        lines.append(f"{total_attacks} flagged requests — review individually. Not conclusive of compromise without corroboration.")
    else:
        lines.append("No web-attack signals found. Continue investigation with other artifacts.")

    result = "\n".join(lines)
    _audit(
        "analyze_nginx_access",
        {"path": path, "top_n_ips": top_n_ips},
        f"{len(entries)} entries, {total_attacks} attacks, {len(chains)} upload chains",
    )
    return result


# ---------------------------------------------------------------------------
# MCP tool: find_webshells
# ---------------------------------------------------------------------------


_WEB_ROOTS = [
    "var/www",
    "srv/http",
    "srv/www",
    "usr/share/nginx",
    "usr/share/apache2",
    "opt/lampp/htdocs",
    "home/*/public_html",
]


_WEBSHELL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # PHP
    (re.compile(r"(?i)eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|gzuncompress|hex2bin)"), "eval of obfuscated blob (PHP)"),
    (re.compile(r"(?i)eval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\["), "eval of request data (PHP)"),
    (re.compile(r"(?i)assert\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\["), "assert of request data (PHP)"),
    (re.compile(r"(?i)(?:system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)\s*\(\s*\$_"), "shell exec of request data (PHP)"),
    (re.compile(r"(?i)create_function\s*\("), "create_function (PHP anonymous code)"),
    (re.compile(r"(?i)preg_replace\s*\(.*/e"), "preg_replace /e modifier (PHP legacy RCE)"),
    (re.compile(r"(?i)(?:include|require)(?:_once)?\s*\(\s*\$_(?:GET|POST|REQUEST)"), "dynamic include of request data"),
    (re.compile(r"\$[A-Za-z_]+\s*=\s*\$_POST\[[^\]]+\];.*eval\s*\(\s*\$", re.S), "POST-to-eval chain"),
    # JSP
    (re.compile(r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\("), "JSP Runtime.exec"),
    (re.compile(r"ProcessBuilder\s*\(\s*.+\s*\)\s*\.\s*start\s*\("), "JSP ProcessBuilder"),
    # ASP
    (re.compile(r"(?i)WScript\.Shell"), "ASP WScript.Shell"),
    (re.compile(r"(?i)Server\.CreateObject\s*\(\s*[\"']Shell\."), "ASP Shell.Application"),
    # CGI/Perl generic
    (re.compile(r"(?i)open\s*\(\s*[^,]+,\s*[\"']\s*\|"), "Perl piped open"),
]


_EXEC_EXTENSIONS = {".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".asp", ".aspx", ".jsp", ".jspx", ".cgi", ".pl", ".py"}


@dataclass
class WebshellFinding:
    path: str
    category: str  # "php", "jsp", "asp", "cgi_perl", "generic"
    reasons: list[str] = field(default_factory=list)
    sample: str = ""
    size: int = 0


def _scan_file_for_webshell(p: Path) -> list[str]:
    try:
        data = p.read_bytes()[:65536]
    except (OSError, PermissionError):
        return []
    text = data.decode(errors="replace")
    reasons = []
    for pat, label in _WEBSHELL_PATTERNS:
        if pat.search(text):
            reasons.append(label)
    return list(dict.fromkeys(reasons))


@mcp.tool()
def find_webshells(root_path: str) -> str:
    """Scan common web roots under the filesystem root for webshell backdoors.

    Searches /var/www, /srv/http, /srv/www, /usr/share/nginx, /opt/lampp/htdocs,
    and every /home/*/public_html for files with executable extensions
    (.php .phtml .asp .aspx .jsp .cgi .pl .py) and matches them against
    classic webshell primitives:

    - PHP: eval(request data), assert(request data), system/passthru/
      shell_exec on request data, preg_replace /e, create_function,
      eval of base64_decode / gzinflate payloads, dynamic include.
    - JSP: Runtime.getRuntime().exec(), ProcessBuilder.
    - ASP: WScript.Shell, Shell.Application.
    - Perl/CGI: piped open.

    Args:
        root_path: Filesystem root to scan (must be inside evidence directory)

    Returns:
        Markdown listing of suspicious files with matched primitives and a
        content sample.
    """
    try:
        validated = _validate_evidence_path(root_path)
    except ValueError as e:
        return f"Error: {e}"
    if not validated.is_dir():
        return f"Not a directory: {root_path}"

    findings: list[WebshellFinding] = []
    scanned = 0

    # Expand web-root globs to actual paths that exist in this snapshot
    roots: list[Path] = []
    for rel in _WEB_ROOTS:
        if "*" in rel:
            # e.g. home/*/public_html
            roots.extend(validated.glob(rel))
        else:
            p = validated / rel
            if p.is_dir():
                roots.append(p)

    for r in roots:
        for p in r.rglob("*"):
            if not p.is_file():
                continue
            if p.suffix.lower() not in _EXEC_EXTENSIONS:
                continue
            scanned += 1
            reasons = _scan_file_for_webshell(p)
            if reasons:
                try:
                    sample = p.read_text(errors="replace")[:300].rstrip()
                except (OSError, PermissionError):
                    sample = ""
                category = {
                    ".jsp": "jsp",
                    ".jspx": "jsp",
                    ".asp": "asp",
                    ".aspx": "asp",
                    ".cgi": "cgi_perl",
                    ".pl": "cgi_perl",
                    ".py": "cgi_perl",
                }.get(p.suffix.lower(), "php")
                findings.append(
                    WebshellFinding(
                        path=str(p.relative_to(validated)),
                        category=category,
                        reasons=reasons,
                        sample=sample,
                        size=p.stat().st_size if p.exists() else 0,
                    )
                )

    lines = [f"# Webshell scan — `{root_path}`", ""]
    lines.append(f"- **Web roots inspected:** {len(roots)}")
    lines.append(f"- **Files with executable extensions scanned:** {scanned}")
    lines.append(f"- **Suspicious files found:** {len(findings)}")
    lines.append("")

    if findings:
        lines.append("## Suspicious files")
        for f in findings:
            lines.append(f"### `{f.path}` ({f.category}, {f.size} bytes)")
            lines.append("- **Matched primitives:**")
            for r in f.reasons:
                lines.append(f"  - {r}")
            if f.sample:
                lines.append("")
                lines.append("```")
                lines.append(f.sample)
                lines.append("```")
            lines.append("")
    else:
        lines.append("No webshell indicators found in scanned files.")

    result = "\n".join(lines)
    _audit(
        "find_webshells",
        {"root_path": root_path},
        f"{scanned} scanned, {len(findings)} flagged",
    )
    return result
