"""
Self-correction framework.

The #1 judging criterion for this hackathon is Autonomous Execution
Quality — specifically real reasoning, failure handling, and
self-correction. This module provides the explicit tools the agent
uses to audit its own output before shipping a verdict.

Three tools:

- `verify_finding(claim_type, params)` — structured re-check of a
  specific claim class. Returns SUPPORTED / CONTRADICTED /
  INSUFFICIENT_EVIDENCE with the raw evidence that justifies the
  verdict. The supported claim types map directly to the findings
  the other tools produce (brute force, successful login,
  persistence artifact, package install, etc.). Every verification
  performs an INDEPENDENT re-read of the underlying file so a
  cached/corrupt tool output can't confirm itself.

- `find_contradictions(claims)` — accepts a list of structured
  claims (a JSON string) and returns any pair that is logically
  inconsistent. Catches things like: "brute force from IP X" while
  also claiming "zero failed auth events." The tool is deliberately
  small on scope — it checks six specific contradiction patterns
  that account for the vast majority of real IR-report errors.

- `get_audit_trail(filter_tool, filter_since, limit)` — reads the
  server's own audit log and returns a structured view. Lets the
  agent confirm that any finding in its report maps to an actual
  tool call. This is the mechanical check that the agent's
  self-reported reasoning chain is real.

All three return Markdown designed for the agent to quote verbatim
into its report's "Verification" section.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from findevil.server import LOGS_DIR, _audit, _validate_evidence_path, mcp


# ---------------------------------------------------------------------------
# verify_finding — structured claim re-check
# ---------------------------------------------------------------------------


_VALID_CLAIM_TYPES = {
    "brute_force_from_ip",
    "successful_login_after_brute_force",
    "user_created",
    "package_installed",
    "webshell_upload_chain",
    "file_modified_in_window",
    "persistence_mechanism_exists",
    "sudo_command_executed",
}


def _read_safe_log(path: Path) -> str | None:
    if not path.is_file():
        return None
    try:
        return path.read_text(errors="replace")
    except (OSError, PermissionError):
        return None


def _verify_brute_force(params: dict[str, Any]) -> tuple[str, list[str]]:
    """Confirm: IP X produced >= N failed login attempts in file Y."""
    from findevil.tools.linux_auth import parse_auth_log

    log_path = params.get("log_path", "")
    ip = params.get("ip", "")
    min_attempts = int(params.get("min_attempts", 10))

    try:
        validated = _validate_evidence_path(log_path)
    except ValueError as e:
        return "INSUFFICIENT_EVIDENCE", [f"invalid log_path: {e}"]

    content = _read_safe_log(validated)
    if content is None:
        return "INSUFFICIENT_EVIDENCE", [f"log file not found or unreadable: {log_path}"]

    events = parse_auth_log(content)
    failed = [
        e for e in events
        if e.kind in ("login_failed", "invalid_user") and e.fields.get("ip") == ip
    ]
    if len(failed) >= min_attempts:
        return "SUPPORTED", [
            f"confirmed: {len(failed)} failed attempts from `{ip}` in {log_path}",
            f"first attempt at line {failed[0].line_number}, last at line {failed[-1].line_number}",
        ]
    elif len(failed) == 0:
        return "CONTRADICTED", [
            f"no failed login attempts from `{ip}` found in {log_path}"
        ]
    else:
        return "CONTRADICTED", [
            f"only {len(failed)} failed attempts from `{ip}`; claim required ≥{min_attempts}"
        ]


def _verify_login_after_bruteforce(params: dict[str, Any]) -> tuple[str, list[str]]:
    from findevil.tools.linux_auth import parse_auth_log

    log_path = params.get("log_path", "")
    ip = params.get("ip", "")
    user = params.get("user", "")

    try:
        validated = _validate_evidence_path(log_path)
    except ValueError as e:
        return "INSUFFICIENT_EVIDENCE", [str(e)]

    content = _read_safe_log(validated)
    if content is None:
        return "INSUFFICIENT_EVIDENCE", ["log missing"]

    events = parse_auth_log(content)
    has_failures = any(
        e.kind in ("login_failed", "invalid_user") and e.fields.get("ip") == ip
        for e in events
    )
    success = [
        e for e in events
        if e.kind == "login_accepted"
        and e.fields.get("ip") == ip
        and (not user or e.fields.get("user") == user)
    ]

    if has_failures and success:
        return "SUPPORTED", [
            f"both conditions met: failed attempts AND successful login from `{ip}`"
            + (f" as user `{user}`" if user else ""),
            f"success at line {success[0].line_number}",
        ]
    elif success and not has_failures:
        return "CONTRADICTED", [
            f"successful login from `{ip}` exists but no prior failures — claim of 'after brute force' is false"
        ]
    elif has_failures and not success:
        return "CONTRADICTED", [
            f"failures present but NO successful login from `{ip}`"
        ]
    else:
        return "CONTRADICTED", [f"neither failures nor successes from `{ip}` found"]


def _verify_user_created(params: dict[str, Any]) -> tuple[str, list[str]]:
    from findevil.tools.linux_auth import parse_auth_log

    log_path = params.get("log_path", "")
    name = params.get("name", "")

    try:
        validated = _validate_evidence_path(log_path)
    except ValueError as e:
        return "INSUFFICIENT_EVIDENCE", [str(e)]

    content = _read_safe_log(validated)
    if content is None:
        return "INSUFFICIENT_EVIDENCE", ["log missing"]

    events = parse_auth_log(content)
    for e in events:
        if e.kind == "user_added" and e.fields.get("name") == name:
            return "SUPPORTED", [
                f"useradd for `{name}` at line {e.line_number} uid={e.fields.get('uid', '?')}"
            ]
    return "CONTRADICTED", [
        f"no useradd event for `{name}` in {log_path} — if the account exists on disk, the attacker wrote /etc/passwd directly"
    ]


def _verify_package_installed(params: dict[str, Any]) -> tuple[str, list[str]]:
    from findevil.tools.linux_packages import parse_apt_history, parse_dpkg_log

    fs_root = params.get("fs_root", "")
    name = params.get("name", "")

    try:
        validated = _validate_evidence_path(fs_root)
    except ValueError as e:
        return "INSUFFICIENT_EVIDENCE", [str(e)]

    seen: list[str] = []
    apt = validated / "var/log/apt/history.log"
    if apt.is_file():
        for e in parse_apt_history(apt.read_text(errors="replace")):
            if e.name == name and e.action == "install":
                seen.append(f"apt history installs `{name}={e.version}` at line {e.source_line}")

    dpkg = validated / "var/log/dpkg.log"
    if dpkg.is_file():
        for e in parse_dpkg_log(dpkg.read_text(errors="replace")):
            if e.name == name and e.action == "install":
                seen.append(f"dpkg log installs `{name}={e.version}` at line {e.source_line}")

    if seen:
        return "SUPPORTED", seen
    return "CONTRADICTED", [f"no apt/dpkg install event for `{name}` found"]


def _verify_webshell_upload_chain(params: dict[str, Any]) -> tuple[str, list[str]]:
    from findevil.tools.linux_web import detect_webshell_upload_chain, parse_access_log

    log_path = params.get("log_path", "")
    ip = params.get("ip", "")  # optional
    path = params.get("path", "")  # optional

    try:
        validated = _validate_evidence_path(log_path)
    except ValueError as e:
        return "INSUFFICIENT_EVIDENCE", [str(e)]

    content = _read_safe_log(validated)
    if content is None:
        return "INSUFFICIENT_EVIDENCE", ["log missing"]

    entries = parse_access_log(content)
    chains = detect_webshell_upload_chain(entries)
    if ip:
        chains = [c for c in chains if c.get("upload_ip") == ip]
    if path:
        chains = [c for c in chains if c.get("path") == path]

    if chains:
        return "SUPPORTED", [
            f"{len(chains)} upload chain(s) confirmed",
            *[
                f"  `{c['path']}` uploaded at {c['upload_time']} (line {c['upload_line']}) → GET at line {c['exec_line']}"
                for c in chains[:5]
            ],
        ]
    return "CONTRADICTED", ["no upload-then-execute chain detected for the given filters"]


def _verify_file_modified_in_window(params: dict[str, Any]) -> tuple[str, list[str]]:
    path = params.get("path", "")
    since = params.get("since_iso", "")
    until = params.get("until_iso", "")

    try:
        validated = _validate_evidence_path(path)
    except ValueError as e:
        return "INSUFFICIENT_EVIDENCE", [str(e)]

    if not validated.is_file():
        return "CONTRADICTED", ["file does not exist at that path"]

    try:
        since_ts = datetime.fromisoformat(since.replace("Z", "+00:00")).timestamp()
        until_ts = datetime.fromisoformat(until.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return "INSUFFICIENT_EVIDENCE", ["invalid timestamp(s)"]

    mt = validated.stat().st_mtime
    iso = datetime.fromtimestamp(mt, tz=timezone.utc).isoformat()
    if since_ts <= mt <= until_ts:
        return "SUPPORTED", [f"file mtime is {iso}, within the claimed window"]
    return "CONTRADICTED", [
        f"file mtime is {iso}, outside window {since} → {until}"
    ]


def _verify_persistence_mechanism_exists(params: dict[str, Any]) -> tuple[str, list[str]]:
    from findevil.tools.linux_persistence import scan_all

    fs_root = params.get("fs_root", "")
    category = params.get("category", "")  # e.g. "systemd", "cron", "pam"

    try:
        validated = _validate_evidence_path(fs_root)
    except ValueError as e:
        return "INSUFFICIENT_EVIDENCE", [str(e)]

    findings = scan_all(validated)
    matching = [f for f in findings if f.category == category and f.severity == "high"]
    if matching:
        return "SUPPORTED", [
            f"{len(matching)} high-severity {category} finding(s)",
            *[f"  `{f.path}` — {f.summary}" for f in matching[:5]],
        ]
    return "CONTRADICTED", [
        f"no high-severity {category} persistence in {fs_root}"
    ]


def _verify_sudo_command_executed(params: dict[str, Any]) -> tuple[str, list[str]]:
    from findevil.tools.linux_auth import parse_auth_log

    log_path = params.get("log_path", "")
    pattern = params.get("command_regex", "")
    user = params.get("user", "")

    try:
        validated = _validate_evidence_path(log_path)
    except ValueError as e:
        return "INSUFFICIENT_EVIDENCE", [str(e)]

    content = _read_safe_log(validated)
    if content is None:
        return "INSUFFICIENT_EVIDENCE", ["log missing"]

    try:
        regex = re.compile(pattern)
    except re.error as e:
        return "INSUFFICIENT_EVIDENCE", [f"invalid regex: {e}"]

    matches = []
    for e in parse_auth_log(content):
        if e.kind != "sudo":
            continue
        if user and e.fields.get("user") != user:
            continue
        cmd = e.fields.get("command", "")
        if regex.search(cmd):
            matches.append((e.line_number, cmd))

    if matches:
        return "SUPPORTED", [
            f"{len(matches)} sudo command(s) matched",
            *[f"  line {ln}: `{cmd}`" for ln, cmd in matches[:5]],
        ]
    return "CONTRADICTED", [
        f"no sudo command matching `/{pattern}/` found"
    ]


_VERIFIER_MAP = {
    "brute_force_from_ip": _verify_brute_force,
    "successful_login_after_brute_force": _verify_login_after_bruteforce,
    "user_created": _verify_user_created,
    "package_installed": _verify_package_installed,
    "webshell_upload_chain": _verify_webshell_upload_chain,
    "file_modified_in_window": _verify_file_modified_in_window,
    "persistence_mechanism_exists": _verify_persistence_mechanism_exists,
    "sudo_command_executed": _verify_sudo_command_executed,
}


@mcp.tool()
def verify_finding(claim_type: str, params: str) -> str:
    """Independently re-check a specific claim against raw evidence.

    Call this AFTER a finding has been produced by another tool, to
    confirm the claim holds up under a fresh read of the underlying
    evidence. Returns SUPPORTED / CONTRADICTED / INSUFFICIENT_EVIDENCE
    plus the raw facts that justify the verdict.

    Supported claim types (pass the exact string as `claim_type`):

    - `brute_force_from_ip` — params: {log_path, ip, min_attempts}
    - `successful_login_after_brute_force` — params: {log_path, ip, user?}
    - `user_created` — params: {log_path, name}
    - `package_installed` — params: {fs_root, name}
    - `webshell_upload_chain` — params: {log_path, ip?, path?}
    - `file_modified_in_window` — params: {path, since_iso, until_iso}
    - `persistence_mechanism_exists` — params: {fs_root, category}
      (category ∈ cron|systemd|ssh|user|shell|library|init|pam|kernel_module|ssh_config|sudoers)
    - `sudo_command_executed` — params: {log_path, command_regex, user?}

    Args:
        claim_type: One of the supported type strings above
        params: JSON-encoded object with the per-type parameters

    Returns:
        Markdown block with verdict and evidence.
    """
    if claim_type not in _VALID_CLAIM_TYPES:
        return (
            f"INVALID claim_type `{claim_type}`. Supported types: "
            + ", ".join(sorted(_VALID_CLAIM_TYPES))
        )
    try:
        params_obj = json.loads(params) if isinstance(params, str) else params
    except json.JSONDecodeError as e:
        return f"INVALID params JSON: {e}"

    verifier = _VERIFIER_MAP[claim_type]
    verdict, reasons = verifier(params_obj)

    lines = [
        f"# Verification — claim: `{claim_type}`",
        "",
        f"- **Verdict:** {verdict}",
        "- **Evidence:**",
        *[f"  - {r}" for r in reasons],
    ]
    out = "\n".join(lines)
    _audit("verify_finding", {"claim_type": claim_type, "params": params_obj}, verdict)
    return out


# ---------------------------------------------------------------------------
# find_contradictions — cross-claim logical consistency
# ---------------------------------------------------------------------------


@dataclass
class Claim:
    id: str
    type: str
    data: dict[str, Any]


def _parse_claims(json_str: str) -> tuple[list[Claim] | None, str | None]:
    try:
        raw = json.loads(json_str)
    except json.JSONDecodeError as e:
        return None, f"invalid JSON: {e}"
    if not isinstance(raw, list):
        return None, "expected JSON array of claim objects"
    claims: list[Claim] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            return None, f"claim {i}: not an object"
        if "type" not in item:
            return None, f"claim {i}: missing 'type'"
        claims.append(
            Claim(id=str(item.get("id", f"c{i}")), type=item["type"], data=item)
        )
    return claims, None


def _find_contradiction_patterns(claims: list[Claim]) -> list[str]:
    """Six specific contradiction patterns that cover the vast majority of
    real-world IR-report errors."""
    issues: list[str] = []
    by_type: dict[str, list[Claim]] = {}
    for c in claims:
        by_type.setdefault(c.type, []).append(c)

    # Pattern 1: brute force + no_failed_logins on same log
    bfs = by_type.get("brute_force_from_ip", [])
    zeros = by_type.get("no_failed_logins", [])
    for b in bfs:
        for z in zeros:
            if b.data.get("log_path") == z.data.get("log_path"):
                issues.append(
                    f"`{b.id}` claims brute force from `{b.data.get('ip')}` but "
                    f"`{z.id}` claims zero failed logins in the same log"
                )

    # Pattern 2: compromise_verdict=confirmed + no_successful_login_from_attacker
    verdict_claims = by_type.get("compromise_verdict", [])
    no_success = by_type.get("no_successful_login_from_ip", [])
    for v in verdict_claims:
        if v.data.get("verdict", "").lower() != "confirmed":
            continue
        for ns in no_success:
            if v.data.get("attacker_ip") == ns.data.get("ip"):
                issues.append(
                    f"`{v.id}` verdict=confirmed with attacker_ip=`{v.data.get('attacker_ip')}` "
                    f"but `{ns.id}` claims no successful login from that IP"
                )

    # Pattern 3: persistence_mechanism_exists on category X + persistence_empty on same X
    pm = by_type.get("persistence_mechanism_exists", [])
    pe = by_type.get("persistence_empty", [])
    for p in pm:
        for e in pe:
            if p.data.get("category") == e.data.get("category"):
                issues.append(
                    f"`{p.id}` says {p.data.get('category')} persistence exists; "
                    f"`{e.id}` says the same category has no findings"
                )

    # Pattern 4: user_created with useradd + user_not_in_log
    uc = by_type.get("user_created", [])
    unl = by_type.get("user_not_in_log", [])
    for u in uc:
        for n in unl:
            if u.data.get("name") == n.data.get("name"):
                issues.append(
                    f"`{u.id}` and `{n.id}` contradict on user `{u.data.get('name')}`: "
                    "one says it was created via useradd in the log, the other says it isn't in the log"
                )

    # Pattern 5: file_modified_in_window vs file_not_found
    fm = by_type.get("file_modified_in_window", [])
    fnf = by_type.get("file_not_found", [])
    for f in fm:
        for n in fnf:
            if f.data.get("path") == n.data.get("path"):
                issues.append(
                    f"`{f.id}` claims `{f.data.get('path')}` was modified, "
                    f"`{n.id}` claims the same path doesn't exist"
                )

    # Pattern 6: multiple attack vectors claimed against one actor
    vectors = by_type.get("initial_access_vector", [])
    if len(vectors) > 1:
        unique = {v.data.get("vector") for v in vectors}
        if len(unique) > 1:
            issues.append(
                f"multiple distinct initial_access_vector claims ({', '.join(sorted(unique))}) "
                "— determine which is primary"
            )

    return issues


@mcp.tool()
def find_contradictions(claims_json: str) -> str:
    """Detect logical inconsistencies across a set of structured claims.

    Accepts a JSON array of claim objects, each with at minimum a `type`
    field plus type-specific fields. Checks six contradiction patterns:

    1. `brute_force_from_ip` vs `no_failed_logins` on the same log
    2. `compromise_verdict=confirmed` with an attacker IP, but
       `no_successful_login_from_ip` for that IP
    3. `persistence_mechanism_exists` in category X vs `persistence_empty`
       in category X
    4. `user_created` via useradd vs `user_not_in_log` for the same name
    5. `file_modified_in_window` vs `file_not_found` for the same path
    6. Multiple `initial_access_vector` claims with different vectors

    The tool flags contradictions only; it does not decide which side is
    correct — the agent still has to go back and verify.

    Args:
        claims_json: JSON array of claim objects

    Returns:
        Markdown block listing any contradictions found.
    """
    claims, err = _parse_claims(claims_json)
    if err:
        return f"INVALID input: {err}"

    issues = _find_contradiction_patterns(claims)

    lines = [
        f"# Contradiction check — {len(claims)} claim(s) inspected",
        "",
    ]
    if issues:
        lines.append(f"⚠ **{len(issues)} contradiction(s) found:**")
        lines.append("")
        for i in issues:
            lines.append(f"- {i}")
    else:
        lines.append("No contradictions detected among the supplied claims.")

    out = "\n".join(lines)
    _audit(
        "find_contradictions",
        {"claim_count": len(claims)},
        f"{len(issues)} contradictions",
    )
    return out


# ---------------------------------------------------------------------------
# get_audit_trail — introspection of the server's own audit.json
# ---------------------------------------------------------------------------


@mcp.tool()
def get_audit_trail(
    filter_tool: str = "",
    filter_since: str = "",
    limit: int = 100,
) -> str:
    """Return the findevil audit trail — the record of every tool call made
    during this session.

    Use this to confirm that a claim in your report maps to an actual
    invocation. For example, before stating "auth_summary verdict was
    LIKELY COMPROMISE", use `get_audit_trail(filter_tool="auth_summary")`
    to verify that tool was actually called and what it returned.

    Args:
        filter_tool: If set, only return entries for this tool name
        filter_since: If set (ISO 8601), only return entries after this time
        limit: Cap on the number of entries (default 100)

    Returns:
        Markdown listing of matching audit entries with tool name, params,
        timestamp, and result summary.
    """
    # Side-channel invocation counter — deliberately NOT in audit.json
    # (that would recurse when get_audit_trail is itself invoked), but
    # still needed by tests/harness/self_correction_audit.py to verify
    # whether Claude actually called this tool.
    try:
        with (LOGS_DIR / "get_audit_trail_invocations.jsonl").open("a") as _fh:
            _fh.write(
                json.dumps(
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "filter_tool": filter_tool,
                        "filter_since": filter_since,
                        "limit": limit,
                    }
                )
                + "\n"
            )
    except OSError:
        pass

    audit_path = LOGS_DIR / "audit.json"
    if not audit_path.is_file():
        return "No audit log exists yet (run another tool first)."

    try:
        lines = audit_path.read_text(errors="replace").splitlines()
    except (OSError, PermissionError) as e:
        return f"Cannot read audit log: {e}"

    entries = []
    for raw in lines:
        if not raw.strip():
            continue
        try:
            obj = json.loads(raw)
            entries.append(obj)
        except json.JSONDecodeError:
            continue

    if filter_tool:
        entries = [e for e in entries if e.get("tool") == filter_tool]
    if filter_since:
        entries = [e for e in entries if e.get("timestamp", "") >= filter_since]

    total = len(entries)
    entries = entries[-limit:]  # most recent first

    out = [
        f"# Audit trail ({total} matching entries, showing last {len(entries)})",
        "",
    ]
    if filter_tool:
        out.append(f"- **Filtered to tool:** `{filter_tool}`")
    if filter_since:
        out.append(f"- **Filtered to entries since:** `{filter_since}`")
    out.append("")

    if entries:
        # Summary of tools seen
        tool_counts = Counter(e.get("tool", "?") for e in entries)
        out.append("## Tool invocation counts")
        for tool, count in tool_counts.most_common():
            out.append(f"- `{tool}`: {count}")
        out.append("")

        out.append("## Entries (newest last)")
        for e in entries:
            ts = e.get("timestamp", "?")
            tool = e.get("tool", "?")
            params = json.dumps(e.get("params", {}))[:200]
            summary = e.get("result_summary", "")[:200]
            out.append(f"- **{ts}** `{tool}` — params: {params}")
            out.append(f"  result: {summary}")
    else:
        out.append("No matching entries.")

    # NOTE: we intentionally DO NOT _audit() this call — recursing into the
    # audit log every time the agent inspects it would bloat the log and
    # could confuse downstream reasoning.
    return "\n".join(out)
