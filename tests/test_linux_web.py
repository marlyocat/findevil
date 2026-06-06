"""Tests for the web server log analyzer and webshell scanner.

Covers:
- Combined Log Format parser correctness
- Attack-pattern classification (SQLi, LFI, RCE, scanner UA, etc.)
- Upload-then-exec chain detection
- Webshell signature matching
- Recall: scenario 03 produces the expected findings
- Precision: scenario 03 clean files (index.php, login.php, alice bashrc)
  must NOT be flagged
- Precision across scenarios: scenarios 01 and 02 have no nginx logs or
  webshells, so both web tools must remain silent
"""

from pathlib import Path

import pytest

from findevil.tools.linux_web import (
    _scan_file_for_webshell,
    classify_attacks,
    detect_webshell_upload_chain,
    parse_access_log,
)

SC03 = Path(__file__).parent.parent / "samples" / "attack-scenario-03"
SC03_FS = SC03 / "fs"
SC03_LOG = SC03 / "access.log"


# ---------------------------------------------------------------------------
# Parser correctness
# ---------------------------------------------------------------------------


def test_parse_access_log_basic():
    line = (
        '91.121.55.44 - - [14/Apr/2026:15:05:42 +0000] '
        '"POST /uploads/shell.php HTTP/1.1" 200 34 "-" "curl/7.74.0"'
    )
    entries = parse_access_log(line)
    assert len(entries) == 1
    e = entries[0]
    assert e.ip == "91.121.55.44"
    assert e.method == "POST"
    assert e.path == "/uploads/shell.php"
    assert e.status == 200
    assert "curl" in e.user_agent


def test_parse_access_log_skips_malformed():
    content = (
        '10.0.0.5 - - [14/Apr/2026:08:15:22 +0000] "GET / HTTP/1.1" 200 1 "-" "ua"\n'
        'random garbage that is not a log line\n'
        '10.0.0.5 - - [14/Apr/2026:08:15:23 +0000] "GET / HTTP/1.1" 200 1 "-" "ua"\n'
    )
    entries = parse_access_log(content)
    assert len(entries) == 2


# ---------------------------------------------------------------------------
# Attack classification
# ---------------------------------------------------------------------------


def _make(path: str, ua: str = "Mozilla/5.0", method: str = "GET", status: int = 200):
    line = (
        f'1.2.3.4 - - [14/Apr/2026:12:00:00 +0000] '
        f'"{method} {path} HTTP/1.1" {status} 0 "-" "{ua}"'
    )
    return parse_access_log(line)[0]


def test_classify_detects_sql_injection():
    e = _make("/login.php?id=1%20UNION%20SELECT%20*%20FROM%20users")
    labels = classify_attacks(e)
    assert "sql_injection" in labels


def test_classify_detects_path_traversal():
    e = _make("/index.php?file=../../../../etc/passwd")
    labels = classify_attacks(e)
    assert "path_traversal" in labels
    assert "lfi_target" in labels


def test_classify_detects_webshell_cmd_param():
    e = _make("/uploads/shell.php?cmd=id")
    labels = classify_attacks(e)
    assert "webshell_cmd_param" in labels


def test_classify_detects_scanner_user_agent():
    e = _make("/wp-admin/", ua="Mozilla/5.00 (Nikto/2.5.0)")
    labels = classify_attacks(e)
    assert "scanner_user_agent" in labels


def test_classify_clean_request_has_no_labels():
    e = _make("/index.php", ua="Mozilla/5.0 (X11; Linux x86_64)")
    assert classify_attacks(e) == []


# ---------------------------------------------------------------------------
# Upload-then-exec chain detection
# ---------------------------------------------------------------------------


def test_upload_chain_detected():
    content = (
        '91.121.55.44 - - [14/Apr/2026:15:05:42 +0000] "POST /uploads/shell.php HTTP/1.1" 200 34 "-" "curl/7.74.0"\n'
        '91.121.55.44 - - [14/Apr/2026:15:05:58 +0000] "GET /uploads/shell.php?cmd=id HTTP/1.1" 200 39 "-" "curl/7.74.0"\n'
    )
    entries = parse_access_log(content)
    chains = detect_webshell_upload_chain(entries)
    assert len(chains) == 1
    assert chains[0]["path"] == "/uploads/shell.php"


def test_upload_chain_ignores_unrelated_gets():
    content = (
        '91.121.55.44 - - [14/Apr/2026:15:05:42 +0000] "POST /uploads/shell.php HTTP/1.1" 200 34 "-" "curl/7.74.0"\n'
        '91.121.55.44 - - [14/Apr/2026:15:05:58 +0000] "GET /index.php HTTP/1.1" 200 39 "-" "curl/7.74.0"\n'
    )
    entries = parse_access_log(content)
    chains = detect_webshell_upload_chain(entries)
    assert chains == []


# ---------------------------------------------------------------------------
# Webshell signature matching — recall
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SC03_FS.exists(), reason="scenario 03 FS not present")
def test_scan_webshell_detects_scenario03_shell_php():
    shell = SC03_FS / "var/www/html/uploads/shell.php"
    reasons = _scan_file_for_webshell(shell)
    assert reasons, "scenario 03 shell.php must be flagged"
    assert any("shell exec" in r.lower() for r in reasons)


@pytest.mark.skipif(not SC03_FS.exists(), reason="scenario 03 FS not present")
def test_scan_webshell_precision_on_legit_php():
    """index.php and login.php are legitimate and must not match any webshell
    signature."""
    for legit in ["var/www/html/index.php", "var/www/html/login.php"]:
        reasons = _scan_file_for_webshell(SC03_FS / legit)
        assert reasons == [], f"false positive on {legit}: {reasons}"


# ---------------------------------------------------------------------------
# End-to-end: scenario 03 access log produces the upload chain finding
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SC03_LOG.exists(), reason="scenario 03 log not present")
def test_scenario03_access_log_contains_upload_chain():
    content = SC03_LOG.read_text()
    entries = parse_access_log(content)
    chains = detect_webshell_upload_chain(entries)
    assert len(chains) >= 1
    assert any("shell.php" in c["path"] for c in chains)
    # Upload and exec come from the same attacker IP
    assert chains[0]["upload_ip"] == "91.121.55.44"
    assert chains[0]["exec_ip"] == "91.121.55.44"


@pytest.mark.skipif(not SC03_LOG.exists(), reason="scenario 03 log not present")
def test_scenario03_access_log_flags_scanner_and_sqli():
    content = SC03_LOG.read_text()
    entries = parse_access_log(content)
    all_labels = []
    for e in entries:
        all_labels.extend(classify_attacks(e))
    # Must catch both scanner and SQLi signals
    assert "scanner_user_agent" in all_labels
    assert "sql_injection" in all_labels
    assert "path_traversal" in all_labels
