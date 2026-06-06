"""Performance / latency regression tests.

These tests assert that the most commonly-invoked tools complete
within a generous wall-clock budget on realistic input sizes. They
catch O(n²) regressions and accidental quadratic blow-ups that pass
unit tests but make a real investigation unusably slow.

Budgets are deliberately loose (~2-5x normal runtime on a modern
laptop) so the tests don't flake on slow CI. They WILL fail if a
refactor actually introduces a quadratic loop on input size.

If a budget here fires and you can't see why, profile with
``python -m cProfile -s cumtime tests/test_performance.py`` rather
than just bumping the budget.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from findevil._table import emit_table
from findevil.tools.linux_persistence import scan_all
from findevil.tools.linux_web import parse_access_log


# ---------------------------------------------------------------------------
# scan_all / find_persistence on a wide tree
# ---------------------------------------------------------------------------


def _build_synthetic_fs(root: Path, n_systemd_units: int, n_cron: int, n_users: int) -> None:
    """Build a fake fs/ tree wide enough to test scanner scaling."""
    (root / "etc/systemd/system").mkdir(parents=True)
    for i in range(n_systemd_units):
        (root / f"etc/systemd/system/svc-{i:04d}.service").write_text(
            "[Unit]\nDescription=svc\n[Service]\nExecStart=/usr/bin/true\n"
        )
    (root / "etc/cron.d").mkdir(parents=True)
    for i in range(n_cron):
        (root / f"etc/cron.d/job-{i:04d}").write_text(
            f"*/{i % 60 + 1} * * * * root /usr/bin/true\n"
        )
    (root / "etc").mkdir(exist_ok=True)
    passwd_lines = ["root:x:0:0:root:/root:/bin/bash\n"]
    for i in range(n_users):
        passwd_lines.append(
            f"user{i:04d}:x:{1000 + i}:{1000 + i}::/home/user{i:04d}:/bin/bash\n"
        )
    (root / "etc/passwd").write_text("".join(passwd_lines))
    (root / "etc/shadow").write_text(
        "root:$6$abc$xyz:19000:0:99999:7:::\n"
        + "".join(f"user{i:04d}:!:19000:0:99999:7:::\n" for i in range(n_users))
    )


def test_scan_all_completes_under_budget_for_1000_units(tmp_path):
    """1000 systemd units + 200 cron files + 500 users — synthetic but
    realistic for a busy production host. Budget: 5 seconds wall-clock.
    A regression to O(n²) on ExecStart parsing or passwd lookup makes
    this overshoot dramatically.
    """
    _build_synthetic_fs(tmp_path, n_systemd_units=1000, n_cron=200, n_users=500)
    started = time.perf_counter()
    findings = scan_all(tmp_path)
    elapsed = time.perf_counter() - started
    assert elapsed < 5.0, f"scan_all took {elapsed:.2f}s on 1000 units; budget 5.0s"
    # Sanity: it didn't accidentally short-circuit
    assert isinstance(findings, list)
    assert len(findings) > 0  # at minimum the units are reported


# ---------------------------------------------------------------------------
# parse_access_log on a 10k-line nginx log
# ---------------------------------------------------------------------------


def test_parse_access_log_under_budget_for_10k_lines():
    """A typical webserver produces 10–100k access log entries per day.
    Parsing 10k lines should complete in well under 2 seconds on any modern
    machine. A regression to backtracking regex would blow this up.
    """
    line = (
        '1.2.3.4 - - [14/Apr/2026:15:03:11 +0000] '
        '"GET /api/v1/health HTTP/1.1" 200 42 "-" "Mozilla/5.0"\n'
    )
    content = line * 10_000
    started = time.perf_counter()
    entries = parse_access_log(content)
    elapsed = time.perf_counter() - started
    assert elapsed < 2.0, f"parse_access_log took {elapsed:.2f}s on 10k lines; budget 2.0s"
    assert len(entries) == 10_000


def test_parse_access_log_under_budget_for_pathological_paths():
    """Long path query strings can trigger catastrophic backtracking in
    naive regex. Confirm we don't hit that.
    """
    long_path = "/api/v1/" + ("a" * 4000)
    line = (
        f'1.2.3.4 - - [14/Apr/2026:15:03:11 +0000] '
        f'"GET {long_path} HTTP/1.1" 200 0 "-" "-"\n'
    )
    content = line * 500
    started = time.perf_counter()
    entries = parse_access_log(content)
    elapsed = time.perf_counter() - started
    # Higher budget; the bigger lines are legitimately more work.
    assert elapsed < 3.0, f"parse_access_log took {elapsed:.2f}s on 500 long-path lines"
    assert len(entries) == 500


# ---------------------------------------------------------------------------
# emit_table on a 50k-row table
# ---------------------------------------------------------------------------


def test_emit_table_under_budget_for_50k_rows_with_top_n():
    """emit_table is the single hottest formatter — every tool that produces
    a tabular report goes through it. Calling it with top_n must short-cut
    rendering past top_n rows, not iterate all of them.
    """
    rows = [[f"item-{i:05d}", str(i), f"detail {i}"] for i in range(50_000)]
    started = time.perf_counter()
    out = emit_table(["name", "id", "detail"], rows, top_n=100)
    elapsed = time.perf_counter() - started
    assert elapsed < 1.0, f"emit_table 50k rows top_n=100 took {elapsed:.3f}s; budget 1.0s"
    # Output should mention the truncation
    assert "more rows hidden" in out
    # Output line count should be 100 + table header + footer note (≤105 lines)
    assert out.count("\n") < 110


def test_emit_table_under_budget_for_5k_rows_full():
    """Without top_n, all 5k rows render. Should still be sub-second."""
    rows = [[f"item-{i:05d}", str(i), f"detail {i}"] for i in range(5_000)]
    started = time.perf_counter()
    out = emit_table(["name", "id", "detail"], rows)
    elapsed = time.perf_counter() - started
    assert elapsed < 1.0, f"emit_table 5k rows full took {elapsed:.3f}s; budget 1.0s"
    assert out.count("\n") >= 5_000


# ---------------------------------------------------------------------------
# Sanity: the strategies above produce non-trivial work
# ---------------------------------------------------------------------------


def test_synthetic_fs_actually_has_content(tmp_path):
    _build_synthetic_fs(tmp_path, n_systemd_units=10, n_cron=5, n_users=3)
    units = list((tmp_path / "etc/systemd/system").glob("*.service"))
    assert len(units) == 10
    cron_files = list((tmp_path / "etc/cron.d").iterdir())
    assert len(cron_files) == 5
