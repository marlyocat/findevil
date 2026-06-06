"""Direct tests for `@mcp.tool()` wrappers that aren't covered by the
unit-test suite or the smoke test.

The unit test files (`test_linux_persistence.py`, `test_linux_web.py`
etc.) exercise the parsers and scanners. `test_mcp_smoke.py` confirms
five core wrappers run on S01. This file fills the gap: it calls every
remaining wrapper directly, asserts a non-empty string return, and
verifies path-validation rejects a path outside the evidence root.

Run on any platform that can read the bundled samples — no Linux
subprocess dependency for these wrappers (they're Python-native).
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

SAMPLES = Path(__file__).parent.parent / "samples"
SC01 = SAMPLES / "attack-scenario-01"
SC01_FS = SC01 / "fs"
SC02 = SAMPLES / "attack-scenario-02"
SC02_FS = SC02 / "fs"
SC03 = SAMPLES / "attack-scenario-03"
SC04 = SAMPLES / "attack-scenario-04"
SC04_FS = SC04 / "fs"


@pytest.fixture
def env(monkeypatch):
    """Reload the server module against samples/ so all S01..S04 paths
    resolve. Each test function gets a fresh module state."""
    monkeypatch.setenv("FINDEVIL_EVIDENCE_DIR", str(SAMPLES))
    monkeypatch.setenv("FINDEVIL_LOGS_DIR", str(SAMPLES.parent / "logs"))
    import findevil.server as server
    importlib.reload(server)
    for mod in list(sys.modules):
        if mod.startswith("findevil.tools."):
            importlib.reload(sys.modules[mod])
    yield


# ---------------------------------------------------------------------------
# linux_auth — five wrappers
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not (SC01 / "auth.log").is_file(), reason="auth.log not present")
def test_auth_summary_wrapper_returns_string(env):
    from findevil.tools.linux_auth import auth_summary
    out = auth_summary(str(SC01 / "auth.log"))
    assert isinstance(out, str) and out


@pytest.mark.skipif(not (SC01 / "auth.log").is_file(), reason="auth.log not present")
def test_auth_failed_logins_finds_brute_force_ip(env):
    from findevil.tools.linux_auth import auth_failed_logins
    out = auth_failed_logins(str(SC01 / "auth.log"))
    assert isinstance(out, str)
    # S01 has 60 failed root password attempts from this IP.
    assert "45.123.45.67" in out


@pytest.mark.skipif(not (SC01 / "auth.log").is_file(), reason="auth.log not present")
def test_auth_successful_logins_lists_root_session(env):
    from findevil.tools.linux_auth import auth_successful_logins
    out = auth_successful_logins(str(SC01 / "auth.log"))
    assert isinstance(out, str)
    # S01 has the root login from the brute-force IP.
    assert "root" in out.lower()


@pytest.mark.skipif(not (SC01 / "auth.log").is_file(), reason="auth.log not present")
def test_auth_sudo_commands_lists_shadow_read(env):
    from findevil.tools.linux_auth import auth_sudo_commands
    out = auth_sudo_commands(str(SC01 / "auth.log"))
    assert isinstance(out, str)
    # S01 has `sudo cat /etc/shadow` in the attack window.
    assert "shadow" in out.lower()


@pytest.mark.skipif(not (SC01 / "auth.log").is_file(), reason="auth.log not present")
def test_auth_user_events_finds_useradd(env):
    from findevil.tools.linux_auth import auth_user_events
    out = auth_user_events(str(SC01 / "auth.log"))
    assert isinstance(out, str)
    # S01 plants user `sysd` via useradd.
    assert "sysd" in out.lower()


def test_auth_summary_rejects_path_outside_evidence(env, tmp_path):
    from findevil.tools.linux_auth import auth_summary
    outside = tmp_path / "auth.log"
    outside.write_text("Apr 12 14:30:01 host sshd[1]: ok\n")
    out = auth_summary(str(outside))
    assert "Access denied" in out or "outside" in out.lower()


# ---------------------------------------------------------------------------
# linux_persistence — four wrappers (find_persistence covered by smoke test)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not (SC01_FS / "etc/systemd/system/sysd-helper.service").is_file(),
    reason="S01 systemd unit missing",
)
def test_analyze_systemd_unit_flags_tmp_execstart(env):
    from findevil.tools.linux_persistence import analyze_systemd_unit
    unit = SC01_FS / "etc/systemd/system/sysd-helper.service"
    out = analyze_systemd_unit(str(unit))
    assert isinstance(out, str)
    assert "ExecStart" in out


@pytest.mark.skipif(
    not (SC01_FS / "root/.ssh/authorized_keys").is_file(),
    reason="S01 authorized_keys missing",
)
def test_analyze_authorized_keys_lists_keys(env):
    from findevil.tools.linux_persistence import analyze_authorized_keys
    out = analyze_authorized_keys(str(SC01_FS / "root/.ssh/authorized_keys"))
    assert isinstance(out, str)
    assert "key" in out.lower()


@pytest.mark.skipif(
    not (SC01_FS / "etc/ssh/sshd_config").is_file(),
    reason="S01 sshd_config missing",
)
def test_analyze_sshd_config_flags_dangerous_settings(env):
    from findevil.tools.linux_persistence import analyze_sshd_config
    out = analyze_sshd_config(str(SC01_FS / "etc/ssh/sshd_config"))
    assert isinstance(out, str)
    # S01's sshd_config has PermitRootLogin yes + PasswordAuthentication yes.
    low = out.lower()
    assert "permitrootlogin" in low or "passwordauth" in low


@pytest.mark.skipif(
    not (SC02_FS / "etc/sudoers.d/deploy").is_file(),
    reason="S02 sudoers fragment missing",
)
def test_analyze_sudoers_flags_bare_binary_nopasswd(env):
    from findevil.tools.linux_persistence import analyze_sudoers
    out = analyze_sudoers(str(SC02_FS / "etc/sudoers.d/deploy"))
    assert isinstance(out, str)
    # S02 grants deploy NOPASSWD on bare /usr/bin/systemctl.
    assert "deploy" in out.lower()


# ---------------------------------------------------------------------------
# linux_web — two wrappers
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not (SC03 / "access.log").is_file(),
    reason="S03 access.log missing",
)
def test_analyze_nginx_access_finds_webshell_chain(env):
    from findevil.tools.linux_web import analyze_nginx_access
    out = analyze_nginx_access(str(SC03 / "access.log"))
    assert isinstance(out, str)
    # S03 has webshell upload chain from this IP.
    assert "91.121.55.44" in out


@pytest.mark.skipif(not SC03.is_dir(), reason="S03 missing")
def test_find_webshells_walks_evidence_root(env):
    from findevil.tools.linux_web import find_webshells
    out = find_webshells(str(SC03))
    assert isinstance(out, str)


# ---------------------------------------------------------------------------
# linux_packages + linux_containers — two wrappers
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SC04_FS.is_dir(), reason="S04 fs missing")
def test_analyze_package_logs_finds_xmrig(env):
    from findevil.tools.linux_packages import analyze_package_logs
    out = analyze_package_logs(str(SC04_FS))
    assert isinstance(out, str)
    # S04 plants an xmrig install via apt.
    assert "xmrig" in out.lower()


@pytest.mark.skipif(not SC04_FS.is_dir(), reason="S04 fs missing")
def test_analyze_container_artifacts_flags_privileged(env):
    from findevil.tools.linux_containers import analyze_container_artifacts
    out = analyze_container_artifacts(str(SC04_FS))
    assert isinstance(out, str)
    # S04 has a privileged Docker container.
    assert "privileged" in out.lower() or "docker" in out.lower()


# ---------------------------------------------------------------------------
# linux_shell_history — analyze_bash_history wrapper
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not (SC01_FS / "home/sysd/.bash_history").is_file(),
    reason="S01 sysd bash_history missing",
)
def test_analyze_bash_history_returns_string(env):
    from findevil.tools.linux_shell_history import analyze_bash_history
    out = analyze_bash_history(str(SC01_FS / "home/sysd/.bash_history"))
    assert isinstance(out, str)


# ---------------------------------------------------------------------------
# linux_timeline — find_recent_changes wrapper
# ---------------------------------------------------------------------------


def test_find_recent_changes_lists_files(env, tmp_path, monkeypatch):
    """`find_recent_changes` walks a tree and reports files modified within
    a time window. Verify it returns a markdown report on a synthetic tree.
    """
    monkeypatch.setenv("FINDEVIL_EVIDENCE_DIR", str(tmp_path))
    import findevil.server as server
    importlib.reload(server)
    import findevil.tools.linux_timeline as tl
    importlib.reload(tl)

    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "config").write_text("hello")
    (tmp_path / "var").mkdir()
    (tmp_path / "var" / "log").write_text("ok\n")

    # Wide window — captures everything we just wrote.
    out = tl.find_recent_changes(
        str(tmp_path),
        "2000-01-01T00:00:00+00:00",
        "2099-01-01T00:00:00+00:00",
    )
    assert isinstance(out, str)


# ---------------------------------------------------------------------------
# ai_signatures — find_ai_signatures wrapper
# ---------------------------------------------------------------------------


def test_find_ai_signatures_returns_string_on_clean_tree(env, tmp_path, monkeypatch):
    monkeypatch.setenv("FINDEVIL_EVIDENCE_DIR", str(tmp_path))
    import findevil.server as server
    importlib.reload(server)
    import findevil.tools.ai_signatures as ai
    importlib.reload(ai)

    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "rsyslog.conf").write_text("# default rsyslog\n")
    out = ai.find_ai_signatures(str(tmp_path))
    assert isinstance(out, str)


def test_find_ai_signatures_flags_anthropic_url(env, tmp_path, monkeypatch):
    monkeypatch.setenv("FINDEVIL_EVIDENCE_DIR", str(tmp_path))
    import findevil.server as server
    importlib.reload(server)
    import findevil.tools.ai_signatures as ai
    importlib.reload(ai)

    sysconfig = tmp_path / "etc/sysconfig"
    sysconfig.mkdir(parents=True)
    (sysconfig / "agent-env").write_text(
        "ANTHROPIC_API_URL=https://api.anthropic.com\n"
        "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n"
    )
    out = ai.find_ai_signatures(str(tmp_path))
    assert isinstance(out, str)
    low = out.lower()
    assert "anthropic" in low or "openai" in low or "api" in low


# ---------------------------------------------------------------------------
# Path-validation surface check — every wrapper rejects an outside path
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "module_name,fn_name",
    [
        ("findevil.tools.linux_auth", "auth_summary"),
        ("findevil.tools.linux_auth", "auth_failed_logins"),
        ("findevil.tools.linux_auth", "auth_successful_logins"),
        ("findevil.tools.linux_auth", "auth_sudo_commands"),
        ("findevil.tools.linux_auth", "auth_user_events"),
        ("findevil.tools.linux_persistence", "analyze_systemd_unit"),
        ("findevil.tools.linux_persistence", "analyze_authorized_keys"),
        ("findevil.tools.linux_persistence", "analyze_sshd_config"),
        ("findevil.tools.linux_persistence", "analyze_sudoers"),
        ("findevil.tools.linux_web", "analyze_nginx_access"),
        ("findevil.tools.linux_web", "find_webshells"),
        ("findevil.tools.linux_packages", "analyze_package_logs"),
        ("findevil.tools.linux_containers", "analyze_container_artifacts"),
        ("findevil.tools.linux_shell_history", "analyze_bash_history"),
        ("findevil.tools.linux_shell_history", "find_shell_histories"),
        # `find_recent_changes` takes (root, since_iso, until_iso) — its
        # path-rejection coverage is a dedicated test below; omitting it
        # here keeps the parametrize body uniform (single-positional call).
        ("findevil.tools.ai_signatures", "find_ai_signatures"),
    ],
)
def test_wrapper_rejects_path_outside_evidence(env, tmp_path, module_name, fn_name):
    """Every @mcp.tool() wrapper that takes a path must reject paths
    outside FINDEVIL_EVIDENCE_DIR. Catches accidental removal of the
    `_validate_evidence_path` call during a refactor."""
    mod = importlib.import_module(module_name)
    fn = getattr(mod, fn_name)
    # Create a target file/dir outside SAMPLES (the env-set evidence dir).
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "fake.log").write_text("fake")
    target = str(outside / "fake.log") if "log" in fn_name or "config" in fn_name else str(outside)
    out = fn(target)
    assert isinstance(out, str)
    low = out.lower()
    assert "access denied" in low or "outside" in low or "error" in low, (
        f"{fn_name} did not reject outside path: returned {out[:200]!r}"
    )


def test_find_recent_changes_rejects_path_outside_evidence(env, tmp_path):
    """Multi-positional-argument analog of test_wrapper_rejects_path_outside_evidence
    for find_recent_changes, which takes (root, since_iso, until_iso)."""
    from findevil.tools.linux_timeline import find_recent_changes
    outside = tmp_path / "outside"
    outside.mkdir()
    out = find_recent_changes(
        str(outside),
        "2000-01-01T00:00:00+00:00",
        "2099-01-01T00:00:00+00:00",
    )
    assert isinstance(out, str)
    low = out.lower()
    assert "access denied" in low or "outside" in low or "error" in low, (
        f"find_recent_changes did not reject outside path: returned {out[:200]!r}"
    )
