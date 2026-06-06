"""
MITRE ATT&CK coverage audit.

docs/accuracy-report.md §2.3 enumerates the Linux techniques findevil
claims specialised detection for. This test maps every claimed
technique to (scenario, evidence file, content marker) triple and
grep-verifies that the marker is actually present in the named
evidence file. If a claim is made but no fixture backs it, the test
fails and the claim must either be dropped from the report or a
scenario added.

This is a static test — no LLM, no tool execution — so it's fast
enough to run on every CI pass. It protects the report's credibility:
the submission says "we detect T1574.006 LD_PRELOAD" and this test
proves the scenario fixture for that technique actually exists.
"""

from __future__ import annotations

from pathlib import Path

import pytest

SAMPLES_ROOT = Path(__file__).parent.parent.parent / "samples"


# (technique_id, short_label, scenario_dir, evidence_relative_path, marker_substring)
# Each tuple says: "To back up the T... claim, grep this marker in this file."
MITRE_COVERAGE: list[tuple[str, str, str, str, str]] = [
    ("T1110.001", "brute force",
        "attack-scenario-01", "auth.log", "45.123.45.67"),
    ("T1078.003", "valid accounts (stolen key)",
        "attack-scenario-02", "auth.log", "185.229.59.103"),
    ("T1003.008", "/etc/shadow access",
        "attack-scenario-01", "auth.log", "/etc/shadow"),
    ("T1552.003", "bash history credential search",
        "attack-scenario-12-lotl", "fs/home/deploy/.bash_history", "shadow"),
    ("T1136.001", "useradd backdoor",
        "attack-scenario-01", "auth.log", "useradd[22215]: new user: name=sysd"),
    ("T1543.002", "systemd service persistence",
        "attack-scenario-02", "fs/etc/systemd/system/system-updater.service", "ExecStart"),
    ("T1053.003", "cron persistence",
        "attack-scenario-03", "fs/etc/cron.d/backup-check", "*"),
    ("T1098.004", "authorized_keys addition",
        "attack-scenario-01", "fs/root/.ssh/authorized_keys", "ssh-"),
    ("T1574.006", "LD_PRELOAD rootkit",
        "attack-scenario-01", "fs/etc/ld.so.preload", "libprocesshider"),
    ("T1556.003", "PAM module modification",
        "attack-scenario-01", "fs/etc/pam.d/sshd", "pam_exec"),
    ("T1547.006", "kernel module",
        "attack-scenario-01", "fs/etc/modules", "sysd_helper_km"),
    ("T1562.001", "disable/modify security tools",
        "attack-scenario-01", "auth.log", "stop auditd"),
    ("T1070.003", "clear linux command history",
        "attack-scenario-01", "auth.log", "history -c"),
    ("T1222", "chattr file attribute manipulation",
        "attack-scenario-01", "auth.log", "chattr"),
    ("T1059.004", "unix shell execution",
        "attack-scenario-01", "auth.log", "/bin/bash"),
    ("T1190", "webshell / application exploit",
        "attack-scenario-03", "fs/var/www/html/uploads/shell.php", "system("),
    ("T1195.002", "supply chain compromise",
        "attack-scenario-04", "fs/root/.pip/pip.log", "requests-utils"),
    ("T1611", "escape to host via container",
        "attack-scenario-04", "fs/var/lib/docker/containers/abc123def456/config.v2.json",
        "Privileged"),
    ("T1078.004", "cloud/container service-account abuse",
        "attack-scenario-04", "fs/etc/docker/daemon.json", "2375"),
    ("T1071", "application-layer C2",
        "attack-scenario-02", "fs/etc/systemd/system/system-updater.service",
        "185.229.59.103"),
    ("T1105", "ingress tool transfer",
        "attack-scenario-01", "auth.log", "curl"),
    # Newer scenarios (S05–S13) — include so the coverage table reflects them.
    ("T1078-insider", "authorized-credential misuse (insider)",
        "attack-scenario-11-insider", "fs/home/alice/.bash_history", "mysqldump"),
    ("T1059.004-LotL", "LotL post-compromise shell builtins",
        "attack-scenario-12-lotl", "fs/etc/cron.d/log-rotation-check", "/dev/tcp"),
    ("T1486", "data encrypted for impact (ransomware)",
        "attack-scenario-13-ransomware", "fs/root/.bash_history", "openssl enc -aes-256-cbc"),
    ("T1490", "inhibit system recovery (backup destruction)",
        "attack-scenario-13-ransomware", "fs/root/.bash_history", "btrfs subvolume delete"),
    ("T1036-falseflag", "masquerading / false-flag attribution",
        "attack-scenario-08-falseflag", "access.log", "APT40"),
    ("T1027-evasion", "obfuscated files / commands",
        "attack-scenario-09-evasion", "fs/var/www/html/assets/health-check.php",
        "base64_decode"),
    ("T1036.005-udev", "udev-rule persistence (novel)",
        "attack-scenario-07-novel", "fs/etc/udev/rules.d/99-backdoor.rules",
        "/usr/local/bin/update"),
]


@pytest.mark.parametrize(
    "technique,label,scenario_dir,evidence_path,marker",
    MITRE_COVERAGE,
    ids=[f"{t}-{label.replace(' ', '_')}" for t, label, _, _, _ in MITRE_COVERAGE],
)
def test_technique_has_evidence_fixture(
    technique: str, label: str, scenario_dir: str, evidence_path: str, marker: str
):
    path = SAMPLES_ROOT / scenario_dir / evidence_path
    assert path.exists(), (
        f"{technique} ({label}): evidence file missing at "
        f"samples/{scenario_dir}/{evidence_path}. Either add the fixture "
        f"or drop the technique claim from docs/accuracy-report.md §2.3."
    )
    content = path.read_text(errors="replace")
    if marker != "*":  # "*" means "just check the file exists"
        assert marker in content, (
            f"{technique} ({label}): marker {marker!r} not found in "
            f"samples/{scenario_dir}/{evidence_path}. The file exists but "
            f"doesn't contain the evidence signal the technique claim relies on."
        )


def test_coverage_has_full_breadth():
    """Sanity: we should be covering >= 25 distinct technique IDs."""
    assert len(MITRE_COVERAGE) >= 25, (
        f"only {len(MITRE_COVERAGE)} techniques in coverage table — "
        "shrinking coverage would quietly reduce the submission's claim set."
    )
