"""Tests for analyze_container_artifacts."""

import json
from pathlib import Path

import pytest

from findevil.tools.linux_containers import (
    _scan_docker_compose,
    _scan_docker_container_config,
    _scan_docker_daemon,
    _scan_k8s_manifest,
)

SC04_FS = Path(__file__).parent.parent / "samples" / "attack-scenario-04" / "fs"


# ---------------------------------------------------------------------------
# Docker container JSON config
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SC04_FS.exists(), reason="scenario 04 FS not present")
def test_scenario04_docker_container_flags_privileged_and_socket_mount():
    cfg = SC04_FS / "var/lib/docker/containers/abc123def456/config.v2.json"
    findings = _scan_docker_container_config(cfg, "var/lib/docker/containers/abc123def456/config.v2.json")
    assert len(findings) == 1
    f = findings[0]
    reasons = " ".join(f.reasons)
    assert "privileged" in reasons.lower()
    assert "SYS_ADMIN" in reasons
    assert "NET_ADMIN" in reasons
    assert "host" in reasons  # NetworkMode=host
    assert "docker.sock" in reasons


def test_docker_container_clean_config_not_flagged(tmp_path: Path):
    cfg = {
        "Name": "/web",
        "Config": {"User": "nobody", "Image": "nginx:latest"},
        "HostConfig": {
            "Binds": [],
            "NetworkMode": "bridge",
            "CapAdd": None,
            "Privileged": False,
            "PidMode": "",
            "IpcMode": "",
        },
    }
    p = tmp_path / "config.v2.json"
    p.write_text(json.dumps(cfg))
    findings = _scan_docker_container_config(p, "clean/config.v2.json")
    assert findings == []


# ---------------------------------------------------------------------------
# Docker daemon
# ---------------------------------------------------------------------------


def test_daemon_does_not_treat_lookalike_loopback_as_safe(tmp_path: Path):
    """Regression: a substring check `"127.0.0.1" not in h` would accept
    `tcp://127.0.0.1.evil.com:2375` as if it were loopback. Path-aware
    parsing must flag it as an exposed TCP listener.
    """
    daemon = tmp_path / "daemon.json"
    daemon.write_text(
        json.dumps({
            "hosts": ["unix:///var/run/docker.sock", "tcp://127.0.0.1.evil.com:2375"],
        })
    )
    findings = _scan_docker_daemon(daemon, "etc/docker/daemon.json")
    assert findings, "lookalike-loopback host should still be flagged as exposed TCP"
    reasons = " ".join(r for f in findings for r in f.reasons)
    assert "tcp" in reasons.lower()
    assert "127.0.0.1.evil.com" in reasons


def test_daemon_real_loopback_not_flagged_as_tcp_listener(tmp_path: Path):
    """Genuine loopback `tcp://127.0.0.1:2375` should not produce a TCP-listener
    finding — only externally-bound TCP should."""
    daemon = tmp_path / "daemon.json"
    daemon.write_text(
        json.dumps({
            "hosts": ["unix:///var/run/docker.sock", "tcp://127.0.0.1:2375"],
        })
    )
    findings = _scan_docker_daemon(daemon, "etc/docker/daemon.json")
    reasons = " ".join(r for f in findings for r in f.reasons)
    assert "daemon listens on TCP" not in reasons


@pytest.mark.skipif(not SC04_FS.exists(), reason="scenario 04 FS not present")
def test_scenario04_daemon_flags_tcp_listener_and_insecure_registry():
    daemon = SC04_FS / "etc/docker/daemon.json"
    findings = _scan_docker_daemon(daemon, "etc/docker/daemon.json")
    assert findings
    reasons = " ".join(r for f in findings for r in f.reasons)
    assert "TCP" in reasons or "tcp" in reasons
    assert "insecure-registries" in reasons


# ---------------------------------------------------------------------------
# docker-compose parsing — unit test
# ---------------------------------------------------------------------------


def test_docker_compose_flags_privileged_and_socket_mount(tmp_path: Path):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "version: '3'\n"
        "services:\n"
        "  worker:\n"
        "    image: worker:latest\n"
        "    privileged: true\n"
        "    network_mode: host\n"
        "    cap_add:\n"
        "      - SYS_ADMIN\n"
        "    volumes:\n"
        "      - /var/run/docker.sock:/var/run/docker.sock\n"
    )
    findings = _scan_docker_compose(compose, "docker-compose.yml")
    assert len(findings) == 1
    reasons = " ".join(findings[0].reasons)
    assert "privileged" in reasons.lower()
    assert "host" in reasons  # network_mode: host
    assert "SYS_ADMIN" in reasons
    assert "docker.sock" in reasons


def test_docker_compose_clean_file_not_flagged(tmp_path: Path):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "version: '3'\n"
        "services:\n"
        "  web:\n"
        "    image: nginx:latest\n"
        "    ports:\n"
        "      - '8080:80'\n"
    )
    findings = _scan_docker_compose(compose, "docker-compose.yml")
    assert findings == []


# ---------------------------------------------------------------------------
# K8s manifests — unit test
# ---------------------------------------------------------------------------


def test_k8s_manifest_flags_privileged_and_host_path(tmp_path: Path):
    manifest = tmp_path / "pod.yaml"
    manifest.write_text(
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata:\n"
        "  name: risky-pod\n"
        "spec:\n"
        "  hostNetwork: true\n"
        "  containers:\n"
        "  - name: main\n"
        "    image: busybox\n"
        "    securityContext:\n"
        "      privileged: true\n"
        "  volumes:\n"
        "  - name: root-fs\n"
        "    hostPath:\n"
        "      path: /\n"
    )
    findings = _scan_k8s_manifest(manifest, "pod.yaml")
    assert len(findings) == 1
    reasons = " ".join(findings[0].reasons)
    assert "privileged" in reasons
    assert "hostNetwork" in reasons
    assert "hostPath" in reasons or "/" in reasons
