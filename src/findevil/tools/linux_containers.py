"""
Container artifact analysis (Docker, containerd, Kubernetes).

Attackers increasingly target containerised Linux workloads. The classic
breakouts and escalations:

- Privileged containers (`docker run --privileged`) — full host access
- Dangerous capabilities (`--cap-add SYS_ADMIN`, `NET_ADMIN`, `SYS_MODULE`)
- Docker socket mounted inside a container (`-v /var/run/docker.sock`)
- Host network / PID namespace sharing (`--network=host`, `--pid=host`)
- hostPath volumes in Kubernetes that mount `/`, `/etc`, or `/root`
- RBAC misconfigs: service accounts with `cluster-admin`

This module scans Docker container JSON configs, docker-compose files,
Docker daemon config, and Kubernetes manifests for these indicators.

Tool: `analyze_container_artifacts(root_path)` — enumerates all container
artifacts and flags each dangerous setting with provenance.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from findevil.server import _audit, _validate_evidence_path, mcp


@dataclass
class ContainerFinding:
    path: str
    kind: str  # "docker_container", "docker_compose", "docker_daemon", "k8s_pod", "k8s_role"
    severity: str
    summary: str
    reasons: list[str] = field(default_factory=list)
    sample: str = ""


# Dangerous capabilities (a minimal set — each of these by itself enables
# meaningful container escape or host takeover)
_DANGEROUS_CAPS = {
    "SYS_ADMIN",  # mount, pivot_root, many syscalls
    "SYS_PTRACE",  # debug host processes
    "SYS_MODULE",  # load kernel modules
    "SYS_RAWIO",  # raw I/O access
    "DAC_READ_SEARCH",  # bypass file-read permission checks
    "NET_ADMIN",  # network stack control
    "NET_RAW",  # raw packet crafting
    "SYSLOG",  # read kmsg
}


_SENSITIVE_HOST_PATHS = {
    "/",  # whole FS
    "/etc",
    "/root",
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/proc",
    "/sys",
    "/var/lib/docker",
    "/etc/kubernetes",
    "/var/log",
}


# ---------------------------------------------------------------------------
# Docker container config parsing (/var/lib/docker/containers/<id>/config.v2.json)
# ---------------------------------------------------------------------------


def _scan_docker_container_config(path: Path, rel_path: str) -> list[ContainerFinding]:
    findings: list[ContainerFinding] = []
    try:
        data = json.loads(path.read_text(errors="replace"))
    except (json.JSONDecodeError, OSError):
        return findings

    host_config = data.get("HostConfig", {})
    name = data.get("Name", rel_path).lstrip("/")

    reasons = []

    # Privileged mode
    if host_config.get("Privileged"):
        reasons.append("container started with --privileged (effectively root on host)")

    # Dangerous capabilities
    caps = host_config.get("CapAdd") or []
    for cap in caps:
        normalised = cap.replace("CAP_", "").upper()
        if normalised in _DANGEROUS_CAPS:
            reasons.append(f"capability added: CAP_{normalised}")

    # Host namespace sharing
    if host_config.get("NetworkMode") == "host":
        reasons.append("NetworkMode=host (shares host network stack)")
    if host_config.get("PidMode") == "host":
        reasons.append("PidMode=host (can ptrace host processes)")
    if host_config.get("IpcMode") == "host":
        reasons.append("IpcMode=host (shares host IPC namespace)")
    if host_config.get("UsernsMode") == "host":
        reasons.append("UsernsMode=host (no user-namespace isolation)")

    # Sensitive host-path mounts
    binds = host_config.get("Binds") or []
    for b in binds:
        # format: /host/path:/container/path[:mode]
        host_part = b.split(":", 1)[0]
        for sensitive in _SENSITIVE_HOST_PATHS:
            if host_part == sensitive or host_part.startswith(sensitive.rstrip("/") + "/"):
                reasons.append(f"mounts sensitive host path `{host_part}` into container")
                break

    # Mounts[] is the modern replacement for Binds
    for mount in host_config.get("Mounts") or []:
        src = mount.get("Source", "")
        if src in _SENSITIVE_HOST_PATHS or any(
            src.startswith(s.rstrip("/") + "/") for s in _SENSITIVE_HOST_PATHS
        ):
            reasons.append(f"mount sources sensitive host path `{src}`")

    if reasons:
        findings.append(
            ContainerFinding(
                path=rel_path,
                kind="docker_container",
                severity="high",
                summary=f"container `{name}` has risky runtime settings",
                reasons=list(dict.fromkeys(reasons)),
                sample=json.dumps(
                    {
                        "Name": name,
                        "Privileged": host_config.get("Privileged"),
                        "CapAdd": caps,
                        "NetworkMode": host_config.get("NetworkMode"),
                        "PidMode": host_config.get("PidMode"),
                        "Binds": binds,
                    },
                    indent=2,
                )[:500],
            )
        )
    return findings


# ---------------------------------------------------------------------------
# docker-compose.yml / .yaml parsing — simple regex-level checks
# ---------------------------------------------------------------------------


_COMPOSE_PRIVILEGED_RE = re.compile(r"^\s*privileged\s*:\s*(?:true|yes)\s*$", re.M | re.I)
_COMPOSE_CAP_ADD_RE = re.compile(r"^\s*cap_add\s*:\s*\n((?:\s+-\s*.+\n)+)", re.M)
_COMPOSE_VOLUMES_RE = re.compile(r"^\s*volumes\s*:\s*\n((?:\s+-\s*[^\n]+\n)+)", re.M)
_COMPOSE_NETWORK_MODE_RE = re.compile(r"^\s*network_mode\s*:\s*[\"']?(host|container:.+)[\"']?", re.M)
_COMPOSE_PID_MODE_RE = re.compile(r"^\s*pid\s*:\s*[\"']?host[\"']?", re.M)


def _scan_docker_compose(path: Path, rel_path: str) -> list[ContainerFinding]:
    findings: list[ContainerFinding] = []
    try:
        content = path.read_text(errors="replace")
    except OSError:
        return findings

    reasons: list[str] = []
    if _COMPOSE_PRIVILEGED_RE.search(content):
        reasons.append("privileged: true set on a service")
    if _COMPOSE_NETWORK_MODE_RE.search(content):
        reasons.append("network_mode: host set on a service")
    if _COMPOSE_PID_MODE_RE.search(content):
        reasons.append("pid: host set on a service")

    cap_match = _COMPOSE_CAP_ADD_RE.search(content)
    if cap_match:
        caps = re.findall(r"-\s*([A-Z_]+)", cap_match.group(1))
        for cap in caps:
            normalised = cap.replace("CAP_", "").upper()
            if normalised in _DANGEROUS_CAPS:
                reasons.append(f"cap_add includes CAP_{normalised}")

    vol_match = _COMPOSE_VOLUMES_RE.search(content)
    if vol_match:
        for line in vol_match.group(1).splitlines():
            bind = re.match(r"\s*-\s*([^:\s]+)(?::|$)", line)
            if not bind:
                continue
            host_path = bind.group(1).strip('"\' ')
            if host_path in _SENSITIVE_HOST_PATHS or any(
                host_path.startswith(s.rstrip("/") + "/") for s in _SENSITIVE_HOST_PATHS
            ):
                reasons.append(f"volume mount sources `{host_path}` from host")

    if reasons:
        findings.append(
            ContainerFinding(
                path=rel_path,
                kind="docker_compose",
                severity="high",
                summary=f"docker-compose file exposes the host",
                reasons=list(dict.fromkeys(reasons)),
                sample=content[:500],
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Docker daemon config (/etc/docker/daemon.json)
# ---------------------------------------------------------------------------


def _scan_docker_daemon(path: Path, rel_path: str) -> list[ContainerFinding]:
    findings: list[ContainerFinding] = []
    try:
        data = json.loads(path.read_text(errors="replace"))
    except (json.JSONDecodeError, OSError):
        return findings

    reasons: list[str] = []

    # TCP listener on any external iface. Parse the host out of `tcp://HOST:PORT`
    # explicitly — a substring check like `"127.0.0.1" not in h` would accept
    # `tcp://127.0.0.1.evil.com:2375` as if it were loopback.
    hosts = data.get("hosts") or []
    for h in hosts:
        if not isinstance(h, str) or not h.startswith("tcp://"):
            continue
        host_part = h[len("tcp://"):].rsplit(":", 1)[0]
        # Strip optional brackets for IPv6 literals.
        host_part = host_part.strip("[]")
        if host_part not in ("127.0.0.1", "localhost", "::1"):
            reasons.append(f"daemon listens on TCP: {h} (must be firewalled / mTLS)")

    # Disabled user namespace remap
    if data.get("userns-remap") == "default":
        pass  # OK — actually enabled
    elif "userns-remap" not in data:
        reasons.append("userns-remap not configured (containers run as real root on host)")

    if data.get("no-new-privileges") is False:
        reasons.append("no-new-privileges disabled (setuid exploits possible)")

    # Insecure registries
    insecure = data.get("insecure-registries") or []
    if insecure:
        reasons.append(f"insecure-registries configured: {insecure} (allows non-TLS pulls)")

    if reasons:
        findings.append(
            ContainerFinding(
                path=rel_path,
                kind="docker_daemon",
                severity="medium",
                summary="Docker daemon configuration weakens isolation",
                reasons=list(dict.fromkeys(reasons)),
                sample=json.dumps(data, indent=2)[:500],
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Kubernetes manifests (pod specs, roles)
# ---------------------------------------------------------------------------


_K8S_PRIVILEGED_RE = re.compile(r"^\s*privileged\s*:\s*true\s*$", re.M)
_K8S_HOSTPATH_RE = re.compile(r"^\s*hostPath\s*:\s*\n\s*path\s*:\s*[\"']?([^\n\"']+)[\"']?", re.M)
_K8S_HOST_NETWORK_RE = re.compile(r"^\s*hostNetwork\s*:\s*true", re.M)
_K8S_HOST_PID_RE = re.compile(r"^\s*hostPID\s*:\s*true", re.M)
_K8S_CLUSTER_ADMIN_RE = re.compile(r"^\s*name\s*:\s*cluster-admin\s*$", re.M)


def _scan_k8s_manifest(path: Path, rel_path: str) -> list[ContainerFinding]:
    findings: list[ContainerFinding] = []
    try:
        content = path.read_text(errors="replace")
    except OSError:
        return findings

    reasons: list[str] = []

    if _K8S_PRIVILEGED_RE.search(content):
        reasons.append("container spec has privileged: true")
    if _K8S_HOST_NETWORK_RE.search(content):
        reasons.append("pod spec has hostNetwork: true")
    if _K8S_HOST_PID_RE.search(content):
        reasons.append("pod spec has hostPID: true")

    for m in _K8S_HOSTPATH_RE.finditer(content):
        host_path = m.group(1).strip()
        if host_path in _SENSITIVE_HOST_PATHS or any(
            host_path.startswith(s.rstrip("/") + "/") for s in _SENSITIVE_HOST_PATHS
        ):
            reasons.append(f"hostPath volume sources `{host_path}`")

    if "ClusterRoleBinding" in content and _K8S_CLUSTER_ADMIN_RE.search(content):
        # Look for obviously bad bindings, e.g. anonymous / default SA
        if re.search(r"subjects\s*:.*?(system:anonymous|default)", content, re.S):
            reasons.append("cluster-admin bound to anonymous or default service account")

    if reasons:
        findings.append(
            ContainerFinding(
                path=rel_path,
                kind="k8s_manifest",
                severity="high",
                summary="Kubernetes manifest weakens pod/cluster isolation",
                reasons=list(dict.fromkeys(reasons)),
                sample=content[:500],
            )
        )
    return findings


# ---------------------------------------------------------------------------
# MCP tool
# ---------------------------------------------------------------------------


@mcp.tool()
def analyze_container_artifacts(root_path: str) -> str:
    """Scan a filesystem root for container / Kubernetes security issues.

    Covers:
    - Docker container configs (/var/lib/docker/containers/*/config.v2.json)
    - Docker daemon config (/etc/docker/daemon.json)
    - docker-compose.yml / docker-compose.yaml anywhere under root
    - Kubernetes manifests (*.yaml / *.yml in /etc/kubernetes/, /var/lib/kubelet/config/)

    Flags: privileged containers, dangerous capabilities (SYS_ADMIN,
    SYS_PTRACE, SYS_MODULE, NET_ADMIN, NET_RAW, DAC_READ_SEARCH, SYSLOG),
    host namespace sharing (NetworkMode=host, PidMode=host), sensitive
    host-path mounts (/, /etc, /root, docker.sock, /proc, /sys), daemon
    TCP listeners without TLS, insecure registries, hostPath volumes in
    k8s, and cluster-admin bindings to default/anonymous accounts.

    Args:
        root_path: Filesystem root to scan

    Returns:
        Markdown report grouped by severity and artifact type.
    """
    try:
        validated = _validate_evidence_path(root_path)
    except ValueError as e:
        return f"Error: {e}"
    if not validated.is_dir():
        return f"Not a directory: {root_path}"

    findings: list[ContainerFinding] = []

    # Docker container configs
    docker_dir = validated / "var/lib/docker/containers"
    if docker_dir.is_dir():
        for cfg in docker_dir.rglob("config.v2.json"):
            findings.extend(_scan_docker_container_config(cfg, str(cfg.relative_to(validated))))

    # docker-compose anywhere under root (not just /etc)
    for p in validated.rglob("docker-compose*.y*ml"):
        if p.is_file():
            findings.extend(_scan_docker_compose(p, str(p.relative_to(validated))))

    # Docker daemon config
    daemon = validated / "etc/docker/daemon.json"
    if daemon.is_file():
        findings.extend(_scan_docker_daemon(daemon, str(daemon.relative_to(validated))))

    # Kubernetes manifests
    k8s_dirs = [
        validated / "etc/kubernetes",
        validated / "var/lib/kubelet/config",
        validated / "etc/kubernetes/manifests",
    ]
    for kd in k8s_dirs:
        if kd.is_dir():
            for p in list(kd.rglob("*.yaml")) + list(kd.rglob("*.yml")):
                if p.is_file():
                    findings.extend(_scan_k8s_manifest(p, str(p.relative_to(validated))))

    if not findings:
        result = f"No container security issues found under `{root_path}`."
        _audit("analyze_container_artifacts", {"root_path": root_path}, "0 findings")
        return result

    sev_order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (sev_order.get(f.severity, 9), f.kind))

    lines = [
        f"# Container artifact analysis — `{root_path}`",
        "",
        f"- **Findings:** {len(findings)}",
        "",
    ]

    current_sev = None
    for f in findings:
        if f.severity != current_sev:
            lines.append(f"## {f.severity.upper()} findings")
            lines.append("")
            current_sev = f.severity
        lines.append(f"### `{f.path}` — {f.summary}")
        lines.append(f"- **Kind:** {f.kind}")
        for r in f.reasons:
            lines.append(f"- ⚠ {r}")
        if f.sample:
            lines.append("```")
            lines.append(f.sample)
            lines.append("```")
        lines.append("")

    result = "\n".join(lines)
    _audit(
        "analyze_container_artifacts",
        {"root_path": root_path},
        f"{len(findings)} findings",
    )
    return result
