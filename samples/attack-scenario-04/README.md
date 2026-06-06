# Attack Scenario 04 — Supply-chain via typosquat + privileged container

Fourth distinct attack pattern. Exercises Phase 2b's package and
container tools. Very different from scenarios 01–03:

- **Not** SSH brute force
- **Not** stolen credentials
- **Not** web shell upload
- **Yes**: supply-chain attack through PyPI typosquat
- **Yes**: container configuration that amplifies impact

## Narrative

A data-processing host runs an ML pipeline in a Docker container. The
containerised service is started with a permissive configuration: it
mounts the Docker socket so the app can dynamically spawn helper
containers, and it uses `--cap-add SYS_ADMIN` for mount operations.
The build pipeline installs Python dependencies via pip.

On 2026-04-15 a developer laptop was compromised. The attacker
publishes a typosquatted PyPI package `requests-utils` (popular
`requests` being the real target) and social-engineers the developer
into adding it to the project's `requirements.txt`. The next CI run
installs it on `data-proc-01`. The package runs a post-install script
that:

1. Reads Docker credentials from `/var/lib/docker` (mounted via the
   socket).
2. Exploits the host's `SYS_ADMIN` capability to gain full host filesystem access.
3. Drops a cryptominer (`xmrig`) installed via apt from a local .deb
   uploaded to /tmp.
4. Writes a systemd user unit in `/home/mlops/.config/systemd/user/`
   that keeps the miner running.

## Expected detection

| Tool | Should detect? | How |
|------|----------------|-----|
| `analyze_package_logs` | **Yes** | apt install of local .deb (xmrig), pip install typosquat `requests-utils` |
| `analyze_container_artifacts` | **Yes** | Docker container with `--privileged` + CAP_SYS_ADMIN + docker.sock mount |
| `find_persistence` (Phase 1) | **Partial** | If the unit is in a scanned systemd directory |
| `analyze_nginx_access` | No — not a web attack |
| `auth_*` tools | No SSH compromise |
| `find_webshells` | No web shells |

The whole-agent test is whether it connects the supply chain **pip
typosquat** to the **privileged container** to explain how the two
amplified each other.

## Files

- `fs/var/log/apt/history.log` — shows legitimate updates plus the
  suspicious local `.deb` install of `xmrig`
- `fs/var/log/dpkg.log` — lower-level log showing the same install
- `fs/root/.pip/pip.log` — records the `requests-utils` typosquat install
- `fs/var/lib/docker/containers/abc.../config.v2.json` — the
  compromised container config
- `fs/etc/docker/daemon.json` — permissive daemon config
- `fs/home/mlops/.config/systemd/user/xmrig.service` — persistence
- `fs/etc/passwd` — clean (no backdoor accounts)
