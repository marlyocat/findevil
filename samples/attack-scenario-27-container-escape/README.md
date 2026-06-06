# Scenario 27 — Container escape with self-destruct

**Ground truth: compromise via privileged container escape; the
container has already destroyed itself.**

A privileged container was launched, escaped to the host namespace
via a host-filesystem bind-mount, wrote an LD_PRELOAD implant to
`/etc/`, patched `/etc/environment` to load it, then auto-stopped
and deleted itself. The container's own filesystem no longer exists.

## Evidence layout (cross-source reasoning required)

- `fs/var/log/containerd/events.log` — the containerd event stream.
  Shows: `/tasks/create` with `privileged=true caps_add=[CAP_SYS_ADMIN,
  CAP_SYS_MODULE, CAP_NET_ADMIN] apparmor=unconfined`; a bind mount
  of `/` → `/host` with `rw=true`; three `chroot /host` exec calls
  patching /etc/environment and dropping `/etc/.implant.so`;
  `/tasks/exit` and `/containers/delete` events ~16 seconds later.
- `fs/var/log/kern.log` — kernel audit corroboration: `cap_capable`
  grants for SYS_ADMIN + SYS_MODULE + NET_ADMIN, an `overlayfs
  mount source=/ target=/host rw=1`, and file-create audits on
  `/etc/environment` and `/etc/.implant.so` by pid 48219 (runc).
- `fs/etc/environment` — the edited line: `LD_PRELOAD=/etc/.implant.so`.
- `fs/etc/.implant.so` — the dropped implant (hidden-dotfile in /etc).
  `strings` shows `c2_host=198.51.100.99`, `c2_port=4444`.
- `auth.log` — no interactive user session during the attack window
  (03:14 UTC). Alice's admin sessions are unrelated.

## Why this is hard

Single-source analysis fails:
- auth.log shows nothing for the attack time window
- /etc/environment looks ordinary to someone who doesn't expand the
  dotfile list — the LD_PRELOAD line is the only anomaly
- containerd's events.log is not in findevil's scan paths; neither
  is kern.log
- The container's own filesystem is gone

The reconstruction requires:
1. Finding `/etc/environment` change
2. Reading it, noticing the LD_PRELOAD pointing at `/etc/.implant.so`
3. Finding the dotfile (hidden, not on the standard persistence list)
4. Cross-referencing containerd events.log to identify WHO wrote it
   — which ties it back to a privileged container that auto-destroyed

## Pass criteria

**Required markers:**
- `LD_PRELOAD` or `.implant.so` — must find the persistence
- `CAP_SYS_ADMIN` or `privileged` — must identify the container
  capability abuse
- `containerd` or `escape` — must connect to the container vector
- `compromise`

**Expected difficulty:** HIGH. findevil has `analyze_container_artifacts`
but it targets `/var/lib/docker/containers/` (surviving container
state), not containerd event streams. If Claude doesn't inspect
`/var/log/containerd/` it won't find the container vector. If
Claude doesn't inspect `/etc/environment` it won't find the
persistence. The attack needs BOTH signals to fully reconstruct.

A partial pass (finds LD_PRELOAD but not the container vector) is
still interesting — it says findevil catches the persistence but
misses the attack origin.
