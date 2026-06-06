# Scenario 23 — Steganographic persistence (typosquat-installed Python lib)

**Ground truth: compromise via a malicious Python package installed
as if it were a corp-standard library.**

Every heuristic in findevil's auth/log/persistence scanners looks
clean:
- auth.log: alice (internal IP, normal hours) runs `apt install`
  and `apt upgrade`. No brute force, no anomalous source.
- No new systemd units, no new cron entries, no new SSH keys,
  no backdoor users, no rootkit.
- apt history shows a package named `python3-corp-telemetry` which
  could plausibly be a corporate tool.

The compromise is inside the Python package body at
`fs/usr/lib/python3/dist-packages/corp_telemetry/__init__.py`. A
~110-line module that looks like legitimate telemetry. Hidden
inside it:

1. **Hardcoded exfil endpoint** at the top:
   `_DIAGNOSTIC_RELAY = "https://api.diagnostic-relay.org/v1/events"`
   — external domain, not `*.corp.internal` like the rest of
   the module's claimed targets.

2. **`_send_diagnostic()` function** on lines ~50–70 that POSTs
   the FULL PROCESS ENVIRONMENT (`dict(os.environ)`) plus `cwd`
   to `_DIAGNOSTIC_RELAY`. Passes `timeout=5`, swallows
   exceptions so it's silent.

3. **`_resolve()` function** on lines ~72–80 claims to "validate a
   hostname via DNS." Actually it calls `_send_diagnostic` on
   EVERY successful resolution — a misleading docstring and
   inline comment claim the diagnostic callback fires only on
   failures; the code calls it on success.

4. **`_validate_hostnames()` function** iterates every host through
   `_resolve`, so any caller (e.g., `configure()`) triggers the
   beacon for every configured hostname.

Result: any process importing this module and calling `configure()`
leaks its environment variables (credentials, tokens,
`AWS_SECRET_ACCESS_KEY`, `DB_PASSWORD` etc. that admins habitually
have in their shell env) to
`api.diagnostic-relay.org` — an attacker-controlled domain.

## Why this is near-impossible to detect

- `find_persistence` finds nothing suspicious (no standard
  persistence path modified)
- `analyze_package_logs` sees `python3-corp-telemetry` installed by
  `apt`, classifies as a normal install (no typosquat pattern,
  no known-bad package name, comes from the distro's apt)
- `auth_*` tools see only legitimate alice activity
- The malicious code is not minified or obfuscated — it looks
  like someone wrote reasonable-quality Python. Heuristic code
  scanners (YARA, bandit, semgrep) would likely miss it unless
  tuned to specific indicators.

To catch this, the investigator must actually READ the module
source. findevil has `strings_extract` and Claude has `Read` —
both can surface the file content, but whether Claude reads it
carefully enough to notice the contradictions between the
docstrings/comments and the actual flow is the open question.

## Pass criteria

**Strong pass:** the report identifies `corp_telemetry/__init__.py`
as the compromise vector, quotes the `api.diagnostic-relay.org`
endpoint, and notes the env-var exfiltration.

**Weak pass:** the report flags the package as suspicious ("worth
deeper review") without confirming the malicious code.

**Fail:** the report concludes no compromise, or flags alice's
`apt install` without reading the package body.

## Expected difficulty

**HIGH.** If Claude misses this, it's a documented honest limit:
findevil's tool layer can't currently inspect arbitrary Python
package bodies for malicious patterns. The agent would have to
proactively decide to read the module source. Whether it does is
what the scenario measures.
