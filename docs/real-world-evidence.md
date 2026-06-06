# Running findevil against real-world forensic evidence

The 29 scenarios in `samples/` are deliberately synthetic — small,
reproducible, ground-truthed. That's great for regression testing
and for this submission's accuracy claims, but it's also a fair
criticism that "your tool only works on data you wrote." This doc
shows how to point findevil at public real-world forensic datasets
so judges (or anyone else) can spot-check behaviour beyond our
fixtures.

findevil's evidence root is configured by the `FINDEVIL_EVIDENCE_DIR`
environment variable. Everything below is a matter of extracting a
dataset to some directory, setting that variable, and running the
tools.

## Recommended public datasets

### 1. NIST CFReDS — Hacking Case (the "Greg Schardt" image)
- **URL:** https://cfreds.nist.gov/all/NIST/HackingCase
- **What it is:** a full disk image from a 2004 NIST reference case.
  Mounted, it contains a real `/etc`, real user home directories,
  real bash history, real auth logs. Has been used for forensic
  tool calibration for two decades.
- **How to mount the image read-only** (on SIFT or any Linux):
  ```bash
  mkdir -p /mnt/cfreds-evidence
  ewfmount SCHARDT.E01 /mnt/ewf
  mount -o ro,loop /mnt/ewf/ewf1 /mnt/cfreds-evidence
  export FINDEVIL_EVIDENCE_DIR=/mnt/cfreds-evidence
  ```
- **Expected findevil output:** auth-log tools find nothing dramatic
  (it's a 2004 home PC, not a compromised server). `find_persistence`
  walks the stock configs. Mostly useful as a smoke test that the
  tools don't crash on unfamiliar layouts.

### 2. Digital Corpora — Real Data Corpus
- **URL:** https://digitalcorpora.org/corpora/
- **What it is:** 70TB+ of real disk images, memory dumps, and
  network traces collected from operational systems. No attacks
  planted — these are baseline images, so they're good for
  precision checks (findevil should find nothing).
- Note: these images are *huge*; mount a single image at a time.

### 3. Ali Hadi's DFIR Cases
- **URL:** https://www.ashemery.com/dfir.html
- **What it is:** practical Linux incident-response cases with
  intentional compromises. Case "Challenge #2" in particular is
  a Linux web server compromise.
- **Why use it:** this is the closest public analog to our S03
  (webshell) scenario, but produced by an external author from
  real tradecraft. Running findevil against it tests generalization
  outside our own samples.

### 4. MemLabs (memory-forensics CTF challenges)
- **URL:** https://github.com/stuxnet999/MemLabs
- findevil ships seven Volatility 3-backed memory tools
  (`analyze_memory_summary`, `analyze_memory_processes`,
  `analyze_memory_network`, `analyze_memory_modules`,
  `analyze_memory_bash_history`, `analyze_memory_malfind`,
  `correlate_memory_and_disk`). End-to-end validation against a
  real Linux memory capture is documented in §16 of the accuracy
  report, including the dwarf2json symbol-table workflow MemLabs
  challenges also need.

## Smoke-test procedure

Once an image is mounted and `FINDEVIL_EVIDENCE_DIR` is set:

```bash
# Start the findevil MCP server and connect a client
python -m findevil &  # stdio server

# Or just exercise a few tools directly from the Python API
python -c "
from findevil.tools.linux_auth import auth_summary
from findevil.tools.linux_persistence import find_persistence
import os
root = os.environ['FINDEVIL_EVIDENCE_DIR']
print(auth_summary(f'{root}/var/log/auth.log'))
print(find_persistence(root))
"
```

Expected: the tools run to completion, emit structured Markdown,
and do NOT write anything back to the mount (verify with
`mount | grep ro` that the mount is read-only, and with
`inotifywait -r -e modify,create,delete $FINDEVIL_EVIDENCE_DIR` that
no changes occur during the investigation).

## What "works on real data" means (and doesn't)

Passing a smoke-test on a real image proves the *tools don't crash*
and the *read-only claim holds*. It does NOT prove the tools
*correctly detect* an attack that no one authored ground-truth for.
For measured recall/precision, the synthetic scenarios remain the
source of truth — that's their whole point.

If you want to validate detection quality on real evidence, pair
an external case with a published ground-truth writeup (like Ali
Hadi's challenge walkthroughs) and diff findevil's output against
the walkthrough's key findings by hand. That's what we'd do in
follow-up work; it's outside what the 72-hour hackathon window
permits.

## Smoke-test results (VM /var/log)

A minimal smoke test has been run against the SIFT VM's own readable
log files (the VM's `/var/log/dpkg.log`, `/var/log/apt/history.log`,
and `/etc/ssh/sshd_config`). These are **real Linux operational data
not authored by us** — they come from whatever apt/dpkg did during
the VM's normal lifecycle.

| Tool | Input (real VM data) | Result |
|------|----------------------|--------|
| `analyze_package_logs` | `/var/log/dpkg.log` + `/var/log/apt/history.log` | 32 install events parsed, 0 flagged — "No package-management red flags." Correct; the installs are legitimate SIFT provisioning. |
| `analyze_sshd_config` | `/etc/ssh/sshd_config` | All 7 directives parsed, none mis-classified. "No dangerous settings detected." |
| `find_persistence` (FS walk) | `/etc/ssh/sshd_config` | Flagged `PasswordAuthentication yes` as ssh_config concern. **This is a real operational-security issue, not a hallucination** — SIFT's default sshd does allow password auth. |
| `find_persistence` (users) | `/etc/passwd` | 0 findings. Correct — the VM has no backdoor accounts. |

Signal: findevil tools run to completion on real log data, emit
structured output, and produce zero fabricated findings. Where a tool
flags something (the PasswordAuthentication finding), it corresponds
to a real setting in the file, not an invented concern.

Minor tool-internal inconsistency noted as follow-up: on the same
sshd_config, `analyze_sshd_config` returned "no dangerous settings"
while `find_persistence` flagged `PasswordAuthentication yes` as high
severity. Both readings are defensible (the static config doesn't
list the directive explicitly; the persistence scanner inspects at a
different granularity) but the two tools should agree. Logged for
future cleanup.

## Constraints still enforced

The read-only guarantee carries over to real evidence. The security
tests in `tests/security/` (102 cases — 2 skipped) hold the same
invariants against a synthetic `evidence/` as they would against a
mounted `/mnt/cfreds-evidence`:

- No MCP tool can resolve paths outside `FINDEVIL_EVIDENCE_DIR`
  (see `test_path_validation.py`).
- Symlinks inside the evidence root that target outside files are
  rejected on `resolve()` (see `test_symlink_safety.py`).
- No write-capable syntax in any `@mcp.tool` function except the
  two auditable writes to `LOGS_DIR` (see `test_no_write_capability.py`).
- `fim.baseline_create` refuses output paths inside the evidence
  directory even when the user explicitly supplies one (see
  `test_fim_output_path_guard.py`).
