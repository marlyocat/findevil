# IR Report — Scenario 28: Hidden Kernel Module (Diamorphine-style LKM Rootkit)

**Case:** attack-scenario-28-hidden-lkm  
**Host:** worker-28  
**Analyst:** findevil autonomous IR agent  
**Report generated:** 2026-04-23 (UTC)  
**Classification:** CONFIRMED COMPROMISE  

---

## Executive Summary

A Diamorphine-style Linux Kernel Module (LKM) rootkit named `rootkit_helper` is actively loaded on worker-28. The module was inserted at **2026-04-17 23:42:11 UTC**, taints the kernel, and provides three attacker capabilities: privilege escalation via `sys_kill` hook, file hiding via `filldir/filldir64` hooks, and self-concealment by removing itself from `/proc/modules` on each read.

The rootkit was **not detected by standard `lsmod`** because it successfully hooks the `/proc/modules` read path. It was detected through cross-source discrepancy analysis: `/sys/module/rootkit_helper/` exists in the sysfs tree (which the module cannot scrub), corroborated by load-time messages preserved in `kern.log`.

---

## Confirmed Findings

### FINDING-01 — Hidden LKM Active in Kernel (CRITICAL)

**Verdict: CONFIRMED**

| Attribute | Value |
|-----------|-------|
| Module name | `rootkit_helper` |
| Loaded at | 2026-04-17 23:42:11 UTC |
| Module file | `/lib/modules/6.8.0-106-generic/extra/rootkit_helper.ko` |
| Version | 1.3 |
| Author | anonymous |
| Kernel taints | Out-of-tree, unsigned |
| Reference count | 3 (active hooks held) |
| In-tree | No |
| Signed | No (signer: none) |

**Detection: /proc/modules vs /sys/module discrepancy**

`/proc/modules` (the data source read by `lsmod`) lists exactly 15 modules — all legitimate kernel/virtualization modules:

```
nft_chain_nat, nf_nat, nf_conntrack, ip6_tables, ip_tables,
x_tables, overlay, ext4, binfmt_misc, intel_rapl_msr,
intel_rapl_common, kvm_intel, kvm, virtio_net, virtio_blk
```

`rootkit_helper` is **absent from this list** — the module hooks the `/proc/modules` read handler and removes its own entry on each invocation.

`/sys/module/rootkit_helper/` **exists as a live sysfs directory** (the kernel's kobject subsystem is a separate data structure the rootkit did not patch), with the following content:

- `modinfo` — confirms module identity, author `anonymous`, unsigned GPL license, not in-tree
- `refcnt` — reads `3`, indicating three active references (held by the installed syscall and filldir hooks)

*Provenance:* `fs/sys/module/rootkit_helper/modinfo`, `fs/sys/module/rootkit_helper/refcnt`

---

### FINDING-02 — Kernel Taint and Hook Installation Recorded in kern.log (CRITICAL)

**Verdict: CONFIRMED**

`kern.log` preserves the full load sequence at kernel uptime offset `[220211]` seconds (~2.5 days post-boot):

```
Apr 17 23:42:11  rootkit_helper: loading out-of-tree module taints kernel.
Apr 17 23:42:11  rootkit_helper: module license 'GPL' taints kernel.
Apr 17 23:42:11  rootkit_helper: Unknown symbol kallsyms_lookup_name (err -2)
Apr 17 23:42:11  rootkit_helper: resolved kallsyms via /proc/kallsyms walk
Apr 17 23:42:11  rootkit_helper: hooked sys_kill for privilege escalation
Apr 17 23:42:11  rootkit_helper: hooked filldir/filldir64 for file hiding
Apr 17 23:42:11  rootkit_helper: hiding self from /proc/modules
Apr 17 23:42:11  rootkit_helper: loaded (refcnt baseline=3)
```

**Notable technical detail:** The module was unable to directly resolve `kallsyms_lookup_name` via the standard exported symbol table (this symbol was un-exported in Linux 5.7+). It fell back to walking `/proc/kallsyms` directly — a known Diamorphine evasion technique to function on modern kernels without a signed symbol reference.

*Provenance:* `fs/var/log/kern.log` lines 3–10

---

### FINDING-03 — Attacker Capabilities Installed (CRITICAL)

The following kernel-level capabilities are confirmed active based on kern.log hook registration messages:

| Hook | Target | Capability |
|------|--------|------------|
| `sys_kill` override | Kernel syscall table | Privilege escalation — any process can become UID 0 by sending a magic signal |
| `filldir` / `filldir64` override | VFS directory read path | File hiding — attacker files and processes omitted from `readdir()` results |
| `/proc/modules` read hook | procfs module list | Self-concealment — removes `rootkit_helper` entry on each `/proc/modules` read |

These capabilities together provide the attacker with stealth (hidden files and module), privilege escalation on demand (ring-0 to UID-0 via kill), and persistence in kernel space.

---

### FINDING-04 — SSH Login by User alice, 3 Days Post-Compromise (MEDIUM)

**Verdict: CONFIRMED (login authentic; relationship to compromise uncertain)**

`auth.log` records a single successful SSH login:

| Field | Value |
|-------|-------|
| Timestamp | 2026-04-20 14:14:22 UTC |
| User | alice (uid=1002) |
| Source IP | 10.0.2.15 |
| Method | publickey (ED25519 SHA256:aliceKey) |
| Session closed | 2026-04-20 14:19:30 UTC (~5 min) |

This login occurred **3 days after** the LKM was loaded (Apr 17). No failed auth attempts precede it. No sudo commands were recorded during the session.

`auth.log` coverage begins Apr 20 and does not reach back to Apr 17, so the account used to load the module is **not determinable from auth artifacts alone**.

*Provenance:* `auth.log` lines 3–5

---

## Indicators of Compromise

| IOC Type | Value | Confidence |
|----------|-------|------------|
| LKM name | `rootkit_helper` | HIGH — confirmed in sysfs, kern.log |
| Module path (on-disk) | `/lib/modules/6.8.0-106-generic/extra/rootkit_helper.ko` | HIGH — from modinfo |
| Module author | `anonymous` | HIGH — from modinfo |
| Load timestamp | 2026-04-17 23:42:11 UTC | HIGH — kern.log |
| Hooked syscall | `sys_kill` | HIGH — kern.log |
| Hooked VFS calls | `filldir`, `filldir64` | HIGH — kern.log |
| Technique | Diamorphine-style self-hiding LKM | HIGH — description field + behavior |
| Kernel version targeted | 6.8.0-106-generic | HIGH — vermagic field |
| SSH login post-compromise | alice @ 10.0.2.15 | MEDIUM — temporal correlation only |

---

## Attack Timeline

| Time (UTC) | Event | Source |
|------------|-------|--------|
| 2026-04-15 02:13:04 | System boot, kernel 6.8.0-106-generic | kern.log |
| 2026-04-15 02:13:18 | SELinux initialized | kern.log |
| 2026-04-17 23:42:11 | `rootkit_helper` LKM loaded; `sys_kill` and `filldir` hooks installed; self-hidden from `/proc/modules` | kern.log |
| **2026-04-17 23:42:11** | **Kernel tainted (out-of-tree, unsigned module)** | kern.log |
| 2026-04-20 08:00:01 | Routine cron job executes as root | auth.log |
| 2026-04-20 14:14:22 | alice logs in via SSH pubkey from 10.0.2.15 | auth.log |
| 2026-04-20 14:19:30 | alice's SSH session closed | auth.log |

**Gap:** No auth log coverage exists for Apr 15–19. The actor who loaded the rootkit cannot be attributed from available log artifacts.

---

## Scope Limitations and Evidence Gaps

| Gap | Impact |
|-----|--------|
| `auth.log` begins Apr 20 — rootkit loaded Apr 17 | Cannot identify the account or source IP used to load the module |
| No shell history files present under `fs/` | Cannot recover commands run to install the rootkit |
| No `lib/` directory in evidence snapshot | Cannot examine the `.ko` binary itself; no hash or YARA analysis possible from this evidence set |
| No cron or systemd persistence found | Rootkit does not auto-reload on reboot from captured artifacts; possible out-of-scope persistence not ruled out |
| `verify_finding(kernel_module)` returned CONTRADICTED | The persistence checker looks for on-disk autoload configuration (e.g., `/etc/modules`, `modprobe.d/`); none exists — rootkit runs from memory only until reboot, consistent with manual `insmod` or `modprobe` insertion |

---

## Detection Method: Cross-Source Correlation

This compromise was **not detectable from a single source**. The multi-source correlation chain that confirms it:

1. **`/proc/modules`** (lsmod-equivalent) — clean; 15 legitimate modules; `rootkit_helper` absent.
2. **`/sys/module/`** — `rootkit_helper/` directory present; module is registered in the kernel's kobject tree. Discrepancy with step 1 is definitive.
3. **`kern.log`** — load event at Apr 17 23:42:11 UTC confirms the module was intentionally inserted; hook messages confirm attacker capabilities; taint flags confirm unsigned out-of-tree provenance.
4. **`modinfo`** — confirms identity (author: anonymous, unsigned, not in-tree), version (1.3), and on-disk path.

Any one source alone is insufficient: kern.log alone names the module but not its current state; sysfs alone shows presence but not timing; /proc/modules alone appears clean.

---

## Recommended Response Actions

1. **Immediate: Isolate worker-28** from the network. The `sys_kill` hook is live and any process can escalate to root on demand.
2. **Do not attempt to `rmmod rootkit_helper`** without first forensically preserving a full memory image — the module may wipe hooks on unload, complicating post-removal analysis.
3. **Capture a memory image** (e.g., `avml` or `/dev/mem` + `lime`) before powering off. Volatility 3 `linux.lsmod` and `linux.check_syscall` plugins can enumerate hooks from the memory dump.
4. **Hash and preserve** `/lib/modules/6.8.0-106-generic/extra/rootkit_helper.ko` before taking the system offline. Submit the hash to threat intel (VirusTotal, OTX).
5. **Examine alice's account** for lateral movement: review `~alice/.ssh/authorized_keys`, check for privilege escalation via the `sys_kill` hook (UID change events in audit log if auditd was running), inspect what files may have been hidden during the Apr 20 session.
6. **Extend log collection window**: recover `/var/log/auth.log.*` (rotated logs) to identify who ran `insmod`/`modprobe` on Apr 17.
7. **Re-image the host**: the kernel is tainted and trust cannot be restored without a clean reinstall. Do not rely on any userspace or kernel output from this host for further investigation.

---

## Verdict

| | |
|--|--|
| **Compromise status** | CONFIRMED |
| **Threat type** | LKM rootkit (Diamorphine-style) |
| **Kernel tainted** | Yes — unsigned, out-of-tree module |
| **Active attacker capabilities** | Privilege escalation (sys_kill hook), file hiding (filldir hook), module self-concealment (/proc/modules hook) |
| **Load time confirmed** | 2026-04-17 23:42:11 UTC |
| **Standard lsmod detection** | BYPASSED — rootkit not visible in /proc/modules |
| **Detection vector used** | /sys/module sysfs discrepancy + kern.log cross-correlation |

---

<!-- scorecard:start -->

## Verification scorecard

Mechanically computed by `scripts/grade_example_reports.py` against the
`agent_guard.SCENARIOS["28"]` markers (case-insensitive substring
match, identical logic to `tests/harness/agent_guard.py`'s grade()
function). No AI self-assessment is involved in these numbers.

| Metric | Score | % |
|---|---|---|
| Required markers found | 4/4 | **100%** |
| Cross-scenario markers absent | 8/8 | **100%** |
| Verdict-correctness confidence | — | **100%** |
| Hallucination-free confidence | — | **100%** |

**Overall confidence: HIGH** — every planted marker for this
scenario was surfaced in the report, and zero markers from any other
scenario leaked in. Re-grade with `python scripts/grade_example_reports.py`.

<!-- scorecard:end -->
