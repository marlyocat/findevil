# Scenario 28 — Hidden kernel module (rootkit via /proc/modules hook)

**Ground truth: rootkit active.** A Diamorphine-style LKM was
loaded on Apr 17 at 23:42 UTC. It hooks `sys_kill` for privilege
escalation, hooks `filldir/filldir64` for file hiding, and hides
itself from `/proc/modules` by removing its entry from the
kernel's module list on each read. But it can't scrub `/sys/module/`
(that's generated from a different data structure) and it can't
un-log the kernel messages that were emitted when it loaded.

## Cross-source detection required

- `fs/proc/modules` — the usual `lsmod` equivalent. The rootkit is
  NOT listed here. 15 legitimate modules (nft_chain_nat, nf_nat,
  overlay, kvm, virtio_*) — looks clean.
- `fs/sys/module/rootkit_helper/` — exists as a directory. Its
  `modinfo` file says:
    ```
    description: Diamorphine-style rootkit hiding itself from /proc/modules
    author: anonymous
    license: GPL (unsigned)
    intree: N
    ```
  `refcnt` reads `3`. The module is present in the kernel's module
  tree even though `/proc/modules` pretends it isn't.
- `fs/var/log/kern.log` — records the load event:
    ```
    rootkit_helper: loading out-of-tree module taints kernel.
    rootkit_helper: hooked sys_kill for privilege escalation
    rootkit_helper: hooked filldir/filldir64 for file hiding
    rootkit_helper: hiding self from /proc/modules
    rootkit_helper: loaded (refcnt baseline=3)
    ```

## Pass criteria

**Required markers:**
- `rootkit_helper` — must name the module
- `/sys/module` — must cite the sysfs-side evidence
- `/proc/modules` — must note the hiding behavior
- `compromise`

**Expected difficulty:** HIGH. findevil has no `lsmod_vs_sysfs`
tool. Claude has to (a) list `/sys/module/` somehow, (b) compare
against `/proc/modules`, (c) notice the missing entry, (d) find
the kern.log load event that corroborates. That's a specific
forensic technique rather than a standard scan.

Partial pass (kern.log alone is enough to see the module loaded)
would still catch the scenario via a different route — but the
discrepancy-detection angle is what tests the "cross-source
correlation" capability.
