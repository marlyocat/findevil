# Scenario 29 — Memory-resident kernel rootkit

## What this scenario tests

Memory forensics integration. The bundled scenarios 01–28 are
**dead-disk** evidence — filesystem snapshots plus log files. This
scenario exercises the **`analyze_memory_*`** tool family against a
Linux memory capture and tests whether the agent correlates memory
state with disk-side persistence.

The most sophisticated Linux malware (Symbiote, BPFDoor, Drovorub-style
LKM rootkits, in-memory ELF loaders) leaves its primary indicators in
RAM. A disk-only investigation can miss the attack entirely. This
scenario forces the agent into that gap.

## Why no .lime is committed

Linux memory dumps are typically 4–32 GB and require a kernel-version-
matched symbol table to analyse. Both are too large to ship in a Git
repo. Instead this directory contains a **fixture script** that, when
run on a SIFT VM with a live target machine, captures a real memory
dump and produces the matching ISF symbols. See `acquire.sh` below or
`docs/memory-forensics.md` in the repo root for the full workflow.

For graders without a target VM, the test suite
(`tests/test_linux_memory.py`, 19 cases) exercises the tool family
end-to-end with mocked Volatility output covering every plugin
including the no-symbols-available degradation path.

## Expected ground truth (what the agent should find)

Once the dump is captured against a Diamorphine-loaded kernel:

| Tool | Expected finding | Verifies |
|---|---|---|
| `analyze_memory_summary` | Verdict: **LIKELY MEMORY-RESIDENT COMPROMISE**. Names hidden module(s). | High-level triage |
| `analyze_memory_modules` | `diamorphine` shows in `linux.check_modules` but NOT in `linux.lsmod` — hidden-module signature | Core rootkit detection |
| `analyze_memory_processes` | `kthrotlds` / `kdevtmpfsi` / similar known-bad process name flagged | Process anomaly |
| `analyze_memory_network` | TCP listener on a reverse-shell handler port (4444 / 1337 / 31337) | C2 infrastructure |
| `analyze_memory_bash_history` | Commands recovered even though `~/.bash_history` is empty on disk | Anti-forensics resistance |
| `analyze_memory_malfind` | One or more RWX regions without backing file | Code injection |
| Cross-correlation | Disk has `etc/modules` line for `diamorphine` AND memory shows it loaded but hidden | High-confidence rootkit verdict |

A correct agent verdict is **"confirmed kernel rootkit"** with both
disk-side and memory-side evidence cited.

## Acquisition workflow

The fixture is built against a victim Ubuntu 22.04 VM. From a SIFT
analyst host with `vol`, `dwarf2json`, and SSH access to the victim:

```bash
# On the victim — capture RAM
sudo apt install -y linux-headers-$(uname -r) build-essential
git clone https://github.com/504ensicsLabs/LiME && cd LiME/src && make
sudo insmod ./lime-$(uname -r).ko "path=/tmp/case29.lime format=lime"

# Plant the rootkit (do this before capture for ground truth)
git clone https://github.com/m0nad/Diamorphine && cd Diamorphine && make
sudo insmod ./diamorphine.ko
echo "diamorphine" | sudo tee -a /etc/modules
sudo kill -64 0   # signal Diamorphine to hide

# Build the symbol table from /usr/lib/debug/vmlinux
dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) > kernel.json
mkdir -p ~/.local/share/volatility3/symbols/linux
mv kernel.json ~/.local/share/volatility3/symbols/linux/

# Transfer dump to analyst host
scp /tmp/case29.lime analyst@:/path/to/findevil/evidence/attack-scenario-29-memory-rootkit/case29.lime
```

## What the agent should NOT do

- Treat absence of disk evidence as "clean." If `find_persistence` finds
  nothing but `analyze_memory_modules` finds a hidden module, the
  verdict is still compromise — that's what memory forensics is for.
- Hallucinate Volatility output if the dump is missing or symbols are
  unavailable. The tools surface "kernel symbols required" with the
  detected banner; the agent should report that limitation rather than
  guess.
