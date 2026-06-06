# Memory forensics with findevil

Findevil exposes a seven-tool family for analysing Linux memory captures
via Volatility 3. This doc covers the workflow end-to-end:

1. Acquiring a memory dump from a Linux host
2. Building or downloading the kernel symbol table
3. Running the `analyze_memory_*` MCP tools
4. Correlating memory state with disk-side findings from `find_persistence`

## Why memory matters

The most sophisticated modern Linux malware leaves its **primary**
indicators in RAM, not on disk:

| Family | Disk artefact | Memory artefact |
|---|---|---|
| **Symbiote** (2022) | `/etc/ld.so.preload` references `/usr/local/lib/libsymbiote.so` | Hooked libc functions in every running process's address space |
| **BPFDoor** (2022) | Brief `/dev/shm/kdmtmpflush` (deletes itself) | Loaded BPF program in kernel; passive listener in process memory |
| **Drovorub-style LKM rootkit** | `/lib/modules/*/extra/*.ko` (sometimes) | Module loaded but hidden from `lsmod` |
| **Diamorphine** (open-source LKM) | `/etc/modules` line, `.ko` in `extra/` | Module hides itself after `kill -64` signal |
| **Reflective ELF loader** / fileless | None | RWX memory region, no backing file |
| **Cobalt-Strike-style beacon** | None | Encoded shellcode in process memory |

A disk-only investigation can miss any of these. Findevil's memory
tools target the canonical Volatility 3 plugins that surface exactly
these classes of artefact.

## Tool family

The first six tools take a single `memory_dump_path` argument that must
resolve inside `FINDEVIL_EVIDENCE_DIR`. The seventh,
`correlate_memory_and_disk`, takes both a memory dump and a filesystem
root and cross-checks findings between them.

| Tool | Wraps | Surfaces |
|---|---|---|
| `analyze_memory_summary` | banners + pslist + netstat + lsmod + check_modules + malfind | One-shot triage with verdict |
| `analyze_memory_processes` | `linux.pslist` | Process tree + known-bad names + orphan-parent anomalies |
| `analyze_memory_network` | `linux.netstat` | Sockets at capture time + reverse-shell port flags |
| `analyze_memory_modules` | `linux.lsmod` + `linux.check_modules` | Hidden-module diff (rootkit signature) |
| `analyze_memory_bash_history` | `linux.bash` | Commands recovered from process heap (resists `history -c`) |
| `analyze_memory_malfind` | `linux.malfind` | RWX-without-backing-file regions (code injection) |
| `correlate_memory_and_disk` | combines `linux.lsmod`/`linux.netstat` with disk-side persistence findings | Discrepancies (e.g. process running from a binary that doesn't exist on disk) |

## Acquisition

### Live target — LiME

[LiME](https://github.com/504ensicsLabs/LiME) is the standard Linux
memory acquisition tool:

```bash
# On the target
sudo apt install -y linux-headers-$(uname -r) build-essential
git clone https://github.com/504ensicsLabs/LiME && cd LiME/src && make
sudo insmod ./lime-$(uname -r).ko "path=/tmp/case.lime format=lime"
```

For sensitive targets, capture over the network instead of writing to
local disk:

```bash
sudo insmod ./lime-$(uname -r).ko "path=tcp:4444 format=lime"
# On analyst host:
nc target-ip 4444 > case.lime
```

### Cloud workloads — AVML

Microsoft's [AVML](https://github.com/microsoft/avml) builds against
`/proc/kcore` without requiring kernel modules — useful when you can't
load LiME (locked-down hosts, FIPS-mode kernels):

```bash
sudo ./avml /path/to/case.avml
```

Both formats are accepted by Volatility 3.

### VM snapshots

For VMware ESXi / vSphere, `.vmem` files alongside `.vmsn` snapshots
are direct memory captures. KVM/QEMU `dump-guest-memory --format=elf`
produces a compatible dump.

## Symbol tables

Volatility 3 needs an **Intermediate Symbol Format (ISF)** JSON
matched to the *exact* kernel version of the captured dump. There are
three paths to obtain one:

### Option 1 — pre-built community symbols

The Volatility Foundation publishes ISFs for many distribution kernels
at `https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip`.
Extract into `~/.cache/volatility3/symbols/linux/`. If the dump's
kernel banner matches, Vol auto-detects it.

**Path warning:** Vol3 looks in `~/.cache/volatility3/symbols/linux/`,
not `~/.local/share/volatility3/symbols/linux/` despite older
documentation suggesting the latter. Empirically verified on
volatility3 v2.28: only the `~/.cache/` path works for auto-loading.

### Option 2 — build from kernel debug symbols

If the target distro ships debug symbols (e.g. `linux-image-X.Y-dbg`
on Debian/Ubuntu), build the ISF locally with
[dwarf2json](https://github.com/volatilityfoundation/dwarf2json):

```bash
# Enable the ddebs.ubuntu.com repo (one-time setup on Ubuntu)
sudo bash -c 'echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse" > /etc/apt/sources.list.d/ddebs.list'
sudo apt install ubuntu-dbgsym-keyring && sudo apt update

# Install kernel debug symbols (~500 MB)
sudo apt install linux-image-$(uname -r)-dbgsym

# Install Go and build dwarf2json
sudo apt install golang-go
git clone https://github.com/volatilityfoundation/dwarf2json /tmp/dwarf2json
(cd /tmp/dwarf2json && go build -o dwarf2json .)

# Generate the ISF
mkdir -p ~/.cache/volatility3/symbols/linux
/tmp/dwarf2json/dwarf2json linux \
    --elf /usr/lib/debug/boot/vmlinux-$(uname -r) \
    > ~/.cache/volatility3/symbols/linux/$(uname -r).json
```

End-to-end empirically verified on the SIFT VM with kernel
6.8.0-106-generic — the resulting 62 MB ISF makes every `linux.*`
plugin work against the matching memory dump.

### Option 3 — capture symbols at acquisition time

When you control the target, capture both the dump *and* the symbol
table in one operation. This is the most forensically sound approach
because it eliminates any chance of using mismatched symbols:

```bash
# As part of acquisition
dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) > /tmp/case-symbols.json
sudo insmod ./lime.ko "path=/tmp/case.lime format=lime"
tar czf case-bundle.tar.gz /tmp/case.lime /tmp/case-symbols.json
```

## Running the tools

```python
# In a Claude Code session with findevil's MCP server
result = analyze_memory_summary("evidence/case29/case.lime")
```

If symbols are missing, the tools return a structured error block
naming the kernel banner so the analyst can fetch the right ISF
without re-running every plugin individually.

## Cross-correlation with disk findings

The strongest verdict comes from **memory + disk agreement**:

| Memory says | Disk says | Verdict |
|---|---|---|
| Hidden module `X` | `/etc/modules` lists `X` AND `lib/modules/*/extra/X.ko` exists | High-confidence kernel rootkit |
| Hidden module `X` | Disk has nothing about `X` | Memory-resident rootkit (attacker scrubbed disk OR loaded directly via `insmod`) |
| No hidden modules | `/etc/modules` lists `X` | Disk-side only — possibly stale / un-loaded module, less critical |
| Process `kdevtmpfsi` running | `/tmp/kdevtmpfsi` binary present | Confirmed Kinsing miner |
| Process `kdevtmpfsi` running | Disk has nothing | Likely fileless / deleted-binary-still-running |

A senior analyst always cross-references memory with disk; the agent
should follow the same pattern. After running `analyze_memory_modules`,
correlate any hidden modules against `find_persistence`'s
`kernel_module` category for `etc/modules` and `/lib/modules/*/extra/`.

## Performance

Volatility 3 plugins are slow on multi-GB dumps. Rough budget on a
SIFT VM (4 vCPU, 8 GB RAM) against an 8 GB dump:

| Plugin | Wall time |
|---|---|
| `banners.Banners` | 5–15 s |
| `linux.pslist` | 30–60 s |
| `linux.netstat` | 30–60 s |
| `linux.lsmod` | 15–30 s |
| `linux.check_modules` | 15–30 s |
| `linux.bash` | 60–120 s |
| `linux.malfind` | 60–180 s |
| `analyze_memory_summary` (all of the above) | 4–10 minutes |

The tools enforce a 10-minute per-plugin timeout. If you need longer,
set `FINDEVIL_VOL_TIMEOUT` (not implemented yet — TODO) or call the
specific plugin tools individually.

## What memory forensics doesn't catch

Honest scope:

- **Encrypted memory regions** (e.g. SEV / TDX confidential VMs) — Vol
  cannot decrypt without keys.
- **Pre-capture deletion** — if the attacker exits all malicious
  processes before capture, only artefacts they couldn't clean up
  (network connection state, filesystem) survive.
- **Highly-customised kernels** — symbol-table acquisition becomes
  hard or impossible. The tools surface this clearly rather than
  hallucinating output.
- **User-space encrypted RAM** (SGX enclaves) — out of scope.

For these cases, lean harder on disk forensics and audit-log analysis.
The tools are **complementary**, not a replacement.
