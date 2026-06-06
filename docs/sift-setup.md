# SIFT Workstation Setup Guide

## What is SIFT?

SANS SIFT (SANS Investigative Forensics Toolkit) is an Ubuntu-based VM with 200+ pre-installed forensic tools. It's the standard platform for this hackathon.

## Option 1: Download Pre-built VM (Recommended)

1. Go to https://www.sans.org/tools/sift-workstation/
2. Download the OVA file
3. Import into your hypervisor:
   - **VirtualBox**: File → Import Appliance → select OVA
   - **VMware**: File → Open → select OVA
4. Recommended VM settings:
   - RAM: 8 GB minimum (16 GB recommended)
   - CPU: 4 cores
   - Disk: 50 GB+

Default credentials:
- Username: `sansforensics`
- Password: `forensics`

## Option 2: Install on Existing Ubuntu

If you already have an Ubuntu 22.04+ VM or WSL:

```bash
# Download and run the SIFT installer
curl -Lo /tmp/sift-cli-linux https://github.com/teamdfir/sift-cli/releases/latest/download/sift-cli-linux
chmod +x /tmp/sift-cli-linux
sudo /tmp/sift-cli-linux install
```

## After Setup

### Install Protocol SIFT (hackathon-specific)

The hackathon provides additional setup via Protocol SIFT:

1. Join the hackathon Slack (link on Devpost page)
2. Follow the Protocol SIFT GitHub instructions for the additional bash script

### Verify Key Tools

```bash
# Check core tools are installed
which file strings xxd grep     # Basic analysis
which vol3                       # Volatility 3 (memory forensics)
which log2timeline               # Timeline generation
which fls icat mmls              # Sleuth Kit (disk forensics)
which yara                       # YARA rules engine
```

### Set Up the Evidence Directory

```bash
sudo mkdir -p /evidence
sudo chown sansforensics:sansforensics /evidence
```

### Get Sample Evidence for Testing

You need forensic images to test against. Free sources:

1. **Digital Corpora** — https://digitalcorpora.org/
   - Has disk images, memory dumps, network captures
   
2. **NIST CFReDS** — https://cfreds.nist.gov/
   - Reference datasets for forensic tool testing

3. **Ali Hadi's cases** — https://www.ashemery.com/dfir.html
   - Practical IR case images

4. **MemLabs** — https://github.com/stuxnet999/MemLabs
   - Memory forensics CTF challenges (great for learning Volatility)

Download a small case to `/evidence/` and you're ready to start testing.

### Install Findevil

```bash
cd /path/to/findevil
pip install -e ".[dev]"
```

## Network Setup

The SIFT VM needs to communicate with Claude Code on your host machine. Options:

- **SSH from host**: Most common. Forward the MCP server over SSH.
- **Shared folder**: Mount evidence from host into VM.
- **Host-only network**: For direct TCP communication.

The simplest approach: develop on your host, SSH into the SIFT VM to run forensic commands. The MCP server runs on the SIFT VM and Claude Code connects to it.
