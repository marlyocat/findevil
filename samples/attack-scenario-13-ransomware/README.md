# Scenario 13 — Ransomware / destructive attack

**Ground truth: destructive compromise completed.** Attacker had
root access (stolen credential or prior vuln; host had weak
`sshd_config` allowing root password auth), ran mass file encryption
with `openssl enc -aes-256-cbc`, shredded originals, deleted
filesystem snapshots and backups, removed audit tooling, truncated
logs, and dropped a ransom note.

## Why this scenario tests a different failure mode

Scenarios 01–12 are detection-centric — the question is "is there a
compromise?" Here the compromise is **blatant**: the ransom note is
literally at `/README_RESTORE_YOUR_FILES.txt`. The test is whether
Claude:

1. Classifies this as **active destruction**, not just "a compromise."
2. Recognizes that **containment > investigation** — the attacker
   is still in the session as of log-truncation, and backups are
   already gone.
3. Uses the surviving evidence (off-host-forwarded auth.log, bash
   history, ransom note) to reconstruct the destruction steps even
   though local logs were truncated.
4. Does NOT try to attribute to a specific threat actor — the ransom
   note is generic, the payment address proves nothing.

## Surviving evidence

- `auth.log` — **preserved by off-host syslog forwarding** (the
  scenario notes this explicitly). Shows the root login from
  `45.77.233.11` at 03:42 UTC, the find-+-openssl pipeline, the
  snapshot deletion, log truncation, auditd/rsyslog removal.
- `fs/root/.bash_history` — the attacker ran `history -c` at the
  end, but the file on disk records the pre-clear sequence.
- `fs/README_RESTORE_YOUR_FILES.txt` — ransom note at fs root.
- `fs/home/alice/Documents/README_RESTORE_YOUR_FILES.txt` — copy
  dropped into user documents directory.
- `fs/home/alice/Documents/quarterly-report.pdf.locked` — a single
  encrypted-file placeholder (real ransomware would produce
  thousands; one is enough to show the pattern).
- `fs/etc/ssh/sshd_config` — shows how the attacker got in: root
  login + password auth were enabled.

## Pass criteria

**Required:**
- `ransomware` OR `ransom` (the attack class must be named)
- `45.77.233.11` (attacker source IP, still visible in the
  off-host-forwarded auth.log)
- `openssl` OR `aes-256-cbc` OR `encrypt` (the encryption mechanism)
- `compromise` verdict

**Strong pass indicators (judged separately):**
- Mentions backup destruction (`btrfs subvolume delete`,
  `rm -rf /var/backups/`)
- Mentions log/auditd tampering
- Recommends containment first (isolate host, don't pay ransom,
  alert legal/law enforcement)

## Failure modes

- **Attribution overreach:** the report names a specific ransomware
  family (LockBit, Conti, ALPHV) from circumstantial evidence. There
  is nothing in this evidence that identifies the strain — the
  generic `*.locked` extension and `openssl` command are what any
  ad-hoc script would produce. Claude should say "generic ransomware
  pattern, no specific family identifiable."
- **Missing the destructive-over-espionage classification:** the
  report treats this as a data-exfiltration incident (wrong — the
  attacker destroyed, did not exfiltrate). Not every compromise is
  espionage.
