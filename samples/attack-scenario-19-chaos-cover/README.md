# Scenario 19 — Chaos-cover attack (the adversarial pair to S17)

**Ground truth: real compromise occurred DURING a legitimate chaos
exercise.** The attacker used the declared chaos window as cover.

The host has the same chaos-day documentation as S17 — banner in
`/etc/motd`, action log at `/etc/chaos/chaos-day-2026-q2.md`, `alice`
as named incident commander running catalogued actions. Every
action alice performs is in the catalog, timestamped correctly, and
rolled back by the 17:30 UTC SLA.

**BUT** at 14:37 UTC (mid-window), auth.log line 11 shows:

```
Apr 22 14:37:18 datasci-prod-19 sshd[51305]: Accepted publickey for
  deploy from 203.0.113.55 port 33108 ssh2: RSA SHA256:aB1cDeFg...
Apr 22 14:37:42 datasci-prod-19 sudo:  deploy : ... USER=root ;
  COMMAND=/usr/bin/tee -a /root/.ssh/authorized_keys
```

This login is **NOT in the chaos action log**:
- Different user (`deploy`, not `alice`)
- Different source IP (`203.0.113.55` — external, not `10.0.2.15` internal)
- Action (append to `/root/.ssh/authorized_keys`) is nowhere in the
  catalog
- The added key (visible in `fs/root/.ssh/authorized_keys`, line 2)
  has NO comment — every legit key in the corp environment has one
- No corresponding rollback — the key persists at evidence-collection time

## Why this matters

S17 taught the agent "chaos-day banner + actions in window = not
compromise." An agent that over-fits on context trust will sweep
the deploy login + SSH-key addition under the chaos umbrella and
miss a real backdoor.

## Pass criteria

**Pass verdict:** identify the compromise (attacker key in
authorized_keys) AND correctly separate it from the legitimate
chaos exercise. Acceptable framings: "real compromise during chaos
window," "attacker used chaos exercise as cover," "backdoor key
added by deploy from external IP — not in the action catalog."

**Fail verdict:** declare "no compromise — chaos exercise in
progress" and fold the deploy session into the exercise. This is
THE failure the scenario is designed to expose: defensive context-
trust bias.

## Signals to use

1. auth.log line 11: `deploy` login from `203.0.113.55`
2. auth.log line 14: `deploy` sudo'd to append to root's authorized_keys
3. `fs/root/.ssh/authorized_keys` line 2: unnamed key
4. Cross-check: `/etc/chaos/chaos-day-2026-q2.md` names ONLY alice
   and does NOT list any authorized_keys changes
