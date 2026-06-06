# Scenario 15 — Legitimate monitoring agent (Wazuh) precision test

**Ground truth: no compromise.** Every artifact on this host is part
of the standard Wazuh deployment maintained by `sec-eng@corp.internal`.

## Why this is a precision test

The Wazuh agent looks exactly like malware to naive heuristics:

- **Persistent systemd service** (`/etc/systemd/system/wazuh-agent.service`)
  running as root on every boot
- **Outbound network connections** on TCP/1514 to `wazuh.corp.internal`
  every 60 seconds — structurally identical to C2 beaconing
- **Certificate pinning** at `/etc/pki/tls/certs/corp-internal-ca.pem`
- **Privileged filesystem access** (`/var/ossec/` owned by the `wazuh`
  user; systemd unit runs as root)
- **Specific sudoers grant** for `wazuh` to run lsof, ss, netstat,
  iptables -L, who, last — clearly privilege-elevating if you don't
  recognise the tool

This is *the* single most common false-positive class in production
IR. An on-call engineer seeing a persistent unit phoning home every
minute will pattern-match to malware unless they recognise the tool.

## Signals that make this identifiable as Wazuh

- `/etc/systemd/system/wazuh-agent.service` — explicit `Description=`
  and `Documentation=https://documentation.wazuh.com/...`
- `/var/ossec/etc/ossec.conf` — the canonical Wazuh agent config;
  names the manager (`wazuh.corp.internal`), the agent name, and
  points at the internal CA
- `/etc/sudoers.d/wazuh` — comment block identifying the rollout
- No other compromise indicators (no webshell, no brute force, no
  backdoor accounts, no rootkit, no unusual cron)

## Pass criteria

**Pass verdict:** the report identifies the Wazuh agent, notes it as
legitimate corporate security tooling, and concludes no compromise.
Acceptable framings: "Wazuh monitoring agent," "legitimate security
tool," "sec-eng standard deployment," "no compromise detected."

**Fail verdict:** the report declares the wazuh-agent.service or its
outbound beacon as C2 / malware / persistence without qualification.
An uncertain report that says "probably Wazuh but need to confirm"
is borderline-acceptable.

## Failure mode this test surfaces

An agent that has seen S02 (stolen-key + systemd beacon) and pattern-
matches to "systemd service + outbound beacon = compromise" without
looking at what the service actually does. This is the weakness
findevil's accuracy report §8.3 explicitly documents — tools have
high-recall by design; the agent is expected to use context to
dismiss legitimate beacons.
