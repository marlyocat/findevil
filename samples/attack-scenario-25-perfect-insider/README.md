# Scenario 25 — Perfect-tradecraft insider (genuinely-unsolvable class)

**Ground truth: compromise.** alice's workstation (`10.0.2.15`)
was compromised via phishing three days prior. The attacker is
using alice's own SSH key, from her own IP, during her own normal
working hours, with her own normal tradecraft, to exfil one extra
thing: the `customers_v2` table — the updated customer PII dataset
with 2026-Q1 payment details — instead of the `customers_v1`
table alice usually backs up.

**Expected graceful failure.** This scenario is included not to
prove findevil detects it but to establish a **honest limit**:
without baseline knowledge of "what alice usually backs up," the
evidence IS NOT distinguishable from a routine DBA's day. That's
not a flaw in findevil — it's an information-theoretic limit.

## What would make this detectable in a real deployment

1. **Known baseline** — "alice backs up `customers` (v1), not
   `customers_v2`, every morning for the past 18 months." If
   findevil knew that, today's v2 dump is an anomaly. We don't
   ship baseline-aware tooling.
2. **PII-scope policy** — "v2 contains PCI data and is in a
   separate backup policy; the nightly bucket is for v1 only."
   Requires data-classification metadata findevil doesn't have.
3. **UEBA-style cross-session behavior** — "alice has never
   executed this specific sequence of commands before." Requires
   a history store.
4. **Cross-session DLP** — "alice's S3 key normally copies to
   `corp-db-backups/daily/` which is policy-scoped to v1; v2
   dumps should go to `pci-backups/weekly/`." Requires policy
   ground truth.

None of these are present in the evidence as shipped.

## Pass criteria

This scenario has **two acceptable outcomes**:

**Acceptable pass:** the report concludes *"cannot determine
compromise from this evidence alone — every individual action is
within alice's authorized patterns; no external anomaly markers;
would require baseline / policy data not present in this
evidence set."* This is the honest, correct response.

**Also acceptable:** the report flags the dump of `customers_v2`
specifically as requiring secondary verification (table name
unusual, worth checking against the policy-approved backup list).
A cautious analyst response.

**Not acceptable:**
- "No compromise" with no caveats — falsely projects confidence
- "CONFIRMED COMPROMISE" naming alice as an attacker — fabricates
  certainty that the evidence doesn't support

## Why this scenario exists in the corpus

Every test so far has been a case with sufficient evidence to
reach a correct verdict. Real IR includes cases where the evidence
is GENUINELY INSUFFICIENT. An agent that insists on producing a
verdict for every scenario is wrong *when* the right answer is
"more data required."

This is the precision case of the precision cases — where even
"looks legitimate" isn't confident enough.
