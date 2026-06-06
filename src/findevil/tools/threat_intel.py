"""
Offline threat-intel integration.

In a real IR case the analyst's first move after spotting an IOC is to
check it against reputation sources. The agent's equivalent needs to
work offline (the SIFT VM is often air-gapped during evidence triage),
so Findevil ships with a bundled IOC cache. In production you'd merge
this with live feeds from abuse.ch, FireHOL, MalwareBazaar, etc.; this
module provides the lookup interface that works identically either way.

Tools:

- `extract_iocs(text)` — regex-based extraction of IPs, domains, URLs,
  MD5/SHA1/SHA256 hashes, Bitcoin addresses, CVE IDs, and emails from
  arbitrary text. The agent runs this over a report or a tool-call
  result to get a typed IOC list.
- `bulk_ioc_lookup(text)` — extracts IOCs from `text` and looks each
  one up against the bundled cache in a single call. Domain lookups
  fall back to parent-domain matches and respect the legitimate
  allow-list (so the agent doesn't over-alert on e.g.
  registry.npmjs.org). Hash lookups dispatch on length
  (32 → MD5, 40 → SHA1, 64 → SHA256).

All results are structured and carry confidence, tags, and a source
citation — the agent can quote these directly into its report's IOC
table.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from findevil.server import _audit, mcp


# ---------------------------------------------------------------------------
# Cache loading
# ---------------------------------------------------------------------------


_DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "threat_intel.json"


@lru_cache(maxsize=1)
def _load_cache() -> dict[str, Any]:
    """Load the bundled IOC cache once."""
    try:
        return json.loads(_DATA_FILE.read_text())
    except (OSError, json.JSONDecodeError) as e:
        # Fail closed — an unusable cache is still usable (all lookups miss)
        return {"_error": str(e), "ips": {}, "hashes": {}, "domains": {}}


# ---------------------------------------------------------------------------
# IOC extraction — regexes
# ---------------------------------------------------------------------------


_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
_DOMAIN_RE = re.compile(
    r"\b(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b",
    re.I,
)
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
_MD5_RE = re.compile(r"\b[a-f0-9]{32}\b", re.I)
_SHA1_RE = re.compile(r"\b[a-f0-9]{40}\b", re.I)
_SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b", re.I)
_BTC_RE = re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,49})\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")


def _is_rfc1918(ip: str) -> bool:
    """Detect private address space so the extractor can tag it separately."""
    try:
        octets = [int(x) for x in ip.split(".")]
    except ValueError:
        return False
    if len(octets) != 4:
        return False
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    if octets[0] == 127:
        return True
    return False


# Short-list of domain-looking strings that should NOT be reported as IOCs
# (too common, generate noise). These are exact matches against the captured
# domain; subdomains of these are still reported.
_DOMAIN_NOISE = {
    "www.w3.org",
    "schemas.microsoft.com",
    "xmlns.microsoft.com",
    "127.0.0.1.nip.io",
}


def extract_iocs_raw(text: str) -> dict[str, list[str]]:
    """Pure function — extract IOCs from text. Returns deduplicated, sorted
    lists per type."""
    urls = list(dict.fromkeys(_URL_RE.findall(text)))
    # Strip trailing punctuation commonly glued to URLs in prose
    urls = [u.rstrip(".,;:!?)\"'") for u in urls]

    domains: list[str] = []
    for d in _DOMAIN_RE.findall(text):
        d = d.lower().strip(".")
        if d in _DOMAIN_NOISE:
            continue
        # Filter obviously-not-domain tokens: file extensions, versions
        if re.fullmatch(r"\d+\.\d+", d):
            continue
        domains.append(d)

    ips_public: list[str] = []
    ips_private: list[str] = []
    for ip in _IPV4_RE.findall(text):
        if _is_rfc1918(ip):
            ips_private.append(ip)
        else:
            ips_public.append(ip)

    return {
        "ipv4_public": sorted(set(ips_public)),
        "ipv4_private": sorted(set(ips_private)),
        "domains": sorted(set(domains)),
        "urls": sorted(set(urls)),
        "md5": sorted({m.lower() for m in _MD5_RE.findall(text)}),
        "sha1": sorted({s.lower() for s in _SHA1_RE.findall(text)}),
        "sha256": sorted({s.lower() for s in _SHA256_RE.findall(text)}),
        "bitcoin": sorted(set(_BTC_RE.findall(text))),
        "cves": sorted({c.upper() for c in _CVE_RE.findall(text)}),
        "emails": sorted(set(_EMAIL_RE.findall(text))),
    }


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------


@dataclass
class IOCVerdict:
    known: bool
    category: str  # "attacker_source", "c2_server", "legitimate", "unknown", ...
    tags: list[str]
    confidence: str  # "high" | "medium" | "low" | "n/a"
    source: str
    notes: str


def _lookup_ip(ip: str) -> IOCVerdict:
    cache = _load_cache()
    entry = (cache.get("ips") or {}).get(ip)
    if not entry:
        return IOCVerdict(False, "unknown", [], "n/a", "-", "not in local IOC cache")
    return IOCVerdict(
        known=True,
        category=entry.get("category", "unknown"),
        tags=list(entry.get("tags", [])),
        confidence=entry.get("confidence", "n/a"),
        source=entry.get("source", "-"),
        notes=entry.get("notes", ""),
    )


def _lookup_domain(domain: str) -> IOCVerdict:
    cache = _load_cache()
    d = domain.lower().strip(".")
    entry = (cache.get("domains") or {}).get(d)
    if entry:
        return IOCVerdict(
            known=True,
            category=entry.get("category", "unknown"),
            tags=list(entry.get("tags", [])),
            confidence=entry.get("confidence", "n/a"),
            source=entry.get("source", "-"),
            notes=entry.get("notes", ""),
        )
    # Look for apex-domain matches: "beta.evil.com" should hit "evil.com"
    parts = d.split(".")
    for i in range(len(parts) - 1):
        parent = ".".join(parts[i:])
        parent_entry = (cache.get("domains") or {}).get(parent)
        if parent_entry:
            return IOCVerdict(
                known=True,
                category=parent_entry.get("category", "unknown"),
                tags=list(parent_entry.get("tags", [])) + ["subdomain_match"],
                confidence=parent_entry.get("confidence", "n/a"),
                source=parent_entry.get("source", "-"),
                notes=f"subdomain of known `{parent}`: "
                + parent_entry.get("notes", ""),
            )
    return IOCVerdict(False, "unknown", [], "n/a", "-", "not in local IOC cache")


def _lookup_hash(h: str) -> IOCVerdict:
    cache = _load_cache()
    h = h.lower()
    entry = (cache.get("hashes") or {}).get(h)
    if not entry:
        return IOCVerdict(False, "unknown", [], "n/a", "-", "not in local IOC cache")
    return IOCVerdict(
        known=True,
        category=entry.get("family", "malware"),
        tags=list(entry.get("tags", [])),
        confidence=entry.get("confidence", "n/a"),
        source=entry.get("source", "-"),
        notes=entry.get("notes", ""),
    )


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------


@mcp.tool()
def extract_iocs(text: str) -> str:
    """Extract IOCs (IPs, domains, URLs, hashes, Bitcoin addresses, CVEs,
    emails) from arbitrary text.

    Useful for pulling a structured IOC list out of an already-written
    report, a log-file snippet, or a shell-history dump. The extractor
    separates RFC1918 IPs from public IPs, de-duplicates per type, and
    strips trailing prose punctuation from URLs.

    Args:
        text: Any text blob to scan

    Returns:
        Markdown report grouped by IOC type.
    """
    iocs = extract_iocs_raw(text)

    lines = ["# IOC extraction", ""]
    total = sum(len(v) for v in iocs.values())
    lines.append(f"- **Total IOCs extracted:** {total}")
    for kind, values in iocs.items():
        if not values:
            continue
        lines.append(f"\n## {kind.replace('_', ' ')} ({len(values)})")
        for v in values[:50]:
            lines.append(f"- `{v}`")
        if len(values) > 50:
            lines.append(f"... {len(values) - 50} more truncated ...")

    _audit("extract_iocs", {"text_len": len(text)}, f"{total} IOCs")
    return "\n".join(lines)


@mcp.tool()
def bulk_ioc_lookup(text: str) -> str:
    """Extract every IOC in `text` and look each one up against the cache.

    Runs `extract_iocs` internally, then for every public IPv4, domain,
    and hex hash it produces a structured reputation verdict (category,
    tags, confidence, source) from the bundled offline IOC cache. Domain
    lookups fall back to parent-domain matches (e.g. `beta.evil.com`
    hits a cache entry for `evil.com` and gets a `subdomain_match`
    tag); hash algorithm is inferred from length (32 → MD5, 40 → SHA1,
    64 → SHA256). RFC1918 addresses and URLs are reported as extracted
    but not looked up.

    Args:
        text: Any text blob — a report draft, a tool output, etc.

    Returns:
        Markdown report grouped by IOC type, with reputation verdicts
        inline per IOC.
    """
    iocs = extract_iocs_raw(text)

    lines = ["# Bulk IOC lookup", ""]
    known_count = 0

    # IPs
    if iocs["ipv4_public"]:
        lines.append(f"## Public IPs ({len(iocs['ipv4_public'])})")
        for ip in iocs["ipv4_public"]:
            v = _lookup_ip(ip)
            if v.known:
                known_count += 1
                lines.append(
                    f"- ⚠ `{ip}` — **{v.category}** "
                    f"(tags: {', '.join(v.tags) or '-'}, confidence: {v.confidence}, "
                    f"source: {v.source})"
                )
            else:
                lines.append(f"- `{ip}` — not in cache")
        lines.append("")

    if iocs["ipv4_private"]:
        lines.append(f"## RFC1918 IPs ({len(iocs['ipv4_private'])})")
        lines.append("(not looked up — private address space)")
        for ip in iocs["ipv4_private"][:20]:
            lines.append(f"- `{ip}`")
        lines.append("")

    # Domains
    if iocs["domains"]:
        lines.append(f"## Domains ({len(iocs['domains'])})")
        for d in iocs["domains"]:
            v = _lookup_domain(d)
            if v.known:
                icon = "✓" if v.category == "legitimate" else "⚠"
                known_count += 1
                lines.append(
                    f"- {icon} `{d}` — **{v.category}** "
                    f"(tags: {', '.join(v.tags) or '-'}, confidence: {v.confidence})"
                )
            else:
                lines.append(f"- `{d}` — not in cache")
        lines.append("")

    # Hashes (all three algorithms)
    for algo in ("md5", "sha1", "sha256"):
        if not iocs[algo]:
            continue
        lines.append(f"## {algo.upper()} hashes ({len(iocs[algo])})")
        for h in iocs[algo]:
            v = _lookup_hash(h)
            if v.known:
                known_count += 1
                lines.append(
                    f"- ⚠ `{h}` — **{v.category}** "
                    f"(family: {v.category}, tags: {', '.join(v.tags) or '-'})"
                )
            else:
                lines.append(f"- `{h}` — not in cache")
        lines.append("")

    # URLs + BTC + CVE + email are reported as extracted only
    for label, vals in (
        ("urls", iocs["urls"]),
        ("Bitcoin addresses", iocs["bitcoin"]),
        ("CVE IDs", iocs["cves"]),
        ("email addresses", iocs["emails"]),
    ):
        if vals:
            lines.append(f"## {label} ({len(vals)})")
            for v_ in vals[:20]:
                lines.append(f"- `{v_}`")
            lines.append("")

    lines.append(f"**Known-bad / known-legitimate hits: {known_count}**")

    total = sum(len(v) for v in iocs.values())
    _audit(
        "bulk_ioc_lookup",
        {"text_len": len(text)},
        f"{total} extracted, {known_count} matched cache",
    )
    return "\n".join(lines)
