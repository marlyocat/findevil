"""Tests for the threat-intel tools."""

from findevil.tools.threat_intel import (
    _is_rfc1918,
    _load_cache,
    _lookup_domain,
    _lookup_hash,
    _lookup_ip,
    bulk_ioc_lookup,
    extract_iocs_raw,
)


# ---------------------------------------------------------------------------
# Cache load + contents
# ---------------------------------------------------------------------------


def test_cache_loads_successfully():
    cache = _load_cache()
    assert "_error" not in cache
    assert cache.get("ips"), "expected at least one IP entry"
    assert cache.get("hashes"), "expected at least one hash entry"
    assert cache.get("domains"), "expected at least one domain entry"


def test_cache_contains_scenario_ips():
    cache = _load_cache()
    ips = cache["ips"]
    # All four scenario attacker IPs must be present
    for ip in ("45.123.45.67", "185.177.124.22", "185.229.59.103", "91.121.55.44"):
        assert ip in ips, f"scenario IP {ip} missing from cache"


# ---------------------------------------------------------------------------
# RFC1918 detection
# ---------------------------------------------------------------------------


def test_rfc1918_detection():
    assert _is_rfc1918("10.0.0.5")
    assert _is_rfc1918("192.168.1.1")
    assert _is_rfc1918("172.16.0.1")
    assert _is_rfc1918("127.0.0.1")
    assert not _is_rfc1918("8.8.8.8")
    assert not _is_rfc1918("45.123.45.67")


# ---------------------------------------------------------------------------
# IOC extraction
# ---------------------------------------------------------------------------


def test_extract_iocs_from_mixed_text():
    text = (
        "Attacker came from 45.123.45.67 using curl https://evil.com/beacon "
        "dropped payload with SHA256 9f0f8f4f86a4bbadcd31881e9fab048338aaddaa5501f34b3a3d56a1fa4ba938 "
        "internal pivot via 10.0.0.5 to mail@corp.com. See CVE-2024-12345."
    )
    iocs = extract_iocs_raw(text)
    assert "45.123.45.67" in iocs["ipv4_public"]
    assert "10.0.0.5" in iocs["ipv4_private"]
    assert "evil.com" in iocs["domains"]
    assert any("evil.com" in u for u in iocs["urls"])
    assert (
        "9f0f8f4f86a4bbadcd31881e9fab048338aaddaa5501f34b3a3d56a1fa4ba938"
        in iocs["sha256"]
    )
    assert "CVE-2024-12345" in iocs["cves"]
    assert "mail@corp.com" in iocs["emails"]


def test_extract_iocs_dedupes():
    text = "45.123.45.67 45.123.45.67 45.123.45.67"
    iocs = extract_iocs_raw(text)
    assert iocs["ipv4_public"] == ["45.123.45.67"]


def test_extract_iocs_strips_url_trailing_punctuation():
    text = "See https://evil.com/beacon, then stop."
    iocs = extract_iocs_raw(text)
    # trailing comma should be stripped off the URL
    assert any(u.endswith("beacon") for u in iocs["urls"])


# ---------------------------------------------------------------------------
# IP lookups
# ---------------------------------------------------------------------------


def test_lookup_known_attacker_ip():
    v = _lookup_ip("45.123.45.67")
    assert v.known is True
    assert "simulated" in v.tags
    assert v.category in ("attacker_source", "c2_server", "scanner")


def test_lookup_unknown_ip():
    v = _lookup_ip("8.8.8.8")
    assert v.known is False
    assert v.confidence == "n/a"


def test_lookup_known_c2_ip():
    v = _lookup_ip("185.177.124.22")
    assert v.known is True
    assert v.category in ("c2_server", "attacker_source", "scanner")


# ---------------------------------------------------------------------------
# Domain lookups
# ---------------------------------------------------------------------------


def test_lookup_known_malicious_domain():
    v = _lookup_domain("pool.supportxmr.com")
    assert v.known is True
    assert v.category == "mining_pool"


def test_lookup_known_legitimate_domain():
    v = _lookup_domain("registry.npmjs.org")
    assert v.known is True
    assert v.category == "legitimate"
    assert "legitimate" in v.tags


def test_lookup_subdomain_match():
    v = _lookup_domain("beta.evil.com")
    assert v.known is True
    assert "subdomain_match" in v.tags


def test_lookup_unknown_domain():
    v = _lookup_domain("random-saas-app.example")
    assert v.known is False


# ---------------------------------------------------------------------------
# Hash lookups
# ---------------------------------------------------------------------------


def test_lookup_known_hash():
    v = _lookup_hash("ac19c0e955e1b4e9c0e28bbe5b6e2c5b5b0ab3adf3e9e3cfe77bbf8c3a86d04b")
    assert v.known is True
    # Category is the family here
    assert v.category == "xmrig"


def test_lookup_unknown_hash():
    v = _lookup_hash("0" * 64)
    assert v.known is False
    assert v.confidence == "n/a"
    assert "not in local" in v.notes


# ---------------------------------------------------------------------------
# Bulk IOC lookup
# ---------------------------------------------------------------------------


def test_bulk_ioc_lookup_highlights_known_attacker():
    text = (
        "Logs show repeated connections from 45.123.45.67 and payload download "
        "from https://185.177.124.22/x.sh. Mining pool pool.supportxmr.com "
        "appears in process args. Internal relay at 10.0.0.5."
    )
    out = bulk_ioc_lookup(text)
    # Known-bad IP should be flagged
    assert "45.123.45.67" in out
    assert "attacker_source" in out
    # Known-bad C2
    assert "185.177.124.22" in out
    assert "c2_server" in out
    # Known mining pool
    assert "pool.supportxmr.com" in out
    assert "mining_pool" in out
    # RFC1918 should be reported but not looked up
    assert "10.0.0.5" in out
    assert "RFC1918" in out


def test_bulk_ioc_lookup_clean_text_returns_no_matches():
    out = bulk_ioc_lookup("Nothing interesting here.")
    # Still should not crash, and should have zero known hits
    assert "Known-bad" in out
    assert ": 0" in out
