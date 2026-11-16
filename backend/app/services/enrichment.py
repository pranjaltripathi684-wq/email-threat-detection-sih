import re
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple
from app.core.config import settings

# Built-in High-Fidelity Forensic Mock Intelligence Database
# Allows full offline demonstration and instant testing without API quotas
MOCK_IP_DATABASE = {
    "185.220.101.5": {
        "country": "Germany",
        "country_code": "DE",
        "region": "Hesse",
        "city": "Frankfurt am Main",
        "latitude": 50.1109,
        "longitude": 8.6821,
        "asn": "AS208294",
        "isp": "Zwiebelfreunde e.V.",
        "org": "Tor Exit Node Network",
        "is_vpn": False,
        "is_tor": True,
        "is_cloud_proxy": False,
        "reverse_dns": "tor-exit-node-5.zwiebelfreunde.de",
        "reputation_score": 85.0
    },
    "45.33.32.156": {
        "country": "United States",
        "country_code": "US",
        "region": "California",
        "city": "Fremont",
        "latitude": 37.5483,
        "longitude": -121.9886,
        "asn": "AS63949",
        "isp": "Linode, LLC",
        "org": "Akamai Cloud Infrastructure",
        "is_vpn": False,
        "is_tor": False,
        "is_cloud_proxy": True,
        "reverse_dns": "li45-33.members.linode.com",
        "reputation_score": 65.0
    },
    "198.51.100.42": {
        "country": "Netherlands",
        "country_code": "NL",
        "region": "North Holland",
        "city": "Amsterdam",
        "latitude": 52.3676,
        "longitude": 4.9041,
        "asn": "AS49981",
        "isp": "WorldStream B.V.",
        "org": "Bulletproof Hosting Infrastructure",
        "is_vpn": True,
        "is_tor": False,
        "is_cloud_proxy": True,
        "reverse_dns": "relay01.nl-infra.net",
        "reputation_score": 90.0
    },
    "209.85.220.41": {
        "country": "United States",
        "country_code": "US",
        "region": "California",
        "city": "Mountain View",
        "latitude": 37.4220,
        "longitude": -122.0841,
        "asn": "AS15169",
        "isp": "Google LLC",
        "org": "Google Mail Infrastructure",
        "is_vpn": False,
        "is_tor": False,
        "is_cloud_proxy": True,
        "reverse_dns": "mail-sor-f41.google.com",
        "reputation_score": 5.0
    },
    "104.244.42.1": {
        "country": "Luxembourg",
        "country_code": "LU",
        "region": "Luxembourg",
        "city": "Roeser",
        "latitude": 49.5414,
        "longitude": 6.1458,
        "asn": "AS59711",
        "isp": "HYDRATEL",
        "org": "Anonymous Relay Provider",
        "is_vpn": True,
        "is_tor": False,
        "is_cloud_proxy": True,
        "reverse_dns": "gw-lux.relay.net",
        "reputation_score": 75.0
    }
}

MOCK_DOMAIN_DATABASE = {
    "paypa1-update.com": {
        "registrar": "NameCheap, Inc. (Mock)",
        "creation_date": "2026-08-15T00:00:00Z",
        "is_newly_registered": True,
        "mx_records": ["mail.paypa1-update.com"],
        "ns_records": ["ns1.bulletproof-dns.com", "ns2.bulletproof-dns.com"],
        "spf_record": "v=spf1 ip4:198.51.100.42 ~all",
        "dmarc_record": "v=DMARC1; p=none;"
    },
    "exec-urgent-request.top": {
        "registrar": "Alibaba Cloud Computing (Mock)",
        "creation_date": "2026-08-20T00:00:00Z",
        "is_newly_registered": True,
        "mx_records": ["mx.exec-urgent-request.top"],
        "ns_records": ["ns1.dnshost.top"],
        "spf_record": "v=spf1 ip4:104.244.42.1 -all",
        "dmarc_record": "v=DMARC1; p=quarantine;"
    },
    "legit-partner.com": {
        "registrar": "MarkMonitor, Inc. (Mock)",
        "creation_date": "2015-03-12T00:00:00Z",
        "is_newly_registered": False,
        "mx_records": ["mail.legit-partner.com"],
        "ns_records": ["ns1.p01.dynect.net"],
        "spf_record": "v=spf1 include:_spf.google.com ~all",
        "dmarc_record": "v=DMARC1; p=reject;"
    }
}

MOCK_THREAT_FEEDS = {
    "198.51.100.42": [
        {"provider": "AbuseIPDB", "severity": "High", "confidence": 0.92, "details": "Reported 142 times for Phishing & Brute-force email relay"}
    ],
    "185.220.101.5": [
        {"provider": "AbuseIPDB", "severity": "Medium", "confidence": 0.85, "details": "Known Tor exit node proxy used in anonymized spam campaigns"}
    ],
    "paypa1-update.com": [
        {"provider": "URLhaus", "severity": "Critical", "confidence": 0.98, "details": "Active credential phishing domain targeting financial institutions"}
    ],
    "44d88612fea8a8f36de82e1278abb02f": [
        {"provider": "VirusTotal", "severity": "Critical", "confidence": 0.99, "details": "Identified as Trojan.Downloader.VBA by 48/72 engines"}
    ]
}


def enrich_ip_address(ip: str) -> Dict[str, Any]:
    """Enriches public IP with Geolocation, ASN, ISP, and proxy indicators."""
    if not ip or ip == "Unknown":
        return {
            "ip_address": ip,
            "country": "Unknown",
            "city": "Unknown",
            "latitude": 0.0,
            "longitude": 0.0,
            "asn": "Unknown",
            "isp": "Unknown",
            "is_vpn": False,
            "is_tor": False,
            "is_cloud_proxy": False,
            "attribution_note": settings.ATTRIBUTION_DISCLAIMER
        }

    # Check mock database first
    if ip in MOCK_IP_DATABASE:
        data = MOCK_IP_DATABASE[ip].copy()
        data["ip_address"] = ip
        data["attribution_note"] = (
            f"Estimated infrastructure location for {ip}: {data['city']}, {data['country']} ({data['asn']}). "
            "Attribution support only; does not definitively establish sender physical presence."
        )
        return data

    # Dynamic fallback simulation for arbitrary public IPs
    octets = ip.split(".")
    hash_val = sum(int(o) for o in octets if o.isdigit()) % 5
    sample_cities = [
        ("United States", "US", "Virginia", "Ashburn", 39.0438, -77.4874, "AS14618", "Amazon.com, Inc.", True),
        ("Germany", "DE", "Bavaria", "Nuremberg", 49.4521, 11.0767, "AS24940", "Hetzner Online GmbH", True),
        ("United Kingdom", "GB", "England", "London", 51.5074, -0.1278, "AS2856", "British Telecommunications PLC", False),
        ("Japan", "JP", "Tokyo", "Tokyo", 35.6762, 139.6503, "AS2516", "KDDI Corporation", False),
        ("France", "FR", "Île-de-France", "Paris", 48.8566, 2.3522, "AS16276", "OVH SAS", True)
    ]
    c_name, c_code, reg, city, lat, lon, asn, isp, is_cloud = sample_cities[hash_val]

    return {
        "ip_address": ip,
        "country": c_name,
        "country_code": c_code,
        "region": reg,
        "city": city,
        "latitude": lat,
        "longitude": lon,
        "asn": asn,
        "isp": isp,
        "org": isp,
        "is_vpn": False,
        "is_tor": False,
        "is_cloud_proxy": is_cloud,
        "reverse_dns": f"host-{ip.replace('.', '-')}.{isp.split()[0].lower()}.net",
        "reputation_score": 10.0 if is_cloud else 0.0,
        "attribution_note": (
            f"Earliest reliable public IP {ip} geolocated to estimated infrastructure in {city}, {c_name}. "
            "Confidence-based assessment; attribution support only."
        )
    }


def enrich_domain(domain: str) -> Dict[str, Any]:
    """Enriches domain with DNS records, registration age, and nameservers."""
    if not domain:
        return {}

    if domain in MOCK_DOMAIN_DATABASE:
        data = MOCK_DOMAIN_DATABASE[domain].copy()
        data["domain_name"] = domain
        return data

    return {
        "domain_name": domain,
        "registrar": "Domain Registrar Services (Mock/Live)",
        "creation_date": "2023-01-01T00:00:00Z",
        "is_newly_registered": False,
        "mx_records": [f"mail.{domain}"],
        "ns_records": [f"ns1.{domain}", f"ns2.{domain}"],
        "spf_record": f"v=spf1 a mx ~all",
        "dmarc_record": "v=DMARC1; p=none;"
    }


def check_threat_intelligence(indicators: List[Dict[str, str]]) -> Tuple[List[Dict[str, Any]], float]:
    """
    Checks indicators (IPs, domains, URLs, hashes) against Threat Intelligence feeds.
    Returns matched feeds and threat intel score contribution (0 to 5).
    """
    matches = []
    max_intel_score = 0.0

    for ind in indicators:
        val = ind.get("value", "")
        ind_type = ind.get("type", "")
        
        if val in MOCK_THREAT_FEEDS:
            for feed_item in MOCK_THREAT_FEEDS[val]:
                matches.append({
                    "indicator_value": val,
                    "indicator_type": ind_type,
                    "provider_name": feed_item["provider"],
                    "severity": feed_item["severity"],
                    "confidence": feed_item["confidence"],
                    "match_details": feed_item["details"]
                })
                if feed_item["severity"] == "Critical":
                    max_intel_score = max(max_intel_score, 5.0)
                elif feed_item["severity"] == "High":
                    max_intel_score = max(max_intel_score, 4.0)
                else:
                    max_intel_score = max(max_intel_score, 2.0)

    return matches, max_intel_score
