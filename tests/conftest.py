"""Shared offline helpers for the OSINT EYE test suite.

Every test module here is 100 % offline: network-dependent paths are mocked.
"""

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _fake_dns_resolver(records: dict):
    """Build a DNSResolver whose internal dnspython resolver is mocked.

    ``records`` maps (domain, record_type) → list of answer strings;
    any other query raises NXDOMAIN (i.e. resolved to []).
    """
    import dns.resolver

    from modules.dns import DNSResolver

    resolver = DNSResolver()
    fake = MagicMock()

    def fake_resolve(domain, record_type, *args, **kwargs):
        key = (str(domain), str(record_type))
        if key in records:
            return list(records[key])
        raise dns.resolver.NXDOMAIN()

    fake.resolve.side_effect = fake_resolve
    resolver.resolver = fake
    return resolver


FULL_RESULTS = {
    "target": "example.com",
    "scan_date": "2024-06-01T12:00:00",
    "depth": "normal",
    "modules": {
        "dns": {
            "domain": "example.com",
            "subdomains": ["www.example.com", "api.example.com"],
            "records": {"A": ["93.184.216.34"], "MX": ["mail.example.com"]},
            "spf": {"exists": True, "record": "v=SPF1 -all"},
            "dmarc": {"exists": True, "policy": "reject"},
        },
        "certs": {"subdomains": ["ct.example.com"]},
        "wayback": {"total_snapshots": 1234, "by_year": {"2023": 900, "2022": 334}},
        "network": {
            "host": "93.184.216.34",
            "status": "up",
            "services": [
                {"port": 443, "protocol": "tcp", "service": "https", "state": "open", "version": "nginx 1.24"},
                {"port": 22, "protocol": "tcp", "service": "ssh", "state": "closed"},
            ],
        },
        "web": {"technologies": {"technologies": ["nginx", "Cloudflare"], "url": "https://example.com"}},
        "endpoints": {"found": [{"path": "/login", "status": 200, "size": 1024}], "sensitive": [{"path": "/.env", "status": 200}], "total_found": 1},
        "emails": {"emails_found": ["admin@example.com"]},
        "cloud_buckets": {"found": [{"url": "s3://example-assets", "provider": "aws", "public": True}], "public": [{"url": "s3://example-assets"}]},
        "github": {"total_findings": 2, "findings": [{"type": "aws_key", "match": "AKIAIOSFODNN7", "url": "https://github.com/x/y"}]},
        "cdn_waf": {"cdn": "Cloudflare", "waf": "Cloudflare"},
        "cve": {"cves": [{"id": "CVE-2024-1234", "description": "Critical RCE in nginx", "severity": [{"score": 9.8, "severity": "CRITICAL"}]}]},
        "takeover": {"vulnerable": [{"subdomain": "old.example.com", "service": "aws", "signature": "NoSuchBucket"}]},
    },
    "correlation": {
        "attack_surface_score": {"score": 78, "severity": "HIGH", "factors": ["Open admin panel", "Public buckets"]}
    },
    "mitre": {
        "total_findings": 3,
        "critical_count": 2,
        "findings": [
            {"technique_id": "T1552.001", "technique_name": "Unsecured Credentials: Credentials In Files", "tactic": "Credential Access", "severity": "CRITICAL"},
            {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access", "severity": "HIGH"},
        ],
    },
    "attack_chains": [
        {
            "name": "Public bucket to data exfiltration",
            "risk_score": 85,
            "difficulty": "Low",
            "steps": [{"step": 1, "action": "Enumerate buckets"}, {"step": 2, "action": "Download objects"}],
        }
    ],
    "ai_analysis": {"risk_score": {"score": 66, "severity": "HIGH"}, "summary": "Focus on exposed .env and buckets."},
    "errors": ["[whois] rate limited"],
}


def _record_console():
    from rich.console import Console

    return Console(record=True, width=140, force_terminal=False, highlight=False)
