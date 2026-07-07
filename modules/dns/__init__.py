"""DNS Module for OSINT EYE"""

from .dns_scanner import DNSResolver, SubdomainEnumerator, ZoneTransfer, DNSScanner
from .subdomain_permutator import (
    SubdomainPermutator,
    SubdomainTakeoverDetector,
    SubdomainMonitor,
)
from .advanced_dns import (
    DNSSECWalker,
    ReverseDNSEnumerator,
    VirtualHostBruteforcer,
    JavaScriptEndpointDiscovery,
    TLSAnalyzer,
    SecurityHeadersAuditor,
    ParameterDiscovery,
    ScreenshotCapture,
)

__all__ = [
    "DNSResolver",
    "SubdomainEnumerator",
    "ZoneTransfer",
    "DNSScanner",
    "SubdomainPermutator",
    "SubdomainTakeoverDetector",
    "SubdomainMonitor",
    "DNSSECWalker",
    "ReverseDNSEnumerator",
    "VirtualHostBruteforcer",
    "JavaScriptEndpointDiscovery",
    "TLSAnalyzer",
    "SecurityHeadersAuditor",
    "ParameterDiscovery",
    "ScreenshotCapture",
]
