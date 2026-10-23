"""DNS Module for OSINT EYE"""

from .advanced_dns import (
    DNSSECWalker,
    JavaScriptEndpointDiscovery,
    ParameterDiscovery,
    ReverseDNSEnumerator,
    ScreenshotCapture,
    SecurityHeadersAuditor,
    TLSAnalyzer,
    VirtualHostBruteforcer,
)
from .dns_scanner import DNSResolver, DNSScanner, SubdomainEnumerator, ZoneTransfer
from .email_security import EmailSecurityAuditor
from .passive_sources import PassiveSubdomainEnumerator
from .subdomain_permutator import (
    SubdomainMonitor,
    SubdomainPermutator,
    SubdomainTakeoverDetector,
)
from .wildcard import WildcardDetector

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
    "WildcardDetector",
    "PassiveSubdomainEnumerator",
    "EmailSecurityAuditor",
]
