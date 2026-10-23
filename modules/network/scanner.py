"""OSINT EYE - Network Scanner Module (Nmap)

Nmap-based port scanning with service/version detection.

Resilience contract:
    Constructing :class:`NetworkScanner` (or the underlying
    :class:`PortScanner`) NEVER raises, even when the ``nmap`` Python
    package or the ``nmap`` binary is missing. The scanner is initialised
    lazily on first use and :meth:`PortScanner.is_available` reports
    whether real scanning is possible. When unavailable, every scan
    returns a graceful-degradation dict::

        {"host": target, "status": "unavailable", "services": [],
         "error": "nmap binary not found in PATH - install nmap (https://nmap.org)"}

    so callers (osint_eye.py CLI, reporters) always get the keys they
    consume ("host" / "services") without exceptions.
"""

import concurrent.futures
import socket

try:  # python-nmap is an optional heavy dependency; never break imports.
    import nmap
except ImportError as _nmap_import_error:  # pragma: no cover - env dependent
    nmap = None  # type: ignore[assignment]
    _NMAP_IMPORT_ERROR = str(_nmap_import_error)
else:
    _NMAP_IMPORT_ERROR = None

# Actionable error returned by scan() when nmap cannot be used.
NMAP_UNAVAILABLE_ERROR = (
    "nmap binary not found in PATH - install nmap (https://nmap.org)"
)

TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899,
    5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800,
    5900, 6000, 6001, 6646, 8000, 8008, 8009, 8080, 8081, 8443, 8888,
    9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156,
]

TOP_20_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080,
]


class PortScanner:
    """Nmap-based port scanner with service detection.

    The underlying ``nmap.PortScanner`` is created lazily on first scan
    (and only once). If the nmap binary is not on PATH (or python-nmap is
    not installed), the object stays usable and every scan method returns
    an "unavailable" result instead of raising ``PortScannerError``.
    """

    def __init__(self, aggressive: bool = False, timing: int = 4):
        self.aggressive = aggressive
        self.timing = timing
        self._nm = None  # Lazy nmap.PortScanner instance.
        self._error: str | None = None

    # ------------------------------------------------------------------
    # Lazy initialisation helpers
    # ------------------------------------------------------------------
    def _ensure_scanner(self) -> bool:
        """Instantiate the nmap PortScanner once; return True if usable.

        Captures ``PortScannerError`` (raised by python-nmap when the
        nmap *binary* is missing from PATH) and ``FileNotFoundError``.
        A stored error string keeps the failure sticky so we do not
        retry (and re-log) on every single scan call.
        """
        if self._nm is not None:
            return True
        if self._error is not None:
            return False
        if nmap is None:
            self._error = (
                f"python-nmap not installed ({_NMAP_IMPORT_ERROR}); "
                f"{NMAP_UNAVAILABLE_ERROR}"
            )
            return False
        try:
            self._nm = nmap.PortScanner()
        except Exception as e:  # PortScannerError / FileNotFoundError / OSError
            self._error = NMAP_UNAVAILABLE_ERROR
            print(f"[!] nmap unavailable: {e}. {NMAP_UNAVAILABLE_ERROR}")
            return False
        return True

    def is_available(self) -> bool:
        """Return True if the nmap binary/backend is ready for scanning."""
        return self._ensure_scanner()

    def unavailable_result(self, host: str) -> dict:
        """Canonical graceful-degradation result when nmap is unusable."""
        return {
            "host": host,
            "status": "unavailable",
            "services": [],
            "error": self._error or NMAP_UNAVAILABLE_ERROR,
        }

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------
    def scan_host(self, host: str, ports: str = None, arguments: str = None) -> dict:
        """Scan a single host; degrades gracefully if nmap is missing."""
        if not self._ensure_scanner():
            return self.unavailable_result(host)

        if not arguments:
            arguments = "-sV"
            if self.aggressive:
                arguments += " -A"
            arguments += f" -T{self.timing}"

        if not ports:
            ports = ",".join(map(str, TOP_100_PORTS))

        try:
            self._nm.scan(host, ports, arguments=arguments)
            return self._parse_scan_results(host)
        except Exception as e:
            print(f"[!] nmap scan failed for {host}: {e}")
            return {
                "host": host,
                "status": "error",
                "services": [],
                "error": str(e),
            }

    def _parse_scan_results(self, host: str) -> dict:
        """Parse nmap scan results"""
        result = {
            "host": host,
            "status": "unknown",
            "addresses": [],
            "protocols": {},
            "os": None,
            "services": [],
        }

        if host not in self._nm.all_hosts():
            return result

        result["status"] = self._nm[host].state()

        if "addresses" in self._nm[host]:
            result["addresses"] = self._nm[host].get("addresses", {})

        if "osmatch" in self._nm[host] and self._nm[host]["osmatch"]:
            result["os"] = self._nm[host]["osmatch"][0].get("name", "")

        for proto in self._nm[host].all_protocols():
            ports = self._nm[host][proto].keys()
            result["protocols"][proto] = list(ports)

            for port in ports:
                port_info = self._nm[host][proto][port]
                service = {
                    "port": port,
                    "protocol": proto,
                    "state": port_info.get("state", ""),
                    "service": port_info.get("name", ""),
                    "version": port_info.get("version", ""),
                    "product": port_info.get("product", ""),
                    "extrainfo": port_info.get("extrainfo", ""),
                }
                result["services"].append(service)

        result["services"].sort(key=lambda x: x["port"])

        return result

    def scan_multiple_hosts(
        self, hosts: list[str], ports: str = None, max_workers: int = 10
    ) -> list[dict]:
        """Scan multiple hosts in parallel (bounded worker pool)."""
        results = []
        max_workers = max(1, min(max_workers, 50))

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.scan_host, host, ports): host for host in hosts
            }

            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    host = futures[future]
                    results.append(
                        {"host": host, "status": "error", "services": [], "error": str(e)}
                    )

        return results

    def quick_scan(self, host: str) -> dict:
        """Quick scan with only top 20 ports"""
        return self.scan_host(host, ",".join(map(str, TOP_20_PORTS)))

    def full_scan(self, host: str) -> dict:
        """Full aggressive scan (settings are local to this scan call)."""
        return self.scan_host(host, arguments="-sV -A -T2")

    def scan_port_list(self, host: str, port_list: list[int]) -> dict:
        """Scan specific port list"""
        return self.scan_host(host, ",".join(map(str, port_list)))

    def detect_web_services(self, hosts: list[str]) -> dict[str, dict]:
        """Detect web services and gather basic info"""
        web_ports = [80, 81, 443, 8080, 8443, 8888, 8000, 8008, 8009]
        results = {}

        for host in hosts:
            host_result = self.scan_host(host, ",".join(map(str, web_ports)))
            if host_result.get("services"):
                web_services = [
                    s
                    for s in host_result["services"]
                    if s["port"] in web_ports and s["state"] == "open"
                ]
                if web_services:
                    results[host] = {
                        "web_ports": web_services,
                        "urls": self._generate_urls(host, web_services),
                    }

        return results

    def _generate_urls(self, host: str, services: list[dict]) -> list[str]:
        """Generate possible URLs (https on TLS ports, http elsewhere)"""
        urls = []

        port_protocols = {}
        for s in services:
            port_protocols[s["port"]] = s.get("service", "http")

        for port in port_protocols:
            if port in [443, 8443]:
                urls.append(f"https://{host}:{port}")
            else:
                urls.append(f"http://{host}:{port}")

        return urls


class ServiceDetector:
    """Service version detection and fingerprinting"""

    def __init__(self):
        self.scanner = PortScanner(aggressive=True)

    def detect_service(self, host: str, port: int) -> dict:
        """Detect service on specific port"""
        result = self.scanner.scan_host(host, str(port), "-sV -sC")

        if result.get("services"):
            return result["services"][0]

        return {}

    def fingerprint_banner(self, host: str, port: int) -> str | None:
        """Grab banner from open port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            try:
                sock.connect((host, port))
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024)
            finally:
                sock.close()

            return banner.decode("utf-8", errors="ignore").strip()
        except (TimeoutError, OSError):
            return None


class NetworkScanner:
    """Main network scanning orchestrator.

    Never raises on construction or on scan(): missing nmap or
    unresolvable targets produce a well-formed result dict with
    "host", "status", "services" (always a list) and "error".
    """

    def __init__(self):
        self.scanner = PortScanner()
        self.detector = ServiceDetector()

    def is_available(self) -> bool:
        """True if the underlying nmap backend is usable."""
        return self.scanner.is_available()

    def scan(self, target: str, scan_type: str = "quick") -> dict:
        """Scan target (IP or domain); always returns a well-formed dict."""
        print(f"[*] Resolving {target}...")

        try:
            if target.replace(".", "").isdigit():
                ip = target
            else:
                ip = socket.gethostbyname(target)
        except (socket.gaierror, OSError) as e:
            return {
                "host": target,
                "status": "error",
                "services": [],
                "error": f"Cannot resolve {target}: {e}",
            }

        if not self.scanner.is_available():
            return self.scanner.unavailable_result(target)

        print(f"[*] Scanning {ip} ({scan_type} scan)...")

        if scan_type == "quick":
            result = self.scanner.quick_scan(ip)
        elif scan_type == "full":
            result = self.scanner.full_scan(ip)
        else:
            result = self.scanner.scan_host(ip)

        # Keep the originally requested target visible to callers.
        result.setdefault("host", target)
        return result

    def scan_subnet(self, subnet: str, ports: str = None) -> dict:
        """Scan an entire subnet (delegates to nmap CIDR support)."""
        print(f"[*] Scanning subnet {subnet}...")

        return self.scanner.scan_host(
            subnet, ports or ",".join(map(str, TOP_20_PORTS))
        )


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python network_scanner.py <target> [scan_type]")
        print("  scan_type: quick, full, or custom")
        sys.exit(1)

    target = sys.argv[1]
    scan_type = sys.argv[2] if len(sys.argv) > 2 else "quick"

    scanner = NetworkScanner()
    results = scanner.scan(target, scan_type)

    print("\n=== Network Scan Results ===")
    print(f"\n[Host: {results.get('host')}]")
    print(f"[Status: {results.get('status')}]")

    if "addresses" in results and isinstance(results["addresses"], dict):
        for addr_type, addr in results["addresses"].items():
            print(f"[{addr_type}: {addr}]")

    print(f"\n[Services: {len(results.get('services', []))}]")
    for svc in results.get("services", [])[:15]:
        if svc["state"] == "open":
            version = svc["version"] or svc.get("product", "")
            print(f"  {svc['port']}/{svc['protocol']} - {svc['service']} {version}")
