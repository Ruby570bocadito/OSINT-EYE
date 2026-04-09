"""OSINT EYE - Network Scanner Module (Nmap)"""

import nmap
import socket
import concurrent.futures
from typing import Dict, List, Optional, Set
import time


class PortScanner:
    """Nmap-based port scanner with service detection"""

    def __init__(self, aggressive: bool = False, timing: int = 4):
        self.nm = nmap.PortScanner()
        self.aggressive = aggressive
        self.timing = timing

        self.top_100_ports = [
            7,
            9,
            13,
            21,
            22,
            23,
            25,
            26,
            37,
            53,
            79,
            80,
            81,
            88,
            106,
            110,
            111,
            113,
            119,
            135,
            139,
            143,
            144,
            179,
            199,
            389,
            427,
            443,
            444,
            445,
            465,
            513,
            514,
            515,
            543,
            544,
            548,
            554,
            587,
            631,
            646,
            873,
            990,
            993,
            995,
            1025,
            1026,
            1027,
            1028,
            1029,
            1110,
            1433,
            1720,
            1723,
            1755,
            1900,
            2000,
            2001,
            2049,
            2121,
            2717,
            3000,
            3128,
            3306,
            3389,
            3986,
            4899,
            5000,
            5009,
            5051,
            5060,
            5101,
            5190,
            5357,
            5432,
            5631,
            5666,
            5800,
            5900,
            6000,
            6001,
            6646,
            8000,
            8008,
            8009,
            8080,
            8081,
            8443,
            8888,
            9100,
            9999,
            10000,
            32768,
            49152,
            49153,
            49154,
            49155,
            49156,
        ]

        self.top_20_ports = [
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            111,
            135,
            139,
            143,
            443,
            445,
            993,
            995,
            1723,
            3306,
            3389,
            5900,
            8080,
        ]

    def scan_host(self, host: str, ports: str = None, arguments: str = None) -> Dict:
        """Scan a single host"""
        if not arguments:
            arguments = "-sV"
            if self.aggressive:
                arguments += " -A"
            arguments += f" -T{self.timing}"

        if not ports:
            ports = ",".join(map(str, self.top_100_ports))

        try:
            self.nm.scan(host, ports, arguments=arguments)
            return self._parse_scan_results(host)
        except Exception as e:
            return {"host": host, "error": str(e), "status": "down"}

    def _parse_scan_results(self, host: str) -> Dict:
        """Parse nmap scan results"""
        result = {
            "host": host,
            "status": "unknown",
            "addresses": [],
            "protocols": {},
            "os": None,
            "services": [],
        }

        if host not in self.nm.all_hosts():
            return result

        result["status"] = self.nm[host].state()

        if "addresses" in self.nm[host]:
            result["addresses"] = self.nm[host].get("addresses", {})

        if "osmatch" in self.nm[host] and self.nm[host]["osmatch"]:
            result["os"] = self.nm[host]["osmatch"][0].get("name", "")

        for proto in self.nm[host].all_protocols():
            ports = self.nm[host][proto].keys()
            result["protocols"][proto] = list(ports)

            for port in ports:
                port_info = self.nm[host][proto][port]
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
        self, hosts: List[str], ports: str = None, max_workers: int = 10
    ) -> List[Dict]:
        """Scan multiple hosts in parallel"""
        results = []

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
                    results.append({"host": host, "error": str(e)})

        return results

    def quick_scan(self, host: str) -> Dict:
        """Quick scan with only top ports"""
        return self.scan_host(host, ",".join(map(str, self.top_20_ports)))

    def full_scan(self, host: str) -> Dict:
        """Full aggressive scan"""
        self.aggressive = True
        self.timing = 2
        return self.scan_host(host)

    def scan_port_list(self, host: str, port_list: List[int]) -> Dict:
        """Scan specific port list"""
        return self.scan_host(host, ",".join(map(str, port_list)))

    def detect_web_services(self, hosts: List[str]) -> Dict[str, Dict]:
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

    def _generate_urls(self, host: str, services: List[Dict]) -> List[str]:
        """Generate possible URLs for web services"""
        urls = []

        port_protocols = {}
        for s in services:
            port_protocols[s["port"]] = s.get("service", "http")

        for port, proto in port_protocols.items():
            if port in [443, 8443]:
                urls.append(f"https://{host}:{port}")
            else:
                urls.append(f"http://{host}:{port}")

        return urls


class ServiceDetector:
    """Service version detection and fingerprinting"""

    def __init__(self):
        self.scanner = PortScanner(aggressive=True)

    def detect_service(self, host: str, port: int) -> Dict:
        """Detect service on specific port"""
        result = self.scanner.scan_host(host, str(port), "-sV -sC")

        if result.get("services"):
            return result["services"][0]

        return {}

    def fingerprint_banner(self, host: str, port: int) -> Optional[str]:
        """Grab banner from open port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))

            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024)
            sock.close()

            return banner.decode("utf-8", errors="ignore").strip()
        except Exception:
            return None


class NetworkScanner:
    """Main network scanning orchestrator"""

    def __init__(self):
        self.scanner = PortScanner()
        self.detector = ServiceDetector()

    def scan(self, target: str, scan_type: str = "quick") -> Dict:
        """Scan target (can be IP or domain)"""
        print(f"[*] Resolving {target}...")

        try:
            if target.replace(".", "").isdigit():
                ip = target
            else:
                ip = socket.gethostbyname(target)
        except socket.gaierror as e:
            return {"error": f"Cannot resolve {target}: {e}"}

        print(f"[*] Scanning {ip} ({scan_type} scan)...")

        if scan_type == "quick":
            result = self.scanner.quick_scan(ip)
        elif scan_type == "full":
            result = self.scanner.full_scan(ip)
        else:
            result = self.scanner.scan_host(ip)

        return result

    def scan_subnet(self, subnet: str, ports: str = None) -> List[Dict]:
        """Scan entire subnet"""
        print(f"[*] Scanning subnet {subnet}...")

        result = self.scanner.scan_host(
            subnet, ports or ",".join(map(str, self.scanner.top_20_ports))
        )

        return result


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

    print(f"\n=== Network Scan Results ===")
    print(f"\n[Host: {results.get('host')}]")
    print(f"[Status: {results.get('status')}]")

    if "addresses" in results:
        for addr_type, addr in results["addresses"].items():
            print(f"[{addr_type}: {addr}]")

    print(f"\n[Services: {len(results.get('services', []))}]")
    for svc in results.get("services", [])[:15]:
        if svc["state"] == "open":
            version = svc["version"] or svc.get("product", "")
            print(f"  {svc['port']}/{svc['protocol']} - {svc['service']} {version}")
