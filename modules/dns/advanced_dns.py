"""OSINT EYE - Advanced DNS Algorithms (DNSSEC, Reverse DNS, VHost)"""

import dns.resolver
import dns.query
import dns.name
import dns.reversename
import dns.dnssec
import dns.rdatatype
import socket
import asyncio
import aiohttp
from typing import List, Dict, Set, Optional, Tuple
from collections import defaultdict


class DNSSECWalker:
    """DNSSEC NSEC/NSEC3 walking for complete zone enumeration"""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout

    def check_dnssec(self, domain: str) -> Dict:
        """Check if domain has DNSSEC enabled"""
        result = {
            "domain": domain,
            "dnssec_enabled": False,
            "signed": False,
            "ds_records": [],
            "dnskey_records": [],
            "rrsig_records": [],
        }

        try:
            ds = self.resolver.resolve(domain, "DS")
            result["ds_records"] = [str(r) for r in ds]
            result["dnssec_enabled"] = True
        except Exception:
            pass

        try:
            dnskey = self.resolver.resolve(domain, "DNSKEY")
            result["dnskey_records"] = [str(r) for r in dnskey]
            result["signed"] = True
        except Exception:
            pass

        try:
            rrsig = self.resolver.resolve(domain, "RRSIG")
            result["rrsig_records"] = [str(r) for r in rrsig]
        except Exception:
            pass

        return result

    def walk_nsec(self, domain: str) -> List[str]:
        """Walk NSEC records for zone enumeration"""
        found = []
        current = domain

        for _ in range(100):
            try:
                answer = self.resolver.resolve(current, "NSEC")
                for rdata in answer:
                    next_name = str(rdata.next).rstrip(".")
                    found.append(next_name)
                    current = next_name

                    if current == domain or current == ".":
                        return found
            except Exception:
                break

        return found

    def walk_nsec3(self, domain: str) -> Dict:
        """Analyze NSEC3 parameters"""
        result = {
            "domain": domain,
            "has_nsec3": False,
            "hash_algorithm": None,
            "flags": None,
            "iterations": None,
            "salt": None,
        }

        try:
            nsec3param = self.resolver.resolve(domain, "NSEC3PARAM")
            for rdata in nsec3param:
                result["has_nsec3"] = True
                result["hash_algorithm"] = rdata.algorithm
                result["flags"] = rdata.flags
                result["iterations"] = rdata.iterations
                result["salt"] = rdata.salt.hex() if rdata.salt else "none"
        except Exception:
            pass

        return result


class ReverseDNSEnumerator:
    """Reverse DNS enumeration for IP ranges"""

    def __init__(self, timeout: int = 2):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout

    def reverse_lookup(self, ip: str) -> Optional[str]:
        """PTR lookup for a single IP"""
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(rev_name, "PTR")
            return str(answers[0]).rstrip(".")
        except Exception:
            return None

    def reverse_range(self, ip_range: str) -> List[Dict]:
        """Reverse DNS for entire /24 range"""
        parts = ip_range.split(".")
        if len(parts) != 4:
            return []

        base = ".".join(parts[:3])
        results = []

        for i in range(1, 255):
            ip = f"{base}.{i}"
            ptr = self.reverse_lookup(ip)
            if ptr:
                results.append({"ip": ip, "ptr": ptr})

        return results

    def reverse_range_async(
        self, ip_range: str, max_concurrent: int = 100
    ) -> List[Dict]:
        """Async reverse DNS for entire /24 range"""
        parts = ip_range.split(".")
        if len(parts) != 4:
            return []

        base = ".".join(parts[:3])
        ips = [f"{base}.{i}" for i in range(1, 255)]

        loop = asyncio.get_event_loop()
        semaphore = asyncio.Semaphore(max_concurrent)

        async def lookup(ip):
            async with semaphore:
                ptr = await loop.run_in_executor(None, self.reverse_lookup, ip)
                if ptr:
                    return {"ip": ip, "ptr": ptr}
                return None

        async def run():
            tasks = [lookup(ip) for ip in ips]
            results = await asyncio.gather(*tasks)
            return [r for r in results if r is not None]

        return loop.run_until_complete(run())


class VirtualHostBruteforcer:
    """Discover virtual hosts on a web server"""

    def __init__(self, timeout: int = 5, threads: int = 50):
        self.timeout = timeout
        self.threads = threads
        self.session = aiohttp.ClientSession()

        self.vhost_prefixes = [
            "www",
            "mail",
            "ftp",
            "admin",
            "dev",
            "test",
            "staging",
            "api",
            "app",
            "portal",
            "dashboard",
            "internal",
            "intranet",
            "extranet",
            "partner",
            "client",
            "customer",
            "vendor",
            "backup",
            "db",
            "monitor",
            "proxy",
            "lb",
            "cdn",
            "old",
            "new",
            "beta",
            "demo",
            "sandbox",
            "webmail",
            "owa",
            "remote",
            "vpn",
            "ssh",
            "git",
            "svn",
            "jenkins",
            "jira",
            "confluence",
            "wiki",
            "blog",
            "forum",
            "shop",
            "store",
            "crm",
            "erp",
            "hr",
            "finance",
            "legal",
        ]

    async def check_vhost(
        self, ip: str, hostname: str, port: int = 80
    ) -> Optional[Dict]:
        """Check if a virtual host exists on an IP"""
        url = f"http://{ip}:{port}" if port != 443 else f"https://{ip}:{port}"

        try:
            async with self.session.get(
                url,
                headers={"Host": hostname},
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                allow_redirects=False,
                ssl=False,
            ) as resp:
                content = await resp.text()

                return {
                    "hostname": hostname,
                    "ip": ip,
                    "port": port,
                    "status": resp.status,
                    "size": len(content),
                    "content_type": resp.headers.get("Content-Type", ""),
                    "server": resp.headers.get("Server", ""),
                    "redirect": resp.headers.get("Location", ""),
                }
        except Exception:
            return None

    async def bruteforce(
        self, ip: str, domain: str = None, port: int = 80
    ) -> List[Dict]:
        """Bruteforce virtual hosts on an IP"""
        hostnames = list(self.vhost_prefixes)

        if domain:
            hostnames.extend([f"{p}.{domain}" for p in self.vhost_prefixes])
            hostnames.append(domain)

        semaphore = asyncio.Semaphore(self.threads)

        async def check(hostname):
            async with semaphore:
                return await self.check_vhost(ip, hostname, port)

        tasks = [check(h) for h in hostnames]
        results = await asyncio.gather(*tasks)

        await self.session.close()

        return [r for r in results if r is not None]


class JavaScriptEndpointDiscovery:
    """Extract endpoints and secrets from JavaScript files"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = aiohttp.ClientSession()

        self.js_patterns = {
            "api_endpoints": [
                r'["\'](/api/[^"\']+)["\']',
                r'["\'](/rest/[^"\']+)["\']',
                r'["\'](/graphql[^"\']*)["\']',
                r'["\'](/[a-z]+/v\d+/[^"\']+)["\']',
                r'fetch\(["\']([^"\']+)["\']',
                r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
                r'url:\s*["\']([^"\']+)["\']',
            ],
            "internal_urls": [
                r'["\'](https?://[a-zA-Z0-9\-\.]+\.internal[^"\']*)["\']',
                r'["\'](https?://[a-zA-Z0-9\-\.]+\.corp[^"\']*)["\']',
                r'["\'](https?://[a-zA-Z0-9\-\.]+\.local[^"\']*)["\']',
                r'["\'](https?://[a-zA-Z0-9\-\.]+\.dev[^"\']*)["\']',
                r'["\'](https?://[a-zA-Z0-9\-\.]+\.staging[^"\']*)["\']',
            ],
            "secrets": [
                r'["\']api[_-]?key["\']\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
                r'["\']secret["\']\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
                r'["\']token["\']\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
                r'["\']password["\']\s*[:=]\s*["\']([^"\']{8,})["\']',
                r"AKIA[0-9A-Z]{16}",
                r"ghp_[a-zA-Z0-9]{36}",
            ],
            "s3_buckets": [
                r"s3\.amazonaws\.com/([a-zA-Z0-9\-\.]+)",
                r'["\']([a-zA-Z0-9\-\.]+)\.s3\.amazonaws\.com["\']',
                r'["\']s3://([a-zA-Z0-9\-\.]+)["\']',
            ],
            "firebase": [
                r"firebaseConfig\s*[:=]\s*\{([^}]+)\}",
                r'apiKey:\s*["\']([a-zA-Z0-9_-]{30,})["\']',
                r'projectId:\s*["\']([^"\']+)["\']',
            ],
        }

    async def fetch_js_files(self, base_url: str) -> List[str]:
        """Find and fetch JavaScript files from a page"""
        js_urls = []

        try:
            async with self.session.get(
                base_url, timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as resp:
                html = await resp.text()

                import re

                scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html)
                for src in scripts:
                    if src.endswith(".js"):
                        if src.startswith("//"):
                            js_urls.append(f"https:{src}")
                        elif src.startswith("/"):
                            from urllib.parse import urljoin

                            js_urls.append(urljoin(base_url, src))
                        else:
                            js_urls.append(src)
        except Exception:
            pass

        return js_urls

    async def analyze_js(self, js_url: str) -> Dict:
        """Analyze a JavaScript file for endpoints and secrets"""
        result = {
            "url": js_url,
            "endpoints": [],
            "internal_urls": [],
            "secrets": [],
            "s3_buckets": [],
            "firebase": [],
        }

        try:
            async with self.session.get(
                js_url, timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as resp:
                content = await resp.text()

                import re

                for category, patterns in self.js_patterns.items():
                    for pattern in patterns:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            if isinstance(match, tuple):
                                match = match[0] if match[0] else match[-1]
                            if match and len(match) > 2:
                                result[category].append(match)

                for key in result:
                    if isinstance(result[key], list):
                        result[key] = list(set(result[key]))[:50]

        except Exception as e:
            result["error"] = str(e)

        return result

    async def scan(self, base_url: str) -> Dict:
        """Full JavaScript analysis"""
        js_urls = await self.fetch_js_files(base_url)

        results = {
            "base_url": base_url,
            "js_files_found": len(js_urls),
            "js_files": js_urls,
            "findings": [],
        }

        for url in js_urls[:20]:
            analysis = await self.analyze_js(url)
            results["findings"].append(analysis)

        await self.session.close()

        return results


class TLSAnalyzer:
    """SSL/TLS configuration analysis"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def analyze(self, hostname: str, port: int = 443) -> Dict:
        """Analyze TLS configuration"""
        result = {
            "host": hostname,
            "port": port,
            "protocols": {},
            "cipher_suites": [],
            "certificate": {},
            "vulnerabilities": [],
            "grade": None,
        }

        try:
            import ssl
            import socket

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (hostname, port), timeout=self.timeout
            ) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    result["protocols"][ssock.version()] = True
                    result["cipher_suites"].append(ssock.cipher()[0])

            for proto in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]:
                try:
                    proto_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    proto_ctx.check_hostname = False
                    proto_ctx.verify_mode = ssl.CERT_NONE

                    if hasattr(ssl, f"{proto.replace('.', '_')}"):
                        proto_ctx.maximum_version = getattr(
                            ssl, f"{proto.replace('.', '_')}"
                        )
                        proto_ctx.minimum_version = getattr(
                            ssl, f"{proto.replace('.', '_')}"
                        )

                    with socket.create_connection(
                        (hostname, port), timeout=self.timeout
                    ) as sock:
                        with proto_ctx.wrap_socket(sock, server_hostname=hostname):
                            result["protocols"][proto] = True
                except Exception:
                    result["protocols"][proto] = False

            ctx_check = ssl.create_default_context()
            ctx_check.check_hostname = False
            ctx_check.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (hostname, port), timeout=self.timeout
            ) as sock:
                with ctx_check.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    result["certificate"] = {
                        "subject": dict(x[0] for x in cert.get("subject", ())),
                        "issuer": dict(x[0] for x in cert.get("issuer", ())),
                        "version": cert.get("version"),
                        "serialNumber": cert.get("serialNumber"),
                        "notBefore": cert.get("notBefore"),
                        "notAfter": cert.get("notAfter"),
                    }

            if result["protocols"].get("SSLv2"):
                result["vulnerabilities"].append("SSLv2 enabled (CRITICAL)")
            if result["protocols"].get("SSLv3"):
                result["vulnerabilities"].append("SSLv3 enabled - POODLE vulnerability")
            if result["protocols"].get("TLSv1"):
                result["vulnerabilities"].append("TLSv1 enabled (deprecated)")
            if result["protocols"].get("TLSv1.1"):
                result["vulnerabilities"].append("TLSv1.1 enabled (deprecated)")

            if not result["vulnerabilities"]:
                result["grade"] = "A"
            elif len(result["vulnerabilities"]) == 1:
                result["grade"] = "B"
            elif len(result["vulnerabilities"]) == 2:
                result["grade"] = "C"
            else:
                result["grade"] = "F"

        except Exception as e:
            result["error"] = str(e)

        return result


class SecurityHeadersAuditor:
    """Audit HTTP security headers"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

        self.required_headers = {
            "Strict-Transport-Security": {
                "severity": "HIGH",
                "description": "HSTS not enabled - vulnerable to downgrade attacks",
            },
            "Content-Security-Policy": {
                "severity": "MEDIUM",
                "description": "No CSP - vulnerable to XSS and injection attacks",
            },
            "X-Content-Type-Options": {
                "severity": "MEDIUM",
                "description": "Missing X-Content-Type-Options - MIME sniffing possible",
            },
            "X-Frame-Options": {
                "severity": "MEDIUM",
                "description": "Missing X-Frame-Options - vulnerable to clickjacking",
            },
            "X-XSS-Protection": {
                "severity": "LOW",
                "description": "Missing X-XSS-Protection header",
            },
            "Referrer-Policy": {
                "severity": "LOW",
                "description": "Missing Referrer-Policy - may leak sensitive URLs",
            },
            "Permissions-Policy": {
                "severity": "LOW",
                "description": "Missing Permissions-Policy - browser features unrestricted",
            },
        }

        self.dangerous_headers = {
            "Server": "Reveals server software",
            "X-Powered-By": "Reveals technology stack",
            "X-AspNet-Version": "Reveals ASP.NET version",
            "X-AspNetMvc-Version": "Reveals ASP.NET MVC version",
        }

    def audit(self, url: str) -> Dict:
        """Audit security headers of a URL"""
        result = {
            "url": url,
            "missing_headers": [],
            "misconfigured_headers": [],
            "information_disclosure": [],
            "score": 100,
            "grade": None,
        }

        try:
            import requests

            resp = requests.get(url, timeout=self.timeout, verify=False)
            headers = dict(resp.headers)

            for header, info in self.required_headers.items():
                if header not in headers:
                    result["missing_headers"].append(
                        {
                            "header": header,
                            "severity": info["severity"],
                            "description": info["description"],
                        }
                    )
                    result["score"] -= {"HIGH": 15, "MEDIUM": 10, "LOW": 5}.get(
                        info["severity"], 5
                    )

            if "Strict-Transport-Security" in headers:
                hsts = headers["Strict-Transport-Security"]
                if "max-age" in hsts.lower():
                    max_age = int(hsts.split("=")[1].split(";")[0].strip())
                    if max_age < 31536000:
                        result["misconfigured_headers"].append(
                            {
                                "header": "Strict-Transport-Security",
                                "issue": f"max-age too low: {max_age}s (recommended: 31536000s)",
                            }
                        )
                        result["score"] -= 10

                if "includeSubDomains" not in hsts:
                    result["misconfigured_headers"].append(
                        {
                            "header": "Strict-Transport-Security",
                            "issue": "Missing includeSubDomains directive",
                        }
                    )
                    result["score"] -= 5

            for header, desc in self.dangerous_headers.items():
                if header in headers:
                    result["information_disclosure"].append(
                        {
                            "header": header,
                            "value": headers[header][:100],
                            "description": desc,
                        }
                    )
                    result["score"] -= 3

            result["score"] = max(0, result["score"])

            if result["score"] >= 90:
                result["grade"] = "A"
            elif result["score"] >= 70:
                result["grade"] = "B"
            elif result["score"] >= 50:
                result["grade"] = "C"
            elif result["score"] >= 30:
                result["grade"] = "D"
            else:
                result["grade"] = "F"

            result["all_headers"] = {k: v[:100] for k, v in headers.items()}

        except Exception as e:
            result["error"] = str(e)

        return result


class ParameterDiscovery:
    """Discover URL parameters through fuzzing"""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

        self.common_params = [
            "id",
            "page",
            "action",
            "cmd",
            "command",
            "exec",
            "execute",
            "query",
            "search",
            "q",
            "s",
            "keyword",
            "keywords",
            "file",
            "filename",
            "path",
            "dir",
            "directory",
            "folder",
            "url",
            "uri",
            "link",
            "dest",
            "destination",
            "redirect",
            "next",
            "return",
            "returnUrl",
            "return_url",
            "continue",
            "view",
            "mode",
            "type",
            "format",
            "lang",
            "language",
            "locale",
            "debug",
            "test",
            "trace",
            "log",
            "logging",
            "admin",
            "config",
            "configuration",
            "setting",
            "settings",
            "user",
            "username",
            "login",
            "email",
            "password",
            "pass",
            "token",
            "key",
            "secret",
            "api_key",
            "apikey",
            "callback",
            "jsonp",
            "cb",
            "data",
            "input",
            "output",
            "result",
            "results",
            "sort",
            "order",
            "limit",
            "offset",
            "start",
            "end",
            "from",
            "to",
            "date",
            "time",
            "timestamp",
            "name",
            "title",
            "description",
            "content",
            "body",
            "message",
            "msg",
            "text",
            "value",
            "val",
            "option",
            "options",
            "param",
            "params",
            "include",
            "require",
            "load",
            "fetch",
            "download",
            "upload",
            "import",
            "export",
            "copy",
            "move",
            "delete",
            "remove",
            "update",
            "create",
            "method",
            "function",
            "func",
            "fn",
            "class",
            "module",
            "component",
            "plugin",
            "template",
            "theme",
            "style",
            "css",
            "js",
            "version",
            "v",
            "release",
            "build",
            "source",
            "target",
            "origin",
            "referrer",
            "ip",
            "host",
            "domain",
            "port",
            "proxy",
            "forward",
            "tunnel",
            "shell",
            "exec",
            "system",
            "passthru",
            "eval",
            "assert",
            "preg_replace",
            "inject",
            "payload",
            "exploit",
        ]

    async def test_parameter(self, url: str, param: str) -> Optional[Dict]:
        """Test if a parameter affects the response"""
        import aiohttp

        test_values = ["1", "test", "'\"", "<script>alert(1)</script>"]

        baseline_size = None
        reflections = []

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    params={param: "baseline"},
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    allow_redirects=False,
                    ssl=False,
                ) as resp:
                    baseline = await resp.text()
                    baseline_size = len(baseline)
                    baseline_status = resp.status

                for value in test_values:
                    async with session.get(
                        url,
                        params={param: value},
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        allow_redirects=False,
                        ssl=False,
                    ) as resp:
                        body = await resp.text()

                        if len(body) != baseline_size or resp.status != baseline_status:
                            reflections.append(
                                {
                                    "value": value,
                                    "status": resp.status,
                                    "size": len(body),
                                    "size_diff": abs(len(body) - baseline_size),
                                }
                            )

        except Exception:
            return None

        if reflections:
            return {
                "parameter": param,
                "url": url,
                "reflections": reflections,
                "interesting": any(
                    r["value"] in ["'<\"", "<script>alert(1)</script>"]
                    for r in reflections
                ),
            }

        return None

    async def discover(self, url: str, max_params: int = 100) -> List[Dict]:
        """Discover parameters on a URL"""
        semaphore = asyncio.Semaphore(30)

        async def test(param):
            async with semaphore:
                return await self.test_parameter(url, param)

        tasks = [test(p) for p in self.common_params[:max_params]]
        results = await asyncio.gather(*tasks)

        return [r for r in results if r is not None]


class ScreenshotCapture:
    """Capture screenshots of web services"""

    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    def capture(self, url: str, output_path: str) -> bool:
        """Capture screenshot using Playwright or fallback"""
        try:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.set_viewport_size({"width": 1280, "height": 720})
                page.goto(url, wait_until="networkidle", timeout=self.timeout * 1000)
                page.screenshot(path=output_path, full_page=True)
                browser.close()
                return True
        except ImportError:
            return self._capture_fallback(url, output_path)
        except Exception:
            return False

    def _capture_fallback(self, url: str, output_path: str) -> bool:
        """Fallback: save HTML instead"""
        try:
            import requests

            resp = requests.get(url, timeout=self.timeout, verify=False)
            with open(output_path.replace(".png", ".html"), "w") as f:
                f.write(resp.text)
            return True
        except Exception:
            return False


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python advanced_dns.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]

    dnssec = DNSSECWalker()
    print(f"\n=== DNSSEC Check for {domain} ===")
    dnssec_result = dnssec.check_dnssec(domain)
    print(f"DNSSEC Enabled: {dnssec_result['dnssec_enabled']}")
    print(f"Signed: {dnssec_result['signed']}")

    reverse = ReverseDNSEnumerator()
    print(f"\n=== Reverse DNS ===")
    try:
        ip = socket.gethostbyname(domain)
        ptr = reverse.reverse_lookup(ip)
        print(f"IP: {ip} -> PTR: {ptr}")
    except Exception as e:
        print(f"Error: {e}")
