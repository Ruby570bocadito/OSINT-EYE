"""OSINT EYE - Burp Suite & Metasploit Export"""

import json
import re
import xml.etree.ElementTree as ET
from xml.dom import minidom
from typing import Dict, List
from datetime import datetime

# Control characters that are illegal in XML 1.0 content.
_XML_BAD_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _d(value) -> Dict:
    """Return value if dict else {} (defensive accessor for scan data)."""
    return value if isinstance(value, dict) else {}


def _l(value) -> List:
    """Return value if list else []."""
    return value if isinstance(value, list) else []


def _cve_sev(cve: Dict) -> Dict:
    """Normalise the many shapes a CVE 'severity' field can take."""
    sev = cve.get("severity")
    if isinstance(sev, list) and sev and isinstance(sev[0], dict):
        return sev[0]
    if isinstance(sev, dict):
        return sev
    return {}


def _xml_safe(text) -> str:
    """Coerce to str and strip characters illegal in XML 1.0 content."""
    if text is None:
        return ""
    return _XML_BAD_CHARS.sub("", str(text))


class BurpExporter:
    """Export scan results to Burp Suite-compatible XML format.

    The output is always well-formed XML (control characters stripped,
    values coerced to strings) so tools can parse it reliably.
    """

    def export(self, results: Dict, filename: str = None) -> str:
        results = _d(results)
        if not filename:
            target = results.get("target") or "unknown"
            filename = f"burp_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"

        root = ET.Element("issues")
        modules = _d(results.get("modules"))

        self._add_web_issues(root, modules)
        self._add_cloud_issues(root, modules)
        self._add_cve_issues(root, modules)
        self._add_takeover_issues(root, modules)

        xml_str = minidom.parseString(
            ET.tostring(root, encoding="unicode")
        ).toprettyxml(indent="  ", encoding=None)

        with open(filename, "w", encoding="utf-8") as f:
            f.write(xml_str)

        print(f"[+] Burp XML saved to: {filename}")
        return filename

    def _add_issue(self, root, name, severity, url, description, remediation):
        issue = ET.SubElement(root, "issue")
        ET.SubElement(issue, "name").text = _xml_safe(name)
        ET.SubElement(issue, "severity").text = _xml_safe(severity)
        ET.SubElement(issue, "host").text = _xml_safe(url)
        ET.SubElement(issue, "path").text = "/"
        ET.SubElement(issue, "type").text = "OSINT Finding"
        ET.SubElement(issue, "detail").text = _xml_safe(description)
        ET.SubElement(issue, "remediation").text = _xml_safe(remediation)
        ET.SubElement(issue, "references").text = "https://owasp.org/"

    def _add_web_issues(self, root, modules):
        web = _d(modules.get("web"))
        # osint_eye stores discovery in modules["endpoints"]; fall back to web
        endpoints = _d(modules.get("endpoints")) or _d(web.get("endpoints"))
        sensitive = _l(endpoints.get("sensitive"))
        web_url = _d(web.get("technologies")).get("url", "")

        for s in sensitive:
            s = _d(s)
            path = s.get("path", "")
            status = s.get("status", "")
            self._add_issue(
                root,
                f"Sensitive File Exposed: {path}",
                "High",
                web_url,
                f"The file {path} is publicly accessible (HTTP {status}). This may contain sensitive configuration or credentials.",
                f"Remove or restrict access to {path}. Implement proper authentication and authorization.",
            )

        techs = _l(_d(web.get("technologies")).get("technologies"))
        if techs:
            self._add_issue(
                root,
                "Technology Stack Disclosure",
                "Information",
                web_url,
                f"The following technologies were identified: {', '.join(str(t) for t in techs)}. This information can be used to target specific vulnerabilities.",
                "Remove or obfuscate technology-identifying headers (Server, X-Powered-By).",
            )

    def _add_cloud_issues(self, root, modules):
        buckets = _l(_d(modules.get("cloud_buckets")).get("public"))
        for b in buckets:
            b = _d(b)
            self._add_issue(
                root,
                f"Public Cloud Bucket: {b.get('url', '')}",
                "High",
                b.get("url", ""),
                f"A cloud storage bucket is publicly accessible. Provider: {b.get('provider', '')}. This may lead to data exposure.",
                "Restrict bucket access to authorized IPs and users. Enable bucket logging and monitoring.",
            )

    def _add_cve_issues(self, root, modules):
        for cve in _l(_d(modules.get("cve")).get("cves"))[:10]:
            cve = _d(cve)
            sev = _cve_sev(cve)
            try:
                score = float(sev.get("score", 0))
            except (TypeError, ValueError):
                score = 0.0
            burp_severity = (
                "High" if score >= 7.0 else "Medium" if score >= 4.0 else "Low"
            )

            self._add_issue(
                root,
                f"Vulnerable Service: {cve.get('id', '')}",
                burp_severity,
                _d(modules.get("network")).get("host", ""),
                f"CVSS {score:g}: {str(cve.get('description', ''))[:200]}",
                f"Update the affected service to the latest version. Review {cve.get('id', '')} for patching guidance.",
            )

    def _add_takeover_issues(self, root, modules):
        for t in _l(_d(modules.get("takeover")).get("vulnerable")):
            t = _d(t)
            self._add_issue(
                root,
                f"Subdomain Takeover: {t.get('subdomain', '')}",
                "High",
                t.get("subdomain", ""),
                f"This subdomain is vulnerable to takeover on {t.get('service', '')}. Signature: {t.get('signature', '')}",
                "Remove the dangling DNS record or claim the resource on the cloud provider.",
            )


class MetasploitExporter:
    """Export scan results to Metasploit-compatible JSON format."""

    def export(self, results: Dict, filename: str = None) -> str:
        results = _d(results)
        if not filename:
            target = results.get("target") or "unknown"
            filename = f"msf_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        msf_data = {
            "workspace": results.get("target") or "",
            "hosts": [],
            "services": [],
            "vulns": [],
            "notes": [],
        }

        network = _d(_d(results.get("modules")).get("network"))
        host = network.get("host") or results.get("target") or ""

        msf_data["hosts"].append(
            {
                "host": host,
                "address": host,
                "name": results.get("target") or "",
                "state": "alive",
                "os_name": "",
                "os_flavor": "",
                "os_sp": "",
                "purpose": "server",
                "info": f"Scanned by OSINT EYE on {results.get('scan_date') or ''}",
            }
        )

        for svc in _l(network.get("services")):
            svc = _d(svc)
            if svc.get("state") == "open":
                msf_data["services"].append(
                    {
                        "host": host,
                        "port": svc.get("port"),
                        "proto": svc.get("protocol", "tcp"),
                        "name": svc.get("service", ""),
                        "state": "open",
                        "info": svc.get("version", ""),
                    }
                )

        for cve in _l(_d(_d(results.get("modules")).get("cve")).get("cves")):
            cve = _d(cve)
            sev = _cve_sev(cve)
            msf_data["vulns"].append(
                {
                    "host": host,
                    "name": cve.get("id", ""),
                    "info": str(cve.get("description", ""))[:200],
                    "refs": [cve.get("id", "")],
                    "severity": sev.get("severity", "normal"),
                }
            )

        subs = _l(_d(_d(results.get("modules")).get("dns")).get("subdomains"))
        if subs:
            msf_data["notes"].append(
                {
                    "host": host,
                    "type": "osint.subdomains",
                    "data": json.dumps(subs, default=str),
                }
            )

        emails = _l(_d(_d(results.get("modules")).get("emails")).get("emails_found"))
        if emails:
            msf_data["notes"].append(
                {
                    "host": host,
                    "type": "osint.emails",
                    "data": json.dumps(emails, default=str),
                }
            )

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(msf_data, f, indent=2, default=str)

        print(f"[+] Metasploit JSON saved to: {filename}")
        return filename


class ConfigProfiles:
    """Save and load scan configuration profiles (JSON files on disk)."""

    def __init__(self, profiles_dir: str = None):
        import os

        if not profiles_dir:
            profiles_dir = os.path.expanduser("~/.osint_eye/profiles")
        os.makedirs(profiles_dir, exist_ok=True)
        self.profiles_dir = profiles_dir

    def save(self, name: str, config: Dict) -> str:
        import os

        path = os.path.join(self.profiles_dir, f"{name}.json")
        config = dict(config or {})
        config["created_at"] = datetime.now().isoformat()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, default=str)
        print(f"[+] Profile saved: {path}")
        return path

    def load(self, name: str) -> Dict:
        import os

        path = os.path.join(self.profiles_dir, f"{name}.json")
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def list_profiles(self) -> List[str]:
        import os

        profiles = []
        for f in os.listdir(self.profiles_dir):
            if f.endswith(".json"):
                profiles.append(f[:-5])
        return sorted(profiles)

    def delete(self, name: str):
        import os

        path = os.path.join(self.profiles_dir, f"{name}.json")
        if os.path.exists(path):
            os.remove(path)

    def get_default_profile(self) -> Dict:
        return {
            "depth": "normal",
            "stealth": False,
            "ai": True,
            "cache": True,
            "modules": [
                "dns",
                "certs",
                "wayback",
                "network",
                "whois",
                "cdn_waf",
                "web",
                "cve",
            ],
            "export": ["json", "markdown", "html", "csv"],
            "rate_limit": 0.0,
            "max_concurrent": 50,
        }

    def get_deep_profile(self) -> Dict:
        return {
            "depth": "deep",
            "stealth": False,
            "ai": True,
            "cache": True,
            "modules": [
                "dns",
                "certs",
                "wayback",
                "network",
                "whois",
                "cdn_waf",
                "web",
                "cve",
                "permutation",
                "takeover",
                "endpoints",
                "cloud",
                "emails",
            ],
            "export": ["json", "markdown", "html", "csv", "pdf", "burp", "metasploit"],
            "rate_limit": 0.0,
            "max_concurrent": 100,
        }

    def get_stealth_profile(self) -> Dict:
        return {
            "depth": "normal",
            "stealth": True,
            "ai": False,
            "cache": True,
            "modules": ["dns", "certs", "network", "cdn_waf"],
            "export": ["json", "markdown"],
            "rate_limit": 5.0,
            "max_concurrent": 5,
        }


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python export_tools.py <results.json> [burp|metasploit|both]")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        results = json.load(f)

    fmt = sys.argv[2] if len(sys.argv) > 2 else "both"

    if fmt in ("burp", "both"):
        BurpExporter().export(results)
    if fmt in ("metasploit", "both"):
        MetasploitExporter().export(results)
