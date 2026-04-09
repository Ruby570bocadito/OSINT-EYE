"""OSINT EYE - Burp Suite & Metasploit Export"""

import json
import xml.etree.ElementTree as ET
from xml.dom import minidom
from typing import Dict, List
from datetime import datetime


class BurpExporter:
    """Export scan results to Burp Suite XML format"""

    def export(self, results: Dict, filename: str = None) -> str:
        if not filename:
            target = results.get("target", "unknown")
            filename = f"burp_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"

        root = ET.Element("issues")

        modules = results.get("modules", {})

        self._add_web_issues(root, modules)
        self._add_cloud_issues(root, modules)
        self._add_cve_issues(root, modules)
        self._add_takeover_issues(root, modules)

        xml_str = minidom.parseString(
            ET.tostring(root, encoding="unicode")
        ).toprettyxml(indent="  ")

        with open(filename, "w") as f:
            f.write(xml_str)

        print(f"[+] Burp XML saved to: {filename}")
        return filename

    def _add_issue(self, root, name, severity, url, description, remediation):
        issue = ET.SubElement(root, "issue")
        ET.SubElement(issue, "name").text = name
        ET.SubElement(issue, "severity").text = severity
        ET.SubElement(issue, "host").text = url
        ET.SubElement(issue, "path").text = "/"
        ET.SubElement(issue, "type").text = "OSINT Finding"
        ET.SubElement(issue, "detail").text = description
        ET.SubElement(issue, "remediation").text = remediation
        ET.SubElement(issue, "references").text = "https://owasp.org/"

    def _add_web_issues(self, root, modules):
        web = modules.get("web", {})
        sensitive = web.get("endpoints", {}).get("sensitive", [])

        for s in sensitive:
            path = s.get("path", "")
            status = s.get("status", "")
            self._add_issue(
                root,
                f"Sensitive File Exposed: {path}",
                "High",
                modules.get("web", {}).get("technologies", {}).get("url", ""),
                f"The file {path} is publicly accessible (HTTP {status}). This may contain sensitive configuration or credentials.",
                f"Remove or restrict access to {path}. Implement proper authentication and authorization.",
            )

        techs = web.get("technologies", {}).get("technologies", [])
        if techs:
            self._add_issue(
                root,
                "Technology Stack Disclosure",
                "Information",
                modules.get("web", {}).get("technologies", {}).get("url", ""),
                f"The following technologies were identified: {', '.join(techs)}. This information can be used to target specific vulnerabilities.",
                "Remove or obfuscate technology-identifying headers (Server, X-Powered-By).",
            )

    def _add_cloud_issues(self, root, modules):
        buckets = modules.get("cloud_buckets", {}).get("public", [])
        for b in buckets:
            self._add_issue(
                root,
                f"Public Cloud Bucket: {b.get('url', '')}",
                "High",
                b.get("url", ""),
                f"A cloud storage bucket is publicly accessible. Provider: {b.get('provider', '')}. This may lead to data exposure.",
                "Restrict bucket access to authorized IPs and users. Enable bucket logging and monitoring.",
            )

    def _add_cve_issues(self, root, modules):
        for cve in modules.get("cve", {}).get("cves", [])[:10]:
            sev = cve.get("severity", [{}])[0] if cve.get("severity") else {}
            score = sev.get("score", 0)
            burp_severity = (
                "High" if score >= 7.0 else "Medium" if score >= 4.0 else "Low"
            )

            self._add_issue(
                root,
                f"Vulnerable Service: {cve.get('id', '')}",
                burp_severity,
                modules.get("network", {}).get("host", ""),
                f"CVSS {score}: {cve.get('description', '')[:200]}",
                f"Update the affected service to the latest version. Review {cve.get('id', '')} for patching guidance.",
            )

    def _add_takeover_issues(self, root, modules):
        for t in modules.get("takeover", {}).get("vulnerable", []):
            self._add_issue(
                root,
                f"Subdomain Takeover: {t.get('subdomain', '')}",
                "High",
                t.get("subdomain", ""),
                f"This subdomain is vulnerable to takeover on {t.get('service', '')}. Signature: {t.get('signature', '')}",
                "Remove the dangling DNS record or claim the resource on the cloud provider.",
            )


class MetasploitExporter:
    """Export scan results to Metasploit-compatible format"""

    def export(self, results: Dict, filename: str = None) -> str:
        if not filename:
            target = results.get("target", "unknown")
            filename = f"msf_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        msf_data = {
            "workspace": results.get("target", ""),
            "hosts": [],
            "services": [],
            "vulns": [],
            "notes": [],
        }

        network = results.get("modules", {}).get("network", {})
        host = network.get("host", results.get("target", ""))

        msf_data["hosts"].append(
            {
                "host": host,
                "address": host,
                "name": results.get("target", ""),
                "state": "alive",
                "os_name": "",
                "os_flavor": "",
                "os_sp": "",
                "purpose": "server",
                "info": f"Scanned by OSINT EYE on {results.get('scan_date', '')}",
            }
        )

        for svc in network.get("services", []):
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

        for cve in results.get("modules", {}).get("cve", {}).get("cves", []):
            sev = cve.get("severity", [{}])[0] if cve.get("severity") else {}
            msf_data["vulns"].append(
                {
                    "host": host,
                    "name": cve.get("id", ""),
                    "info": cve.get("description", "")[:200],
                    "refs": [cve.get("id", "")],
                    "severity": sev.get("severity", "normal"),
                }
            )

        subs = results.get("modules", {}).get("dns", {}).get("subdomains", [])
        if subs:
            msf_data["notes"].append(
                {
                    "host": host,
                    "type": "osint.subdomains",
                    "data": json.dumps(subs),
                }
            )

        emails = results.get("modules", {}).get("emails", {}).get("emails_found", [])
        if emails:
            msf_data["notes"].append(
                {
                    "host": host,
                    "type": "osint.emails",
                    "data": json.dumps(emails),
                }
            )

        with open(filename, "w") as f:
            json.dump(msf_data, f, indent=2)

        print(f"[+] Metasploit JSON saved to: {filename}")
        return filename


class ConfigProfiles:
    """Save and load scan configuration profiles"""

    def __init__(self, profiles_dir: str = None):
        import os

        if not profiles_dir:
            profiles_dir = os.path.expanduser("~/.osint_eye/profiles")
        os.makedirs(profiles_dir, exist_ok=True)
        self.profiles_dir = profiles_dir

    def save(self, name: str, config: Dict) -> str:
        path = f"{self.profiles_dir}/{name}.json"
        config["created_at"] = datetime.now().isoformat()
        with open(path, "w") as f:
            json.dump(config, f, indent=2)
        print(f"[+] Profile saved: {path}")
        return path

    def load(self, name: str) -> Dict:
        path = f"{self.profiles_dir}/{name}.json"
        with open(path) as f:
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

        path = f"{self.profiles_dir}/{name}.json"
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
