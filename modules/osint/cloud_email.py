"""OSINT EYE - Cloud Bucket Discovery & Email Enumeration"""

import requests
import re
import socket
from typing import Dict, List, Set, Optional
from urllib.parse import urlparse
import concurrent.futures


class CloudBucketDetector:
    """Detect exposed cloud storage buckets (no API keys)"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        )

        self.bucket_patterns = {
            "aws_s3": [
                "https://{name}.s3.amazonaws.com",
                "https://s3.amazonaws.com/{name}",
                "https://{name}.s3.{region}.amazonaws.com",
            ],
            "gcp_storage": [
                "https://storage.googleapis.com/{name}",
                "https://storage.cloud.google.com/{name}",
            ],
            "azure_blob": [
                "https://{name}.blob.core.windows.net",
            ],
            "digitalocean_spaces": [
                "https://{name}.{region}.digitaloceanspaces.com",
            ],
        }

        self.regions = [
            "us-east-1",
            "us-west-1",
            "us-west-2",
            "eu-west-1",
            "eu-central-1",
            "ap-southeast-1",
            "ap-northeast-1",
            "sa-east-1",
        ]

        self.bucket_name_patterns = [
            "{domain}",
            "{domain}-assets",
            "{domain}-static",
            "{domain}-media",
            "{domain}-uploads",
            "{domain}-files",
            "{domain}-backups",
            "{domain}-data",
            "{domain}-public",
            "{domain}-private",
            "{domain}-dev",
            "{domain}-prod",
            "{domain}-staging",
            "{domain}-test",
            "{domain}-backup",
            "{domain}-logs",
            "{domain}-images",
            "{domain}-docs",
            "{domain}-config",
            "{domain}-db",
            "{domain}-storage",
            "{domain}-cdn",
            "{domain}-content",
            "{domain}-app",
            "assets-{domain}",
            "static-{domain}",
            "media-{domain}",
            "uploads-{domain}",
            "files-{domain}",
            "backups-{domain}",
            "{short_domain}",
            "{short_domain}-assets",
            "{short_domain}-static",
            "{short_domain}-media",
            "{short_domain}-uploads",
            "{short_domain}-backups",
        ]

    def _check_bucket(self, url: str, provider: str) -> Dict:
        """Check if a bucket exists and is accessible"""
        result = {
            "url": url,
            "provider": provider,
            "exists": False,
            "public": False,
            "listable": False,
            "status": None,
            "size": None,
        }

        try:
            response = self.session.get(url, timeout=self.timeout)
            result["status"] = response.status_code
            result["size"] = len(response.content)

            if response.status_code == 200:
                result["exists"] = True

                if "ListBucketResult" in response.text or "Contents" in response.text:
                    result["listable"] = True
                    result["public"] = True
                elif "<?xml" in response.text and "Error" in response.text:
                    result["exists"] = True
                    if "AccessDenied" in response.text:
                        result["public"] = False
                    elif "NoSuchBucket" in response.text:
                        result["exists"] = False
                else:
                    result["public"] = True

            elif response.status_code == 403:
                result["exists"] = True
                result["public"] = False
            elif response.status_code == 404:
                result["exists"] = False

        except Exception:
            pass

        return result

    def _generate_bucket_names(self, domain: str) -> List[str]:
        """Generate possible bucket names from domain"""
        names = set()

        parts = domain.split(".")
        short = parts[0] if len(parts) > 1 else domain

        for pattern in self.bucket_name_patterns:
            name = pattern.replace("{domain}", domain.replace(".", "-"))
            name = name.replace("{short_domain}", short)
            names.add(name)

        return list(names)

    def _generate_urls(self, bucket_name: str) -> List[tuple]:
        """Generate URLs for a bucket name"""
        urls = []

        for provider, patterns in self.bucket_patterns.items():
            for pattern in patterns:
                if "{region}" in pattern:
                    for region in self.regions[:3]:
                        url = pattern.replace("{name}", bucket_name).replace(
                            "{region}", region
                        )
                        urls.append((url, provider))
                else:
                    url = pattern.replace("{name}", bucket_name)
                    urls.append((url, provider))

        return urls

    def scan(self, domain: str, max_workers: int = 30) -> Dict:
        """Scan for exposed cloud buckets"""
        print(f"[*] Generating bucket names for {domain}...")
        bucket_names = self._generate_bucket_names(domain)

        all_urls = []
        for name in bucket_names:
            all_urls.extend(self._generate_urls(name))

        print(f"[*] Testing {len(all_urls)} bucket URLs...")

        results = {
            "domain": domain,
            "found": [],
            "public": [],
            "listable": [],
            "total_tested": 0,
        }

        def check_url(url_provider):
            url, provider = url_provider
            return self._check_bucket(url, provider)

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(check_url, url_provider): url_provider
                for url_provider in all_urls
            }

            for future in concurrent.futures.as_completed(futures):
                results["total_tested"] += 1
                result = future.result()

                if result["exists"]:
                    results["found"].append(result)
                    if result["public"]:
                        results["public"].append(result)
                    if result["listable"]:
                        results["listable"].append(result)

        return results


class EmailEnumerator:
    """Enumerate email addresses from public sources"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        )

        self.email_pattern = re.compile(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        )

        self.name_sources = [
            "https://www.google.com/search?q=site:{domain}+email",
            "https://www.google.com/search?q=site:{domain}+contact",
            'https://www.google.com/search?q=site:{domain}+"@{domain}"',
        ]

    def extract_from_web(self, domain: str) -> Set[str]:
        """Extract emails from web pages"""
        emails = set()

        urls_to_check = [
            f"https://{domain}",
            f"https://{domain}/about",
            f"https://{domain}/contact",
            f"https://{domain}/team",
            f"https://{domain}/careers",
            f"https://{domain}/privacy",
            f"https://{domain}/terms",
            f"https://www.{domain}/contact",
        ]

        for url in urls_to_check:
            try:
                response = self.session.get(url, timeout=self.timeout)
                found = self.email_pattern.findall(response.text)

                for email in found:
                    if email.endswith(domain):
                        emails.add(email.lower())

            except Exception:
                continue

        return emails

    def extract_from_whois(self, whois_data: Dict) -> Set[str]:
        """Extract emails from WHOIS data"""
        emails = set()

        if whois_data.get("emails"):
            for email in whois_data["emails"]:
                emails.add(email.lower())

        return emails

    def generate_emails(self, domain: str, names: List[str]) -> List[str]:
        """Generate possible email addresses from names"""
        emails = []

        formats = [
            "{first}.{last}@{domain}",
            "{first}{last}@{domain}",
            "{first}_{last}@{domain}",
            "{first}@{domain}",
            "{last}@{domain}",
            "{first[0]}{last}@{domain}",
            "{first}{last[0]}@{domain}",
            "{first}.{last[0]}@{domain}",
            "{first[0]}.{last}@{domain}",
        ]

        for name in names:
            parts = name.lower().split()
            if len(parts) >= 2:
                first, last = parts[0], parts[-1]
            elif len(parts) == 1:
                first = parts[0]
                last = parts[0]
            else:
                continue

            for fmt in formats:
                try:
                    email = fmt.format(first=first, last=last, domain=domain)
                    emails.append(email)
                except Exception:
                    continue

        return emails

    def verify_email(self, email: str) -> Dict:
        """Verify if an email might be valid (basic check)"""
        result = {
            "email": email,
            "format_valid": False,
            "domain_exists": False,
            "mx_records": False,
            "disposable": False,
        }

        if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
            return result

        result["format_valid"] = True

        domain = email.split("@")[1]

        disposable_domains = [
            "mailinator.com",
            "tempmail.com",
            "guerrillamail.com",
            "10minutemail.com",
            "throwaway.email",
            "yopmail.com",
        ]

        if domain in disposable_domains:
            result["disposable"] = True
            return result

        try:
            socket.gethostbyname(domain)
            result["domain_exists"] = True
        except Exception:
            pass

        try:
            import dns.resolver

            answers = dns.resolver.resolve(domain, "MX")
            result["mx_records"] = len(answers) > 0
        except Exception:
            pass

        return result

    def scan(self, domain: str, whois_data: Dict = None) -> Dict:
        """Full email enumeration scan"""
        print(f"[*] Enumerating emails for {domain}...")

        results = {
            "domain": domain,
            "emails_found": [],
            "generated_emails": [],
            "verified": [],
        }

        web_emails = self.extract_from_web(domain)
        results["emails_found"] = sorted(list(web_emails))

        if whois_data:
            whois_emails = self.extract_from_whois(whois_data)
            results["emails_found"] = sorted(list(web_emails | whois_emails))

        for email in results["emails_found"][:20]:
            verification = self.verify_email(email)
            results["verified"].append(verification)

        return results


class CDNDetector:
    """Detect CDN and WAF usage"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()

        self.cdn_headers = {
            "Cloudflare": [
                "cf-ray",
                "cf-cache-status",
                "cf-request-id",
                "cf-connecting-ip",
            ],
            "CloudFront": [
                "x-amz-cf-id",
                "x-amz-cf-pop",
                "x-cache: Hit from cloudfront",
            ],
            "Fastly": ["x-served-by", "x-cache", "x-timer", "fastly"],
            "Akamai": ["akamai-grn", "x-akamai-transformed", "x-true-ip"],
            "Incapsula": ["x-iinfo", "x-cdn", "incap_ses", "visid_incap"],
            "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
            "StackPath": ["x-sp-url", "x-sp-cdn"],
            "KeyCDN": ["x-keycdn-zone"],
            "BunnyCDN": ["x-bunny-cache", "x-bunnycdn"],
            "Vercel": ["x-vercel-id", "x-vercel-cache"],
            "Netlify": ["x-nf-request-id", "x-nf-cache"],
        }

        self.waf_indicators = {
            "Cloudflare": ["cloudflare", "cf-", "__cfduid"],
            "AWS WAF": ["aws.waf", "x-amzn-waf"],
            "Akamai WAF": ["akamai", "x-akamai"],
            "Imperva": ["imperva", "incap_", "visid_"],
            "F5 BIG-IP": ["BIGipServer", "F5"],
            "ModSecurity": ["ModSecurity", "mod_security"],
            "Barracuda": ["barra_counter_session", "BNI__BARRACUDA_LB_COOKIE"],
            "FortiWeb": ["FORTIWAFSID", "fortiwaf"],
            "DenyAll": ["sessioncookie="],
            "Sucuri WAF": ["sucuri", "x-sucuri"],
            "Wordfence": ["wordfence", "wfvt_"],
            "Comodo WAF": ["comodo"],
            "NSFocus": ["nsfocus"],
        }

    def detect(self, url: str) -> Dict:
        """Detect CDN and WAF"""
        result = {"url": url, "cdn": None, "waf": None, "headers": {}, "indicators": []}

        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)

            for header, value in response.headers.items():
                result["headers"][header] = value

            for cdn, headers in self.cdn_headers.items():
                for header in headers:
                    if header.lower() in [h.lower() for h in response.headers]:
                        result["cdn"] = cdn
                        result["indicators"].append(f"CDN: {cdn} (header: {header})")
                        break

            html = response.text.lower()
            for waf, indicators in self.waf_indicators.items():
                for indicator in indicators:
                    if indicator.lower() in html:
                        result["waf"] = waf
                        result["indicators"].append(
                            f"WAF: {waf} (indicator: {indicator})"
                        )
                        break

            if not result["cdn"] and not result["waf"]:
                result["indicators"].append("No CDN or WAF detected")

        except Exception as e:
            result["error"] = str(e)

        return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python cloud_scanner.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]

    bucket_detector = CloudBucketDetector()
    results = bucket_detector.scan(domain)

    print(f"\n=== Cloud Bucket Results ===")
    print(f"Found: {len(results['found'])} buckets")
    print(f"Public: {len(results['public'])} buckets")
    print(f"Listable: {len(results['listable'])} buckets")

    for bucket in results["found"]:
        print(f"  [{bucket['provider']}] {bucket['url']} - Public: {bucket['public']}")
