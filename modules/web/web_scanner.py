"""OSINT EYE - Web Technology Detection & Endpoint Discovery"""

import requests
import re
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse
import concurrent.futures


class TechDetector:
    """Detect web technologies without API keys"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        )

        self.tech_signatures = {
            "headers": {
                "X-Powered-By": {
                    "PHP": "PHP",
                    "Express": "Node.js/Express",
                    "ASP.NET": "ASP.NET",
                    "Python": "Python",
                    "Ruby": "Ruby",
                    "Flask": "Flask",
                    "Django": "Django",
                    "Rails": "Ruby on Rails",
                    "Laravel": "Laravel",
                    "Symfony": "Symfony",
                    "Spring": "Spring Framework",
                    "Next.js": "Next.js",
                    "Nuxt": "Nuxt.js",
                    "Gatsby": "Gatsby",
                },
                "Server": {
                    "nginx": "Nginx",
                    "Apache": "Apache",
                    "IIS": "Microsoft IIS",
                    "lighttpd": "Lighttpd",
                    "Caddy": "Caddy",
                    "OpenResty": "OpenResty",
                    "CloudFront": "AWS CloudFront",
                    "cloudflare": "Cloudflare",
                    "AkamaiGHost": "Akamai",
                    "Varnish": "Varnish",
                    "Google Frontend": "Google Cloud",
                    "Microsoft-HTTPAPI": "Microsoft HTTPAPI",
                    "Tengine": "Tengine",
                },
                "X-AspNet-Version": "ASP.NET",
                "X-AspNetMvc-Version": "ASP.NET MVC",
                "X-Django": "Django",
                "X-Generator": {
                    "WordPress": "WordPress",
                    "Drupal": "Drupal",
                    "Joomla": "Joomla",
                    "Magento": "Magento",
                    "Ghost": "Ghost",
                    "Strapi": "Strapi",
                    "Contentful": "Contentful",
                },
                "X-Shopid": "Shopify",
                "X-Wix-Request-Id": "Wix",
                "X-Squarespace-Server": "Squarespace",
                "X-Tumblr-User": "Tumblr",
            },
            "html_patterns": {
                "WordPress": [r"wp-content", r"wp-includes", r"wp-json"],
                "Drupal": [r"drupalSettings", r"/sites/default/files", r"drupal.js"],
                "Joomla": [r"/media/system/js", r"joomla", r"com_content"],
                "Magento": [r"magento", r" Mage.", r" skin/frontend/"],
                "Shopify": [r"cdn\.shopify\.com", r"Shopify\."],
                "React": [r"react", r"react-dom", r"__react"],
                "Angular": [r"ng-app", r"ng-version", r"angular"],
                "Vue.js": [r"vue", r"__vue__", r"v-bind", r"v-for"],
                "jQuery": [r"jquery", r"jQuery"],
                "Bootstrap": [r"bootstrap", r"bootstrap\.css", r"bootstrap\.js"],
                "Tailwind": [r"tailwind", r"tailwind\.css"],
                "Font Awesome": [r"font-awesome", r"fontawesome"],
                "Google Analytics": [
                    r"googletagmanager\.com",
                    r"google-analytics\.com",
                    r"gtag",
                ],
                "Google Tag Manager": [r"googletagmanager\.com/gtm"],
                "Cloudflare": [r"cloudflare", r"cf-", r"__cfduid"],
                "reCAPTCHA": [r"recaptcha", r"g-recaptcha"],
                "Stripe": [r"stripe\.com", r"Stripe"],
                "PayPal": [r"paypal\.com", r"PayPal"],
                "Hotjar": [r"hotjar\.com"],
                "Intercom": [r"intercom\.io", r"Intercom"],
                "Zendesk": [r"zendesk\.com", r"Zendesk"],
                "Salesforce": [r"salesforce\.com", r"salesforce"],
                "HubSpot": [r"hubspot\.com", r"hs-"],
                "Mailchimp": [r"mailchimp\.com", r"mc-", r"mailchimp"],
                "Sentry": [r"sentry\.io", r"Sentry"],
                "New Relic": [r"newrelic\.com", r"newrelic"],
                "Datadog": [r"datadog\.com", r"dd-"],
                "Elastic APM": [r"elastic\.co", r"elastic-apm"],
            },
            "cookies": {
                "wordpress": "WordPress",
                "wp-settings": "WordPress",
                "PHPSESSID": "PHP",
                "JSESSIONID": "Java/Tomcat",
                "ASP.NET_SessionId": "ASP.NET",
                "connect.sid": "Node.js/Express",
                "cf_clearance": "Cloudflare",
                "cf_use_ob": "Cloudflare",
                "_shopify": "Shopify",
                "_shopify_s": "Shopify",
                "_fbp": "Facebook Pixel",
                "_ga": "Google Analytics",
                "_gid": "Google Analytics",
                "hubspotutk": "HubSpot",
                "intercom-id": "Intercom",
                "_zendesk": "Zendesk",
            },
            "paths": {
                "/wp-login.php": "WordPress",
                "/wp-admin/": "WordPress",
                "/wp-json/": "WordPress REST API",
                "/administrator/": "Joomla",
                "/user/login": "Drupal",
                "/admin/login": "Generic Admin",
                "/phpmyadmin/": "phpMyAdmin",
                "/server-status": "Apache Status",
                "/.env": "Environment File",
                "/robots.txt": "Robots File",
                "/sitemap.xml": "Sitemap",
                "/api/": "API Endpoint",
                "/graphql": "GraphQL",
                "/swagger.json": "Swagger/OpenAPI",
                "/swagger-ui/": "Swagger UI",
                "/actuator/": "Spring Boot Actuator",
                "/health": "Health Check",
                "/metrics": "Metrics Endpoint",
                "/debug/vars": "Go Debug",
                "/version": "Version Endpoint",
            },
        }

    def detect(self, url: str) -> Dict:
        """Detect technologies on a URL"""
        result = {
            "url": url,
            "technologies": set(),
            "headers": {},
            "cookies": {},
            "status_code": None,
            "response_time": None,
            "ssl_info": {},
            "redirects": [],
        }

        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)

            result["status_code"] = response.status_code
            result["response_time"] = response.elapsed.total_seconds()

            if response.history:
                result["redirects"] = [r.url for r in response.history]

            for header, value in response.headers.items():
                result["headers"][header] = value

                if header in self.tech_signatures["headers"]:
                    sig = self.tech_signatures["headers"][header]
                    if isinstance(sig, dict):
                        for pattern, tech in sig.items():
                            if pattern.lower() in value.lower():
                                result["technologies"].add(tech)
                    elif isinstance(sig, str):
                        result["technologies"].add(sig)

            for cookie_name in response.cookies:
                for pattern, tech in self.tech_signatures["cookies"].items():
                    if pattern.lower() in cookie_name.lower():
                        result["technologies"].add(tech)

            html = response.text.lower()
            for tech, patterns in self.tech_signatures["html_patterns"].items():
                for pattern in patterns:
                    if re.search(pattern.lower(), html):
                        result["technologies"].add(tech)
                        break

            result["technologies"] = sorted(list(result["technologies"]))

        except Exception as e:
            result["error"] = str(e)

        return result

    def detect_multiple(self, urls: List[str], max_workers: int = 10) -> List[Dict]:
        """Detect technologies on multiple URLs"""
        results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.detect, url): url for url in urls}

            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())

        return results


class EndpointDiscovery:
    """Discover web endpoints and paths"""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        )

        self.common_paths = [
            "/admin",
            "/admin/",
            "/admin/login",
            "/admin/dashboard",
            "/administrator",
            "/administrator/",
            "/wp-admin",
            "/wp-admin/",
            "/wp-login.php",
            "/login",
            "/login/",
            "/signin",
            "/auth",
            "/api",
            "/api/",
            "/api/v1",
            "/api/v2",
            "/api/v3",
            "/graphql",
            "/graphiql",
            "/swagger",
            "/swagger-ui",
            "/swagger-ui.html",
            "/swagger.json",
            "/docs",
            "/api-docs",
            "/redoc",
            "/actuator",
            "/actuator/health",
            "/actuator/env",
            "/actuator/beans",
            "/health",
            "/healthcheck",
            "/status",
            "/ping",
            "/metrics",
            "/prometheus",
            "/debug",
            "/debug/vars",
            "/version",
            "/info",
            "/config",
            "/configuration",
            "/phpmyadmin",
            "/phpMyAdmin",
            "/pma",
            "/.env",
            "/.git",
            "/.git/config",
            "/.gitignore",
            "/.htaccess",
            "/.htpasswd",
            "/robots.txt",
            "/sitemap.xml",
            "/sitemap_index.xml",
            "/crossdomain.xml",
            "/clientaccesspolicy.xml",
            "/backup",
            "/backup/",
            "/backups",
            "/bak",
            "/old",
            "/old/",
            "/temp",
            "/tmp",
            "/test",
            "/config.php",
            "/config.yml",
            "/config.json",
            "/settings.json",
            "/database.yml",
            "/wp-config.php",
            "/web.config",
            "/server-status",
            "/server-info",
            "/console",
            "/shell",
            "/terminal",
            "/manager",
            "/manager/html",
            "/manager/status",
            "/jenkins",
            "/hudson",
            "/solr",
            "/solr/",
            "/solr/admin",
            "/elasticsearch",
            "/kibana",
            "/dashboard",
            "/dashboard/",
            "/portal",
            "/portal/",
            "/myaccount",
            "/account",
            "/profile",
            "/register",
            "/signup",
            "/register/",
            "/forgot-password",
            "/reset",
            "/reset-password",
            "/upload",
            "/upload/",
            "/uploads",
            "/upload.php",
            "/download",
            "/download/",
            "/downloads",
            "/files",
            "/files/",
            "/file",
            "/images",
            "/img",
            "/css",
            "/js",
            "/static",
            "/assets",
            "/media",
            "/content",
            "/blog",
            "/blog/",
            "/news",
            "/news/",
            "/forum",
            "/forum/",
            "/forums",
            "/wiki",
            "/wiki/",
            "/kb",
            "/help",
            "/support",
            "/support/",
            "/contact",
            "/about",
            "/about/",
            "/team",
            "/careers",
            "/privacy",
            "/terms",
            "/tos",
            "/favicon.ico",
            "/robots.txt",
            "/humans.txt",
            "/.well-known/",
            "/.well-known/security.txt",
            "/security.txt",
            "/security",
            "/CHANGELOG.md",
            "/CHANGELOG",
            "/changelog.txt",
            "/README.md",
            "/README",
            "/readme.txt",
            "/LICENSE",
            "/LICENSE.md",
            "/license.txt",
            "/package.json",
            "/composer.json",
            "/Gemfile",
            "/requirements.txt",
            "/setup.py",
            "/Makefile",
            "/Dockerfile",
            "/docker-compose.yml",
            "/Vagrantfile",
            "/.travis.yml",
            "/.gitlab-ci.yml",
            "/Jenkinsfile",
            "/circle.yml",
            "/wp-content/",
            "/wp-includes/",
            "/xmlrpc.php",
            "/wp-json/wp/v2/",
            "/cgi-bin/",
            "/cgi-bin/test-cgi",
            "/scripts/",
            "/scripts/setup.php",
            "/test/",
            "/test.php",
            "/info.php",
            "/phpinfo.php",
            "/elmah.axd",
            "/trace.axd",
            "/web-console",
            "/jmx-console",
            "/invoker/",
            "/status",
            "/jboss",
            "/manager/",
            "/host-manager/",
            "/adminer",
            "/adminer.php",
            "/dbadmin",
            "/myadmin",
            "/couchdb",
            "/_utils/",
            "/redis",
            "/memcached",
            "/rabbitmq",
            "/management/",
            "/kafka",
            "/zookeeper",
        ]

        self.sensitive_paths = [
            "/.env",
            "/.env.local",
            "/.env.production",
            "/.env.staging",
            "/.env.development",
            "/.env.test",
            "/.git/config",
            "/.git/HEAD",
            "/.gitignore",
            "/.svn/entries",
            "/.svn/wc.db",
            "/.DS_Store",
            "/.htaccess",
            "/.htpasswd",
            "/wp-config.php",
            "/wp-config.php.bak",
            "/config.php",
            "/config.php.bak",
            "/config.yml",
            "/config.json",
            "/config.yaml",
            "/config.xml",
            "/database.yml",
            "/database.json",
            "/secrets.json",
            "/credentials.json",
            "/id_rsa",
            "/id_dsa",
            "/id_ecdsa",
            "/id_rsa.pub",
            "/authorized_keys",
            "/etc/passwd",
            "/etc/shadow",
            "/proc/self/environ",
            "/proc/version",
            "/server-status",
            "/server-info",
            "/phpinfo.php",
            "/info.php",
            "/test.php",
            "/debug.php",
            "/phpmyadmin/",
            "/pma/",
            "/backup.sql",
            "/backup.zip",
            "/backup.tar.gz",
            "/dump.sql",
            "/dump.sql.gz",
            "/database.sql",
            "/db.sql",
            "/db_backup.sql",
            "/web.config",
            "/web.config.bak",
            "/appsettings.json",
            "/appsettings.Production.json",
            "/aws-credentials.json",
            "/.aws/credentials",
            "/.kube/config",
            "/kubeconfig",
            "/terraform.tfstate",
            "/terraform.tfvars",
            "/.terraform/",
            "/.terraform.tfstate.lock.info",
            "/docker-compose.yml",
            "/Dockerfile",
            "/Jenkinsfile",
            "/.jenkins/",
            "/.ssh/",
            "/.ssh/authorized_keys",
            "/.bash_history",
            "/.bashrc",
            "/.profile",
            "/.npmrc",
            "/.yarnrc",
            "/.pypirc",
            "/.pip/pip.conf",
            "/.docker/config.json",
            "/.config/gcloud/credentials.db",
        ]

    def discover(
        self, base_url: str, paths: List[str] = None, max_workers: int = 20
    ) -> Dict:
        """Discover endpoints on a target"""
        if not base_url.endswith("/"):
            base_url += "/"

        target_paths = paths or self.common_paths

        results = {
            "base_url": base_url,
            "found": [],
            "not_found": [],
            "errors": [],
            "total_tested": 0,
        }

        def check_path(path):
            url = urljoin(base_url, path.lstrip("/"))
            try:
                resp = self.session.get(
                    url, timeout=self.timeout, allow_redirects=False
                )

                status = resp.status_code

                if status in [200, 301, 302, 401, 403, 405, 500]:
                    return {
                        "url": url,
                        "path": path,
                        "status": status,
                        "size": len(resp.content),
                        "content_type": resp.headers.get("Content-Type", ""),
                        "redirect": resp.headers.get("Location", "")
                        if status in [301, 302]
                        else None,
                    }
            except Exception as e:
                return {"url": url, "path": path, "error": str(e)}

            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(check_path, path): path for path in target_paths}

            for future in concurrent.futures.as_completed(futures):
                results["total_tested"] += 1
                result = future.result()

                if result:
                    if "error" in result:
                        results["errors"].append(result)
                    elif result.get("status"):
                        results["found"].append(result)

        results["found"].sort(key=lambda x: x.get("status", 0))

        return results

    def discover_sensitive(self, base_url: str) -> Dict:
        """Discover sensitive files"""
        return self.discover(base_url, self.sensitive_paths)

    def discover_apis(self, base_url: str) -> Dict:
        """Discover API endpoints"""
        api_paths = [
            "/api",
            "/api/",
            "/api/v1",
            "/api/v1/",
            "/api/v2",
            "/api/v2/",
            "/api/v3",
            "/api/v3/",
            "/graphql",
            "/graphiql",
            "/swagger",
            "/swagger-ui",
            "/swagger-ui.html",
            "/swagger.json",
            "/api-docs",
            "/openapi.json",
            "/rest",
            "/rest/",
            "/rest/api",
            "/actuator",
            "/actuator/health",
            "/actuator/env",
            "/health",
            "/health/",
            "/status",
            "/status/",
            "/metrics",
            "/metrics/",
            "/prometheus",
            "/debug",
            "/debug/",
            "/debug/vars",
            "/version",
            "/version/",
            "/info",
            "/info/",
            "/config",
            "/config/",
            "/configuration",
            "/admin/api",
            "/api/admin",
            "/oauth/token",
            "/oauth/authorize",
            "/auth",
            "/auth/",
            "/auth/login",
            "/token",
            "/token/",
            "/jwt",
            "/graphql",
            "/playground",
            "/altair",
        ]

        return self.discover(base_url, api_paths)


class SensitiveDataDetector:
    """Detect sensitive data in responses"""

    def __init__(self):
        self.patterns = {
            "api_key": r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
            "aws_key": r"(?i)(AKIA[0-9A-Z]{16})",
            "aws_secret": r'(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?',
            "private_key": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "jwt_token": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "password": r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\']{8,})["\']?',
            "token": r'(?i)(token|auth[_-]?token|access[_-]?token)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
            "connection_string": r'(?i)(mysql|postgres|mongodb|redis)://[^\s"\']+',
            "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
            "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
            "phone": r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b",
            "github_token": r"ghp_[a-zA-Z0-9]{36}",
            "slack_token": r"xox[baprs]-[a-zA-Z0-9-]+",
            "slack_webhook": r"https://hooks\.slack\.com/services/[a-zA-Z0-9/]+",
            "google_api": r"AIza[0-9A-Za-z_-]{35}",
            "firebase": r"(?i)firebase[_-]?config|firebase[_-]?app",
            "heroku_key": r"(?i)heroku[_-]?api[_-]?key",
            "mailgun": r"key-[a-zA-Z0-9]{32}",
            "sendgrid": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
            "twilio": r"(?i)twilio[_-]?account[_-]?sid",
            "stripe": r"(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{24,}",
            "base64_encoded": r'(?i)(?:password|secret|key|token)\s*[:=]\s*["\']?[A-Za-z0-9+/]{20,}={0,2}["\']?',
        }

    def scan_content(self, content: str) -> Dict[str, List[str]]:
        """Scan content for sensitive data patterns"""
        findings = {}

        for pattern_name, pattern in self.patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                cleaned = []
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    cleaned.append(match)

                findings[pattern_name] = list(set(cleaned))[:20]

        return findings

    def scan_url(self, url: str) -> Dict:
        """Scan a URL for sensitive data"""
        result = {"url": url, "findings": {}, "status_code": None, "content_length": 0}

        try:
            session = requests.Session()
            session.headers.update(
                {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                }
            )

            response = session.get(url, timeout=10)
            result["status_code"] = response.status_code
            result["content_length"] = len(response.content)

            result["findings"] = self.scan_content(response.text)

        except Exception as e:
            result["error"] = str(e)

        return result


class WebScanner:
    """Main web scanning orchestrator"""

    def __init__(self):
        self.tech_detector = TechDetector()
        self.endpoint_discovery = EndpointDiscovery()
        self.sensitive_detector = SensitiveDataDetector()

    def scan(self, target: str) -> Dict:
        """Full web scan"""
        if not target.startswith("http"):
            target = f"https://{target}"

        results = {
            "target": target,
            "technologies": {},
            "endpoints": {},
            "sensitive_data": {},
        }

        print(f"[*] Detecting technologies on {target}...")
        results["technologies"] = self.tech_detector.detect(target)

        print(f"[*] Discovering API endpoints...")
        results["endpoints"]["apis"] = self.endpoint_discovery.discover_apis(target)

        print(f"[*] Scanning for sensitive data...")
        results["sensitive_data"] = self.sensitive_detector.scan_url(target)

        return results


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python web_scanner.py <url>")
        sys.exit(1)

    scanner = WebScanner()
    results = scanner.scan(sys.argv[1])

    print(f"\n=== Web Scan Results ===")

    tech = results["technologies"]
    if tech.get("technologies"):
        print(f"\n[Technologies] {', '.join(tech['technologies'])}")

    endpoints = results["endpoints"].get("apis", {})
    if endpoints.get("found"):
        print(f"\n[API Endpoints Found: {len(endpoints['found'])}]")
        for ep in endpoints["found"][:10]:
            print(f"  [{ep['status']}] {ep['path']}")

    sensitive = results["sensitive_data"]
    if sensitive.get("findings"):
        print(f"\n[Sensitive Data]")
        for category, items in sensitive["findings"].items():
            print(f"  {category}: {len(items)} found")
