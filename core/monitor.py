"""OSINT EYE - Subdomain Monitoring Daemon"""

import asyncio
import time
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Dict, List, Callable, Optional
from pathlib import Path

from modules.dns import DNSScanner
from modules.dns.subdomain_permutator import SubdomainPermutator
from modules.certs import CertScanner
from core.session_cache import ScanCache


class AlertManager:
    """Send alerts via various channels"""

    def __init__(self):
        self.handlers = []

    def add_handler(self, handler: Callable):
        self.handlers.append(handler)

    def send(
        self, alert_type: str, message: str, severity: str = "medium", data: Dict = None
    ):
        for handler in self.handlers:
            try:
                handler(alert_type, message, severity, data or {})
            except Exception:
                pass

    @staticmethod
    def log_handler(alert_type, message, severity, data):
        timestamp = datetime.now().isoformat()
        print(f"[ALERT] [{severity.upper()}] [{alert_type}] {message}")

    @staticmethod
    def file_handler(logfile: str):
        def handler(alert_type, message, severity, data):
            timestamp = datetime.now().isoformat()
            entry = json.dumps(
                {
                    "timestamp": timestamp,
                    "type": alert_type,
                    "severity": severity,
                    "message": message,
                    "data": data,
                }
            )
            with open(logfile, "a") as f:
                f.write(entry + "\n")

        return handler

    @staticmethod
    def email_handler(smtp_config: Dict, recipients: List[str]):
        def handler(alert_type, message, severity, data):
            try:
                msg = MIMEMultipart()
                msg["From"] = smtp_config["from"]
                msg["To"] = ", ".join(recipients)
                msg["Subject"] = f"[OSINT EYE] [{severity.upper()}] {alert_type}"

                body = f"""
OSINT EYE Alert

Type: {alert_type}
Severity: {severity}
Time: {datetime.now().isoformat()}

{message}

Data: {json.dumps(data, indent=2)}
                """
                msg.attach(MIMEText(body, "plain"))

                server = smtplib.SMTP(
                    smtp_config["server"], smtp_config.get("port", 587)
                )
                server.starttls()
                server.login(smtp_config["user"], smtp_config["password"])
                server.send_message(msg)
                server.quit()
            except Exception:
                pass

        return handler

    @staticmethod
    def webhook_handler(url: str):
        def handler(alert_type, message, severity, data):
            try:
                import requests

                requests.post(
                    url,
                    json={
                        "type": alert_type,
                        "severity": severity,
                        "message": message,
                        "data": data,
                        "timestamp": datetime.now().isoformat(),
                    },
                    timeout=10,
                )
            except Exception:
                pass

        return handler


class SubdomainMonitor:
    """Monitor targets for subdomain changes"""

    def __init__(
        self, targets: List[str], check_interval: int = 3600, cache: bool = True
    ):
        self.targets = targets
        self.check_interval = check_interval
        self.alert_manager = AlertManager()
        self.alert_manager.add_handler(AlertManager.log_handler)
        self.scan_cache = ScanCache() if cache else None
        self.running = False
        self.dns_scanner = DNSScanner()
        self.permutator = SubdomainPermutator(threads=50)
        self.cert_scanner = CertScanner()
        self.baseline = {}

    def set_baseline(self, target: str):
        """Establish baseline for a target"""
        subdomains = set()

        if self.scan_cache:
            cached = self.scan_cache.get_subdomains(target)
            subdomains.update(s["subdomain"] for s in cached)

        self.baseline[target] = subdomains

    async def check_target(self, target: str) -> Dict:
        """Check a single target for changes"""
        new_subdomains = set()

        try:
            dns_result = self.dns_scanner.scan(target, "basic")
            new_subdomains.update(dns_result.get("subdomains", []))
        except Exception:
            pass

        try:
            cert_result = self.cert_scanner.scan(target)
            new_subdomains.update(cert_result.get("subdomains", []))
        except Exception:
            pass

        try:
            perm_result = self.permutator.enumerate(target, list(new_subdomains)[:10])
            new_subdomains.update(perm_result)
        except Exception:
            pass

        if self.scan_cache:
            for sub in new_subdomains:
                self.scan_cache.add_subdomain(target, sub, "monitor")

        baseline = self.baseline.get(target, set())
        discovered = new_subdomains - baseline

        if discovered:
            self.baseline[target] = new_subdomains

        return {
            "target": target,
            "total_subdomains": len(new_subdomains),
            "new_subdomains": sorted(list(discovered)),
            "timestamp": datetime.now().isoformat(),
        }

    async def check_all(self) -> List[Dict]:
        """Check all targets"""
        results = []
        for target in self.targets:
            result = await self.check_target(target)
            if result["new_subdomains"]:
                self.alert_manager.send(
                    "new_subdomains",
                    f"Found {len(result['new_subdomains'])} new subdomains for {target}",
                    "high",
                    {"new": result["new_subdomains"], "target": target},
                )
            results.append(result)
        return results

    async def run_once(self) -> List[Dict]:
        """Run a single check cycle"""
        return await self.check_all()

    async def run_daemon(self, max_cycles: int = 0):
        """Run as daemon"""
        self.running = True
        cycle = 0

        print(f"[*] Starting OSINT EYE Monitor")
        print(f"[*] Targets: {', '.join(self.targets)}")
        print(f"[*] Check interval: {self.check_interval}s")
        print(f"[*] Setting baselines...")

        for target in self.targets:
            self.set_baseline(target)
            print(f"  - {target}: {len(self.baseline[target])} known subdomains")

        print(f"[*] Monitoring started")

        while self.running:
            if max_cycles > 0 and cycle >= max_cycles:
                break

            cycle += 1
            print(f"\n[{'=' * 40}]")
            print(
                f"[*] Check #{cycle} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )

            results = await self.check_all()

            for result in results:
                if result["new_subdomains"]:
                    print(
                        f"\n[+] {result['target']}: {len(result['new_subdomains'])} new subdomains"
                    )
                    for sub in result["new_subdomains"][:10]:
                        print(f"    + {sub}")

            if self.running and (max_cycles == 0 or cycle < max_cycles):
                await asyncio.sleep(self.check_interval)

        print(f"\n[*] Monitor stopped after {cycle} cycles")

    def stop(self):
        self.running = False


class PassiveDNSDatabase:
    """Build a passive DNS database from scan results"""

    def __init__(self, db_path: str = None):
        if not db_path:
            db_dir = Path.home() / ".osint_eye" / "pdns"
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / "pdns.db")

        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        import sqlite3

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS pdns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    query TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    target TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    count INTEGER DEFAULT 1,
                    UNIQUE(query, record_type, value)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pdns_query ON pdns(query)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pdns_value ON pdns(value)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pdns_target ON pdns(target)")

    def ingest_scan(self, results: Dict):
        """Ingest scan results into passive DNS"""
        import sqlite3

        now = datetime.now().isoformat()
        modules = results.get("modules", {})

        records_to_insert = []

        dns = modules.get("dns", {})
        for sub in dns.get("subdomains", []):
            records_to_insert.append((sub, "A", "", results.get("target", "")))

        for rtype, values in dns.get("records", {}).items():
            for value in values:
                records_to_insert.append(
                    (results.get("target", ""), rtype, value, results.get("target", ""))
                )

        certs = modules.get("certs", {})
        for sub in certs.get("subdomains", []):
            records_to_insert.append((sub, "CT", "", results.get("target", "")))

        with sqlite3.connect(self.db_path) as conn:
            for query, rtype, value, target in records_to_insert:
                conn.execute(
                    """INSERT INTO pdns (query, record_type, value, target, first_seen, last_seen, count)
                       VALUES (?, ?, ?, ?, ?, ?, 1)
                       ON CONFLICT(query, record_type, value)
                       DO UPDATE SET last_seen = ?, count = count + 1""",
                    (query, rtype, value, target, now, now, now),
                )

    def lookup(self, query: str, record_type: str = None) -> List[Dict]:
        """Look up passive DNS records"""
        import sqlite3

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            if record_type:
                cursor = conn.execute(
                    "SELECT * FROM pdns WHERE query = ? AND record_type = ? ORDER BY last_seen DESC",
                    (query, record_type),
                )
            else:
                cursor = conn.execute(
                    "SELECT * FROM pdns WHERE query = ? ORDER BY last_seen DESC",
                    (query,),
                )

            return [dict(row) for row in cursor.fetchall()]

    def reverse_lookup(self, value: str) -> List[Dict]:
        """Find all queries that resolved to a value"""
        import sqlite3

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM pdns WHERE value = ? ORDER BY last_seen DESC",
                (value,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_stats(self) -> Dict:
        """Get database statistics"""
        import sqlite3

        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM pdns").fetchone()[0]
            unique_queries = conn.execute(
                "SELECT COUNT(DISTINCT query) FROM pdns"
            ).fetchone()[0]
            unique_values = conn.execute(
                "SELECT COUNT(DISTINCT value) FROM pdns"
            ).fetchone()[0]
            targets = conn.execute(
                "SELECT COUNT(DISTINCT target) FROM pdns"
            ).fetchone()[0]

            return {
                "total_records": total,
                "unique_queries": unique_queries,
                "unique_values": unique_values,
                "targets": targets,
            }


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python monitor.py <target> [interval_seconds]")
        sys.exit(1)

    target = sys.argv[1]
    interval = int(sys.argv[2]) if len(sys.argv) > 2 else 3600

    monitor = SubdomainMonitor([target], check_interval=interval)

    try:
        asyncio.run(monitor.run_daemon(max_cycles=5))
    except KeyboardInterrupt:
        monitor.stop()
        print("\n[*] Monitor stopped")
