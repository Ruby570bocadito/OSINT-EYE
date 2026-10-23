"""OSINT EYE - Subdomain Monitoring Daemon"""

import asyncio
import json
import smtplib
from collections.abc import Callable
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any

from core.logging_config import get_logger
from core.session_cache import ScanCache
from modules.certs import CertScanner
from modules.dns import DNSScanner
from modules.dns.subdomain_permutator import SubdomainPermutator

logger = get_logger(__name__)

# Signature every alert channel must honour (alert_type, message, severity, data).
AlertHandler = Callable[[str, str, str, dict[str, Any]], None]


class AlertManager:
    """Send alerts via various channels"""

    def __init__(self) -> None:
        self.handlers: list[AlertHandler] = []

    def add_handler(self, handler: AlertHandler) -> None:
        self.handlers.append(handler)

    def send(
        self,
        alert_type: str,
        message: str,
        severity: str = "medium",
        data: dict[str, Any] | None = None,
    ) -> None:
        for handler in self.handlers:
            try:
                handler(alert_type, message, severity, data or {})
            except Exception as e:
                # A broken alert channel must never take the monitor down.
                logger.error(
                    "Alert handler %s failed: %s",
                    getattr(handler, "__name__", handler),
                    e,
                )

    @staticmethod
    def log_handler(
        alert_type: str, message: str, severity: str, data: dict[str, Any]
    ) -> None:
        logger.info("[ALERT] [%s] [%s] %s", severity.upper(), alert_type, message)

    @staticmethod
    def file_handler(logfile: str) -> AlertHandler:
        def handler(
            alert_type: str, message: str, severity: str, data: dict[str, Any]
        ) -> None:
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
    def email_handler(
        smtp_config: dict[str, Any], recipients: list[str]
    ) -> AlertHandler:
        def handler(
            alert_type: str, message: str, severity: str, data: dict[str, Any]
        ) -> None:
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
                    smtp_config["server"], smtp_config.get("port", 587), timeout=15
                )
                try:
                    server.starttls()
                    server.login(smtp_config["user"], smtp_config["password"])
                    server.send_message(msg)
                finally:
                    try:
                        server.quit()
                    except Exception:
                        pass
            except Exception as e:
                logger.error("Email alert failed: %s", e)

        return handler

    @staticmethod
    def webhook_handler(url: str) -> AlertHandler:
        from modules.web.ssrf_guard import is_safe_webhook_url

        if not is_safe_webhook_url(url):
            logger.error(
                "Webhook URL refused (https and public host required; "
                "private/metadata IPs are blocked): %s",
                url,
            )
            return lambda *args, **kwargs: None

        def handler(
            alert_type: str, message: str, severity: str, data: dict[str, Any]
        ) -> None:
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
            except Exception as e:
                logger.error("Webhook alert failed: %s", e)

        return handler


class SubdomainMonitor:
    """Monitor targets for subdomain changes"""

    def __init__(
        self, targets: list[str], check_interval: int = 3600, cache: bool = True
    ) -> None:
        self.targets = targets
        self.check_interval = check_interval
        self.alert_manager = AlertManager()
        self.alert_manager.add_handler(AlertManager.log_handler)
        self.scan_cache = ScanCache() if cache else None
        self.running = False
        self.dns_scanner = DNSScanner()
        self.permutator = SubdomainPermutator(threads=50)
        self.cert_scanner = CertScanner()  # type: ignore[no-untyped-call]  # modules/ aún sin tipar (type-hints-modules, fase 2 de PUL-2)
        self.baseline: dict[str, set[str]] = {}

    def set_baseline(self, target: str) -> None:
        """Establish baseline for a target"""
        subdomains: set[str] = set()

        if self.scan_cache:
            cached = self.scan_cache.get_subdomains(target)
            subdomains.update(s["subdomain"] for s in cached)

        self.baseline[target] = subdomains

    async def check_target(self, target: str) -> dict[str, Any]:
        """Check a single target for changes"""
        new_subdomains: set[str] = set()

        # Lazily build the baseline (from cache) so run_once() callers get a
        # meaningful diff too; previously a missing baseline re-alerted everything.
        if target not in self.baseline:
            self.set_baseline(target)

        # The scanners are blocking (requests/threads) - run them in worker
        # threads so the event loop (and stop()) stays responsive.
        try:
            dns_result = await asyncio.to_thread(self.dns_scanner.scan, target, "basic")
            new_subdomains.update(dns_result.get("subdomains") or [])
        except Exception as e:
            logger.warning("DNS check failed for %s: %s", target, e)

        try:
            cert_result = await asyncio.to_thread(self.cert_scanner.scan, target)
            new_subdomains.update(cert_result.get("subdomains") or [])
        except Exception as e:
            logger.warning("CT check failed for %s: %s", target, e)

        try:
            perm_result = await asyncio.to_thread(
                self.permutator.enumerate, target, list(new_subdomains)[:10]
            )
            new_subdomains.update(perm_result or [])
        except Exception as e:
            logger.warning("Permutation check failed for %s: %s", target, e)

        if self.scan_cache:
            for sub in new_subdomains:
                self.scan_cache.add_subdomain(target, sub, "monitor")

        baseline = self.baseline.get(target, set())
        discovered = new_subdomains - baseline

        if discovered:
            # Merge instead of replace so subs seen in prior cycles stay known.
            self.baseline[target] = set(baseline) | new_subdomains

        return {
            "target": target,
            "total_subdomains": len(new_subdomains),
            "new_subdomains": sorted(discovered),
            "timestamp": datetime.now().isoformat(),
        }

    async def check_all(self) -> list[dict[str, Any]]:
        """Check all targets"""
        results: list[dict[str, Any]] = []
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

    async def run_once(self) -> list[dict[str, Any]]:
        """Run a single check cycle"""
        return await self.check_all()

    async def run_daemon(self, max_cycles: int = 0) -> None:
        """Run as daemon (max_cycles=0 means run until stop() is called)"""
        self.running = True
        cycle = 0

        logger.info("Starting OSINT EYE Monitor")
        logger.info("Targets: %s", ", ".join(self.targets))
        logger.info("Check interval: %ss", self.check_interval)
        logger.info("Setting baselines...")

        for target in self.targets:
            self.set_baseline(target)
            logger.info(
                "  - %s: %d known subdomains", target, len(self.baseline[target])
            )

        logger.info("Monitoring started")

        while self.running:
            if max_cycles > 0 and cycle >= max_cycles:
                break

            cycle += 1
            logger.info("%s", "=" * 40)
            logger.info(
                "Check #%d - %s", cycle, datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )

            try:
                results = await self.check_all()
            except Exception as e:
                # A failing cycle (network outage, scanner bug) must not kill the daemon.
                logger.error("Check cycle #%d failed: %s", cycle, e)
                results = []

            for result in results:
                if result["new_subdomains"]:
                    logger.info(
                        "%s: %d new subdomains",
                        result["target"],
                        len(result["new_subdomains"]),
                    )
                    for sub in result["new_subdomains"][:10]:
                        logger.info("    + %s", sub)

            if self.running and (max_cycles == 0 or cycle < max_cycles):
                await self._interruptible_sleep(self.check_interval)

        logger.info("Monitor stopped after %d cycles", cycle)

    async def _interruptible_sleep(self, seconds: float) -> None:
        """Sleep in short slices so stop() is honoured promptly (no stale asyncio.sleep)."""
        step = 1.0
        slept = 0.0
        while self.running and slept < seconds:
            chunk = min(step, seconds - slept)
            await asyncio.sleep(chunk)
            slept += chunk

    def stop(self) -> None:
        self.running = False


class PassiveDNSDatabase:
    """Build a passive DNS database from scan results"""

    def __init__(self, db_path: str | None = None) -> None:
        if not db_path:
            db_dir = Path.home() / ".osint_eye" / "pdns"
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / "pdns.db")

        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
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

    def ingest_scan(self, results: dict[str, Any]) -> None:
        """Ingest scan results into passive DNS"""
        import sqlite3

        now = datetime.now().isoformat()
        modules = results.get("modules", {}) or {}
        if not isinstance(modules, dict):
            modules = {}

        records_to_insert: list[tuple[str, str, str, str]] = []

        dns = modules.get("dns") or {}
        if not isinstance(dns, dict):
            dns = {}

        for sub in dns.get("subdomains") or []:
            records_to_insert.append((sub, "A", "", results.get("target", "")))

        dns_records = dns.get("records") or {}
        if not isinstance(dns_records, dict):
            dns_records = {}
        for rtype, values in dns_records.items():
            if isinstance(values, str):
                values = [values]
            elif not isinstance(values, (list, tuple, set)):
                continue
            for value in values:
                records_to_insert.append(
                    (results.get("target", ""), rtype, value, results.get("target", ""))
                )

        certs = modules.get("certs") or {}
        if not isinstance(certs, dict):
            certs = {}
        for sub in certs.get("subdomains") or []:
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

    def lookup(
        self, query: str, record_type: str | None = None
    ) -> list[dict[str, Any]]:
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

    def reverse_lookup(self, value: str) -> list[dict[str, Any]]:
        """Find all queries that resolved to a value"""
        import sqlite3

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM pdns WHERE value = ? ORDER BY last_seen DESC",
                (value,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_stats(self) -> dict[str, Any]:
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
