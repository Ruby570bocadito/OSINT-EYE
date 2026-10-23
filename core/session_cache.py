"""OSINT EYE - SQLite Cache & Session Manager"""

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path


class ScanCache:
    """SQLite-based cache for scan results"""

    def __init__(self, db_path: str = None):
        if not db_path:
            cache_dir = Path.home() / ".osint_eye" / "cache"
            cache_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(cache_dir / "scan_cache.db")

        self.db_path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        """Open a connection with a generous busy timeout.

        Multiple worker threads write to the cache concurrently (scan phases),
        so the default 5s busy timeout is too tight under load.
        """
        return sqlite3.connect(self.db_path, timeout=30)

    def _init_db(self):
        """Initialize database tables"""
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    depth TEXT DEFAULT 'normal',
                    results TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS subdomains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    subdomain TEXT NOT NULL,
                    source TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    ip TEXT,
                    UNIQUE(target, subdomain, source)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT DEFAULT 'tcp',
                    service TEXT,
                    version TEXT,
                    state TEXT DEFAULT 'open',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    UNIQUE(target, host, port, protocol)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS http_responses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL UNIQUE,
                    status_code INTEGER,
                    content_hash TEXT,
                    content_length INTEGER,
                    headers TEXT,
                    technologies TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_subdomains_target ON subdomains(target)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_ports_target ON ports(target)
            """)

    def save_scan(
        self, target: str, scan_type: str, results: dict, depth: str = "normal"
    ):
        """Save a complete scan result"""
        def _json_fallback(obj):
            if isinstance(obj, set):
                return list(obj)
            return str(obj)

        with self._connect() as conn:
            conn.execute(
                """INSERT INTO scans (target, scan_type, timestamp, depth, results)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    target,
                    scan_type,
                    datetime.now().isoformat(),
                    depth,
                    json.dumps(results, default=_json_fallback),
                ),
            )

    def get_last_scan(self, target: str, max_age_hours: int = 24) -> dict | None:
        """Get the most recent scan if within age limit"""
        cutoff = (datetime.now() - timedelta(hours=max_age_hours)).isoformat()

        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """SELECT * FROM scans WHERE target = ? AND timestamp > ?
                   ORDER BY timestamp DESC LIMIT 1""",
                (target, cutoff),
            )
            row = cursor.fetchone()

            if row:
                results = self._parse_results(row["results"])
                return {
                    "timestamp": row["timestamp"],
                    "depth": row["depth"],
                    "results": results,
                }
        return None

    @staticmethod
    def _parse_results(raw: str) -> dict:
        """Deserialize the results column defensively.

        The cache file lives on disk and can be manipulated: treat anything
        that is not a JSON object as a cache miss (empty dict) so a tampered
        or corrupt row never injects a non-dict into consumers.
        """
        try:
            results = json.loads(raw) if raw else {}
        except (TypeError, ValueError, RecursionError):
            return {}
        if not isinstance(results, dict):
            return {}
        return results

    def add_subdomain(self, target: str, subdomain: str, source: str, ip: str = None):
        """Add or update a subdomain"""
        now = datetime.now().isoformat()

        with self._connect() as conn:
            conn.execute(
                """INSERT INTO subdomains (target, subdomain, source, first_seen, last_seen, ip)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(target, subdomain, source)
                   DO UPDATE SET last_seen = ?, ip = ?""",
                (target, subdomain, source, now, now, ip, now, ip),
            )

    def get_subdomains(self, target: str, source: str = None) -> list[dict]:
        """Get all known subdomains for a target"""
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row

            if source:
                cursor = conn.execute(
                    """SELECT * FROM subdomains WHERE target = ? AND source = ?
                       ORDER BY last_seen DESC""",
                    (target, source),
                )
            else:
                cursor = conn.execute(
                    """SELECT * FROM subdomains WHERE target = ?
                       ORDER BY last_seen DESC""",
                    (target,),
                )

            return [dict(row) for row in cursor.fetchall()]

    def get_new_subdomains(self, target: str, since: str) -> list[str]:
        """Get subdomains discovered since a timestamp"""
        with self._connect() as conn:
            cursor = conn.execute(
                """SELECT DISTINCT subdomain FROM subdomains
                   WHERE target = ? AND first_seen > ?""",
                (target, since),
            )
            return [row[0] for row in cursor.fetchall()]

    def add_port(
        self,
        target: str,
        host: str,
        port: int,
        service: str = None,
        version: str = None,
        protocol: str = "tcp",
    ):
        """Add or update a port"""
        now = datetime.now().isoformat()

        with self._connect() as conn:
            conn.execute(
                """INSERT INTO ports (target, host, port, protocol, service, version, state, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?)
                   ON CONFLICT(target, host, port, protocol)
                   DO UPDATE SET last_seen = ?, service = ?, version = ?""",
                (
                    target,
                    host,
                    port,
                    protocol,
                    service,
                    version,
                    now,
                    now,
                    now,
                    service,
                    version,
                ),
            )

    def get_ports(self, target: str) -> list[dict]:
        """Get all known ports for a target"""
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """SELECT * FROM ports WHERE target = ? ORDER BY port""",
                (target,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_diff(self, target: str, since: str) -> dict:
        """Get changes since last scan"""
        diff = {
            "new_subdomains": self.get_new_subdomains(target, since),
            "new_ports": [],
            "changes": [],
        }

        with self._connect() as conn:
            cursor = conn.execute(
                """SELECT * FROM ports WHERE target = ? AND first_seen > ?""",
                (target, since),
            )
            diff["new_ports"] = [dict(row) for row in cursor.fetchall()]

        return diff

    def get_stats(self, target: str) -> dict:
        """Get cache statistics for a target"""
        with self._connect() as conn:
            sub_count = conn.execute(
                "SELECT COUNT(DISTINCT subdomain) FROM subdomains WHERE target = ?",
                (target,),
            ).fetchone()[0]

            port_count = conn.execute(
                "SELECT COUNT(DISTINCT host || ':' || port) FROM ports WHERE target = ?",
                (target,),
            ).fetchone()[0]

            scan_count = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE target = ?",
                (target,),
            ).fetchone()[0]

            last_scan = conn.execute(
                "SELECT MAX(timestamp) FROM scans WHERE target = ?",
                (target,),
            ).fetchone()[0]

            sources = conn.execute(
                "SELECT DISTINCT source FROM subdomains WHERE target = ?",
                (target,),
            ).fetchall()

            return {
                "total_subdomains": sub_count,
                "total_ports": port_count,
                "total_scans": scan_count,
                "last_scan": last_scan,
                "sources": [r[0] for r in sources],
            }

    def cleanup(self, max_age_days: int = 90):
        """Remove old entries"""
        cutoff = (datetime.now() - timedelta(days=max_age_days)).isoformat()

        with self._connect() as conn:
            conn.execute("DELETE FROM scans WHERE timestamp < ?", (cutoff,))
            conn.execute("DELETE FROM subdomains WHERE last_seen < ?", (cutoff,))
            conn.execute("DELETE FROM ports WHERE last_seen < ?", (cutoff,))
            conn.execute(
                "DELETE FROM http_responses WHERE last_seen < ?", (cutoff,)
            )


class SessionManager:
    """Manage scan sessions with incremental updates"""

    def __init__(self, cache: ScanCache = None):
        self.cache = cache or ScanCache()
        self.active_sessions = {}

    def start_session(self, target: str, depth: str = "normal") -> dict:
        """Start a new scan session"""
        session_id = hashlib.md5(
            f"{target}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:12]

        last_scan = self.cache.get_last_scan(target, max_age_hours=24)

        session = {
            "id": session_id,
            "target": target,
            "depth": depth,
            "started_at": datetime.now().isoformat(),
            "last_scan": last_scan,
            "is_incremental": last_scan is not None,
            "known_subdomains": [],
            "known_ports": [],
        }

        if last_scan:
            session["known_subdomains"] = self.cache.get_subdomains(target)
            session["known_ports"] = self.cache.get_ports(target)

        self.active_sessions[session_id] = session

        return session

    def get_incremental_targets(self, session: dict) -> dict:
        """Get only new targets to scan"""
        if not session["is_incremental"]:
            return {"full_scan": True}

        known_subs = {s["subdomain"] for s in session["known_subdomains"]}
        known_ports = {(p["host"], p["port"]) for p in session["known_ports"]}

        return {
            "full_scan": False,
            "exclude_subdomains": list(known_subs),
            "exclude_ports": list(known_ports),
            "last_scan_time": session["last_scan"]["timestamp"],
        }

    def finalize_session(self, session_id: str, results: dict):
        """Save session results to cache"""
        session = self.active_sessions.get(session_id)
        if not session:
            return

        target = session["target"]

        for sub in results.get("subdomains", []):
            self.cache.add_subdomain(target, sub, "scan")

        for port_info in results.get("ports", []):
            self.cache.add_port(
                target,
                port_info.get("host", target),
                port_info.get("port"),
                port_info.get("service"),
                port_info.get("version"),
            )

        self.cache.save_scan(target, "full", results, session["depth"])

        if session_id in self.active_sessions:
            del self.active_sessions[session_id]

    def get_session_diff(self, session_id: str) -> dict:
        """Get what changed in this session"""
        session = self.active_sessions.get(session_id)
        if not session or not session["last_scan"]:
            return {"is_new": True}

        return self.cache.get_diff(
            session["target"],
            session["last_scan"]["timestamp"],
        )


if __name__ == "__main__":
    cache = ScanCache()

    cache.add_subdomain("example.com", "www.example.com", "dns", "93.184.216.34")
    cache.add_subdomain(
        "example.com", "api.example.com", "permutation", "93.184.216.35"
    )
    cache.add_port("example.com", "93.184.216.34", 80, "http", "Apache 2.4")

    stats = cache.get_stats("example.com")
    print(f"Cache stats: {stats}")

    subs = cache.get_subdomains("example.com")
    print(f"Subdomains: {[s['subdomain'] for s in subs]}")
