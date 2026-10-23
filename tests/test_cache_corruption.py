"""Offline regression tests for H-006 (TEST): corrupt cache.db crash.

A garbage scan_cache.db used to crash every scan at startup with
``sqlite3.DatabaseError: file is not a database`` raised from the schema
bootstrap. ScanCache now quarantines the file (never destroys it), warns
through the osint_eye logger and recreates a fresh cache so the scan
keeps going.
"""
import sqlite3
from pathlib import Path



from core.session_cache import ScanCache

GARBAGE = b"CORRUPTED GARBAGE NOT A SQLITE DB"


class TestCorruptCacheRecovery:
    """A corrupt cache file must never take a scan down."""

    def test_corrupt_db_is_quarantined_and_recreated(self, tmp_path):
        db = tmp_path / "scan_cache.db"
        db.write_bytes(GARBAGE)

        cache = ScanCache(db_path=str(db))

        # the scan continues: the fresh cache is fully usable
        assert db.exists()
        # nothing is silently destroyed: the original bytes live in the
        # quarantine file
        quarantine = Path(str(db) + ".corrupt")
        assert quarantine.exists()
        assert quarantine.read_bytes() == GARBAGE

        cache.save_scan("example.com", "quick", {"target": "example.com"}, "quick")
        restored = cache.get_last_scan("example.com")
        assert restored is not None
        assert restored["results"]["target"] == "example.com"

    def test_recovery_warns_through_the_logger(self, tmp_path, caplog):
        db = tmp_path / "scan_cache.db"
        db.write_bytes(GARBAGE)

        with caplog.at_level("WARNING", logger="osint_eye.core.session_cache"):
            ScanCache(db_path=str(db))

        warning = next(
            (r for r in caplog.records if "not a valid SQLite database" in r.message),
            None,
        )
        assert warning is not None, "operator must be told the cache was reset"
        assert str(tmp_path) in warning.getMessage()

    def test_second_corruption_does_not_overwrite_quarantine(self, tmp_path):
        db = tmp_path / "scan_cache.db"
        db.write_bytes(GARBAGE)
        ScanCache(db_path=str(db))

        # corrupt it again: the fixed .corrupt name is already taken, so a
        # timestamped quarantine file must be used instead of overwriting
        db.write_bytes(GARBAGE)
        ScanCache(db_path=str(db))

        quarantined = sorted(p.name for p in tmp_path.glob("scan_cache.db*.corrupt"))
        assert len(quarantined) == 2, quarantined

    def test_healthy_db_is_never_touched(self, tmp_path, caplog):
        db = tmp_path / "scan_cache.db"
        cache = ScanCache(db_path=str(db))
        cache.save_scan("example.com", "quick", {"target": "example.com"}, "quick")

        with caplog.at_level("WARNING", logger="osint_eye.core.session_cache"):
            ScanCache(db_path=str(db))

        assert not list(tmp_path.glob("*.corrupt"))
        assert not [r for r in caplog.records if "not a valid" in r.message]
        # data written before the reopen survives
        assert ScanCache(db_path=str(db)).get_last_scan("example.com") is not None
