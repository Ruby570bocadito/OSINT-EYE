"""SEG regression: deserialización defensiva de la caché SQLite.

Un cache.db manipulado no debe poder inyectar valores no-dict en los
consumidores de ScanCache.get_last_scan() ni tumbar el parseo
(RecursionError por anidación profunda).
"""

import json
import sqlite3

import pytest

from core.session_cache import ScanCache, SessionManager

TARGET = "example.com"


@pytest.fixture()
def cache(tmp_path):
    return ScanCache(db_path=str(tmp_path / "scan_cache.db"))


def _insert_raw_scan(cache: ScanCache, raw_results: str, timestamp: str = "2026-10-24T10:00:00"):
    with sqlite3.connect(cache.db_path) as conn:
        conn.execute(
            "INSERT INTO scans (target, scan_type, timestamp, depth, results)"
            " VALUES (?, ?, ?, ?, ?)",
            (TARGET, "quick", timestamp, "normal", raw_results),
        )


@pytest.mark.parametrize(
    "payload",
    [
        "not json at all {{{",
        json.dumps([1, 2, 3]),
        json.dumps(None),
        json.dumps(123),
        json.dumps("texto"),
        json.dumps(True),
        json.dumps(3.14),
        "[" * 20000 + "]" * 20000,
    ],
)
def test_get_last_scan_payload_hostil_devuelve_dict_vacio(cache, payload):
    _insert_raw_scan(cache, payload)
    scan = cache.get_last_scan(TARGET)
    assert scan is not None
    assert scan["results"] == {}


def test_get_last_scan_resultados_legitimos_se_preservan(cache):
    results = {"modules": {"dns": {"subdomains": ["a.example.com"]}}}
    cache.save_scan(TARGET, "quick", results, "quick")
    scan = cache.get_last_scan(TARGET)
    assert scan["results"] == results
    assert scan["depth"] == "quick"


def test_get_last_scan_columna_nula_devuelve_dict_vacio(cache):
    _insert_raw_scan(cache, None)
    scan = cache.get_last_scan(TARGET)
    assert scan is not None
    assert scan["results"] == {}


def test_scan_fuera_de_ventana_no_se_devuelve(cache):
    _insert_raw_scan(cache, "{}", timestamp="2000-01-01T00:00:00")
    assert cache.get_last_scan(TARGET, max_age_hours=24) is None


def test_session_con_cache_hostil_no_crash(cache):
    _insert_raw_scan(cache, json.dumps([1, 2, 3]))
    manager = SessionManager(cache)
    session = manager.start_session(TARGET)
    assert session["is_incremental"] is True
    targets = manager.get_incremental_targets(session)
    assert targets["full_scan"] is False
