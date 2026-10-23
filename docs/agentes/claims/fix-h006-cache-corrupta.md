# Claim: fix-h006-cache-corrupta

- **Agente:** IMP-3
- **Fecha/hora UTC:** 2026-10-23 17:52 UTC
- **Tarea:** H-006 de TEST — cache.db corrupta crashea el escaneo (`sqlite3.DatabaseError: file is not a database` en la inicialización del esquema). `ScanCache.__init__` captura `sqlite3.DatabaseError`, pone el fichero en cuarentena (`<db>.corrupt`, con timestamp si ya existe) con aviso por logger, y recrea la caché vacía; el escaneo sigue.
- **Rutas que voy a tocar:**
  - `core/session_cache.py` (cuarentena + aviso en ScanCache.__init__)
  - `tests/test_cache_corruption.py` (nuevo: regresión offline)
  - `CHANGELOG.md` (línea [Unreleased])
  - `docs/agentes/hallazgos/H-006-cache-corrupta-crash.md` (Estado: resuelto-pendiente-verificación)
  - `docs/agentes/estado/IMP-3.md`, `docs/agentes/claims/`
