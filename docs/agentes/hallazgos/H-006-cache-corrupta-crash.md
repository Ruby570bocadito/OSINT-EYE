---
Tipo: bug
Severidad: MEDIO
Persona: operador
Dirigido a: IMP-3
Estado: resuelto-pendiente-verificación
---
Pasos para reproducir: `cp ~/.osint_eye/cache/scan_cache.db /tmp/backup.db && printf 'CORRUPTED GARBAGE NOT A SQLITE DB' > ~/.osint_eye/cache/scan_cache.db && python osint_eye.py example.com --depth quick --no-ai --modules dns` (restaurar después con el backup).
Resultado esperado: la caché corrupta se detecta al inicializar: se recrea el fichero (o se desactiva la caché) con un aviso claro, y el escaneo sigue.
Resultado real: crash con traceback y EXIT=1. Salida literal: `sqlite3.DatabaseError: file is not a database` originada en `core/session_cache.py` (`conn.execute("""` de la inicialización del esquema). El operador no recibe pista de dónde vive la caché ni de cómo recuperarla.
Sugerencia: envolver la inicialización de SessionCache en try/except `sqlite3.DatabaseError`; al fallar, renombrar el fichero a `.corrupt` y recrearlo vacío (o correr con `--no-cache`) imprimiendo el aviso.

Resolución (IMP-3): `ScanCache.__init__` envuelve `_init_db()` en try/except `sqlite3.DatabaseError`;
al fallar, `_quarantine_corrupt_db()` renombra el fichero a `<db_path>.corrupt` (timestamp si ya
existe — nunca se destruye) con aviso WARNING vía `osint_eye.core.session_cache` logger, y recrea la
caché vacía: el escaneo sigue. Si ni siquiera se puede mover/borrar el fichero, el error original se
re-lanza (caso sin remedio, message claro en el log). Regresión: tests/test_cache_corruption.py
(4 tests: cuarentena+recuperación funcional, aviso por logger, segunda corrupción sin sobrescribir,
db sana intacta).
