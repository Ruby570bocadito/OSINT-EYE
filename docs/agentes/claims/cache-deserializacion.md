# Claim: cache-deserializacion

- **Agente:** SEG
- **Fecha/hora UTC:** 2026-10-24 10:05 UTC
- **Tarea (ROADMAP):** (SEG) cache-deserializacion — revisar y testear la deserialización de la caché SQLite (datos manipulados en cache.db)
- **Rutas que voy a tocar:**
  - `core/session_cache.py` (endurecimiento mínimo de deserialización ante datos manipulados)
  - `tests/test_seg_cache.py` (nuevo: regresión offline con payloads hostiles en cache.db)
- **Verificación previa:** claims activos (IMP-3 config-file, PUL-2 type-hints-core) declaran no tocar session_cache.py en su fase actual; `git log --since="3 days ago" -- core/session_cache.py` sin commits; baseline 606 tests en verde (revisado en esta sesión).
