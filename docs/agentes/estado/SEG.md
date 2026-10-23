# Estado SEG — Seguridad y bugs

Actualizado: 2026-10-24 11:20 UTC · Ronda 5 v2.2 · **Semáforo: 🟢 VERDE** (suite 668 en verde, 2 tareas ROADMAP entregadas)

## Hecho (últimas 24 h)

- [x] cache-deserializacion (ROADMAP) — `_parse_results()` en `ScanCache.get_last_scan`: un cache.db manipulado ya no puede inyectar valores no-dict en los consumidores (list/int/str/None/bool → dict vacío, tratado como cache miss) ni tumbar el parseo con JSON anidado profundo (RecursionError capturado junto a TypeError/ValueError). 12 tests offline con payloads hostiles sobre cache.db de fixture en tests/test_seg_cache.py. 02d0038.
- [x] audit-deps (ROADMAP) — pip-audit 2.10.1 sobre requirements.txt: **0 vulnerabilidades conocidas** (2026-10-24). Propuesta de mínimos seguros enviada a PUL-1 vía Peticiones (no toco requirements.txt: zona PUL-1).
- Verificación previa de la tarea: claims activos de IMP-3/PUL-2 no solapaban con session_cache.py (PUL-2 lo excluye explícitamente de su fase 1a).

## En curso

- (nada)

## Bloqueado

- (nada)

## Peticiones a otras zonas

- (PUL-1) audit-deps, parte "fijar mínimos seguros": al sincronizar dependencias, subir en requirements.txt `requests>=2.32.0` (CVE-2024-35195 en sesiones con verify=False a nivel sesión, fijado en 2.32.0; el suelo actual 2.31.0 es vulnerable) y `aiohttp>=3.10.11` (acumula fixes 2024: CVE-2024-23334, CVE-2024-30251, CVE-2024-27316). El resto de suelos actuales no tienen advisories conocidos entre su suelo y la versión resuelta hoy; no hace falta subirlos.
- (IMP-2) Pendiente de mi ronda 1: CSP por nonce en dashboard_template.html cuando toque la plantilla.
- (IMP-1) Pendiente: absorber ssrf_guard.safe_get en el HTTPClient compartido (webhook-guard del Banco lo reutilizará).

## Propuestas para el roadmap

- (IMP-3) sanitize-console — saneado único de bytes de control en targets/datos externos antes de imprimir (H-004, sigue abierto) — osint_eye.py, ui/, modules/
- (SEG, próximas rondas) webhook-guard (Banco) y revisión del mismo patrón en --export-cypher/--plugin-dir (rutas de fichero controladas por el operador).
