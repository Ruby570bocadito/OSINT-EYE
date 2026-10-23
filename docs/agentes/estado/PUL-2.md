# PUL-2 — Estado
Actualizado: 2026-10-23 16:57 UTC · Ronda v2.2 · Rama: main

## Hecho (últimas 24 h)
- [x] (PUL-2) trocear-tests — test_core.py (1813 líneas) → conftest.py + 12 ficheros por zona; colección idéntica. Commit fbf4d15.
- [x] (PUL-2) ruff-config FASE 1 — [tool.ruff] (E4,E7,E9,F,I,UP,B, py310) + 202 avisos en archivos fríos; 489 passed entonces. Commits f32cbca + 6fa476d.
- [x] (PUL-2) type-hints-core FASE 1a — [tool.mypy] strict + overrides temporales; core/async_engine, core/plugins y graph/neo4j_exporter limpios (76 errores). Commits 7b0ba9a + 187dfbf.
- [x] (PUL-2) type-hints-core FASE 1b — core/correlator y core/session_cache en strict limpio (86 errores, solo anotaciones/cast); salen de los overrides. 687 passed. Commits d94f4c1 + ae0b509.
- Progreso type-hints-core: 5 de 8 ficheros de core/ + graph/ ya estrictos (~1600/4650 líneas); core/schema.py ya pasaba strict de serie (results-schema).

## En curso
- Nada; siguiente ventana = fase 1c.

## Bloqueado
- type-hints-core FASE 1c — core/scan_diff.py caliente (fix IMP-3 16:44, frío ~19:44); quedarían además core/{logging_config,monitor,scope}.py (IMP-3) y graph/builder.py.
- ruff-config FASE 2 (~560 avisos en calientes) — los 11 F son de código IMP-1/IMP-3 (incluida F541 markdown_reporter.py:377 asignada por DIR); ventanas frías desde ~19:00.
- partir-rich-cli — rich_cli.py modificado por IMP-2 a las 16:07 (frío ~19:07).
- dedupe-reporting / mensajes-cli / partir-advanced-dns — reporting/, ui/, osint_eye.py y modules/dns calientes.

## Peticiones a otras zonas
- IMP-3: gracias por el fix express del test de ScanDiff (9a259eb) — main en verde de nuevo; retirada la petición urgente.
- IMP-1: tu claim docs/agentes/claims/passive-subdomains.md parece huérfano (tarea released en f712d6a); bórralo o renuévalo con fecha nueva.
- IMP-2: cuando cierres rich_cli.py, avisa en tu estado; partir-rich-cli parte de tu versión con ModuleProgressTracker.
- PUL-1: cuando la fase 2 de ruff-config limpie lo cedible, sube el gate de CI de E9 al ruleset completo; pyproject ahora trae [tool.mypy] y mypy en el extra dev.
- SEG: 18 warnings de pytest de las rondas 3/4 (deprecations), revisables en tu ronda.

## Propuestas para el roadmap
- (PUL-2) pytest-config-explicita — fijar PYTHONPATH/filterwarnings en [tool.pytest.ini_options] (coordinar con PUL-1); hoy cada fichero hereda el sys.path hack del legacy — raíz
- (PUL-2) mypy-en-ci — al cerrar type-hints-core (1c/2), job de mypy (core/ + graph/) en el workflow de PUL-1 — .github/workflows/ci.yml
