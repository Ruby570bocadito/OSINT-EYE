# PUL-2 — Estado
Actualizado: 2026-10-23 16:50 UTC · Ronda v2.2 · Rama: main

## Hecho (últimas 24 h)
- [x] (PUL-2) trocear-tests — test_core.py (1813 líneas) → conftest.py + 12 ficheros por zona; colección idéntica. Commit fbf4d15.
- [x] (PUL-2) ruff-config FASE 1 — [tool.ruff] (E4,E7,E9,F,I,UP,B, py310) + 202 avisos corregidos solo en archivos fríos; 489 passed. Commits f32cbca + 6fa476d.
- [x] (PUL-2) type-hints-core FASE 1a — [tool.mypy] strict con overrides temporales para zonas sin tipar + core/async_engine.py, core/plugins.py y graph/neo4j_exporter.py en strict limpio (76 errores corregidos, solo anotaciones y cast no-op); dev extra con mypy. 670 passed. Commits 7b0ba9a + 187dfbf.

## En curso
- type-hints-core FASE 1b: core/correlator.py (44 errores) y core/session_cache.py (40), ambos fríos desde septiembre. Reclamaré al terminar de publicar esta fase.

## Bloqueado
- ruff-config FASE 2 (~560 avisos en calientes) — rich_cli hasta ~19:07, core/schema ~18:56, modules/* ~19:01, osint_eye ~19:12; los 11 avisos F son de código IMP-1/IMP-3 (F541 markdown_reporter.py:377 asignada por DIR).
- partir-rich-cli — rich_cli.py modificado por IMP-2 a las 16:07.
- dedupe-reporting / mensajes-cli / partir-advanced-dns — reporting/, ui/, osint_eye.py y modules/dns calientes.
- type-hints-core FASE 1c — core/scan_diff.py vuelve a estar caliente (fix de IMP-3 a las 16:44).

## Peticiones a otras zonas
- IMP-3 URGENTE: main está en rojo desde tu 4e8f864 — tests/test_core_scan_diff.py::TestScanDiffReuse llama compare() con UN argumento (differ.compare(_scan([...], [...]))), pero la firma exige (old_results, new_results). O haces old_results opcional con la semántica de reuso que asume tu test, o el test pasa los dos argumentos. No lo toco: es tu zona y está caliente.
- IMP-1: tu claim docs/agentes/claims/passive-subdomains.md parece huérfano (tarea released en f712d6a); bórralo o renuévalo con fecha nueva.
- IMP-2: cuando cierres rich_cli.py (dashboard-autorefresco), avisa; partir-rich-cli parte de tu versión.
- PUL-1: cuando la fase 2 de ruff-config limpie lo cedible, sube el gate de CI de E9 al ruleset completo.
- SEG: 17-18 warnings de pytest de las rondas 3/4 (deprecations), revisables en tu ronda.

## Propuestas para el roadmap
- (PUL-2) pytest-config-explicita — fijar PYTHONPATH/filterwarnings en [tool.pytest.ini_options] (coordinar con PUL-1); hoy cada fichero hereda el sys.path hack del legacy — raíz
- (PUL-2) mypy-en-ci — cuando type-hints-core llegue a 1c, job de mypy (solo core/ graph/) en el workflow de PUL-1 — .github/workflows/ci.yml
