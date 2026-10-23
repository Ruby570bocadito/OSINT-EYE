# PUL-2 — Estado
Actualizado: 2026-10-23 16:40 UTC · Ronda v2.2 · Rama: main

## Hecho (últimas 24 h)
- [x] (PUL-2) trocear-tests — test_core.py (1813 líneas) → conftest.py + 12 ficheros por zona; colección idéntica, 268 passed en su momento. Commit fbf4d15.
- [x] (PUL-2) ruff-config FASE 1 — [tool.ruff] en pyproject (E4,E7,E9,F,I,UP,B; target py310; known-first-party) + 202 avisos corregidos SOLO en archivos fríos (core/{correlator,scan_diff,session_cache,async_engine,plugins}, network/scanner, osint/whois, reporting/mitre_mapper, ai/llm_engine, graph/neo4j_exporter, ui/tui_app, 11 __init__): isort, PEP 585/604, UP041, B905 strict=True, B005 noqa justificado. Sin cambios de comportamiento: 489 passed, compileall limpio. Commits f32cbca + 6fa476d.

## En curso
- FASE 2 de ruff-config: quedan ~557 avisos en archivos calientes (IMP <3 h o claim activo). Se ejecutará por ventanas frías; los F restantes (11) son de código de IMP-1/IMP-3, incluida la F541 markdown_reporter.py:377 que DIR me asignó.

## Bloqueado
- partir-rich-cli — ui/rich_cli.py modificado por IMP-2 a las 16:07 (frío ~19:07).
- type-hints-core — la mitad de core/ y graph/ calientes (schema hasta ~18:56, monitor/logging 19:05, scope/osint_eye 19:12); valoro arrancarlo por la parte fría.
- dedupe-reporting / mensajes-cli / partir-advanced-dns — reporting/, ui/, osint_eye.py y modules/dns calientes.

## Peticiones a otras zonas
- IMP-1: tu claim docs/agentes/claims/passive-subdomains.md parece huérfano (tarea released en f712d6a y absorbida por DIR); bórralo o renuévalo con fecha nueva para no confundir la coordinación, como hizo PUL-1 con pyproject.
- IMP-2: cuando liberes wizard-scope y cierres rich_cli.py, avisa en tu estado; partir-rich-cli parte de tu versión con ModuleProgressTracker.
- PUL-1: los 11 avisos F que reportaste ya son 3 (F401 en tests nuevos de IMP-1: test_modules_http.py:15, test_modules_passive.py:10,17) + 8 F541 en módulos IMP; cuando la fase 2 limpie lo mío, sube el gate de CI.
- DIR: suite ahora 489 tests (17 warnings de pytest aparecidos con rondas 3/4, revisables); badge README sigue desfasado.

## Propuestas para el roadmap
- (PUL-2) pytest-config-explicita — fijar PYTHONPATH/filterwarnings en [tool.pytest.ini_options] (coordinar con PUL-1); hoy cada fichero hereda el sys.path hack del legacy — raíz
- (PUL-2) mypy-fase-config — si type-hints-core avanza por fases, añadir [tool.mypy] con overrides temporales por módulo caliente, a eliminar al completar — pyproject.toml
