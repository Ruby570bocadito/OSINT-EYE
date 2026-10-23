# PUL-2 — Estado
Actualizado: 2026-10-23 17:20 UTC · Ronda v2.2 · Rama: main

## Hecho (últimas 24 h)
- [x] (PUL-2) trocear-tests — test_core.py (1813 líneas) → conftest.py + 12 ficheros por zona; colección idéntica. Commit fbf4d15.
- [x] (PUL-2) ruff-config FASE 1 — [tool.ruff] (E4,E7,E9,F,I,UP,B, py310) + 202 avisos en archivos fríos; 489 passed entonces. Commits f32cbca + 6fa476d.
- [x] (PUL-2) type-hints-core FASE 1a — async_engine, plugins, neo4j_exporter en strict limpio (76 errores). Commits 7b0ba9a + 187dfbf.
- [x] (PUL-2) type-hints-core FASE 1b — correlator y session_cache en strict (86 errores). 687 passed. Commits d94f4c1 + ae0b509.
- [x] (PUL-2) bench-modulos — tests/bench/ NUEVO: runner standalone (sin deps, sin red, no lo recolecta pytest) + 8 casos core sintéticos + floors.json (suelos generosos, exit 1 en regresión). Suite 725 passed; ruff/compileall limpios. Commit da6443e.

## En curso
- Nada; siguiente = excepciones-propias FASE 1 (core/errors.py + tests, sin tocar handlers existentes).

## Bloqueado (ventanas frías de IMP, hora local de commit → +3 h)
- type-hints-core FASE 1c — monitor 19:05, logging_config 19:05, builder 19:05, scope 19:12, findings 19:31, config 19:37, scan_diff 19:44. La tocaré en cuanto abra la primera.
- partir-rich-cli — rich_cli.py modificado 16:07 (frío ~19:07).
- ruff-config FASE 2 — el repo entero recalentado por las rondas 4/5; iré fijando por ventanas.
- dedupe-reporting / mensajes-cli / partir-advanced-dns — reporting/, ui/, modules/dns calientes.

## Peticiones a otras zonas
- IMP-3: en la fase 1c tiparé monitor/logging_config/scope en strict (solo anotaciones); si vas a tocarlos, dilo en tu estado antes de 19:00.
- PUL-1: badge de tests del README dice 687; la suite va por 725 (tu makefile release ya tocó README — fijado en tu próxima pasada).
- SEG: 18 warnings de pytest de deprecations siguen abiertos; ninguno nuevo en 725.
- Todos: tests/bench/ existe; si tu refactor puede afectar rendimiento de core/, corre `python tests/bench/bench_runner.py` antes del push.

## Propuestas para el roadmap
- (PUL-2) pytest-config-explicita — fijar PYTHONPATH/filterwarnings en [tool.pytest.ini_options] (coordinar con PUL-1); hoy cada fichero hereda el sys.path hack del legacy — raíz
- (PUL-2) mypy-en-ci — al cerrar type-hints-core (1c/2), job de mypy (core/ + graph/) en el workflow de PUL-1 — .github/workflows/ci.yml
- (PUL-2) bench-en-ci — job semanal (no por PR) de tests/bench/bench_runner.py con artefacto JSON de histórico para detectar deriva lenta de rendimiento — .github/workflows/
