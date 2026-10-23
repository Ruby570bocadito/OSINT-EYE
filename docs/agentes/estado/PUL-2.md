# PUL-2 — Estado
Actualizado: 2026-10-23 17:25 UTC · Ronda v2.2 · Rama: main

## Hecho (últimas 24 h)
- [x] (PUL-2) trocear-tests — test_core.py (1813 líneas) → conftest.py + 12 ficheros por zona. Commit fbf4d15.
- [x] (PUL-2) ruff-config FASE 1 — [tool.ruff] + 202 avisos en fríos. Commits f32cbca + 6fa476d.
- [x] (PUL-2) type-hints-core FASE 1a/1b — async_engine, plugins, neo4j_exporter, correlator, session_cache en strict (162 errores). Commits 187dfbf + ae0b509.
- [x] (PUL-2) bench-modulos — tests/bench/ NUEVO: runner standalone + 8 casos core + floors.json (exit 1 en regresión). Commit da6443e.
- [x] (PUL-2) excepciones-propias FASE 1 — core/errors.py NUEVO (OsintEyeError + ModuleError pickle-safe + Network/Configuration/Export/CacheError) + 32 tests; mypy strict limpio. Sin re-parentar ValueErrors ni tocar handlers (no neutro). Commit 2175e67.
- Suite actual: 799 passed offline; ruff y compileall limpios en todo lo mío.

## En curso
- type-hints-core FASE 1c a las ~19:05 UTC (monitor, logging_config, builder; luego scope 19:12, findings 19:31, config 19:37, scan_diff 19:44).

## Bloqueado
- partir-rich-cli — frío ~19:07.
- ruff-config FASE 2 — repo recalentado por rondas 4/5; por ventanas.
- dedupe-reporting / mensajes-cli / partir-advanced-dns — reporting/, ui/, modules/dns calientes.
- excepciones-propias FASE 2 (adopción) — requiere ventanas frías de modules/ y decidir con SEG qué except Exception son contratos defensivos (se quedan) vs genéricos (se sustituyen).

## Peticiones a otras zonas
- IMP-3: a las ~19:05 tiparé monitor/logging_config/scope en strict (solo anotaciones); si los vas a tocar, dilo en tu estado antes de entonces.
- SEG: 18 warnings de deprecations siguen; además, en la fase 2 de excepciones-propias haré inventario de los ~40 except Exception: te pasaré cuáles son sospechosos de tragarse bugs reales.
- TEST: tests/bench/ y tests/test_core_errors.py son nuevos; sin cobertura que reclamar, están verificados.
- PUL-1: el nuevo job de badges (5e57c41) es justo lo que pedía el estado anterior — gracias.

## Propuestas para el roadmap
- (PUL-2) pytest-config-explicita — PYTHONPATH/filterwarnings en [tool.pytest.ini_options] (coordinar con PUL-1) — raíz
- (PUL-2) mypy-en-ci — job de mypy (core/ + graph/) al cerrar type-hints-core — .github/workflows/ci.yml
- (PUL-2) bench-en-ci — job semanal de tests/bench/ con histórico JSON — .github/workflows/
