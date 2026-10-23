# PUL-2 — Estado
Actualizado: 2026-10-23 20:16 UTC · Ronda v2.2 · Rama: main

## Hecho (últimas 24 h)
- [x] (PUL-2) trocear-tests / ruff-config F1 / type-hints F1a+F1b / bench-modulos / excepciones-propias F1 — sesiones 1-3 anteriores.
- [x] (PUL-2) ruff-config FASE 2 ronda 1 — core/schema.py: 57 avisos typing (3ca4bb2).
- [x] (PUL-2) type-hints-core FASE 1c — scope, logging_config, builder en strict (b09f017).
- [x] (PUL-2) type-hints-core FASE 1d — findings, config, scan_diff en strict (6c91155).
- [x] (PUL-2) type-hints-core FASE FINAL — monitor en strict (4ea6dc9). **core/ + graph/ al 100% en mypy --strict** (16 ficheros, ~4650 líneas); overrides de pyproject reducidos a modules.* (siguiente fase: type-hints-modules).
- Suite: 1060 passed offline; compileall y ruff limpios en todo lo tocado; cero cambios de comportamiento en toda la sesión.

## En curso
- Nada. Próxima tarea grande: partir-rich-cli.

## Bloqueado
- partir-rich-cli — rich_cli.py libre desde 19:07 (44 avisos ruff además de la división); tarea grande, arranque en la próxima sesión.
- ruff-config FASE 2 — ~618 avisos en calientes (tls_audit 48, rich_cli 44, permutator 33, nvd 30…); por ventanas.
- excepciones-propias FASE 2 (adopción real) — coordinar con SEG el inventario de except Exception.
- dedupe-reporting / mensajes-cli / partir-advanced-dns — por ventanas frías.

## Peticiones a otras zonas
- TODOS: core/ y graph/ son mypy --strict desde 4ea6dc9 — si añades código ahí, mantenlo tipado (mypy fallará si no; propongo activarlo en CI, ver propuestas).
- IMP-3: config.py y findings.py quedaron en strict con casts no-op; los accessors de Config devuelven lo mismo que antes.
- SEG: monitor.py incluye tu webhook-guard intacto; el alias AlertHandler documenta la firma que deben cumplir los canales.
- TEST: 1060 tests en verde tras cada fase; tests/bench/ disponible para refactors de rendimiento.

## Propuestas para el roadmap
- (PUL-2) mypy-en-ci — core/ + graph/ ya son strict: job de mypy en el workflow de PUL-1 — .github/workflows/ci.yml
- (PUL-2) types-networkx-en-dev — stubs en el extra dev; elimina el type: ignore de graph/builder.py — pyproject.toml
- (PUL-2) pytest-config-explicita — PYTHONPATH/filterwarnings en [tool.pytest.ini_options] (coordinar con PUL-1) — raíz
