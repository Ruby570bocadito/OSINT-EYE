# PUL-2 — Estado
Actualizado: 2026-10-23 19:09 UTC · Ronda v2.2 · Rama: main

## Hecho (últimas 24 h)
- [x] (PUL-2) trocear-tests / ruff-config F1 / type-hints F1a+F1b / bench-modulos / excepciones-propias F1 — ver sesiones anteriores. Commits fbf4d15, f32cbca+6fa476d, 187dfbf+ae0b509, da6443e, 2175e67.
- [x] (PUL-2) ruff-config FASE 2 ronda 1 — core/schema.py: 57 avisos (typing PEP 585, TypedDicts intactos; el formato preexistente de IMP-3 queda fuera). Commits 3ca4bb2 + 93708c3.
- [x] (PUL-2) type-hints-core FASE 1c — scope.py (9), logging_config.py y graph/builder.py (41 ocultos) en mypy strict; salen de overrides; networkx/pyvis sin stubs → ignore justificados. monitor.py entra temporal en overrides (otro agente lo tocó 17:11, frío 20:11). Cero cambios de comportamiento, 1056 passed. Commit b09f017.
- Progreso type-hints-core: 8 de 9 ficheros de core/ + graph/ estrictos (queda monitor 20:11, findings 19:31, config 19:37, scan_diff 19:44 → 1d).

## En curso
- Preparando borradores 1d (findings/config/scan_diff) para las ventanas de 19:31-19:44.

## Bloqueado
- type-hints-core FASE 1d — findings 19:31, config 19:37, scan_diff 19:44; monitor.py 20:11 (cierra core/ + graph/).
- partir-rich-cli — rich_cli.py modificado 16:07 por IMP-2 (frío 19:07, YA LIBRE — la haré tras la 1d si la sesión sigue).
- ruff-config FASE 2 — quedan ~618 avisos en calientes (tls_audit 48, rich_cli 44, permutator 33, nvd 30…); por ventanas.
- excepciones-propias FASE 2 (adopción) — coordinar con SEG qué except Exception son contratos.

## Peticiones a otras zonas
- IMP-3: tipé scope/logging_config/builder en strict solo con anotaciones; config.py y findings.py siguen tus errores mypy visibles (13 y 11) — si los vas a tocar antes de mi ventana 1d, dilo en tu estado.
- SEG: session_cache sigue strict tras tu fix H-006 — gracias por mantener las anotaciones; los 24 errores restantes de core/ son findings+config.
- TEST: 1056 tests; mi suite offline sigue 100% verde tras cada fase.
- PUL-1: badge de tests del README quedó en 687; la suite va por 1056 (con tu nuevo job de badges debería auto-refrescarse).

## Propuestas para el roadmap
- (PUL-2) pytest-config-explicita — PYTHONPATH/filterwarnings en [tool.pytest.ini_options] (coordinar con PUL-1) — raíz
- (PUL-2) mypy-en-ci — job de mypy (core/ + graph/) al cerrar type-hints-core — .github/workflows/ci.yml
- (PUL-2) types-networkx-en-dev — stubs de networkx en el extra dev para eliminar el type: ignore de graph/builder.py y ganar comprobación en builder/neo4j — pyproject.toml
