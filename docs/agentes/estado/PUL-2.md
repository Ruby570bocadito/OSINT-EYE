# PUL-2 — Estado
Actualizado: 2026-10-23 16:35 UTC · Ronda v2.2 · Rama: main

## Hecho (últimas 24 h)
- [x] (PUL-2) trocear-tests — tests/test_core.py (1813 líneas, heredado) → tests/conftest.py (helpers compartidos) + 12 ficheros test_<zona>_*.py según OWNERSHIP (modules: dns/sources · core: engines/graph/ai/osint_eye · reporting: export/mitre · ui: cli/wizard/dashboard/tui). Reubicación byte a byte, ningún test cambiado: colección idéntica y 268 passed offline tras integrar la ronda 2. Commit fbf4d15.

## En curso
- Nada (las tareas restantes de mi zona tienen solape con claims activos, ver Peticiones).

## Bloqueado
- (PUL-2) ruff-config — pyproject.toml está reclamado por PUL-1 (claim pyproject); retomo cuando libere o coordino sección [tool.ruff].
- (PUL-2) partir-rich-cli — ui/rich_cli.py es ruta objetivo del claim activo progreso-por-modulo (IMP-2).
- (PUL-2) type-hints-core — core/ y graph/ en uso por logging-real (IMP-3).

## Peticiones a otras zonas
- PUL-1: cuando crees pyproject.toml (tarea pyproject v2.2), deja la sección [tool.ruff] vacía o avisa en tu estado; ruff-config la completará sin pisar tus metadatos/extras.
- IMP-2: al terminar progreso-por-modulo en rich_cli.py, avisa en tu estado para que partir-rich-cli pueda planificar el troceado sobre tu versión.
- DIR: main/master quedaron unificados en ronda 1-2 y la ALTA rama-canonical se respeta; nada pendiente, solo constancia de que trabajé desde main.

## Propuestas para el roadmap
- (PUL-2) conftest-fixtures-locales — servidores DNS/HTTP desechables en tests/fixtures/ como fixtures de conftest, reutilizables por los test_* y por los e2e de TEST sin red — tests/conftest.py, tests/fixtures/
- (PUL-2) pytest-config-explicita — fijar PYTHONPATH/filterwarnings en [tool.pytest.ini_options] (coordinar con PUL-1); hoy cada fichero hereda el sys.path hack del legacy — raíz
