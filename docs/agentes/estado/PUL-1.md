# Estado PUL-1 — Repo y documentación

Actualizado: 2026-10-23 (sesión v2.2, ronda 4 — version-unica + pre-commit + release-auto)

## Hecho (últimas 24 h)

- [x] version-unica (Ahora) — fuente única en core/__init__.py (`__version__ = "2.1.1"`); banner CLI lo importa (antes "v2.1" fijo), pyproject lo deriva vía [tool.setuptools.dynamic] attr (verificado: pip show 2.1.1 tras reinstall), job badges lo lee por regex de core. 3 tests nuevos en tests/test_pul_version.py (semver, pyproject dynamic, subprocess --help offline).
- [x] pre-commit-hooks (Banco) — .pre-commit-config.yaml: ruff con la puerta E9 de CI (rev v0.17.2), end-of-file-fixer y trailing-whitespace (exclude ^data/ y *.md); pre-commit al extra [dev]; guía opcional en CONTRIBUTING. Verificado con run --all-files.
- [x] release-auto (Siguiente) — .github/workflows/release.yml: push de tag v* → valida tag == __version__ → build sdist/wheel → notas extraídas del CHANGELOG (.github/scripts/extract_changelog.py, probado con 2.1.1 y fallo limpio en 9.9.9) → imagen a GHCR (v+latest, build-arg VERSION) → GitHub Release. Dockerfile toma la versión por ARG (ciclo cerrado con version-unica).

## En curso

- Nada. Cierre de ronda (3 tareas entregadas).

## Bloqueado

- Nada. (PyPI publish del Banco requiere alta del paquete por el propietario: propuesta pypi-publish abajo.)

## Peticiones a otras zonas

- IMP-2: ui/rich_cli.py:228 y :740 aún dicen "v2.1" fijo — importad `from core import __version__` e interpolated (test_pul_version.py ya cubre el banner de argparse; el Rich banner queda en vuestra zona).
- IMP-3: drift de versión en plantillas de reportes: core/scan_diff.py:509 ("v1.0"), reporting/export.py:388 ("v1.0"), reporting/pdf_reporter.py:175/283/626 ("v2.0") — usad `core.__version__`.
- PUL-2: trailing whitespace en modules/osint/google.py, modules/osint/github.py y tests/test_modules_wildcard.py — el hook de pre-commit los corregirá en vuestro próximo commit que los toque (excluidos de mi release por zona).
- DIR: tachar version-unica, pre-commit-hooks y release-auto del ROADMAP.

## Propuestas para el roadmap

- [ ] (PUL-1) pypi-publish — job de publish a PyPI en release.yml con trusted publishing (requiere que el propietario dé de alta el publisher en pypi.org) — .github/
- [ ] (PUL-1) usage-en — (reiterada 3ª) traducción fiel de docs/USAGE.md a docs/USAGE.en.md — docs/
- [ ] (PUL-1) changelog-compare-links — enlaces de comparación al pie del CHANGELOG ([2.1.1]: .../compare/v2.1.0...v2.1.1) — CHANGELOG.md

## Notas de transparencia

- Suite en 902 tests al cerrar; 2 push rechazados por carrera con la flota, resueltos con rebase y delta-check (sin re-validar si el delta no tocaba código).
- pre-commit excluye data/ (wordlists de IMP-1) y *.md; los 3 .py con trailing whitespace quedan para sus dueños.
