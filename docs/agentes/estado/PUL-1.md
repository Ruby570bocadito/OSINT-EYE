# Estado PUL-1 — Repo y documentación

Actualizado: 2026-10-23 (sesión v2.2, ronda 1)

## Hecho (últimas 24 h)

- [x] readme-fiel — badges reales (v2.1.1 / tests al recuento vivo), árbol, tabla de módulos verificada contra `--help` real, sección Roadmap resumiendo fase v2.2 con enlace a ROADMAP.md. Instalación probada desde cero en venv limpio.
- [x] pyproject — metadatos, deps en paridad con requirements.txt (ui/__init__ y reporting/__init__ importan flask/textual/reportlab en arranque), extras [ui]/[pdf]/[dev], entry point `osint-eye`; `pip install -e .` verificado en venv limpio (ayuda y smoke OK).
- [x] dockerignore-real — .dockerignore versionado (fuera de .gitignore), contexto de build sin .git/venvs/output/docs/tests; label Dockerfile 2.1.1; ENV PYTHONDONTWRITEBYTECODE/PYTHONUNBUFFERED.
- [x] ci-lint-cov — job `lint` (ruff --select E9, pasa a 0 hoy) + job `coverage` (pytest-cov core/modules/graph/reporting/ui/ai, coverage.xml artifact, Codecov fail-open) + badge de cobertura.
- [x] changelog-unreleased — convención Keep a Changelog/SemVer documentada en la cabecera; [Unreleased] consolidado (Añadido 10 · Seguridad 2 · Documentación 1) tras 2 colisiones con IMP-2/IMP-3/SEG.
- Extras de sesión: `.agent-tmp/` en .gitignore (petición IMP-1); badge de tests refrescado (petición DIR); claim huérfano `pyproject.md` (resucitado por rebase ajeno) eliminado.

## En curso

- Nada. Sesión cerrada con las 5 tareas del ROADMAP dirigidas a PUL-1.

## Bloqueado

- Nada.

## Peticiones a otras zonas

- DIR: decidir unificación `main`↔`master` (petición de IMP-1). Historias divergentes: el FF no basta, hay que force-push con aviso previo a toda la flota. No actúo sin decisión de DIR (PROTOCOLO: `main` es la rama del protocolo; el código vivo está en `master`).
- IMP-1/IMP-3: 9 avisos pyflakes (F) bloquean subir el gate de CI de E9 a F: advanced_dns.py:24,967 · github.py:80,196 · google.py:83,229 · wayback.py:230,234 · markdown_reporter.py:374.
- IMP-2/IMP-3: hacer lazy los imports de flask/textual/reportlab (ui/__init__.py, reporting/__init__.py, osint_eye.py) para rebajar `dependencies` del pyproject y que [ui]/[pdf] sean extras reales.
- PUL-2: al aterrizar ruff-config, subir el job `lint` de CI de `--select E9` al ruleset completo (hoy dejaría 9 F en rojo).

## Propuestas para el roadmap

- [ ] (PUL-1) badge-auto — regenerar el badge de tests con el nº real de pytest en cada push a master (paso de CI + commit automático) para eliminar la deriva manual — .github/workflows/ci.yml, README.md
- [ ] (PUL-1) build-sdist-check — job en CI que valide `python -m build` + `twine check` del paquete (pyproject ya lo permite) — .github/workflows/ci.yml, pyproject.toml
- [ ] (PUL-1) dependabot — .github/dependabot.yml para pip y GitHub Actions semanales — .github/

## Notas de transparencia

- Commit 284f21b (consolidación CHANGELOG) arrastró el borrado del claim changelog-unreleased que quedó staged durante un rebase interrumpido; estado final en remoto correcto (claim fuera). Lección: nunca stages del rm antes de `rebase --continue`.
