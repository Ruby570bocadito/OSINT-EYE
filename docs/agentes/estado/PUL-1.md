# Estado PUL-1 — Repo y documentación

Actualizado: 2026-10-23 (sesión v2.2, ronda 3 — 3 entregas + 2 verificaciones "ya hecha")

## Hecho (últimas 24 h)

- [x] makefile (Banco) — Makefile con help/install/test/coverage/lint/docker/clean, espejo de PROTOCOLO §0 y del CI; verificado con `make test` (suite verde) y `make lint`.
- [x] badges-dinamicos (Banco, propuesta badge-auto ronda 2) — job `badges` en ci.yml: cuenta la suite con `pytest --collect-only`, lee la versión de pyproject.toml y commitea `.github/badges/{tests,version}.json` (endpoint shields.io) con `[skip ci]` en cada push a main; READMEs pasan de badges estáticos a endpoint. Sembrados a 767; el CI los refresca solo.
- [x] contributing (Siguiente) — CONTRIBUTING.md (setup con Makefile, reglas offline/escaneo autorizado, checklist PR), SECURITY.md (divulgación privada), plantillas bug/feature + PR. En inglés, canónico público.
- [x] pyproject — VERIFICADA ya hecha (596a017): venv limpio, `pip install -e .` + entry point `osint-eye --help` OK, extras [ui]/[pdf]/[dev] y paridad 13 deps. Para que DIR la tache.
- [x] gitignore-output (Banco) — VERIFICADA ya hecha: output/, .agent-tmp/, `*.db`, `.osint_eye/` y volcados raíz cubiertos (403633e). Para que DIR la tache.

## En curso

- Nada. Cierre de ronda (3 tareas entregadas + 2 verificadas).

## Bloqueado

- version-unica (Ahora): osint_eye.py acumula claims activos (webhook-guard SEG, fix-h003 IMP-3, tls-audit/js-secrets IMP-1, fix-h004 IMP-3). Retomo en cuanto se libere.

## Peticiones a otras zonas

- DIR: tachar pyproject y gitignore-output del ROADMAP (verificadas arriba).
- DIR/propietario: el job `badges` commitea con GITHUB_TOKEN (`contents: write` a nivel de job); si el repo tiene los permisos de workflow en "read-only", actívalos en Settings → Actions → Workflow permissions o el job fallará de forma visible.
- TEST: cuando subas los 3 PNG de demo-assets-nuevos, los enlaces del README.md quedarán vivos solos (ya referenciados por nombre estable); no hace falta tocar nada más.

## Propuestas para el roadmap

- [ ] (PUL-1) release-auto — workflow de release: tag → build sdist/wheel → GitHub Release con notas del CHANGELOG → imagen en GHCR; reduce el release manual a `git tag && push` — .github/
- [ ] (PUL-1) usage-en — (reiterada, ronda 2) traducción fiel de docs/USAGE.md a docs/USAGE.en.md ahora que el canónico público es inglés — docs/
- [ ] (PUL-1) examples-perfiles — examples/ con osint_eye.toml de ejemplo (quick recon, CI estricto con --fail-on, monitor) enlazados desde README y USAGE — examples/, docs/

## Notas de transparencia

- La suite siguió creciendo durante la sesión (725 → 767 → 847 al traer main); validé cada push contra el estado rebased y el delta sin cambios de código se verificó antes del push final (ventanas de carrera con la flota).
- Sin nueva dependencia; pyyaml solo en venv local para validar YAML (no versionado).
