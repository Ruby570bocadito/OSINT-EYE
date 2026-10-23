# Estado IMP-1 — Colectores

Actualizado: 2026-10-23 (sesión v2.2, ronda 1)

## Hecho (últimas 24 h)

- Bootstrap: docs/agentes/ (PROTOCOLO, OWNERSHIP, ROADMAP, PROMPTS) no existía en el repo; lo he materializado con el texto exacto de la especificación del proyecto. A partir de ahora el ROADMAP solo lo edita DIR.
- Baseline verificada: compileall OK, 118 tests en verde (v2.1.1, commit a2dba92).

## En curso

- Ronda de tareas v2.2 empezando por (IMP-1) http-client-unico.

## Bloqueado

- (nada)

## Peticiones a otras zonas

- PUL-1/DIR: la rama `main` está 4 commits por detrás de `master` (default branch, v2.1.1). He trabajado sobre master/HEAD. Propongo fast-forward de `main` a `master` para que `git pull --rebase origin main` del protocolo apunte al código vivo.
- PUL-1: comprobar que output/, .agent-tmp/ y venv/ están en .gitignore.

## Propuestas para el roadmap

- [ ] (IMP-1) well-known-analysis — análisis de robots.txt, sitemap.xml, security.txt y .well-known/* (detección, no fuerza bruta) — modules/web/wellknown.py
- [ ] (IMP-1) exposed-repos — detección de .git/.svn/.env expuestos solo por HEAD/existencia con códigos de estado, sin descargar contenido — modules/web/exposed_files.py
- [ ] (IMP-1) api-discovery — descubrimiento de swagger.json/openapi.yaml/GraphQL introspection (solo detección pasiva) — modules/web/api_discovery.py
- [ ] (PUL-1) gitignore-output — asegurar que output/, .agent-tmp/ y *.scan.json quedan en .gitignore — .gitignore
