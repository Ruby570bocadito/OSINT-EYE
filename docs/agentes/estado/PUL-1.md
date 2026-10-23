# Estado PUL-1 — Repo y documentación

Actualizado: 2026-10-23 (sesión v2.2, ronda 2 — revisión general + ALTA readme-en-desde-cero)

## Hecho (últimas 24 h)

- [x] readme-en-desde-cero (ALTA, petición del propietario) — README.md nuevo 100% inglés escrito desde cero: quickstart, 19 módulos, exit codes, scope, TOML, exports, dashboard, monitor/plugins/AI, arquitectura, env vars, testing; todo verificable con --help/tests/árbol. README en español conservado como README.es.md con enlaces cruzados. Assets nuevos referenciados por nombre estable (placeholder hasta entrega IMP-2). Línea en CHANGELOG.
- [x] readme-fiel-r2 — Codecov sin pin de rama, flags --scope/--exclude/--fail-on/--log-* con exit codes, SARIF, dashboard multiescaneo+export, dns ampliado, árbol. Badge refrescado a cierre (petición DIR).
- [x] usage-sync (Banco, como revisión ④) — USAGE.md rehecha: scope/autorización, modo CI, logging, TOML (esquema verificado contra core/config.py), dashboard, variables OSINT_EYE_*.
- [x] limpieza (revisión ①) — sin backups/temp/pycache/salidas/residuo IA versionados; nada que borrar. tui_app.py dormido (sin --tui) → nota a IMP-2.
- [x] deps-sync (revisión ③, verificado a Hecho por DIR ronda 5) — fuera nvdlib/waybackpy/beautifulsoup4/lxml; urllib3 declarado; venv limpio + pip install -e . + suite verde; paridad 13/13; URL changelog a main.
- [x] changelog-consolidacion — [Unreleased] canónico (Añadido · Cambiado · Documentación · Corregido · Seguridad): 12 features reclasificadas de "Seguridad" a "Añadido".
- [x] docs/agentes/ (revisión ⑤) — solo los 4 ficheros + claims/estado/hallazgos.

## En curso

- Nada. Cierre de ronda.

## Bloqueado

- Nada.

## Peticiones a otras zonas

- IMP-2: el README en inglés referencia dashboard-dark.png, graph-view.png y cli-progress.png (nombres estables de demo-assets-nuevos) — hasta tu entrega quedan como imágenes rotas; el README lo advierte. Cuando subas los PNG/GIF no hace falta tocar el README.
- IMP-3: el test rojo de scan_diff a mitad de ronda quedó resuelto por vosotros; suite en verde al consolidar. Nada pendiente.
- DIR: rama-canonical cumplida (todo contra main). Hallazgos H-001..H-012 leídos; ninguno dirigido a PUL-1.

## Propuestas para el roadmap

- [ ] (PUL-1) badge-auto — la suite pasó de 519 a 706 en ESTA sesión: refresco manual insostenible; job de CI que regenere el badge en cada push a main — .github/workflows/ci.yml, README.md
- [ ] (PUL-1) dependabot — .github/dependabot.yml para pip y GitHub Actions semanales (reiterada) — .github/
- [ ] (PUL-1) usage-en — traducción fiel de docs/USAGE.md a docs/USAGE.en.md (o EN canónica) ahora que el README canónico es inglés — docs/USAGE.md

## Notas de transparencia

- scripts/resolve_changelog.py (ronda 1) reutilizado y ampliado con migraciones de sección; idempotente.
- Badge final: 706 (recuento del push de cierre). El conteo sigue subiendo con la flota: badge-auto lo resolvería de raíz.
