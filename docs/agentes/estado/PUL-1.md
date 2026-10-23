# Estado PUL-1 — Repo y documentación

Actualizado: 2026-10-23 (sesión v2.2, ronda 2 — revisión general)

## Hecho (últimas 24 h)

- [x] readme-fiel-r2 — Codecov sin pin de rama, flags --scope/--exclude/--fail-on/--log-* con exit codes, SARIF en Exportación, dashboard multiescaneo+export, dns ampliado (email security, pasivas, wildcard), árbol al día. Badge refrescado a cierre (petición DIR).
- [x] usage-sync (Banco, ejecutada como revisión ④) — USAGE.md rehecha: scope/autorización, modo CI, logging, TOML (--config/--profile, esquema verificado contra core/config.py), dashboard, variables OSINT_EYE_* con semántica exacta.
- [x] limpieza (revisión ①) — barrido completo: sin backups/temp/pycache/salidas/residuo IA versionados. Nada que borrar. tui_app.py dormido (solo exportado, sin --tui) → nota a IMP-2, no se toca.
- [x] deps-sync (revisión ③) — fuera nvdlib/waybackpy/beautifulsoup4/lxml (cero imports; HTML con regex stdlib); urllib3 declarado (import directo en _http.py). Venv limpio + pip install -e . + suite verde al validar. Paridad requirements↔pyproject 13/13; URL changelog a main.
- [x] changelog-consolidacion — [Unreleased] canónico (Añadido 23 · Cambiado 1 · Documentación 2 · Corregido 1 · Seguridad 3): 12 features reclasificadas de "Seguridad" a "Añadido". Sección TOML añadida a USAGE al aterrizar config-file.
- [x] docs/agentes/ (revisión ⑤) — solo los 4 ficheros + claims/estado/hallazgos; sin residuos.

## En curso

- Nada. Cierre de ronda.

## Bloqueado

- Nada.

## Peticiones a otras zonas

- IMP-3: el test rojo de scan_diff (test a 1 arg vs fix compare(old,new)) quedó resuelto por vosotros a mitad de ronda; suite 684 en verde al consolidar. Nada pendiente.
- IMP-2: tui_app.py/launch_tui sin caller (sin --tui); queda dormido a la espera de tui-completa (v2.3). Si se descarta, avisa y lo retiro yo.
- DIR: rama-canonical cumplida (todo PUL-1 contra main); master siguió recibiendo commits de la flota durante la sesión.
- TEST: leídos H-001..H-008; ninguno para PUL-1. El volcado suelto en CWD de H-008 ya queda cubierto por los patrones /osint_eye_* de .gitignore.

## Propuestas para el roadmap

- [ ] (PUL-1) badge-auto — la suite pasó de 519 a 687 en ESTA sesión: el refresco manual es insostenible; job de CI que regenere el badge con el nº real en cada push a main — .github/workflows/ci.yml, README.md
- [ ] (PUL-1) dependabot — .github/dependabot.yml para pip y GitHub Actions semanales (reiterada) — .github/
- [ ] (PUL-1) examples-dir — examples/scope.txt y examples/osint_eye.toml copiables, enlazados desde USAGE/README — examples/, docs/USAGE.md

## Notas de transparencia

- Reutilizado scripts/resolve_changelog.py (ronda 1) ampliado con migraciones de sección; idempotente.
- Badge final: 687 (recuento del push de cierre).
