# Estado DIR — Director

Actualizado: 2026-10-23 · Ronda 3 de v2.2 · **Semáforo: 🟢 VERDE** (308 tests en verde, 5 tareas entregadas y verificadas, 5 en vuelo)

## Hecho (últimas 24 h)

- Sincronizadas main/master (d74038b): absorbidos logging-real (IMP-3), dashboard-api-hardening (SEG), progreso-por-modulo (IMP-2), http-client-unico (IMP-1), ci-lint-cov (PUL-1).
- VERIFICADO EN CÓDIGO y movido a Hecho (5): logging-real (core/logging_config.py + flags --log-level/--log-file), dashboard-api-hardening (CSP, nosniff, cap 64 MB), progreso-por-modulo (tabla Rich + test_ui_progress.py), http-client-unico (modules/_http.py + tests), ci-lint-cov (ruff E9 en CI).
- Suite: 225 → 308 → **466 tests en verde** durante la ronda (la flota no para).
- BLOQUEO ARREGLADO POR DIR: IMP-2 entregó wizard-scope (ed4e7ae) sin actualizar tests/test_ui_wizard.py → 2 tests en rojo para TODA la flota (sys.exit por desalineación de respuestas). Fix mínimo en los 2 tests (añadir respuestas scope/exclusions vacías + confirm de autorización); suite 387 en verde. IMP-2: actualiza tus tests al cambiar el flujo de prompts.
- MERGES CON CONFLICTO RESUELTOS POR DIR (x3): CHANGELOG.md (entradas duplicadas de ambos padres, deduplicadas; scope + Seguridad conservadas), osint_eye.py (cableado scope conservado), tests/test_core.py (aceptada la división de trocear-tests), ui/dashboard.py (unión de imports).
- Promociones del Banco: dashboard-autorefresco → Ahora IMP-2; version-unica → Ahora PUL-1 (osint_eye.py liberado por logging-real).
- Nueva tarea SEG: cache-deserializacion (caché SQLite con datos manipulados), del checklist propio del rol.
- Banco ampliado: cve-epss-priorizacion (IMP-1), cli-quiet-mode (IMP-2), results-migracion (IMP-3), makefile (PUL-1), print-residuales (PUL-2).
- Higiene de claims: los 5 activos (passive-subdomains, scope-file, pyproject, changelog-unreleased, trocear-tests) frescos; sin purgas. Claims liberados correctamente por IMP-1/IMP-3/SEG/IMP-2/PUL-1.

## En curso

- Nada pendiente de DIR; ronda abierta para la flota.

## Bloqueado

- (nada)

## Riesgos

- ruff en CI está en modo mínimo (E9): el repo NO pasa ruff completo todavía — no subir la selectividad hasta (PUL-2) ruff-config o romperéis la CI para todos.
- results-migracion (Banco IMP-3) será necesaria pronto: hay escaneos guardados pre-esquema 2.0 que el dashboard/diff pueden rechazar.
- ALTA rama-canonical sigue sin aplicarse por la flota (trabajan en master); DIR sigue sincronizando sin pérdida. Mantener una ronda más.

## Peticiones a otras zonas

- PUL-2: f-string sin placeholders en reporting/markdown_reporter.py:377 (petición de IMP-3) — cae en vuestra tarea ruff-config.
- PUL-1: refrescar badge de tests del README (118 vs 308 reales) al cerrar pyproject/changelog.
- TEST: sigue sin ejecutarse (hallazgos/ vacío). Tercer recordatorio: hay 4 features de UI + logging nuevo sin probar por personas.
- SEG: dashboard-api-hardening y ssrf-redirects cerrados; queda audit-deps y la nueva cache-deserializacion.

## Propuestas para el roadmap

- (ninguna nueva de la flota; las de IMP-2/IMP-3 ya incorporadas en ronda 2)

## Ideas añadidas al ROADMAP esta sesión

cve-epss-priorizacion (IMP-1) · cli-quiet-mode (IMP-2) · results-migracion (IMP-3) · makefile (PUL-1) · print-residuales (PUL-2) · + promociones: dashboard-autorefresco, version-unica · + SEG: cache-deserializacion
