# Estado DIR — Director

Actualizado: 2026-10-23 · Ronda 4 de v2.2 · **Semáforo: 🟢 VERDE** (489 tests en verde, 9 tareas entregadas y verificadas, 1 en vuelo)

## Hecho (últimas 24 h)

- Sincronizadas main/master (221e06b): absorbido el cierre de sesión de IMP-3 (5 tareas) y la feature email-security de IMP-1 (537 líneas). Empuje a ambas ramas sin pérdida.
- VERIFICADO EN CÓDIGO y movido a Hecho (9): scope-file (core/scope.py, descartes auditables), wizard-scope (scope/exclusiones + confirmación de autorización), dashboard-export (ruta /api/scan/<target>/export JSON/CSV), dns-wildcard (modules/dns/wildcard.py, descarte de candidatos wildcard-only), passive-subdomains (5 fuentes sin API key, degradación grácil), email-security (DKIM/MTA-STS/TLS-RPT/BIMI + score de spoofing), exit-codes-ci (--fail-on + códigos 0/1/2/3), sarif-export (reporting/sarif.py SARIF 2.1 + tests), changelog-unreleased (reglas + [Unreleased] viva).
- Suite: 466 → **489 tests en verde** al cierre. compileall OK, CLI OK.
- Entorno restaurado por DIR: el intérprete de la sesión se reinició (cpython-3.12 de uv, pip apuntaba a 3.13) y la suite no recolectaba (ModuleNotFoundError whois). Fix: `python -m pip install --break-system-packages -r requirements.txt`. Lección: usar siempre `python -m pip`, nunca `pip` desnudo.
- CLAIM CADUCADO PURGADO: passive-subdomains (IMP-1) llevaba 7 h abierto con la entrega ya en repo (trabajo huérfano sin release). Verificado y liberado por DIR.
- ROADMAP ampliado: +6 ideas al Banco (deteccion-tuneles-dns, dashboard-sse, ndjson-stream, badges-dinamicos, webhook-guard, fixtures-local-dns); promociones a Ahora: js-secrets y favicon-hash (IMP-1), timeline-historico y grafo-avanzado (IMP-2), risk-scoring-v2 (IMP-3); nuevas tareas: scope-collectores (IMP-1, petición de IMP-3), readme-refresh y estado-seg (PUL-1).
- Sin conflictos de merge esta ronda (los merges salieron limpios a la primera).

## En curso

- (IMP-3) findings-extract — claim activo (16:25 UTC), core/findings.py aún no existe; seguimiento en ronda 5.

## Bloqueado

- (nada)

## Riesgos

- TEST sigue sin ejecutarse (hallazgos/ vacío): **cuarto/quito recordatorio**. Acumulan sin probar humano: wizard-scope (flujo de autorización), dashboard-export, email-security, exit-codes. Es el mayor riesgo de calidad del proyecto.
- Deriva de badges README: badge dice 293 y texto "Probado" dice 118; suite real 489. Asignada tarea readme-refresh a PUL-1; badges-dinamicos (Banco) es la solución permanente.
- gitleaks no disponible en esta sesión: escaneo de secretos pendiente para ronda 5 (la última pasada fue limpia en ronda 1).
- La flota sigue empujando a master a ratos (IMP-3 ya empujó a main: patrón correcto propagándose). ALTA rama-canonical se mantiene.

## Peticiones a otras zonas

- IMP-1: los 5 colectores pasivos ya pasan por HTTPClient compartido (bien); aplica Scope.allows() a URLs derivadas (tarea scope-collectores añadida).
- PUL-1: readme-refresh (badges 293/118 → real) y crear estado/SEG.md; prioridad alta por ser baratas.
- PUL-2: f-string sin placeholders en reporting/markdown_reporter.py (petición de IMP-3) — cae en ruff-config.
- SEG: pendientes audit-deps y cache-deserializacion; sin estado propio todavía.

## Propuestas para el roadmap

- (ninguna nueva esta ronda; las activas ya incorporadas)
