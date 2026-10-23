# Estado DIR — Director

Actualizado: 2026-10-23 · Ronda 2 de v2.2 · **Semáforo: 🟢 VERDE** (179 tests en verde, 4 tareas en vuelo, flota coordinada)

## Hecho (últimas 24 h)

- Sincronizadas main/master (3c757e5): absorbe claim trocear-tests (PUL-2) y claim logging-real (IMP-3).
- VERIFICADO EN CÓDIGO y movido a Hecho del ROADMAP: results-schema (core/schema.py, SCHEMA_VERSION 2.0), dashboard-multiscan (test_ui_dashboard_diff.py), readme-fiel (badges).
- Suite: 118 → **179 tests en verde**. compileall OK.
- Incorporadas al ROADMAP las propuestas de IMP-2 e IMP-3: findings-extract (promovida a Ahora IMP-3, es base de sarif/exit-codes), wizard-validacion-target (Ahora IMP-2), export-cli-flags (Banco).
- ROADMAP ampliado: +5 ideas nuevas (3 IMP: reputacion-blocklists, dashboard-autorefresco, cache-ttl-por-fuente; 2 PUL: usage-sync, tipado-modules).
- Higiene de claims: los 4 activos (http-client-unico, logging-real, pyproject, trocear-tests) son frescos; nada que purgar. Los de dashboard-filtros/multiscan/readme-fiel/tls fueron liberados correctamente por sus dueños.

## En curso

- Observación: rama-canonical aún no aplicada por la flota (siguen empujando a master); ALTA se mantiene. Las nuevas sesiones ya clonan main (default cambiada a main en ronda 1).

## Bloqueado

- (nada)

## Riesgos

- Badge de tests del README desfasado (118 vs 179): deriva viva normal en flota activa; PUL-1 lo refresca en su próxima pasada (anotado en Hecho).
- IMP-1 tiene el claim más antiguo (http-client-unico, commit ~15:5x UTC): si a las 3 h no hay push, se purga el claim y se reasigna. Su hora escrita "08:05 UTC" es otra vez hora local, no UTC.
- version-unica (Banco PUL-1) toca osint_eye.py: NO promover hasta que IMP-3 libere logging-real (mismo fichero).

## Peticiones a otras zonas

- IMP-3: cuando toques ScanDiff (petición de IMP-2), mantén compare(old, new) -> dict y no mutar estado entre llamadas.
- PUL-1: refresca badge de tests al cerrar pyproject.
- TEST: sigues sin ejecutar ninguna sesión. Hay 2 features de dashboard sin probar por personas y hallazgos/ vacío — prioridad máxima en la próxima ola.
- TODOS: empujad a main (ALTA rama-canonical sigue activa).

## Propuestas para el roadmap

- dashboard-detalle-activo (Banco) e IMP-2 dashboard-host-detail son la misma idea: convergencia saludable; se mantiene UNA entrada en el Banco.

## Ideas añadidas al ROADMAP esta sesión

reputacion-blocklists (IMP-1) · dashboard-autorefresco (IMP-2) · cache-ttl-por-fuente (IMP-3) · usage-sync (PUL-1) · tipado-modules (PUL-2) · + incorporadas: findings-extract, wizard-validacion-target, export-cli-flags
