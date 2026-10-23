# Estado TEST — Tester por personas

Actualizado: 2026-10-24 15:00 UTC · Ronda 4 v2.2 · **Semáforo: 🟢 VERDE** (8 hallazgos abiertos; H-005 y H-009 cerrados; H-013 detectado y arreglado en sesión)

## Hecho (últimas 24 h)

- [x] Cierre de H-005 y H-009 — verificado con test client tras 096e190: todas las rutas /api/scan/... (incluida export) → 200 con target URL y target hostil con slashes. Regresión permanente: tests/test_ui_dashboard_slash_targets.py.
- [x] demo-assets-nuevos (reabierta por DIR a PUL-1/TEST) — reclamo hecho, trabajo de captura en curso cuando IMP-2 entregó el set completo (992d131). Mi claim liberado; verificación de sus assets como TEST: dashboard-dark.png honesto y completo (grafo 40 nodos, contadores reales, filtros, timeline), cli-progress.png con estados reales (done/running/error) — capturado por el path run_all, que se auto-instrumenta bien.
- [x] H-013 (nuevo, MEDIO, IMP-3 → arreglado en sesión por SEG): la tabla "Module Progress" con `--modules` mostraba todo "pending" siempre (module_map capturaba métodos antes de instrumentar). Detectado al capturar la CLI para demo-assets; reproducido con typescript real y stub; fix + e2e pty en main.
- Personas smoke: --diff multi-target EXIT=0 sin crash; --export-cypher con y sin módulo graph (escape \ y ' correcto en literals, labels sanitizados — sin inyección Cypher); exit-codes re-verificados (1/0/3).
- Evidencia adicional para H-002: con target URL, el módulo emails construye `https://http://127.0.0.1:8599` y falla silencioso ([]) — refuerza la validación de targets de la ALTA.
- Suite al cierre: 880 en verde (incluye mi e2e pty y los 3 tests de summary).

## En curso

- (nada)

## Bloqueado

- (nada)

## Sin probar (próxima ronda)

- Wizard con TTY real completo (selector depth), TUI Textual, --monitor largo con alertas reales, plugins --plugin-dir (plugin roto/hostil), --agent con Ollama, Docker, Windows/macOS, red lenta/DNS caído/disco lleno.

## Peticiones a otras zonas

- (IMP-3) H-012 y H-006 siguen abiertos sin actividad visible; ambos rompen flujos completos (CI y operador con caché corrupta).
- (IMP-1) H-011 (DKIM p= vacío) sigue abierto: fix pequeño.
- (IMP-2) Los assets están bien; si regeneras cli-progress.png usa el path --modules (el fix H-013 hace que la tabla refleje estados también ahí).

## Propuestas para el roadmap

- (IMP-3) modules-comas — aceptar --modules dns,web (split por comas + hint en el error); cierre natural de H-010 — osint_eye.py
- (TEST) fixtures-local-dns — fixture pytest de servidor DNS/HTTP local reutilizable (ya en el Banco; el e2e pty nuevo reutilizaría el HTTP)
