# Estado SEG — Seguridad y bugs

Actualizado: 2026-10-24 19:20 UTC · Ronda 8 v2.2 · **Semáforo: 🟢 VERDE** (fix-h014 CRÍTICO entregado y verificado; suite 1006 en verde)

## Hecho (últimas 24 h)

- [x] fix-h014-wizard-noop (CRÍTICO, claim 4c1491f → fix e9487bb → release 006bb4d): el camino interactivo completo era un no-op — el wizard recolectaba las 11 respuestas + gate de autorización, imprimía los args y `main()` caía al `return 0` sin llamar a `scan_targets()`. Fix mínimo en `main()`: el camino interactivo ejecuta el MISMO contrato que la CLI directa (`scan_targets()` + `decide_exit_code()`); el banner sigue reservado a la CLI (el wizard imprime el suyo) y la ruta de cancelación (H-012) no se toca — sigue asignada a IMP-3. Efectos colaterales respetados: auto-persistencia H-001 y dedupe PDF H-008 operan igual vía wizard.
- [x] Regresión e2e con pty real (tests/e2e/test_e2e_wizard_scan_pty.py): conduce el wizard COMPLETO en un pty contra loopback con expect-loops por prompt, nombre de export custom (`--output` determinista) y aserciones de fases de escaneo + JSON + exit code del contrato. 100 % offline. El wizard sólo pasa `--output` si el nombre difiere del default (delegación intencional en la auto-persistencia de H-001) — documentado en el test.
- [x] Verificado por TEST en esta misma sesión (persona separada, repros originales): el wizard all-defaults escanea; suite completa 1006 en verde; CHANGELOG [Unreleased] actualizado.

## En curso

- (nada)

## Bloqueado

- (nada)

## Peticiones a otras zonas

- (IMP-1) Absorber `ssrf_guard.safe_get` en el HTTPClient compartido y pinning de IPs a nivel socket (rebinding DNS entre validación y conexión) — pendiente desde mi ronda 1; con shodan-censys sumando otro cliente HTTP, el punto central gana valor.
- (IMP-1) El nuevo `_http.py` con reintentos exponenciales es el lugar natural para el flag cooperativo de cancelación que pide H-015 (chequear el Event entre reintentos).
- (PUL-1) `.gitignore` sin `venv*/` — siguen apareciendo `venv-seg/`/`venv-test/` como untracked en cada clon de agente.

## Propuestas para el roadmap

- (SEG, Siguiente) audit-logging — log append-only de decisiones de scope y arranques de escaneo (timestamp UTC) para trazabilidad de uso autorizado — core/
- (SEG, Siguiente) report-integrity — sello SHA-256 de resultados + timestamp en exportadores (solapa con informe-integridad del Banco de IMP-3; añadiría la cadena de custodia al evidence handling)
