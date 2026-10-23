# Estado TEST — Tester por personas

Actualizado: 2026-10-24 19:20 UTC · Ronda 6 v2.2 · **Semáforo: 🟢 VERDE** (7 hallazgos cerrados con repros originales; 4 features nuevas smoke OK; 1 hallazgo nuevo H-015 MEDIO; suite 1006 en verde)

## Hecho (últimas 24 h)

- [x] Verificación y CIERRE masivo de los fixes aterrizados por la flota, con los repros ORIGINALES de cada hallazgo: H-001 (auto-persist `osint_eye_<target>_<ts>.json` + mensaje), H-002 (5 casos: 4 normalizados visibles en `results.target`, `not_a_domain!!` → exit 2 accionable), H-007 (SIGINT → exit 130 limpio con parciales, sin traceback; latencia fichada aparte), H-008 (`-o base --pdf` → exactamente 1 PDF), H-010 (`dns,web` aceptado; desconocido → error corto con hint, 11 líneas vs muro ~40), H-011 (one-liner example.com: `present=False`, 18 selectores `p=` vacío en `revoked`). Commit close 6f48abc.
- [x] H-014 (CRÍTICO) verificado y CERRADO: fix de SEG (e9487bb) — el repro original del wizard con TODOS los defaults arranca el escaneo real (Phase 1 en salida; adiós al no-op). Contrato completo (exit code + export JSON) fijado por la regresión e2e pty nueva `tests/e2e/test_e2e_wizard_scan_pty.py` (rc=0 + `wiz_scan.json`, 101 s, 100 % offline).
- [x] Smoke de las 4 features nuevas de la flota, todo en verde: shodan-censys SIN claves → proveedores `skipped`, escaneo sigue, rc=0; asn-ip-ranges (módulo network) sobre loopback → grácil, JSON con sección network; tui-completa → arranca tras el escaneo en pty real y sale limpio con 'q' (rc=0); dashboard-vacio-guiado + tema-claro → quickstart con comandos exactos servido en el HTML, `prefers-color-scheme` presente y cero recursos CSS externos.
- [x] H-015 nuevo (MEDIO): el exit 130 del fix H-007 llega correcto pero tras **87 s** — `concurrent.futures.wait(p1)` sin timeout + `shutdown(wait=True)` del context manager retienen el KeyboardInterrupt hasta que los módulos en vuelo agotan sus timeouts/reintentos (faulthandler: main en `run_all → join`, worker wayback bloqueado en `create_conn` a web.archive.org). Sugerencia: cancelación cooperativa (Event + chequeos en `_http`) y `shutdown(wait=False, cancel_futures=True)`.

## En curso

- (nada)

## Bloqueado

- (nada)

## Sin probar (próxima ronda)

- Docker (Dockerfile nuevo con ARG VERSION), Windows/macOS, `--monitor` largo con alertas reales y webhook, `--agent` con Ollama, red DNS caída/disco lleno/red lenta sostenida (H-015 agrava este escenario).

## Peticiones a otras zonas

- (IMP-3) H-015 (MEDIO): la cancelación cooperativa propuesta elimina la percepción de cuelgue; el mismo Event sirve para resume-scan a futuro.
- (IMP-3) H-012 sigue abierto (cancelación del wizard exit 0): es el ÚNICO hallazgo interactivo que queda; el e2e pty de H-014 da el arnés listo para su regresión.
- (PUL-1) `.gitignore` sigue sin `venv*/` (solo `venv/` y `.venv/`): los venvs de agente (`venv-seg/`, `venv-test/`) siguen apareciendo como untracked en cada clon.

## Propuestas para el roadmap

- (TEST, Banco) personas-deshonestas — batería de repros con DNS que responde TXT degenerados (DKIM p=, SPF +all, DMARC none) como fixture local reutilizable; nace del hallazgo H-011 y del patrón de datos hostiles que ya dio 2 bugs.
