# Estado SEG — Seguridad y bugs

Actualizado: 2026-10-24 13:10 UTC · Ronda 6 v2.2 · **Semáforo: 🟢 VERDE** (suite 745 en verde, 2 entregas + 1 revisión pedida por IMP-2)

## Hecho (últimas 24 h)

- [x] csv-formula-dash — revisión pedida por IMP-2 (estado/IMP-2.md): `_safe_download_name` **segura** (whitelist mata traversal/CRLF/comillas, cap 80); `_csv_cell` con hueco: faltaba `-` en los prefijos de fórmula (OWASP CSV injection = + - @; Excel evalúa `-1+1`). Fix de 1 línea + 5 tests offline (tests/test_seg_csv.py).
- [x] webhook-guard (Banco, etiqueta SEG) — `AlertManager.webhook_handler` hacía `requests.post(url)` sin validar: `--webhook` podía enviar alertas con datos del escaneo a loopback/RFC1918/metadatos. Ahora: `ssrf_guard.is_safe_webhook_url()` (https-only + host público), fail-fast en CLI con parser.error (exit 2, verificado: rechaza http://127.0.0.1 y https://169.254.169.254; acepta https público) y cinturón runtime (handler no-op). 20 tests offline. CHANGELOG [Unreleased].
- Revisión cypher-export (persona TEST): `_cypher_str` escapa \ y ' en literals simple-comillados, labels sanitizados por `_neo4j_label` — sin inyección Cypher, sin hallazgo.

## En curso

- (nada)

## Bloqueado

- (nada)

## Peticiones a otras zonas

- (IMP-2) CSV/Filename revisado: veredicto en mi Hecho; el fix de `-` ya está en main (misma protección para tu tabla de assets del dashboard).
- (IMP-3) Cuando aterrice fix-h012 (wizard exit codes): la ruta CLI directa ya devuelve 3; el wizard debe reutilizar decide_exit_code/EXIT_NOTHING_SCANNED, no inventar códigos.
- (IMP-1) Pendiente de mi ronda 1: absorber ssrf_guard.safe_get en el HTTPClient compartido (webhook-guard ya reutiliza el guard para --webhook).

## Propuestas para el roadmap

- (SEG, Siguiente) audit-logging — log inmutable (append-only) de decisiones de scope (discards) y arranques de escaneo con timestamp UTC, para trazabilidad de uso autorizado — core/
- (SEG, Siguiente) path-guard-reporting — validar base de `-o` y rutas de export PDF/CSV contra escapes del CWD (H-003 va en ALTA; esta propuesta cubre el mismo patrón en reporting/ export_all)
