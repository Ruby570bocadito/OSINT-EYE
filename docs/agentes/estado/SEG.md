# Estado SEG — Seguridad y bugs

Actualizado: 2026-10-24 15:00 UTC · Ronda 7 v2.2 · **Semáforo: 🟢 VERDE** (suite 880 en verde, 4 fixes entregados esta sesión)

## Hecho (últimas 24 h)

- [x] csv-formula-dash — revisión pedida por IMP-2: `_safe_download_name` segura; `_csv_cell` sin `-` en prefijos de fórmula (OWASP: = + - @). Fix 1 línea + 5 tests (tests/test_seg_csv.py).
- [x] webhook-guard (Banco, etiqueta SEG) — `--webhook` hacía `requests.post(url)` sin validar (SSRF a loopback/RFC1918/metadatos). Ahora `ssrf_guard.is_safe_webhook_url()` (https-only + host público), fail-fast CLI (exit 2) y cinturón runtime. 20 tests. CHANGELOG.
- [x] dashboard-summary-tech — `get_summary()` con doble `_as_dict()`: la lista real de TechDetector ('Nginx','PHP') se volvía {} (branch muerto) y el dashboard pintaba siempre "0 Technologies". Acepta ambas formas + ausente→[]. 3 tests (tmp_path). CHANGELOG [Corregido].
- [x] fix-progress-table-wiring — H-013: la tabla "Module Progress" con `--modules` mostraba todo "pending" siempre: `module_map` capturaba los métodos bound ANTES de instrument_engine(). Fix de orden + comentario. Regresión e2e con pty real (tests/e2e/test_e2e_progress_pty.py; la tabla solo renderiza en TTY). Evidencia previa: typescript con 0 "running"/0 "done"/1140 "pending".

## En curso

- (nada)

## Bloqueado

- (nada)

## Peticiones a otras zonas

- (IMP-1) Absorber ssrf_guard.safe_get en el HTTPClient compartido y pinning de IPs a nivel socket (rebinding DNS entre validación y conexión) — pendiente de mi ronda 1.
- (IMP-2) El path `--modules` de la CLI es el de producción para usuarios avanzados: cuando toques rich_cli, considera un test de integración del dispatch (mi fix va con e2e pty).
- (PUL-1) `.gitignore` sigue sin `venv*/` (solo `venv/` y `.venv/`); en este entorno los venvs de agente desaparecen entre rondas — con `venv*/` cubierto nadie los versiona por accidente.

## Propuestas para el roadmap

- (SEG, Siguiente) audit-logging — log append-only de decisiones de scope y arranques de escaneo (timestamp UTC) para trazabilidad de uso autorizado — core/
- (SEG, Siguiente) report-integrity — sello SHA-256 de resultados + timestamp en exportadores (solapa con informe-integridad del Banco de IMP-3; añadiría la cadena de custodia al evidence handling)
