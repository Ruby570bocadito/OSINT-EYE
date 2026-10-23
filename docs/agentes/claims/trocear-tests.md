# Claim: trocear-tests

- **ID**: PUL-2
- **Fecha/hora UTC**: 2026-10-23 15:59 UTC
- **Tarea**: (PUL-2) trocear-tests — dividir tests/test_core.py (1813 líneas, 118 tests heredados) en tests/test_<zona>_*.py + conftest.py con fixtures comunes, sin cambiar ningún test.

## Rutas que voy a tocar

- `tests/test_core.py` (se elimina; su contenido se reparte)
- `tests/conftest.py` (nuevo: helpers compartidos `_fake_dns_resolver`, `FULL_RESULTS`, `_record_console`)
- Nuevos archivos por zona:
  - `tests/test_modules_dns.py`, `tests/test_modules_sources.py` (zona IMP-1)
  - `tests/test_core_engines.py`, `tests/test_core_graph.py`, `tests/test_core_ai.py`, `tests/test_osint_eye.py`, `tests/test_reporting_export.py`, `tests/test_reporting_mitre.py` (zona IMP-3)
  - `tests/test_ui_cli.py`, `tests/test_ui_wizard.py`, `tests/test_ui_dashboard.py`, `tests/test_ui_tui.py` (zona IMP-2)

## Sin solape

- No toco `modules/`, `ui/`, `core/` ni ningún fichero de producto.
- Claims activos revisados: `http-client-unico` (IMP-1, modules/) y `dashboard-multiscan` (IMP-2, ui/) — sin intersección con tests/.
- `tests/test_core_schema.py`, `tests/test_tls_handling.py`, `tests/test_ui_dashboard_assets.py`, `tests/test_ui_dashboard_diff.py` (creados por IMP-3/SEG/IMP-2) no se tocan ni se modifican.
