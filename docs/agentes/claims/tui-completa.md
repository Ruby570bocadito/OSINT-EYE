# Claim: tui-completa

- **Agente:** IMP-2
- **Fecha/hora UTC:** 2026-10-23 17:41 UTC
- **Tarea (ROADMAP · Siguiente v2.3):** TUI Textual navegable con los resultados (tablas, detalle por activo, atajos) — ui/tui_app.py
- **Rutas que voy a tocar:**
  - `ui/tui_app.py` (reescritura: ScanScreen con TabbedContent Overview/Assets/DNS/Network/Findings, filtro de assets, AssetDetailScreen modal con ficha por activo, atajos y Footer; se conservan `_coerce_record_values`, `launch_tui` y la firma de `OSINTEyeTUI`)
  - `tests/test_ui_tui.py` (extensión: lógica pura + pilot tests 100 % offline con asyncio.run; los 3 tests legacy intactos)
  - `osint_eye.py` (SOLO cableado mínimo OWNERSHIP: flag `--tui` + despacho idéntico al bloque `--dashboard`, tras el escaneo)
  - `CHANGELOG.md` (una línea bajo [Unreleased])
- **Diseño:** reutiliza la vista canónica `ui.dashboard._collect_assets` (import perezoso dentro del método — sin duplicar el contrato `results`); ficha de detalle agrega por nombre los módulos que reportan el mismo activo; degradación grácil si flask no está (tabla vacía + aviso, nunca crash); cero red.
- **NO toco:** ui/dashboard.py, ui/rich_cli.py, ui/wizard.py, core/, modules/, reporting/
