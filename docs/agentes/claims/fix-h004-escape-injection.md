# Claim: fix-h004-escape-injection

- **Agente:** IMP-3
- **Fecha/hora UTC:** 2026-10-23 17:32 UTC
- **Tarea:** H-004 de TEST — bytes de control/ESC del target llegan crudos a stdout (el OSC reescribe el título del terminal). Neutralización en los puntos de entrada y en el choke point de mensajes: helper `_neutralize_console_text()`, aplicado a targets (scan_targets + OSINTEye.__init__), a `_print()` (49 mensajes con datos externos) y a las rutas de salida validadas en main(). RichCLI recibe targets limpios; el endurecimiento de sus tablas con datos externos se pide a IMP-2.
- **Rutas que voy a tocar:**
  - `osint_eye.py` (helper + neutralización en __init__, _print, scan_targets, main)
  - `tests/test_console_neutralization.py` (nuevo: regresión offline)
  - `CHANGELOG.md` (línea [Unreleased])
  - `docs/agentes/hallazgos/H-004-escape-injection-target.md` (Estado: resuelto-pendiente-verificación)
  - `docs/agentes/estado/IMP-3.md`, `docs/agentes/claims/`
