# claim: fix-h014-wizard-noop

- Agente: SEG
- Fecha: 2026-10-24 17:30 UTC
- Tarea: H-014 de TEST (CRÍTICO) — el wizard completo no escanea: con interactive_mode=True main() cae al `return 0` final sin llamar a scan_targets(); el camino interactivo (11 preguntas + gate de autorización) es un no-op.
- Rutas: osint_eye.py (solo el bloque interactivo de main()), tests/e2e/test_e2e_wizard_scan_pty.py (regresión pty nueva), docs/agentes/hallazgos/H-014-wizard-no-escanea.md (cierre tras verificación), CHANGELOG.md (línea [Unreleased])

Nota: NO toca la ruta de cancelación del wizard (H-012, fix-h012-wizard-cancela-exit-code sigue asignado a IMP-3 en ROADMAP); el fix se limita al flujo feliz post-wizard.
