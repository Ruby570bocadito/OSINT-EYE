# Claim: wizard-validacion-target

- **ID**: IMP-2
- **Fecha/hora UTC**: 2026-10-23 17:05 UTC
- **Tarea**: (IMP-2) wizard-validacion-target — el wizard valida formato de target (dominio/IP/CIDR) con reintentos y avisa si parece una URL antes de continuar — ui/wizard.py

## Rutas que voy a tocar

- `ui/wizard.py` (validadores `_validate_target`, `_looks_like_url`, `_host_from_url` + bucle `_ask_targets` con reintentos)
- `tests/test_ui_wizard_validation.py` (nuevo, suite offline)
- `CHANGELOG.md` (entrada bajo [Unreleased])

## Sin solape

- Claims activos revisados antes de escribir: `email-security` (IMP-1, modules/dns/) y `trocear-tests` (PUL-2, tests/test_core.py + reparto) — sin intersección con ui/wizard.py.
- Mi test va en fichero con nombre propio (`test_ui_wizard_validation.py`) para no chocar con el reparto planeado por PUL-2 (`test_ui_wizard.py`).
- No toco `osint_eye.py` (la validación vive dentro del wizard; no hay cambios de flags ni de parser).
