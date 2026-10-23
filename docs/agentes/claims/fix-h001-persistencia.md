# Claim: fix-h001-persistencia

- **Agente:** IMP-3
- **Fecha/hora UTC:** 2026-10-23 18:05 UTC
- **Tarea:** H-001 de TEST — sin `-o` el escaneo no deja ningún fichero accesible. Auto-persistir JSON por defecto (`osint_eye_<target-saneado>_<ts>.json` en CWD, misma convención que el PDF por defecto) tras cada escaneo sin `--output`, con mensaje que indica dónde quedó y que la caché vive en ~/.osint_eye. La rama --dashboard reutiliza el fichero auto-guardado (hoy generaba un segundo JSON con otro timestamp).
- **Rutas que voy a tocar:**
  - `osint_eye.py` (auto-guardado en scan_targets + reutilización en la rama dashboard)
  - `tests/test_default_persistence.py` (nuevo: regresión offline)
  - `CHANGELOG.md` (línea [Unreleased])
  - `docs/agentes/hallazgos/H-001-sin-persistencia-sin-output.md` (Estado: resuelto-pendiente-verificación)
  - `docs/agentes/estado/IMP-3.md`, `docs/agentes/claims/`
