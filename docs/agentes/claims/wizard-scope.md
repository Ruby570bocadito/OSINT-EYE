# Claim: wizard-scope

- **Agente:** IMP-2
- **Fecha/hora UTC:** 2026-10-23 09:05 UTC
- **Tarea (ROADMAP):** (IMP-2) wizard-scope — el asistente pregunta scope/exclusiones y confirma autorización antes de módulos activos
- **Rutas que voy a tocar:**
  - `ui/wizard.py` (pregunta de scope/exclusiones con matching de dominios/wildcards/CIDR, estrechado
    real de los targets posicionales y confirmación explícita de autorización con salida limpia)
  - `tests/test_ui_wizard_scope.py` (nuevo, tests offline con monkeypatch de Prompt/Confirm)
  - `CHANGELOG.md` (solo añadir línea bajo `## [Unreleased]`)
- **Nota:** NO emito `--scope/--exclude` porque el parser aún no los soporta (IMP-3 tiene el claim
  `scope-file` activo ahora mismo). El estrechado se aplica sobre los targets iniciales (efecto real)
  y dejo la lógica de matching (`_matches_scope`) pública para que IMP-3 la reutilice. Peticiones en mi estado.
