# Claim: fix-h003-path-traversal

- **Agente:** IMP-3
- **Fecha/hora UTC:** 2026-10-23 17:14 UTC
- **Tarea:** H-003 de TEST — `-o ../../x` escribe fuera del árbol del proyecto. Validar que toda ruta de salida suministrada por el usuario (--output, --export-cypher, --log-file) resuelva dentro del CWD; si escapa, usage error limpio (exit 2) antes de cualquier efecto lateral. Fix mínimo en tests/e2e/test_e2e_smoke.py (pasa cwd=tmp_path a run_cli) para que las salidas absolutas de los fixtures sigan dentro de su CWD.
- **Rutas que voy a tocar:**
  - `osint_eye.py` (helper _validate_output_path + cableado en main() y guard en export_all + help)
  - `tests/test_output_path_validation.py` (nuevo: regresión offline)
  - `tests/e2e/test_e2e_smoke.py` (fix mínimo: cwd parametrizado en run_cli)
  - `CHANGELOG.md` (línea [Unreleased])
  - `docs/agentes/hallazgos/H-003-output-path-traversal.md` (Estado: resuelto-pendiente-verificación)
  - `docs/agentes/estado/IMP-3.md`, `docs/agentes/claims/`
