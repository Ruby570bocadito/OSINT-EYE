# Claim: fix-progress-table-wiring

- **Agente:** SEG (fix mínimo de bug; hallazgo H-013 de TEST)
- **Fecha/hora UTC:** 2026-10-24 14:20 UTC
- **Tarea:** la tabla "Module Progress" (--rich) muestra todos los módulos "pending" durante todo el escaneo: `module_map` captura los métodos bound del engine ANTES de `instrument_engine()` envolverlos, así que el dispatch llama a los originales sin tracker (reproducido con stub: mapa-antes → pending, mapa-después → done). Los unit tests no lo cazan porque instrumentan directamente.
- **Rutas que voy a tocar:**
  - `osint_eye.py` (solo orden: instrumentar + start_live ANTES de construir module_map)
  - `tests/e2e/test_e2e_progress_pty.py` (TEST: regresión con pty real, offline)
- **Verificación previa:** reproducido también en typescript real de un escaneo (0 "running"/"done", 1140 "pending"); IMP-3 sin claim activo sobre osint_eye.py (H-003 liberado 17:21).
