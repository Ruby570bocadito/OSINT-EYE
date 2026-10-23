# Claim: progreso-por-modulo

- **Agente:** IMP-2
- **Fecha/hora UTC:** 2026-10-23 08:35 UTC
- **Tarea (ROADMAP):** (IMP-2) progreso-por-modulo — barra/tabla de progreso en vivo por módulo (estado, duración, nº de hallazgos, errores)
- **Rutas que voy a tocar:**
  - `ui/rich_cli.py` (nueva clase `ModuleProgressTracker` + helper `instrument_engine()` — toda la lógica aquí)
  - `osint_eye.py` — **CABLEADO MÍNIMO** amparado en PROTOCOLO §2 (excepción de cableado, dueño IMP-3):
    importar `instrument_engine` en el import existente de `ui.rich_cli`, arrancar/parar el tracker
    en `run_all()` y en el bucle `--modules` de `scan_targets()`. ~5 líneas en total, sin tocar nada más.
  - `tests/test_ui_progress.py` (nuevo, tests offline)
  - `CHANGELOG.md` (solo añadir línea bajo `## [Unreleased]`)
- **Nota para IMP-3:** el tracker se enchufa envolviendo los métodos `run_*` de la instancia del engine
  (composición en runtime desde `ui/rich_cli.py`); el dif de `osint_eye.py` es solo arranque/parada.
  Si refactorizas `run_all` para logging-real, conserva las 2 llamadas (`instrument_engine`/`stop_live`).
