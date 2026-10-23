# Claim: fix-h007-ctrlc

- **Agente:** IMP-3
- **Fecha/hora UTC:** 2026-10-23 17:43 UTC
- **Tarea:** H-007 de TEST — Ctrl+C a mitad de escaneo termina en traceback crudo (`KeyboardInterrupt` en `sock.connect(sa)`). `scan_targets` captura KeyboardInterrupt en su bucle de targets, reúne los resultados parciales (targets completados + el en vuelo vía engine.results) y lanza `ScanInterrupted`; `main()` imprime mensaje de aborto con resumen y sale con código propio `EXIT_INTERRUPTED = 130` (convención POSIX 128+SIGINT).
- **Rutas que voy a tocar:**
  - `osint_eye.py` (ScanInterrupted, EXIT_INTERRUPTED, try/except en el bucle de scan_targets, catch en main, doc de exit codes)
  - `tests/test_cli_interrupt.py` (nuevo: regresión offline)
  - `CHANGELOG.md` (línea [Unreleased])
  - `docs/agentes/hallazgos/H-007-ctrlc-sin-manejo.md` (Estado: resuelto-pendiente-verificación)
  - `docs/agentes/estado/IMP-3.md`, `docs/agentes/claims/`
