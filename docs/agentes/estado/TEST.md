# Estado TEST — Tester por personas

Actualizado: 2026-10-24 16:10 UTC · Ronda 5 v2.2 · **Semáforo: 🔴 ROJO** (H-014 CRÍTICO nuevo: el wizard completo no escanea nunca)

## Hecho (últimas 24 h)

- [x] Verificación y CIERRE de H-003, H-004 y H-006 con los repros originales (TTY/entornos limpios): `-o ../../x` → exit 2 accionable sin fichero fuera del CWD; OSC/doble-ESC/BEL → 0 bytes de control (texto inerte); caché corrupta → exit 0, cuarentena `.corrupt` + recreación con WARNING. Commits close: H-003/H-004/H-006.
- [x] Persona plugins: directorio con plugin válido + roto (syntax error) + hostil (run() lanza) → roto reportado y saltado, hostil capturado y registrado en results, válido ejecutado, escaneo EXIT=0 sin traceback. Degradación grácil correcta.
- [x] Persona wizard con TTY real (pty): flujo de cancelación → H-012 sigue abierto (EXIT=0; evidencia refrescada). Flujo feliz → **H-014 CRÍTICO nuevo**: 11 respuestas + autorización 'y' → imprime `args: example.com --depth normal --rich` y sale EXIT=0 SIN escanear nada: main() cae a `return 0` sin llamar a scan_targets() cuando interactive_mode=True. El wizard completo es un no-op.
- Nota UX (propuesta, no hallazgo): 11 prompts consecutivos para un usuario nuevo (cada feature añadió el suyo); los defaults son sensatos pero valoraría un modo avanzado o agrupar.
- Suite al cierre de mi ronda: 880 en verde (los cierres no tocan código).

## En curso

- (nada)

## Bloqueado

- (nada)

## Sin probar (próxima ronda)

- TUI Textual (IMP-2 tiene claim tui-completa activo; probar cuando aterrice), --monitor largo con alertas reales, --agent con Ollama, Docker, Windows/macOS, red lenta/DNS caído/disco lleno.

## Peticiones a otras zonas

- (IMP-3) **H-014 (CRÍTICO) es la prioridad absoluta**: el wizard es la primera experiencia del usuario nuevo y hoy no hace nada. El fix propuesto reutiliza scan_targets + decide_exit_code; un e2e pty como el de H-013 lo cubre.
- (IMP-3) H-012 sigue abierto (cancelación exit 0); H-006 verificado y cerrado esta ronda.
- (IMP-1) H-011 (DKIM p= vacío) sigue abierto: fix pequeño.

## Propuestas para el roadmap

- (IMP-2) wizard-modo-avanzado — agrupar las 11 preguntas del wizard en básicas (target/autorización/depth) + bloque avanzado opt-in (IA, PDF, dashboard, stealth) — ui/wizard.py
- (TEST) fixtures-local-dns — fixture pytest de servidor DNS/HTTP local reutilizable (ya en el Banco; el e2e pty lo reutilizaría)
