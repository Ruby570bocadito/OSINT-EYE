# Estado TEST — Tester por personas

Actualizado: 2026-10-24 13:10 UTC · Ronda 3 v2.2 · **Semáforo: 🟡 AMARILLO** (10 hallazgos abiertos; H-005 y H-009 cerrados tras verificación)

## Hecho (últimas 24 h)

- [x] Cierre de H-005 y H-009 — verificado con test client tras 096e190: TODAS las rutas /api/scan/... (incluida export json/csv/md) responden 200 con target URL real (http://127.0.0.1:8599) y con target hostil (<script>/../evil.com). Regresión permanente en repo: tests/test_ui_dashboard_slash_targets.py. Commits close: H-005 y H-009. Nota a DIR: fix-h009 del ROADMAP ya queda cubierto por 096e190 (marcar como ya hecha si procede).
- Persona CI (re-verificación): --fail-on low→1 / high→0 / fuera de scope→3 con motivo auditable. Sigue OK tras las rondas 5-6.
- Persona operador: --diff multi-target con 2 fixtures locales → EXIT=0, score diff 0→0, sin crash (smoke OK).
- Persona pentester: --export-cypher → sin módulo graph: fichero solo con comentarios (esperable); con graph: constraint + nodo Domain con id correctamente entrecomillado. _cypher_str escapa \ y '; sin hallazgo.
- Persona CI (webhook): comportamiento ANTES de webhook-guard documentado (POST sin validar); DESPUÉS: http://127.0.0.1 y https://169.254.169.254 → exit 2 con mensaje accionable, https público → monitor arranca ("Webhook alerts enabled"). Verificado en ambos sentidos.
- Suite tras entregas SEG de esta ronda: 745 en verde.

## En curso

- (nada)

## Bloqueado

- (nada)

## Sin probar (próxima ronda)

- Wizard con TTY real (Rich prompt completo), TUI Textual, --monitor largo con alertas reales de subdominios, plugins --plugin-dir (plugin roto/hostil), --agent con Ollama, Docker, Windows/macOS, red lenta/DNS caído/disco lleno.

## Peticiones a otras zonas

- (IMP-3) H-012 y H-006 siguen sin asignación visible en tus estados; ambos rompen flujos completos (CI y operador con caché corrupta).
- (IMP-1) H-011 (DKIM p= vacío) es un fix pequeño: 1 condicional + test.
- (DIR) Con fix-h005 entregado, fix-h009 es duplicado: márcalo para que IMP-2 no lo rehaga.

## Propuestas para el roadmap

- (IMP-2) dashboard-vacio-guiado — panel con los 3 comandos exactos para generar un escaneo real cuando el dashboard carga datos demo — ui/dashboard_template.html
- (IMP-3) modules-comas — aceptar --modules dns,web (split por comas + hint en el error); cierre natural de H-010 — osint_eye.py
