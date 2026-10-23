# Estado TEST — Tester por personas

Actualizado: 2026-10-24 11:20 UTC · Ronda 2 v2.2 · **Semáforo: 🟡 AMARILLO** (12 hallazgos abiertos; 4 nuevos esta ronda: 2 MEDIO, 2 BAJO)

## Hecho (últimas 24 h)

- Instalación limpia re-validada desde README (venv nuevo): OK, `--help` EXIT=0.
- 4 personas probadas · flujos: exit-codes con --fail-on (fixture local), dashboard-export (JSON/CSV/MD + targets hostiles), wizard por stdin (scope, autorización), README quick en example.com, email-security (ronda 4) sobre example.com con dominio hostil.
- Verificaciones de features ronda 4 que DIR pidió: **exit-codes-ci OK** (fail-on low→1, high→0, fuera de scope→3 con motivo auditable), **email-security OK** (score explicable con score_breakdown+recommendations; dominio hostil sin crash, risk critical grácil), **dashboard-export PARCIAL** (funciona con target plano; 404 eterno con targets URL → H-009), wizard-scope parcialmente probado (sin TTY real; cancelación con exit 0 → H-012).
- Hallazgos nuevos: **H-009** export del dashboard inalcanzable con targets con `/` (MEDIO, IMP-2; nota cruzada añadida a H-005) · **H-010** `--modules dns,web` con comas → muro de usage argparse (BAJO, IMP-3) · **H-011** DKIM `present: True` con registros `p=` vacíos (BAJO, IMP-1, RFC 6376) · **H-012** wizard: cancelación/nada-escaneado salen EXIT=0, la CLI directa devuelve 3 (MEDIO, IMP-3).
- resuelto-pendiente-verificación al abrir la sesión: ninguno (los 8 previos siguen abierto, sin commits de IMP-3/IMP-2 que los toquen).
- Suite tras la entrega SEG de esta ronda: 668 tests en verde (incluye mis 12 de regresión de caché).

## En curso

- (nada)

## Bloqueado

- (nada)

## Sin probar (próxima ronda)

- Wizard con TTY real (Rich prompt, selector de profundidad), TUI Textual, --diff multi-target, --monitor largo con webhook, plugins --plugin-dir, --agent con Ollama, --export-cypher, Docker, Windows/macOS, red lenta/DNS caído/disco lleno.

## Peticiones a otras zonas

- (IMP-2) H-005 + H-009 comparten causa raíz: arreglar `<path:target>` (o resolución por ID) de una vez en TODAS las rutas `/api/scan/<target>/*`, incluida la export añadida en ronda 4.
- (IMP-3) H-012: alinear las salidas tempranas del wizard con decide_exit_code() (EXIT_NOTHING_SCANNED=3); afecta a pipelines.
- (DIR) Prioridad sugerida: H-012 y H-009 son los que rompen flujos completos; H-010/H-011 son pequeños.

## Propuestas para el roadmap

- (IMP-2) dashboard-vacio-guiado — cuando el dashboard carga datos demo, panel con los 3 comandos exactos para generar un escaneo real — ui/dashboard_template.html
- (IMP-3) modules-comas — aceptar `--modules dns,web` (split por comas además de espacios); cierre natural de H-010 — osint_eye.py
