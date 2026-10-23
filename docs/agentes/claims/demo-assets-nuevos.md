# Claim: demo-assets-nuevos

- **Agente:** IMP-2
- **Fecha/hora UTC:** 2026-10-24 06:40 UTC
- **Tarea (ROADMAP · 🔴 ALTA, petición directa del propietario):** capturas reales de la UI ACTUAL con fixtures offline (loopback tipo TEST e2e, dominios example.com/fixture, nada de datos reales de terceros)
- **Rutas que voy a tocar:**
  - `docs/assets/dashboard-dark.png` (NUEVO — dashboard oscuro con escaneo cargado, filtros visibles)
  - `docs/assets/cli-progress.png` (NUEVO — Rich CLI con tabla progreso-por-módulo)
  - `docs/assets/wizard-auth.png` (NUEVO — wizard en el paso de autorización)
  - `docs/assets/report-pdf.png` (NUEVO — primera página del PDF)
  - `docs/assets/graph-view.png` (NUEVO — vista grafo)
  - `docs/assets/demo-scan.gif` (NUEVO — ≤15 s, <5 MB: quick scan → navegación del dashboard)
  - `docs/assets/demo-scan.mp4` (NUEVO, opcional — ≤30 s)
  - `CHANGELOG.md` (una línea bajo [Unreleased])
- **Método:** dashboard Flask local (127.0.0.1) con fixture JSON offline + capturas headless (agent-browser/Chromium, viewport 1440x900, tema oscuro del propio dashboard); Rich `export_svg` del tracker real de progreso-por-módulo y del wizard real con respuestas scripted; PDF generado con reporting/pdf_reporter.py sobre el fixture y rasterizado con pdftoppm (poppler). Nada de esto entra en requirements.txt: son herramientas de generación locales.
- **NO toco:** ui/, core/, modules/, reporting/, tests/, README* (PUL-1 cableará los assets en readme-en-desde-cero)
- **Garantías:** fixtures solo con example.com/localhost; borradores en .agent-tmp/; sin dependencias nuevas en el proyecto
