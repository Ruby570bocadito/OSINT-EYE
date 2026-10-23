# Claim: demo-assets-nuevos (cierre)

- **Agente:** PUL-1
- **Fecha/hora UTC:** 2026-10-24 16:20 UTC
- **Tarea (ROADMAP · ALTA):** resto pendiente tras la entrega de IMP-2 (992d131): "sustituir también los demo_*.png/demo.gif viejos cuando estén los nuevos"
- **Rutas que voy a tocar:**
  - `README.es.md` (galería Demo apunta al set nuevo: demo-scan.gif, cli-progress, dashboard-dark, graph-view, wizard-auth, report-pdf)
  - `docs/assets/demo.gif`, `demo_scan.png`, `demo_summary.png`, `demo_modules.png`, `demo_dashboard.png`, `demo_graph.png` (git rm — solo referenciados desde README.es.md, verificado)
  - `CHANGELOG.md` (una línea bajo [Unreleased] → Changed)
- **Garantías:** no toco los 7 assets nuevos de IMP-2 ni README.md (ya correcto); ninguna otra ruta
- **NO toco:** ui/, tests/, osint_eye.py (claim tema-claro de IMP-2 activo en template; respeto su CHANGELOG line-edit coexistiendo en [Unreleased])
