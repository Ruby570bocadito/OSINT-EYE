# Zonas — OSINT EYE

| ID | Rol | Rutas que puede modificar/borrar |
|----|-----|----------------------------------|
| DIR | Director | docs/agentes/ROADMAP.md, docs/agentes/OWNERSHIP.md, docs/agentes/PROTOCOLO.md, docs/agentes/PROMPTS.md, limpieza de docs/agentes/claims/ (claims >3 h) |
| IMP-1 | Colectores (fuentes de datos) | modules/ (dns, certs, web, network, osint, cve y módulos nuevos), data/wordlists/, tests/test_modules_*.py, tests/fixtures/modules/ |
| IMP-2 | Interfaz (CLI, TUI, dashboard) | ui/ (rich_cli, wizard, tui_app, dashboard, dashboard_template.html), docs/assets/, tests/test_ui_*.py |
| IMP-3 | Núcleo, análisis y salidas | osint_eye.py, core/, graph/, reporting/, ai/, tests/test_core_*.py, tests/test_reporting_*.py, tests/fixtures/scans/ |
| PUL-1 | Pulimiento: repo y documentación | README.md, docs/USAGE.md, docs/ (salvo docs/agentes/ y docs/assets/), CHANGELOG.md, LICENSE, .gitignore, requirements*.txt, pyproject.toml, Dockerfile, .dockerignore, .github/, árbol de carpetas, archivos muertos/duplicados en todo el repo |
| PUL-2 | Pulimiento: calidad de código | Refactors sin cambio de comportamiento en cualquier .py (tipado, docstrings, nombres, imports, duplicados, código muerto dentro de archivos), configuración de lint/format (ruff), troceado de tests/test_core.py, consistencia visual de CLI/dashboard (solo apariencia) |
| SEG | Seguridad + bugs | Solo fixes mínimos de bugs/vulnerabilidades en cualquier ruta, siempre con claim previo y test de regresión |
| TEST | QA por personas | tests/e2e/, docs/agentes/hallazgos/ (crea y cierra hallazgos). NUNCA modifica código de producto |

## Reglas de convivencia

- PUL-1 y PUL-2 no refactorizan ni mueven una ruta con claim activo de otro agente.
- PUL-1 mueve/borra archivos; PUL-2 cambia el contenido del código. Si un refactor de PUL-2 exige mover archivos, lo pide a PUL-1 en "Peticiones" (o reclama ambas rutas y lo menciona en el claim).
- PUL-2 no toca un archivo que un IMP haya modificado en las últimas 3 h (`git log --since="3 hours ago" -- <archivo>`).
- Contratos entre zonas: el dict `results` (`results["modules"][<nombre>]`) que producen los colectores (IMP-1) y consumen núcleo/salidas (IMP-3) y la UI (IMP-2). Cambiar su forma exige: claim de IMP-3 sobre core/schema.py (cuando exista), actualización de los consumidores, y nota en "Peticiones" de los demás IMP.
- Si se lanzan más instancias (p. ej. IMP-4 para modules/osint/), DIR añade antes una fila aquí y recorta la zona de origen.
