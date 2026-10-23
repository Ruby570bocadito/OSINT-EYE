# Claim: readme-fiel

- **Agente:** PUL-1
- **Fecha/hora UTC:** 2026-10-23 15:51 UTC
- **Tarea (ROADMAP):** (PUL-1) readme-fiel — badges reales (versión 2.1.1, 118 tests), árbol actualizado, comandos probados desde cero, sección Roadmap enlazada a docs/agentes/ROADMAP.md
- **Rutas que voy a tocar:**
  - `README.md` (badges de versión/tests, cifras reales, roadmap enlazado)
  - `CHANGELOG.md` (solo añadir línea bajo `## [Unreleased]`)
- **Verificación previa:** venv limpio creado desde cero en esta sesión; `pip install -r requirements.txt` + `python osint_eye.py --help` OK; `pytest -q tests/` = 118 passed; `git log --since="3 days ago" -- README.md` = sin cambios recientes de otros agentes.
