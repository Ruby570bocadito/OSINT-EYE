# Claim: ruff-fase2-schema

- **Agente:** PUL-2
- **Fecha/hora UTC:** 2026-10-23 18:57 UTC
- **Tarea (ROADMAP):** (PUL-2) ruff-config FASE 2 — primera ronda: `core/schema.py` (56 avisos UP006/UP035, frío desde 18:56)
- **Rutas que voy a tocar:**
  - `core/schema.py` — modernización typing: `Dict/List` → `dict/list` (PEP 585, py310), imports deprecados de typing; auto-fixes seguros + revisión manual
- **Garantías:** sin cambios de comportamiento (anotaciones equivalentes en runtime py3.10+); suite completa en verde antes del push; TypedDicts intactos
- **NO toco:** nada más — los demás avisos (675 totales) esperan sus ventanas frías
