# Claim: usage-sync

- **Agente:** PUL-1
- **Fecha/hora UTC:** 2026-10-24 17:50 UTC
- **Tarea (Banco · Pulimiento):** docs/USAGE.md sincronizado con los flags actuales (--profile, --monitor, exports) con ejemplos probados — docs/USAGE.md
- **Rutas que voy a tocar:**
  - `docs/USAGE.md` (nuevos: --tui, --modules con comas + error accionable H-010, catálogo completo de claves --modules incl. shodan_censys/reverse_ip/social_footprint/leak_check y pasos correlation/graph/mitre/chains, confinamiento de -o H-003, auto-persistencia H-001, Ctrl+C 130 H-007, cuarentena de caché H-006, guard de --webhook, --export-cypher, contrato BaseModule + link a docs/plugins.md; ejemplos verificados offline)
  - `docs/index.md` (corrección menor de docs-sitio: los 12 colectores no agotan el catálogo --modules; link a la tabla completa en USAGE)
  - `CHANGELOG.md` (línea bajo [Unreleased] → Añadido/Documentación)
- **Garantías:** ejemplos solo de rutas offline (--modules, errores de uso con exit 2); ningún escaneo real en la verificación; sin tocar código
- **NO toco:** osint_eye.py, ui/, tests/
