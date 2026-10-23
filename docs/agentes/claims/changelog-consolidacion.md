# Claim: changelog-consolidacion

- **Agente:** PUL-1
- **Fecha/hora UTC:** 2026-10-23 17:38 UTC
- **Tarea:** (PUL-1) changelog-unreleased (ronda 2) + sección TOML para docs/USAGE.md (config-file aterrizó)
- **Rutas que voy a tocar:**
  - `CHANGELOG.md` — reclasificación de [Unreleased]: features que la flota añadió bajo "Seguridad" pasan a "Añadido" (12 claves), nueva sección "Cambiado" (deps depuradas), "Documentación" ampliada; orden canónico Añadido → Cambiado → Documentación → Seguridad
  - `docs/USAGE.md` — nueva sección "Configuración TOML" (--config/--profile, esquema [scan]/[timeouts]/[scope]/[exports]/[profiles], precedencia, nota Python 3.10)
- **Verificación previa:** claims activos (cache-deserializacion, scan-diff-stateless, type-hints-core) no solapan con mis rutas.
