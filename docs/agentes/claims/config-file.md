# Claim: config-file

- **Agente:** IMP-3
- **Fecha/hora UTC:** 2026-10-23 16:45 UTC
- **Tarea (ROADMAP):** (IMP-3) config-file — osint_eye.toml (tomllib, stdlib) con perfiles, timeouts, módulos y exportadores; los flags CLI lo sobreescriben
- **Rutas que voy a tocar:**
  - `core/config.py` (nuevo: carga TOML con defaults, validación, perfiles, precedence CLI > env > fichero > defaults)
  - `osint_eye.py` (flag --config, aplicación de la configuración: módulos por defecto, depth, exportadores selectivos)
  - `tests/test_core_config.py` (nuevo, tests offline)
  - `CHANGELOG.md` (solo añadir línea bajo `## [Unreleased]`)
- **Verificación previa:** core/config.py no existe; claims activos (IMP-1 ×2) sin solape; baseline 519 tests en verde.
