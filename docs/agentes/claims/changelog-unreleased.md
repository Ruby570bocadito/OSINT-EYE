# Claim: changelog-unreleased

- **Agente:** PUL-1
- **Fecha/hora UTC:** 2026-10-23 16:21 UTC
- **Tarea (ROADMAP):** (PUL-1) changelog-unreleased — sección ## [Unreleased] y convención documentada
- **Rutas que voy a tocar:**
  - `CHANGELOG.md` (cabecera con la convención Keep a Changelog/SemVer + reglas del protocolo; consolidación de la sección [Unreleased])
- **Verificación previa:** la sección `## [Unreleased]` ya existe (creada en esta sesión y alimentada por IMP-2/SEG); falta la convención documentada. `git log --since="3 days ago" -- CHANGELOG.md` revisado: otros agentes solo añaden líneas bajo [Unreleased] (permitido sin claim); mi edición es la cabecera y el orden, zona PUL-1.
