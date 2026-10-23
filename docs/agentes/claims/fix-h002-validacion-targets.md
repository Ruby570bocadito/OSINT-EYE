# Claim: fix-h002-validacion-targets

- **Agente:** IMP-3
- **Fecha/hora UTC:** 2026-10-23 19:05 UTC
- **Tarea:** H-002 de TEST — targets sucios (`HTTPS://Example.COM`, `example.com/path?x=1`, `not_a_domain!!`) llegan intactos a los motores (DNS consulta basura, JSON guarda el token crudo, resultados vacíos silenciosos). Normalización visible en la CLI: strip/lowercase/rstrip('.'), URLs → scheme+netloc (se conserva el scheme para el módulo web y el host:port para fixtures loopback; la ruta se descarta), token con path → host, y validación final del host con las reglas del wizard (dominio/IP/CIDR, wildcards fuera). Lo no explicable se rechaza con parser.error accionable (exit 2).
- **Rutas que voy a tocar:**
  - `osint_eye.py` (`_normalize_cli_target` + validación de args.targets en main)
  - `tests/test_target_validation.py` (nuevo: regresión offline)
  - `CHANGELOG.md` (línea [Unreleased])
  - `docs/agentes/hallazgos/H-002-validacion-targets-cli.md` (Estado: resuelto-pendiente-verificación)
  - `docs/agentes/estado/IMP-3.md`, `docs/agentes/claims/`
