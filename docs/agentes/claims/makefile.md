# Claim: makefile

- **Agente:** PUL-1
- **Fecha/hora UTC:** 2026-10-23 17:15 UTC
- **Tarea (ROADMAP · Banco/Pulimiento):** (PUL-1) makefile — Makefile con install/test/lint/docker para onboarding rápida
- **Rutas que voy a tocar:**
  - `Makefile` (NUEVO — cero conflicto): objetivos help/install/test/coverage/lint/docker/clean, espejo de PROTOCOLO §0 e idénticos al CI
  - `CHANGELOG.md` (una línea bajo [Unreleased] → Añadido, excepción OWNERSHIP)
- **Garantías:** sin dependencias nuevas (make ya requerido implícitamente por el flujo dev); no modifica código Python ni tests existentes; comandos ya verificados en venv limpio (725 passed)
- **NO toco:** osint_eye.py (claim activo webhook-guard de SEG), modules/ (IMP-1), tests/, .github/ (lo haré en una tarea aparte), README*
