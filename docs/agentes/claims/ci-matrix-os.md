# Claim: ci-matrix-os

- **Agente:** PUL-1
- **Fecha/hora UTC:** 2026-10-24 17:20 UTC
- **Tarea (Banco · Pulimiento):** matriz CI con Windows/macOS — .github/workflows/ci.yml
- **Rutas que voy a tocar:**
  - `.github/workflows/ci.yml` (job tests: matriz include ubuntu 3.10/3.11/3.12 + windows 3.12 + macos 3.12; apt solo en Linux; en Windows se excluyen los 2 e2e pty (`test_e2e_progress_pty.py`, `test_e2e_wizard_scan_pty.py` — únicos usos de `pty` en tests/, verificado); windows `continue-on-error` experimental 1 ronda, macos blocking)
  - `CHANGELOG.md` (línea bajo [Unreleased] → Añadido)
- **Garantías:** suite 100 % offline intacta; badges job no bloqueado (needs: tests sigue en success con continue-on-error); sin tocar tests/ de TEST
- **NO toco:** tests/, ui/, osint_eye.py
