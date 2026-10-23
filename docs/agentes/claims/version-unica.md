# Claim: version-unica

- **Agente:** PUL-1
- **Fecha/hora UTC:** 2026-10-23 17:40 UTC
- **Tarea (ROADMAP · Ahora):** (PUL-1) version-unica — única fuente de __version__ en core/ leída por banner CLI; banner dice v2.1 y el repo va por 2.1.1
- **Rutas que voy a tocar:**
  - `core/__init__.py` (añade `__version__ = "2.1.1"` al inicio, antes de los imports)
  - `osint_eye.py` (docstring sin versión + argparse description con f-string `v{__version__}`; 2 líneas, nada más)
  - `pyproject.toml` (`dynamic = ["version"]` + `[tool.setuptools.dynamic] attr = "core.__version__"`; pyproject deja de ser segunda fuente)
  - `.github/workflows/ci.yml` (job badges: leer versión por regex de core/__init__.py; el tomllib de pyproject dejaría de funcionar con dynamic)
  - `tests/test_pul_version.py` (NUEVO: semver + subprocess `--help` offline que exige `v{__version__}` en el banner)
  - `CHANGELOG.md` (línea bajo [Unreleased] → Cambiado)
- **Verificación previa:** sin claims activos sobre estas rutas (fix-h006 IMP-3 va a core/session_cache.py y tests/test_cache_corruption.py; js-secrets IMP-1 a modules/web/; TEST a docs/assets/); `git log --since="5 hours ago"` en las rutas solo muestra releases ya liberados (H-003/H-004, badges propios)
- **NO toco:** ui/rich_cli.py (banner v2.1 → Peticiones a IMP-2), reporting/* y core/scan_diff.py (v1.0/v2.0 en plantillas → Peticiones a IMP-3), modules/, docs/assets/
