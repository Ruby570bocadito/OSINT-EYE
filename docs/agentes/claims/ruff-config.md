# Claim: ruff-config

- **Agente:** PUL-2
- **Fecha/hora UTC:** 2026-10-23 16:26 UTC
- **Tarea (ROADMAP):** (PUL-2) ruff-config — configurar ruff (pyflakes, isort, pyupgrade, bugbear) y dejar el repo en 0 avisos sin cambios de comportamiento
- **Rutas que voy a tocar (fase 1, archivos fríos):**
  - `pyproject.toml` (solo añadir `[tool.ruff]`/`[tool.ruff.lint]`; NO toco metadatos/extras de PUL-1)
  - Fixes automáticos + manuales SOLO en archivos sin actividad IMP <3 h y sin claim activo:
    - `core/`: `scan_diff.py`, `correlator.py`, `session_cache.py`, `async_engine.py`, `plugins.py`, `__init__.py`
    - `modules/network/scanner.py`, `modules/osint/whois.py`
    - `reporting/mitre_mapper.py`, `reporting/__init__.py`
    - `ai/llm_engine.py`, `ai/__init__.py`
    - `graph/neo4j_exporter.py`, `graph/__init__.py`
    - `ui/tui_app.py`, `ui/__init__.py`
    - `modules/{dns,network,osint,web,certs,cve}/__init__.py`
- **NO toco (fase 2, calientes — IMP <3 h o claim activo):** `core/{schema,scope,monitor,logging_config}.py`, `osint_eye.py`, `graph/builder.py`, `reporting/{export,export_tools,markdown_reporter,pdf_reporter}.py`, `ui/{rich_cli,wizard,dashboard}.py`, `modules/{_http,dns/*,web/*,osint/github,google,cloud_email,cve/nvd,certs/cert_scanner}.py`, tests nuevos de IMP.
- **Verificación previa:** baseline 371 passed offline; inventario ruff: 689 avisos (615 auto-fix), ~196 en archivos fríos de esta lista; los 11 avisos F restantes están en archivos de IMP-1/IMP-3 (ya solicitados por PUL-1 en su estado).
- **Sin cambios de comportamiento:** los fixes son import-sort/pyupgrade mecánicos; B905 con strict=True (longitud 1:1 garantizada por gather); UP041 auto (alias py3.10); B005 en mitre_mapper se preserva con noqa justificado (semántica de charset intencional).
