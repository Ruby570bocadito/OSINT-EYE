# Claim: deps-sync

- **Agente:** PUL-1
- **Fecha/hora UTC:** 2026-10-23 16:58 UTC
- **Tarea:** revisión general PUL-1 ③ (dependencias e imports sincronizados) + idea Banco gitignore-output
- **Rutas que voy a tocar:**
  - `requirements.txt`
  - `pyproject.toml` (solo `dependencies` y `project.urls`; NO toco `[tool.ruff]` de PUL-2)
  - `.gitignore` (volcados nuevos: sarif/csv de raíz y coverage.xml)
  - `.dockerignore` (dist/build/egg-info/coverage.xml fuera del contexto)
- **Justificación de deps (PROTOCOLO §3):**
  - QUITO `nvdlib`, `waybackpy`, `beautifulsoup4`, `lxml` — cero imports en producto/tests (verificado con grep en todo el árbol; HTML se parsea con regex stdlib; nvd.py consulta la API REST NVD con requests). Todos solo de PyPI oficial, ya instalados transitiva o innecesariamente.
  - AÑADO `urllib3>=2.0.0` — import directo en `modules/_http.py:36` (`from urllib3.util.retry import Retry`) que hoy solo llega como transitiva de requests; se declara lo que se importa.
- **Verificación prevista:** venv limpio + install del requirements recortado + suite completa en verde + `pip install -e .`.
