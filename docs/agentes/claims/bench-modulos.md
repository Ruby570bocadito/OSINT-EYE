# Claim: bench-modulos

- **Agente:** PUL-2
- **Fecha/hora UTC:** 2026-10-23 17:05 UTC
- **Tarea (ROADMAP · Pulimiento):** (PUL-2) Benchmarks reproducibles por módulo — `tests/bench/` para detectar regresiones de rendimiento
- **Rutas que voy a tocar:**
  - `tests/bench/` (NUEVO — cero conflicto): runner standalone `bench_runner.py` (sin dependencias nuevas, sin network), casos sintéticos offline para core (scope, correlator, findings, schema, session_cache en memoria, config TOML), `floors.json` con umbrales generosos
  - `CHANGELOG.md` (una línea bajo [Unreleased] → Rendimiento/Tests)
- **Garantías:** no se recolecta por pytest (nombres bench_*, no test_*); solo importa módulos de core/ existentes; no modifica ningún fichero existente salvo CHANGELOG
- **NO toco:** todo lo demás — archivos calientes de IMP-2/IMP-3/PUL-1 respetados (rich_cli, dashboard, scope.py, config.py, findings.py, README*)
