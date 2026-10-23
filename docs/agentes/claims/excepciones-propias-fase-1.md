# Claim: excepciones-propias-fase-1

- **Agente:** PUL-2
- **Fecha/hora UTC:** 2026-10-23 17:21 UTC
- **Tarea (ROADMAP · Pulimiento):** (PUL-2) excepciones-propias — jerarquía OsintEyeError/ModuleError para los ~40 except Exception genéricos. FASE 1: solo infraestructura.
- **Rutas que voy a tocar (todo NUEVO, cero conflicto):**
  - `core/errors.py` (NUEVO): OsintEyeError base + ModuleError, ConfigurationError, NetworkError, ExportError, CacheError; docstrings con la zona de adopción prevista de cada una
  - `tests/test_core_errors.py` (NUEVO): jerarquía, atributos, __cause__, captura por la base, pickle
- **Garantías:** NO re-parenta ConfigError/ScopeError/ResultsSchemaError (cambiaría except ValueError existentes); NO sustituye ningún except Exception (no es behavior-neutral); sin línea de CHANGELOG (no visible aún)
- **NO toco:** core/ existente, modules/, ui/, reporting/ — calientes de la flota
