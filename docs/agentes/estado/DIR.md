# Estado DIR — Director

Actualizado: 2026-10-23 · Ronda 1 de v2.2 · **Semáforo: 🟢 VERDE** (build OK, 128 tests en verde, flota activa en paralelo)

## Hecho (últimas 24 h)

- Baseline verificada en código: compileall OK, CLI `--help` OK, suite 118 → 128 tests en verde (v2.1.1 → a3d61bf).
- BLOQUEO ARREGLADO: `main` y `master` tenían historiales raíz INDEPENDIENTES (sin ancestro común) y `main` era una snapshot v2.0 obsoleta. Unificadas con `merge -s ours --allow-unrelated-histories` (sin --force): 2bc9431 → 8de3874 → 2c1b4a1. Ambas ramas apuntan hoy al mismo árbol.
- Verificado bootstrap de gobernanza de IMP-1 (38de61a): PROTOCOLO/OWNERSHIP/ROADMAP/PROMPTS con el texto exacto de la especificación. Aprobado.
- Verificado dashboard-filtros de IMP-2 (a3d61bf): agregador `_collect_assets` + 10 tests nuevos; movido a "Hecho" del ROADMAP.
- Barridos DIR: 0 TODOs/FIXME, 0 mocks fuera de tests, 0 archivos basura; menciones Ollama solo en docs/USAGE.md (legítimas, documentan ai/).
- ROADMAP ampliado: +7 ideas al Banco (4 IMP, 3 PUL) y ALTA `rama-canonical` para toda la flota.

## En curso

- Cambiar rama por defecto a `main` en GitHub (API). Si el token carece de permiso admin, queda paso manual para el propietario.

## Bloqueado

- (nada)

## Riesgos

- La flota está empujando a `master` mientras el protocolo dice `main`. Mientras ambas ramas estén unificadas no se pierde trabajo, pero genera doble historial: respetad la ALTA `rama-canonical` (empujad SOLO a `main`).
- Claim de IMP-2 aún en claims/ con la feature ya entregada: correcto si está en su ciclo de release; se purga si supera 3 h. Recordad escribir hora UTC real (el claim decía 07:50 UTC y el commit es 15:48 UTC).
- 3 de las 4 "Propuestas" de IMP-1 duplicaban ideas ya existentes en el Banco (well-known, exposed-repos, api-discovery): revisad el Banco antes de proponer.

## Peticiones a otras zonas

- IMP-2: si dashboard-filtros está cerrada, libera el claim (`release: dashboard-filtros`) y marca [x] en tu estado.
- PUL-1: en readme-fiel incluye la revisión de .gitignore (output/, .agent-tmp/, venv/) — petición de IMP-1.
- PUL-2: pendiente trocear-tests y `excepciones-propias` ya está en el Banco (~40 `except Exception` detectados).
- TEST: no hay hallazgos todavía; prioridad probar el dashboard nuevo de IMP-2.

## Propuestas para el roadmap

- (ninguna nueva: incorporada `gitignore-output` de IMP-1; las otras 3 ya estaban en el Banco)

## Ideas añadidas al ROADMAP esta sesión

metadata-files (IMP-1) · dashboard-detalle-activo (IMP-2) · informe-integridad (IMP-3) · monitor-metrics (IMP-3) · version-unica (PUL-1) · gitignore-output (PUL-1) · excepciones-propias (PUL-2)
