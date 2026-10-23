# Protocolo de trabajo de los agentes — OSINT EYE

Fuente única de reglas. Todos los prompts (PROMPTS.md) apuntan aquí.
Equipo: DIR · IMP-1 · IMP-2 · IMP-3 · PUL-1 · PUL-2 · SEG · TEST (zonas en OWNERSHIP.md).

## 0. Comandos del proyecto

```
python -m venv venv && . venv/bin/activate
pip install -r requirements.txt pytest
python -m compileall -q osint_eye.py core graph ai modules ui reporting tests   # compila
PYTHONPATH=. pytest -q tests/                                                   # tests offline (deben pasar siempre)
python osint_eye.py --help                                                      # smoke test CLI
```

Los tests son 100 % offline: ningún test nuevo puede depender de la red, de nmap ni de Ollama (usa fixtures, monkeypatch o respuestas grabadas en tests/fixtures/).

## 1. Ciclo por tarea (obligatorio)

1. `git pull --rebase origin main`
   Lee docs/agentes/ROADMAP.md, docs/agentes/OWNERSHIP.md, los docs/agentes/estado/*.md de los demás y los hallazgos abiertos dirigidos a tu ID en docs/agentes/hallazgos/ (los CRÍTICO/ALTO van antes que el ROADMAP; usa el id del hallazgo como slug del claim; al arreglarlo, pon `Estado: resuelto-pendiente-verificación` en el archivo e indica el commit; NO lo borres, lo cierra TEST).
2. Elige UNA tarea de tu zona. Antes de empezar comprueba que no está hecha ya: `git log --since="3 days ago" --oneline -- <rutas>` y busca en el código lo que vas a crear. Si ya existe, no lo rehagas: márcala en tu estado como "ya hecha" para que DIR la tache y pasa a otra.
3. RECLAMA la tarea (cerrojo):
   - Crea docs/agentes/claims/<slug-de-la-tarea>.md con: tu ID, fecha/hora UTC, rutas que vas a tocar.
   - Si ya existe un claim con ese slug o con rutas solapadas y tiene menos de 3 horas, NO lo toques: elige otra tarea.
   - `git add` solo ese archivo, commit `claim: <slug> (<ID>)`, `git push origin HEAD:main`.
   - Si el push es rechazado: `git pull --rebase`, vuelve a mirar claims. Si alguien reclamó antes, elige otra tarea.
4. Trabaja solo en las rutas reclamadas. Commits pequeños y atómicos (Conventional Commits: `feat(dns): ...`, `fix(dashboard): ...`, `refactor(core): ...`, `docs: ...`, `test: ...`, `chore: ...`).
5. Antes de CADA push: `git pull --rebase origin main`, compila, `pytest -q tests/`, y push.
   - Push rechazado: repite pull --rebase y push (hasta 3 veces).
   - Conflicto: resuélvelo conservando la intención de AMBOS cambios. Nunca `--force`, nunca descartes el trabajo ajeno.
   - Tests en rojo por tu cambio: no hagas push. Tests en rojo por cambio ajeno: avisa en "Peticiones" al dueño.
6. Al terminar: borra tu claim (commit `release: <slug>`), marca la tarea [x] en tu estado (no en el ROADMAP: el ROADMAP solo lo edita DIR), actualiza tu estado/<ID>.md, push.
7. Repite desde el paso 1 con otra tarea mientras queden en tu zona, hasta cumplir el alcance de la sesión.

## 2. Zonas

Solo modificas, mueves o borras archivos de tu zona (ver OWNERSHIP.md). Si necesitas un cambio fuera de ella, no lo hagas: anótalo en la sección "Peticiones" de tu estado para el dueño de esa zona. Excepciones:

- Un fallo que rompe el build o los tests para todos: arréglalo mínimo y menciónalo.
- Registrar un módulo/flag nuevo en osint_eye.py (dueño IMP-3): cualquier IMP puede añadir el cableado mínimo (import + registro en el catálogo + flag), con claim sobre osint_eye.py y sin tocar nada más del archivo.
- Tests: cada zona añade sus tests en su propio archivo tests/test_<zona>_*.py. No añadas más tests a tests/test_core.py (es un archivo heredado que PUL-2 va a trocear).

## 3. Higiene del repo

- Borradores, volcados, logs, salidas de escaneo y pruebas sueltas: SOLO en .agent-tmp/ (ignorado por git). Nunca en la raíz ni en carpetas del proyecto. Las salidas reales de la herramienta van a output/ (ignorado).
- Escaneos de prueba: solo contra example.com, localhost, o fixtures. Nunca contra dominios de terceros.
- No crees archivos nuevos de documentación salvo que el ROADMAP lo pida. Los informes viven en estado/<ID>.md (se sobrescriben).
- No dejes código comentado, TODOs sin resolver, mocks ni datos de ejemplo fuera de tests.
- Nada de menciones a IA/modelos/asistentes en commits, código, comentarios, docs (el módulo ai/ y Ollama son funcionalidad del producto y sí se documentan). Identidad git: la ya configurada, no la cambies.
- Cualquier dependencia nueva: justificarla en el commit, solo desde PyPI oficial, y añadirla a requirements.txt en el mismo commit. Preferencia fuerte por la librería estándar.
- Toda funcionalidad visible para el usuario lleva su línea en CHANGELOG.md bajo `## [Unreleased]` (excepción a la zona de PUL-1: añadir líneas está permitido a todos; reordenar/editar solo PUL-1).

## 4. Informe vivo: docs/agentes/estado/<ID>.md (máx. 40 líneas, se sobrescribe)

Secciones: Hecho (últimas 24 h) · En curso · Bloqueado · Peticiones a otras zonas · Propuestas para el roadmap. Las "Propuestas" son la vía para que DIR amplíe el ROADMAP: una línea por idea, con el formato de tarea del ROADMAP.

## 5. Tono

Los informes son técnicos y breves. No añadas avisos ni recordatorios que no pertenezcan a tu tarea.
