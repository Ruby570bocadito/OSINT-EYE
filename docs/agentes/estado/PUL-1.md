# Estado PUL-1 — Repo y documentación

Actualizado: 2026-10-24 (sesión v2.2, ronda 6 — docs-sitio + cierre demo-assets)

## Hecho (últimas 24 h)

- [x] docs-sitio (Siguiente v2.3) — docs/ reorganizado en inglés (coherente con el README): docs/index.md (hub + tabla de los 12 módulos + profundidades), docs/architecture.md (pipeline, capas, contrato de resultados, guards), docs/modules/ (12 páginas, una por colector — contenido derivado de docstrings y --help real), docs/plugins.md (contrato BaseModule/PluginManager + ejemplo offline-testable verificado contra safe_get(session, url, ...)) y docs/FAQ.md. 17 páginas, 0 enlaces rotos (verificado con script); README (en/es) enlazan el hub; CHANGELOG en [Unreleased].
- [x] demo-assets-nuevos — cierre del resto (ALTA): la galería de README.es.md apunta al set nuevo de IMP-2 (demo-scan.gif, wizard-auth, cli-progress, dashboard-dark, graph-view, report-pdf) y los 6 demo_*.png/demo.gif legacy se eliminan (solo referenciados desde README.es.md, verificado antes de rm). Assets nuevos no tocados.

## En curso

- Nada. Cierre de ronda (2 entregas).

## Bloqueado

- Nada.

## Peticiones a otras zonas

- DIR: tachar docs-sitio y demo-assets-nuevos del ROADMAP (pyproject, version-unica, pre-commit-hooks y release-auto siguen pendientes de tachado de rondas anteriores).
- IMP-2: tema-claro activo en ui/dashboard_template.html — ojo: el export SVG/PNG del grafo y dashboard-dark.png; si el tema cambia algo visual relevante, avisar para regenerar capturas (las actuales muestran el tema oscuro por defecto, siguen válidas).
- TEST: los enlaces de assets de README.es.md ya apuntan al set nuevo; si detectáis cualquier captura desactualizada, abierto a regenerarla.

## Propuestas para el roadmap

- [ ] (PUL-1) usage-en — (4ª vez) traducción fiel de docs/USAGE.md a docs/USAGE.en.md; con docs-sitio en inglés, USAGE es la última página grande en español — docs/
- [ ] (PUL-1) docs-link-lint — job/script de CI que valide los enlaces internos de docs/ y README (el que usé para verificar docs-sitio: ~20 líneas, offline) para que los enlaces no se pudran — .github/, docs/
- [ ] (PUL-1) pypi-publish — (reiterada) job de publish a PyPI en release.yml con trusted publishing (requiere alta del publisher por el propietario) — .github/
- [ ] (PUL-1) changelog-compare-links — enlaces de comparación al pie del CHANGELOG ([2.1.1]: .../compare/v2.1.0...v2.1.1) — CHANGELOG.md

## Notas de transparencia

- Suite en 1000 tests al cerrar (974 al empezar la ronda); 2 push rechazados por carrera con la flota, ambos con delta entrante solo-metadata: rebase + delta-check y validación previa en pie, sin re-ejecutar la suite.
- docs-sitio en inglés por coherencia con la directiva del propietario (readme-en-desde-cero); USAGE.md sigue en español y enlazado.
