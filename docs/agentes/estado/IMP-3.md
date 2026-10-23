# Estado IMP-3 — Núcleo, análisis y salidas

Actualizado: 2026-10-23 (sesión v2.2, ronda 2 — cierre: 5 tareas)

## Hecho (últimas 24 h)

- [x] (IMP-3) findings-extract — `core/findings.py`: Finding inmutable con severidad normalizada
  (CVSS nombre>score>low), evidencia, fingerprint estable, ordenación determinista y resúmenes;
  `reporting/sarif.py` delega en él (OE001-OE007 + properties.evidence/sourceModule).
- [x] (IMP-3) config-file — `core/config.py`: osint_eye.toml (tomllib), [scan]/[timeouts]/[scope]/[exports],
  perfiles [profiles.<nombre>]; precedencia CLI > perfil > fichero; validación estricta (claves
  desconocidas = usage error); export_all() acepta formats=.
- [x] Petición IMP-2 — ScanDiff.compare() resetea su esqueleto (new_ports/cves/buckets ya no acumulan
  entre llamadas reutilizadas); tests de regresión en tests/test_core_scan_diff.py.
- [x] Petición IMP-2 — MarkdownReporter.build_text(): informe como texto sin escribir fichero,
  byte a byte igual a generate().
- [x] Petición PUL-1 — imports perezosos de reportlab (PEP 562 en reporting/__init__ + propiedad
  diferida en OSINTEye): `import osint_eye`/`import reporting` no cargan reportlab; extra [pdf] real.
  Incluido el fix del f-string pyflakes en markdown_reporter.py:386.
- Suite al cierre: 692 tests offline en verde; pyflakes limpio en todo lo tocado.

## En curso

- (nada — próxima sesión: config-file ya hecho, quedan risk-scoring-v2 y trend-analysis de v2.3)

## Bloqueado

- (nada)

## Peticiones a otras zonas

- IMP-2: ui/__init__.py sigue importando flask/textual en eager — falta vuestra mitad de la petición
  de PUL-1 (imports perezosos) para que [ui] sea un extra real.
- IMP-2: el dashboard ya puede usar `MarkdownReporter.build_text()` para la descarga MD sin fichero temporal.

## Propuestas para el roadmap

- [ ] (IMP-3) dashboard-findings-api — endpoint /api/scan/<target>/findings sirviendo core/findings.py (lista canónica + summary) para alimentar el explorador de hallazgos con severidades consistentes — osint_eye.py (cableado mínimo), core/findings.py
- [ ] (IMP-3) export-cli-flags — --export sarif,stix,csv,... con exportadores selectivos en lugar de exportar todo con --output (export_all ya soporta formats=) — osint_eye.py
