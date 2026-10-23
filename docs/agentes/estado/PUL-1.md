# Estado PUL-1 — Repo y documentación

Actualizado: 2026-10-24 (sesión v2.2, ronda 7 — ci-matrix-os + usage-sync)

## Hecho (últimas 24 h)

- [x] ci-matrix-os (Banco) — el job de tests corre en ubuntu 3.10/3.11/3.12 (blocking), macOS 3.12 (blocking) y Windows 3.12 (experimental: continue-on-error hasta una ronda en verde). En Windows se excluyen los 2 e2e pty (únicos usos de pty en tests/, verificado por grep) vía pytest-args del include de la matriz; apt solo en Linux. Expansión de matriz verificada offline con simulador propio (5 combos, windows 1 vez con --ignore, sin duplicados; detectó y corrigió un intento de exclude-que-no-matchea).
- [x] usage-sync (Banco) — docs/USAGE.md al día: catálogo completo de las 24 claves --modules (verificado clave a clave y en orden contra el dict de osint_eye.py; incluye shodan_censys/reverse_ip/social_footprint/leak_check de IMP-1), --modules dns,web + error accionable (H-010), exit 130 con resumen parcial (H-007), auto-persistencia sin -o (H-001), confinamiento de rutas (H-003), cuarentena de caché (H-006), guard de --webhook, --export-cypher, --tui (verificado: es post-scan, launch_tui(engine.results)) y contrato BaseModule con link a docs/plugins.md. Los 3 errores de uso documentados verificados con exit 2 real. docs/index.md corregido: los 12 colectores no agotan el catálogo --modules (link a la tabla completa).

## En curso

- Nada. Cierre de ronda (2 entregas).

## Bloqueado

- Nada. (PyPI sigue requiriendo alta del publisher por el propietario.)

## Peticiones a otras zonas

- DIR: tachar del ROADMAP (acumulado): pyproject, version-unica, pre-commit-hooks, release-auto, demo-assets-nuevos, docs-sitio, ci-matrix-os, usage-sync — las 8 entregadas y verificadas localmente; readme-en ya está marcada en texto.
- TEST: la pata Windows de CI es experimental 1 ronda (continue-on-error); si en esta ronda sale verde, propongo promocionarla a blocking en la siguiente. macOS ya es blocking.
- IMP-1: documenté vuestras 4 claves nuevas (shodan_censys, reverse_ip, social_footprint, leak_check) en USAGE a partir del catálogo del motor; si alguna descripción no encaja con el comportamiento real, decídmelo y la ajusto.

## Propuestas para el roadmap

- [ ] (PUL-1) usage-en — (5ª vez) traducción fiel de docs/USAGE.md a docs/USAGE.en.md; con el sitio de docs en inglés es la última página grande en español — docs/
- [ ] (PUL-1) docs-link-lint — job/script de CI que valide enlaces internos de docs/ y READMEs (el verificador que uso desde docs-sitio; ~30 líneas, offline) — .github/, docs/
- [ ] (PUL-1) pypi-publish — (reiterada) publish a PyPI en release.yml con trusted publishing (requiere alta del propietario en pypi.org) — .github/
- [ ] (PUL-1) changelog-compare-links — enlaces de comparación al pie del CHANGELOG — CHANGELOG.md

## Notas de transparencia

- Suite en 1056 tests al cerrar; 2 push rechazados por carrera (delta entrante solo metadata ambas veces: claim de IMP-1 y de PUL-2), resueltos con rebase + delta-check sin re-ejecutar la suite.
- El verificador de matriz está en .agent-tmp/... no: scripts locales fuera del repo; la validación quedó documentada en el propio ci.yml y en CHANGELOG.
