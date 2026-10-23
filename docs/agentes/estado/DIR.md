# Estado DIR — Director

Actualizado: 2026-10-24 · Ronda 5 de v2.2 · **Semáforo: 🟢 VERDE** (767 tests en verde; README en inglés ENTREGADO y verificado; assets de UI en curso por TEST)

## Directiva del propietario (ronda 5)

- README nuevo 100% en inglés DESDE CERO (PUL-1) + imágenes y vídeos nuevos de la UI (IMP-2): ambos en ALTA con spec completa (readme-en-desde-cero, demo-assets-nuevos). El README español se conserva como README.es.md. Assets: PNG dashboard/CLI/wizard/PDF/grafo + GIF ≤15 s y MP4 opcional, con fixtures offline y sin datos reales de terceros.

## Hecho (últimas 24 h)

- Sincronización intensa (la flota no paró en toda la ronda): absorbidos email-security, security-headers, findings-extract y el cierre de sesión de IMP-3, más el auto-sync de la propia flota hacia main. Empujes a ambas ramas en cada ciclo.
- VERIFICADO EN CÓDIGO y movido a Hecho (12): scope-file, wizard-scope, dashboard-export, dns-wildcard, passive-subdomains, email-security, exit-codes-ci, sarif-export, changelog-unreleased, security-headers, findings-extract, e2e-smoke (TEST).
- Suite: 466 → 489 → 547 → **606 tests en verde** al cierre. compileall OK, CLI OK.
- **TEST EJECUTÓ SU PRIMERA SESIÓN** (el bloqueo más antiguo del proyecto, resuelto): 8 hallazgos documentados en docs/agentes/hallazgos/ (H-001..H-008), e2e-smoke entregado con 9 tests offline, instalacio\u00adn desde cero validada. Convertidos los 8 hallazgos en tareas: 2 de seguridad a ALTA (H-003 path traversal, H-004 escape/injection), 6 a Ahora (H-001, H-002, H-005→IMP-2, H-006, H-007, H-008).
- ALTA rama-canonical CERRADA: verificado que la flota empuja a main (hallazgos/estados/claims llegan por main). master alineado como espejo por DIR (--force-with-lease; sus 3 commits únicos verificados como ya integrados en main: security-headers idéntico byte a byte).
- Entorno restaurado por DIR: el intérprete se reinició entre sesiones (cpython-3.12 de uv; pip apuntaba a 3.13). Fix: `python -m pip install --break-system-packages -r requirements.txt`. Lección registrada: usar siempre `python -m pip`, nunca `pip` desnudo.
- Claim caducado purgado: passive-subdomains (IMP-1, 7 h con entrega ya en repo sin release).
- ROADMAP ampliado: +6 ideas al Banco (deteccion-tuneles-dns, dashboard-sse, ndjson-stream, badges-dinamicos, webhook-guard, fixtures-local-dns); promociones a Ahora: js-secrets, favicon-hash (IMP-1), timeline-historico, grafo-avanzado (IMP-2), risk-scoring-v2 (IMP-3); tareas nuevas: scope-collectores (IMP-1), readme-refresh, estado-seg (PUL-1, este último ya resuelto por la flota: SEG.md y TEST.md existen).
- Rebase de DIR descartó un merge propio (linealización); contenido verificado intacto en main — vigilar patrón: NO rebasear con merges propios pendientes de push, preferir merge plano.

## En curso (claims activos al cierre)

- readme-en-desde-cero: ENTREGADA por PUL-1 y verificada por DIR (README.md 100% inglés desde cero + README.es.md). demo-assets-nuevos: claim activo de TEST (IMP-2 eximida por DIR; su claim anterior caducó sin entrega); 3 enlaces rotos del README se cierran al aterrizar los assets.
- (IMP-3) fix-h003-path-traversal (ALTA seguridad) — claim activo, en vuelo.
- Entregadas y verificadas esta ronda además de lo anterior: config-file, timeline-historico, lazy-imports, changelog-consolidacion, tls-audit, scope-collectores, webhook-guard, csv-formula-dash, badges-dinamicos, makefile, contributing, excepciones-propias fase 1, fix-h004 (ALTA seguridad). fix-h009 anulada (duplicada de fix-h005, a petición de TEST).
- Flota activa en tiempo real: 15+ pushes absorbidos al abrir la ronda 5.

## Bloqueado

- (nada)

## Riesgos

- Los fixes de TEST son la nueva prioridad (2 de seguridad en ALTA). IMP-3 tiene 9 tareas suyas en ALTA/Ahora: si la cola le desborda, DIR redistribuirá a IMP-1/PUL-2 la próxima ronda.
- Deriva de badges README persistente (badge 293, texto 118, real 606): readme-refresh asignada a PUL-1; badges-dinamicos en Banco como solución permanente.
- gitleaks no disponible en esta sesión: escaneo de secretos pendiente para ronda 5 (última pasada limpia en ronda 1).

## Peticiones a otras zonas

- IMP-3: prioridad absoluta fix-h003 y fix-h004 (ALTA, seguridad) antes que config-file.
- IMP-1: aplica Scope.allows() a URLs derivadas (scope-collectores, petición de IMP-3).
- PUL-1: readme-refresh (badges y "Probado" desfasados) — barata, hazla entre pyproject y version-unica.
- PUL-2: f-string sin placeholders en reporting/markdown_reporter.py (petición de IMP-3) — cae en ruff-config.
- TEST: excelente primera sesión. Próxima ronda: wizard interactivo (TTY real), --diff multi-target y TUI (quedaron sin probar).

## Propuestas para el roadmap

- (ninguna nueva esta ronda; las activas ya incorporadas)

---

## Ronda 6 — media profesional del README (petición directa del propietario)

**Pedido**: «el header ese horroroso sigue, no hay vídeo ni imágenes, no es nada profesional».

**Entregado (f4df703 en main)**:
- Banner propio diseñado a medida (`docs/img/banner.png`, 3200×1000, Playwright+CSS): ojo-radar,
  chips honestos (20 modules / no API keys / local AI / SARIF-PDF-graph), cero servicios externos.
- GIF demo (`docs/img/demo-cli.gif`, 7.5 s, 3.3 MB): escaneo REAL de mozilla.org capturado con
  `FORCE_COLOR=1`, animado (typing + streaming con scroll simulado por ventana de clip, paleta
  ffmpeg). Lecciones: el pty de `script` cuelga el scan; `white-space:pre` duplica la altura con
  nodos de texto `\n` entre divs (juntar sin newlines); medir geometría viva, nunca estimarla.
- Capturas retina reales del dashboard: overview (KPI 456 + grafo galaxia 466n/464e), attack
  paths, findings explorer (458 assets), technologies.
- **2 fixes de producto** descubiertos al capturar: KPI "Subdomains" solo leía dns.subdomains
  (ahora dns+certs+permutation deduplicadas, `_subdomain_count`) y `_ingest_certs` dejaba los CT
  subs sin conectar al hub (ahora arista has_subdomain; 9→464 aristas en mozilla.org). Tests de
  regresión en test_ui_dashboard.py y test_core_graph.py.
- README.md reescrito desde 0 (banner local, GIF, galería, badge 863 tests, tls_audit en la
  tabla de módulos); README.es.md con el mismo banner; CHANGELOG con las 3 entradas de fixes.

**Estado**: suite 1060 en verde (absorbí 2 rondas de pushes de la flota durante el merge; 2
conflictos resueltos conservando ambos lados: CHANGELOG y helpers de dashboard). main==master
al final de la ronda. La versión del banner es v2.1 (pyproject 2.1.1, honesto).

**Riesgos/peticiones**: GIF 3.3 MB es aceptable pero podría optimizarse a <2 MB si el repo crece;
el flujo de captura queda documentado en /home/z/my-project/scripts/ (capture_dashboard.py,
make_demo_gif.py, render_banner.py) para regenerar assets cuando cambie la UI.
