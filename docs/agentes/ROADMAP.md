# ROADMAP — OSINT EYE

Único escritor: DIR. El resto propone en la sección "Propuestas" de su estado/<ID>.md. Formato de tarea: `- [ ] (ID destino) slug — descripción en una línea — rutas`. Prioridad: ALTA → Ahora → Siguiente → Banco de ideas. Dentro de cada bloque, de arriba abajo. El foco del proyecto son las implementaciones (IMP-1/2/3); el pulimiento (PUL-1/2) va en segundo plano pero nunca se para; SEG y TEST tiran de hallazgos.

Fase actual: v2.2 — «Fiable y extensible» (base: v2.1.1, 118 tests offline en verde). Objetivo de fase: contrato de datos estable, logging real, scope seguro, salidas para CI, README fiel.

## 🔴 ALTA (urgente, va antes que todo)

- [x] (TODOS) rama-canonical — CERRADA ronda 4: la flota empuja a `main` (verificado: findings/estados/hallazgos de la flota llegan por main); `master` queda como espejo alineado por DIR (--force-with-lease, contenido único de master verificado como ya integrado en main) — transversal
- [ ] (IMP-3) fix-h003-path-traversal — H-003 de TEST: `-o` con path traversal escribe fuera del directorio previsto; sanear/validar ruta de salida — osint_eye.py, reporting/ (claim activo, en vuelo)
- [x] (IMP-3) fix-h004-escape-injection — ENTREGADA ronda 5 (cc0d2ec, release bd1f34c): bytes de control neutralizados antes del terminal; verificado por DIR
- [ ] (PUL-1) readme-en-desde-cero — [x] ENTREGADA ronda 5 (7708983): README.md en inglés desde cero (373 líneas, 14 secciones), README.es.md conservado con cross-links; verificado por DIR (100% inglés, badges honestos, todo lo documentado existe en código incl. TOML config)
- [ ] (IMP-2 → REABIERTA a PUL-1/TEST, ronda 5) demo-assets-nuevos — **petición directa del propietario (ronda 5), URGENTE: el README nuevo ya referencia 3 ficheros que no existen (docs/assets/dashboard-dark.png, cli-progress.png, graph-view.png — enlaces rotos en portada)**: capturas reales de la UI ACTUAL con fixtures offline (loopback tipo TEST e2e, dominios example.com/fixture, nada de datos reales de terceros); mínimos para cerrar los enlaces rotos: dashboard-dark.png (dashboard oscuro con escaneo cargado y filtros visibles), cli-progress.png (Rich CLI con tabla progreso-por-módulo), graph-view.png (vista grafo); deseados después: wizard-auth.png, report-pdf.png, 1 GIF demo-scan.gif (≤15 s, <5 MB) y MP4 opcional (≤30 s); sustituir también los demo_*.png/demo.gif viejos cuando estén los nuevos; Playwright/headless contra el dashboard local o asciinema→gif para CLI; IMP-2 queda eximida (está en grafo-avanzado) pero puede revisar los assets — docs/assets/

## 🟢 Ahora (fase v2.2)

### Fixes de hallazgos TEST (ronda 4 — tras los dos de ALTA)

- [ ] (IMP-3) fix-h006-cache-corrupta — H-006 de TEST: cache.db corrupta crashea el escaneo; capturar, avisar y regenerar — core/session_cache.py
- [ ] (IMP-3) fix-h007-ctrlc — H-007 de TEST: Ctrl+C a mitad de escaneo termina crudo; capturar, imprimir resumen parcial y salir limpio — osint_eye.py
- [ ] (IMP-3) fix-h001-persistencia — H-001 de TEST: sin `-o` el resultado no se persiste en ningún sitio; auto-guardar en output/ o avisar explícitamente — osint_eye.py
- [ ] (IMP-3) fix-h008-pdf-duplicado — H-008 de TEST: el PDF se genera duplicado en export_all; deduplicar — reporting/
- [ ] (IMP-3) fix-h002-validacion-targets — H-002 de TEST: validar formato de target en la CLI (gemelo CLI de wizard-validacion-target); rechazar URLs como targets con mensaje accionable — osint_eye.py
- [ ] (IMP-2) fix-h005-dashboard-slash — [x] ENTREGADA ronda 5 (096e190): verificado por DIR (test_ui_dashboard_slash_targets.py)
- [x] (IMP-2) fix-h009-dashboard-export-slash — ANULADA ronda 5 a petición de TEST: duplicada de fix-h005 (ya entregada y verificada); no asignar a IMP-2
- [ ] (IMP-3) fix-h012-wizard-cancela-exit-code — H-012 de TEST (MEDIO): cancelar en el wizard termina con exit 0; debe salir con código no-cero y mensaje claro (importa a CI) — ui/wizard.py, osint_eye.py
- [ ] (IMP-1) fix-h011-dkim-p-vacio — H-011 de TEST (BAJO): registro DKIM con p= vacío produce falso positivo; tratar "p=" vacío como política sin clave, no como válida — modules/dns/email_security.py
- [ ] (IMP-3) fix-h010-modules-comas — H-010 de TEST (BAJO): la lista de --modules acepta/ensucia con comas; normalizar entrada y mensaje de error (aceptar --modules dns,web con split por comas + hint en el error, propuesta TEST) — osint_eye.py

### IMP-3 — Núcleo, análisis y salidas

- [ ] (IMP-3) risk-scoring-v2 — puntuación explicable: cada punto de riesgo enlaza a la evidencia que lo genera; pesos configurables — core/correlator.py (promocionada del Siguiente, ronda 4; encadena con findings-extract)

### IMP-1 — Colectores

- [ ] (IMP-1) js-secrets — extracción de secretos/endpoints/claves en ficheros JS (regex + entropía) con verificación de falsos positivos — modules/web/ (promocionada del Siguiente, ronda 4; claim activo)
- [ ] (IMP-1) favicon-hash — hash mmh3 del favicon para pivotar tecnologías y hosts relacionados — modules/web/ (promocionada del Siguiente, ronda 4)
- [ ] (IMP-1) fix-h011-dkim-p-vacio — H-011 de TEST (BAJO): registro DKIM con p= vacío produce falso positivo; tratar "p=" vacío como política sin clave, no como válida — modules/dns/email_security.py

### IMP-2 — Interfaz

- [ ] (IMP-2) wizard-validacion-target — el wizard valida formato de target (dominio/IP/CIDR) con reintentos y avisa si parece una URL antes de continuar — ui/wizard.py (propuesta IMP-2, ronda 2)
- [ ] (IMP-2) grafo-avanzado — filtros por tipo de nodo, búsqueda, resaltar caminos de ataque, exportar PNG/SVG — ui/dashboard_template.html (promocionada del Siguiente, ronda 4)

### PUL-1 — Repo y documentación

- [ ] (PUL-1) pyproject — pyproject.toml con metadatos, extras ([ui], [pdf], [dev]) y entry point osint-eye; pip install -e . funciona — pyproject.toml, requirements*.txt
- [ ] (PUL-1) version-unica — única fuente de __version__ en core/ leída por banner CLI y CHANGELOG; banner dice v2.1 y el repo va por 2.1.1 — core/__init__.py, osint_eye.py (promocionada del Banco, ronda 3; osint_eye.py liberado por logging-real)

### PUL-2 — Calidad de código

- [ ] (PUL-2) trocear-tests — dividir tests/test_core.py (1800 líneas) en tests/test_<zona>_*.py + conftest.py con fixtures comunes, sin cambiar ningún test — tests/
- [ ] (PUL-2) ruff-config — configurar ruff (pyflakes, isort, pyupgrade, bugbear) y dejar el repo en 0 avisos sin cambios de comportamiento — pyproject.toml, **/*.py
- [ ] (PUL-2) partir-rich-cli — ui/rich_cli.py (1200 líneas) en submódulos por panel, misma salida byte a byte — ui/
- [ ] (PUL-2) type-hints-core — tipado completo de core/ y graph/, mypy --strict limpio en esas rutas — core/, graph/ (fases 1a y 1b entregadas ronda 5: async_engine, plugins, neo4j_exporter en mypy strict; claim activo)

### SEG / TEST

- [ ] (SEG) audit-deps — [x] ENTREGADA ronda 5 (ver estado SEG: pip-audit y mínimos seguros junto a cache-deserializacion); verificar detalles en ronda 6

## 🟡 Siguiente (v2.3 — «Inteligencia»)

### IMP-1

- [ ] (IMP-1) shodan-censys — integración Shodan/Censys/FOFA opcional con clave del usuario por variable de entorno; se salta sin clave — modules/osint/
- [ ] (IMP-1) asn-ip-ranges — ASN, rangos IP y netblocks de la organización (RDAP/ipwhois) para ampliar la superficie — modules/network/asn.py
- [ ] (IMP-1) screenshots — capturas de los hosts web vivos (Playwright opcional, extra [shots]) para el informe y el dashboard — modules/web/screenshots.py
- [ ] (IMP-1) reverse-ip-vhosts — vecinos en la misma IP y descubrimiento de virtual hosts — modules/network/
- [ ] (IMP-1) leak-check — comprobación de dominios en fuentes públicas de brechas sin API key (solo metadatos, nunca credenciales) — modules/osint/
- [ ] (IMP-1) social-footprint — cuentas de la organización en GitHub/GitLab/Docker Hub/npm/PyPI — modules/osint/
- [ ] (IMP-1) async-collectors — migrar colectores I/O-bound al core/async_engine.py (medir antes/después) — modules/

### IMP-2

- [ ] (IMP-2) tui-completa — TUI Textual navegable con los resultados (tablas, detalle por activo, atajos) — ui/tui_app.py
- [ ] (IMP-2) i18n — textos de CLI/dashboard en ES/EN con --lang — ui/
- [ ] (IMP-2) tema-claro — tema claro/oscuro en el dashboard respetando prefers-color-scheme — ui/dashboard_template.html
- [ ] (IMP-2) informe-html-interactivo — informe HTML autónomo (un archivo) con tablas ordenables y grafo — ui/ + Peticiones a IMP-3

### IMP-3

- [ ] (IMP-3) trend-analysis — tendencias entre escaneos históricos de la caché SQLite (crecimiento, rotación, regresiones) — core/
- [ ] (IMP-3) alertas-nativas — notificadores Telegram/Discord/Slack/email/webhook genérico con plantillas, reintentos y deduplicación — core/notifiers/
- [ ] (IMP-3) plugin-api-v2 — API de plugins versionada con metadatos, dependencias entre módulos y plantilla cookiecutter-like — core/plugins.py
- [ ] (IMP-3) resume-scan — reanudar un escaneo interrumpido desde la caché (checkpoint por módulo) — core/session_cache.py, osint_eye.py
- [ ] (IMP-3) ai-resumen — resumen ejecutivo y priorización con Ollama sobre el JSON, con salida estructurada validada y fallback determinista sin IA — ai/
- [ ] (IMP-3) export-stix — exportación STIX 2.1 / MISP de indicadores — reporting/
- [ ] (IMP-3) export-nuclei-targets — lista de objetivos lista para nuclei/httpx/ffuf — reporting/export_tools.py

### PUL-1

- [ ] (PUL-1) docs-sitio — docs/ reorganizado: arquitectura, módulos (uno por página), cómo escribir un plugin, FAQ — docs/
- [ ] (PUL-1) release-auto — workflow de release: tag → build → GitHub Release con changelog e imagen en GHCR — .github/
- [ ] (PUL-1) contributing — CONTRIBUTING.md, plantillas de issue/PR, SECURITY.md — raíz, .github/

### PUL-2

- [ ] (PUL-2) dedupe-reporting — unificar lógica duplicada entre export.py, export_tools.py, markdown_reporter.py y pdf_reporter.py (una sola capa de "vista" de resultados) — reporting/
- [ ] (PUL-2) partir-advanced-dns — modules/dns/advanced_dns.py (965 líneas) en piezas por técnica — modules/dns/
- [ ] (PUL-2) nombres-consistentes — nombres de módulos/claves coherentes (cdn_waf, endpoints, cloud…) entre catálogo, results y docs — transversal
- [ ] (PUL-2) mensajes-cli — revisión de textos de la CLI: mismo idioma, tono y formato de errores accionables — ui/, osint_eye.py

## 🔵 Banco de ideas (DIR lo amplía cada ronda; se promueven a "Ahora"/"Siguiente")

### Implementaciones

- (IMP-1) Detección de paneles de login y tecnologías por firmas tipo Wappalyzer locales (JSON de firmas versionado).
- (IMP-1) Enumeración de buckets por permutaciones del nombre de la organización con verificación de listado.
- (IMP-1) Descubrimiento de APIs: swagger.json, openapi.yaml, GraphQL introspection (solo detección).
- (IMP-1) Análisis de robots.txt, sitemap.xml, security.txt y .well-known/*.
- (IMP-1) Detección de repositorios .git/.svn/.env expuestos (solo HEAD/existencia, sin descargar).
- (IMP-1) Typosquatting: dominios parecidos registrados (dnstwist-like) para phishing.
- (IMP-2) Modo "informe para cliente": plantilla con logo, alcance y conclusiones editables.
- (IMP-2) Vista mapa (geolocalización de IPs) sin servicios externos (GeoLite2 local opcional).
- (IMP-2) Atajos de teclado y modo presentación en el dashboard.
- (IMP-3) Modo servidor/API REST para lanzar escaneos (cola de trabajos) además de consultarlos.
- (IMP-3) Base de datos de activos persistente por organización (no solo por escaneo).
- (IMP-3) Deduplicación y normalización de activos (mayúsculas, puntos finales, IDN/punycode).
- (IMP-3) Mapeo a OWASP / CWE además de MITRE ATT&CK.
- (IMP-2) cli-quiet-mode — --quiet/--json-only para pipelines (solo JSON a stdout, cero decoración) complementando exit-codes-ci — osint_eye.py, ui/rich_cli.py
- (IMP-1) metadata-files — metadatos de documentos públicos enlazados desde el dominio (PDF/DOCX/XLSX: autor, software, rutas internas) — modules/web/metadata.py
- (IMP-2) dashboard-detalle-activo — ficha de cada activo en el dashboard: módulos que lo reportan, evidencia y primera/última vez visto — ui/dashboard.py, ui/dashboard_template.html
- (IMP-3) informe-integridad — sello de integridad (SHA-256 de resultados + timestamp UTC + versión de esquema) en todos los exportadores — reporting/
- (IMP-3) monitor-metrics — métricas del modo monitor en formato Prometheus servidas por el dashboard local (127.0.0.1) — core/monitor.py, ui/dashboard.py
- (IMP-3) export-cli-flags — --export sarif,stix,csv,... con exportadores selectivos en lugar de exportar todo con --output — osint_eye.py, reporting/ (propuesta IMP-3, ronda 2)
- (IMP-1) reputacion-blocklists — consultar blocklists públicas sin API key (URLhaus, OpenPhish, PhishTank) para marcar dominio/IP como malicioso conocido — modules/osint/blocklists.py
- (IMP-1) cve-epss-priorizacion — enriquecer los CVE con EPSS (API pública sin clave) y CISA KEV para priorizar por probabilidad de explotación — modules/cve/
- (IMP-3) cache-ttl-por-fuente — TTLs distintos por fuente en la caché SQLite (DNS corto, wayback largo) en lugar de TTL global — core/session_cache.py
- (IMP-3) results-migracion — migrador de escaneos antiguos (sin schema_version) al esquema 2.0 al cargarlos en dashboard/diff — core/schema.py, ui/dashboard.py
- (IMP-1) deteccion-tuneles-dns — heurísticas de DNS tunneling: labels largos/alta entropía, volumen anómalo de TXT, FQDNs sospechosos — modules/dns/
- (IMP-2) dashboard-sse — progreso del escaneo en vivo vía Server-Sent Events (menos polling que el autorefresco, un solo canal) — ui/dashboard.py, ui/dashboard_template.html
- (IMP-3) ndjson-stream — salida incremental NDJSON por módulo/hallazgo para consumo en vivo por otros procesos y pipelines — reporting/
- (PUL-1) badges-dinamicos — workflow que actualiza el badge de tests y versión en cada push (fin de la deriva manual: README dice 293 y la suite va por 489) — .github/workflows/
- (TEST) fixtures-local-dns — fixture pytest de servidor DNS/HTTP local reutilizable para el e2e offline y futuros tests de red — tests/conftest.py, tests/fixtures/
- (IMP-2) dashboard-vacio-guiado — panel con los 3 comandos exactos para generar un escaneo real cuando el dashboard carga datos demo (propuesta TEST, ronda 5) — ui/dashboard_template.html
- (SEG) webhook-guard — [x] ENTREGADA ronda 5 (cfd9cd7): --webhook exige https y host público + test_seg_webhook.py; verificado por DIR

### Pulimiento

- (PUL-1) Paquete en PyPI y pipx install osint-eye.
- (PUL-1) Pre-commit hooks (ruff, end-of-file, trailing whitespace).
- (PUL-1) Matriz CI con Windows/macOS.
- (PUL-2) Benchmarks reproducibles por módulo (tests/bench/) para evitar regresiones de rendimiento.
- (PUL-2) Eliminar estado global/singletons y pasar dependencias explícitas.
- (PUL-1) gitignore-output — garantizar output/, .agent-tmp/ y volcados de escaneo en .gitignore (petición de IMP-1) — .gitignore
- (PUL-1) makefile — Makefile con install/test/lint/docker para onboarding rápida — Makefile
- (PUL-2) excepciones-propias — jerarquía de errores (OsintEyeError/ModuleError) para sustituir los ~40 except Exception genéricos detectados — core/errors.py, core/, modules/
- (PUL-1) usage-sync — docs/USAGE.md sincronizado con los flags actuales (--profile, --monitor, exports) con ejemplos probados — docs/USAGE.md
- (PUL-2) tipado-modules — tipado completo de modules/ (mypy) como segunda fase tras type-hints-core de core/ y graph/ — modules/
- (PUL-2) print-residuales — revisar print() que queden en modules/ tras logging-real (solo Rich CLI puede escribir a stdout) — modules/, graph/

## ✅ Hecho (DIR mueve aquí lo verificado; se poda cada fase)

- v2.1.1 — dashboard rediseñado, 15 fixes de QA, 118 tests offline.
- v2.2 ronda 1 — dashboard-filtros: buscador y filtros por severidad/tipo/módulo, sin CDN; verificado por DIR en código (commit a3d61bf, suite en 128 tests en verde).
- v2.2 ronda 2 — results-schema: core/schema.py con SCHEMA_VERSION 2.0, TypedDicts y validate_results(); verificado por DIR (suite 179 en verde).
- v2.2 ronda 2 — dashboard-multiscan: selector de escaneos + vista diff reutilizando core/scan_diff.py; verificado por DIR (test_ui_dashboard_diff.py).
- v2.2 ronda 2 — readme-fiel: badges v2.1.1, árbol y enlaces al ROADMAP; verificado por DIR (nota: badge de tests quedó en 118, suite actual 179 — refrescar en próxima pasada PUL-1).
- v2.2 ronda 2b — ssrf-redirects: modules/web/ssrf_guard.py dedicado + test_seg_ssrf_guard.py (no seguir redirecciones a IP privadas/metadatos); verificado por DIR (suite 225 en verde).
- v2.2 ronda 2b — dockerignore-real: .dockerignore versionado fuera de .gitignore y contexto de build limpio; verificado por DIR.
- v2.2 ronda 3 — http-client-unico: modules/_http.py compartido (timeout, reintentos/backoff, rate-limit por host, UA, proxy) + tests; verificado por DIR.
- v2.2 ronda 3 — logging-real: árbol de logging en core/ con --log-level/--log-file, core/graph/reporting migrados, 201 líneas de tests; verificado por DIR.
- v2.2 ronda 3 — progreso-por-modulo: tabla de progreso en vivo por módulo en Rich CLI + tests; verificado por DIR.
- v2.2 ronda 3 — dashboard-api-hardening: CSP, nosniff, límite de 64 MB en carga de escaneos + tests de SEG; verificado por DIR.
- v2.2 ronda 3 — ci-lint-cov: job de ruff en CI (E9 de momento; ruff-config completo llega con PUL-2); verificado por DIR.
- v2.2 ronda 4 — scope-file: core/scope.py (dominios/wildcards/IPs/CIDR, descartes auditables en results["scope"]); verificado por DIR (489 tests en verde).
- v2.2 ronda 4 — wizard-scope: el asistente pide scope/exclusiones y exige confirmación explícita de autorización antes de escanear; verificado por DIR.
- v2.2 ronda 4 — dashboard-export: ruta /api/scan/<target>/export con JSON y CSV, nombres de fichero sanitizados; verificado por DIR.
- v2.2 ronda 4 — dns-wildcard: modules/dns/wildcard.py, detección previa a enumeración; candidatos wildcard-only se descartan (wildcard_skipped); verificado por DIR.
- v2.2 ronda 4 — passive-subdomains: modules/dns/passive_sources.py (HackerTarget, OTX, Anubis, RapidDNS, CertSpotter) con degradación grácil y validación hostil de respuestas; integrado en modo full de dns_scanner; verificado por DIR (claim caducado purgado).
- v2.2 ronda 4 — email-security: modules/dns/email_security.py (DKIM, MTA-STS, TLS-RPT, BIMI, MX, score de spoofing explicable) + 255 líneas de tests; verificado por DIR.
- v2.2 ronda 4 — exit-codes-ci: --fail-on low|medium|high con decide_exit_code() y códigos 0/1/2/3 documentados en --help y CHANGELOG; verificado por DIR.
- v2.2 ronda 4 — sarif-export: reporting/sarif.py (SARIF 2.1 con partialFingerprints estables, niveles error/warning/note) + test_reporting_sarif.py; verificado por DIR.
- v2.2 ronda 4 — changelog-unreleased: reglas de equipo bajo el formato Keep a Changelog + sección [Unreleased] viva (la flota la usa en cada entrega); verificado por DIR.
- v2.2 ronda 4 (tardía) — security-headers: modules/web/headers_audit.py (CORS, cookies Secure/HttpOnly, severidades, CSP/HSTS/XFO) + integración web_scanner + 210 líneas de tests; verificado por DIR (547 tests en verde).
- v2.2 ronda 4 (tardía) — findings-extract: core/findings.py, capa canónica de hallazgos (Finding con severidad normalizada, fingerprint estable y evidencia); SARIF/exit-codes/risk-scoring consumen de aquí; verificado por DIR (606 tests en verde).
- v2.2 ronda 4 (tardía) — e2e-smoke (TEST): tests/e2e/test_e2e_smoke.py, 9 tests 100% offline (subprocess + fixtures loopback); TEST ejecutó su primera sesión completa con 8 hallazgos documentados en docs/agentes/hallazgos/ (H-001..H-008); verificado por DIR.
- v2.2 ronda 5 — dashboard-autorefresco: polling de la API en modo monitor con auto_refresh en cfg, límites 5–3600 s (ui/dashboard.py + template); verificado por DIR (684 tests en verde).
- v2.2 ronda 5 — cache-deserializacion (SEG): deserialización defensiva de la columna results en ScanCache + test_seg_cache.py; verificado por DIR.
- v2.2 ronda 5 — fix-h005-dashboard-slash: targets con `/` servidos por el dashboard + test_ui_dashboard_slash_targets.py (hallazgo TEST cerrado); verificado por DIR.
- v2.2 ronda 5 — deps-sync (PUL-1): requirements de 17 a 13 deps (nvdlib/waybackpy/beautifulsoup4/lxml eliminadas, urllib3 declarado); verificado por DIR.
- v2.2 ronda 5 — estado-seg: docs/agentes/estado/SEG.md creado por la flota (PUL-1 lo cubre sin tarea propia); verificado por DIR.
- v2.2 ronda 5 (parcial) — type-hints-core: fases 1a y 1b (async_engine, plugins, neo4j_exporter, correlator, session_cache en mypy strict); tarea sigue abierta para resto de core/ y graph/.
- v2.2 ronda 5 (tardía) — config-file: core/config.py (osint_eye.toml, tomllib, fallback en 3.10) + flag --config cableado; verificado por DIR.
- v2.2 ronda 5 (tardía) — timeline-historico: vista de evolución entre escaneos en el dashboard + test_ui_timeline.py; verificado por DIR.
- v2.2 ronda 5 (tardía) — lazy-imports-reportlab (IMP-3): import diferido de reportlab + test_core_lazy_imports.py (CLI arranca sin extras pesados); verificado por DIR.
- v2.2 ronda 5 (tardía) — **readme-en-desde-cero (PUL-1, directiva del propietario)**: README.md nuevo 100% inglés escrito desde cero (373 líneas, 14 secciones: quickstart, scope/autorización, módulos, exportes, TOML, dashboard, monitor/plugins/AI, arquitectura, testing/CI, uso responsable) + README.es.md conservado con cross-links; verificado por DIR (0 hispanismos, badges honestos, toda feature documentada existe en código); claim purgado por DIR tras verificación (entrega sin release).
- v2.2 ronda 5 (tardía) — changelog-consolidacion (PUL-1): [Unreleased] consolidada; verificado por DIR vía release 7207948.
- v2.2 ronda 5 (tardía) — tls-audit (IMP-1): modules/certs/tls_audit.py (versiones de protocolo, cifrados débiles, certificado y cadena); verificado por DIR (release d53e652).
- v2.2 ronda 5 (tardía) — scope-collectores (IMP-1): Scope.allows() aplicado a URLs derivadas en colectores + test_modules_scope.py; verificado por DIR (release 8c73661).
- v2.2 ronda 5 (tardía) — webhook-guard (SEG): --webhook exige https y host público (reutiliza lógica anti-SSRF) + test_seg_webhook.py; verificado por DIR.
- v2.2 ronda 5 (tardía) — csv-formula-dash (SEG): prefijo anti-fórmula en _csv_cell (revisión de IMP-2); verificado por DIR.
- v2.2 ronda 5 (tardía) — badges-dinamicos (PUL-1): job de CI regenera tests.json/version.json en cada push y los README usan endpoint dinámico — fin de la deriva manual de badges; verificado por DIR (release b8f362d).
- v2.2 ronda 5 (tardía) — makefile (PUL-1): Makefile con help/install/test/coverage/lint/docker/clean espejo del CI; verificado por DIR (release ad94fa6).
- v2.2 ronda 5 (tardía) — contributing (PUL-1): CONTRIBUTING.md, SECURITY.md y plantillas de issue/PR; verificado por DIR (release dceee49).
- v2.2 ronda 5 (tardía) — excepciones-propias fase 1 (PUL-2): jerarquía OsintEyeError/ModuleError en core/; verificado por DIR (release ccce453); tarea del Banco sigue abierta para migrar los ~40 except Exception.
- v2.2 ronda 5 (tardía) — fix-h004-escape-injection (IMP-3, ALTA seguridad): bytes de control neutralizados antes del terminal; verificado por DIR (release bd1f34c, H-004 a resuelto-pendiente-verificación).
