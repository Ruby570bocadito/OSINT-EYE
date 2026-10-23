# ROADMAP — OSINT EYE

Único escritor: DIR. El resto propone en la sección "Propuestas" de su estado/<ID>.md. Formato de tarea: `- [ ] (ID destino) slug — descripción en una línea — rutas`. Prioridad: ALTA → Ahora → Siguiente → Banco de ideas. Dentro de cada bloque, de arriba abajo. El foco del proyecto son las implementaciones (IMP-1/2/3); el pulimiento (PUL-1/2) va en segundo plano pero nunca se para; SEG y TEST tiran de hallazgos.

Fase actual: v2.2 — «Fiable y extensible» (base: v2.1.1, 118 tests offline en verde). Objetivo de fase: contrato de datos estable, logging real, scope seguro, salidas para CI, README fiel.

## 🔴 ALTA (urgente, va antes que todo)

- [ ] (TODOS) rama-canonical — trabajad y empujad SOLO contra `main`: main y master están unificados al mismo árbol (ronda DIR 2026-10-23); master queda como espejo hasta próxima ronda DIR — transversal

## 🟢 Ahora (fase v2.2)

### IMP-3 — Núcleo, análisis y salidas

- [ ] (IMP-3) findings-extract — extractor único de hallazgos (takeover, buckets públicos, secretos, CVE, ficheros sensibles) a lista canónica con severidad y evidencia, reutilizable por SARIF/exit-codes/risk-scoring — core/findings.py (propuesta IMP-3, ronda 2)
- [ ] (IMP-3) logging-real — sustituir print() en core/graph/reporting por logging con --log-level y --log-file; Rich solo para la salida de usuario — core/, graph/, reporting/, osint_eye.py
- [ ] (IMP-3) scope-file — --scope scope.txt / --exclude (dominios, wildcards, CIDR): ningún módulo activo toca algo fuera de scope; los descartes se registran — core/scope.py, osint_eye.py
- [ ] (IMP-3) sarif-export — exportación SARIF 2.1 de hallazgos (takeover, buckets públicos, secretos, CVE) para GitHub Code Scanning — reporting/sarif.py
- [ ] (IMP-3) exit-codes-ci — --fail-on high|medium|low con códigos de salida documentados para usar OSINT EYE en pipelines — osint_eye.py
- [ ] (IMP-3) config-file — osint_eye.toml (tomllib, stdlib) con perfiles, timeouts, módulos y exportadores; los flags CLI lo sobreescriben — core/config.py, osint_eye.py

### IMP-1 — Colectores

- [ ] (IMP-1) http-client-unico — cliente HTTP compartido (timeout por defecto, reintentos con backoff, User-Agent configurable, rate-limit por host, proxy) y migrar los requests.get sueltos — modules/_http.py, modules/**
- [ ] (IMP-1) passive-subdomains — nuevas fuentes pasivas sin API key: HackerTarget, AlienVault OTX, Anubis/jldc, RapidDNS, CertSpotter; dedupe con crt.sh — modules/dns/passive_sources.py
- [ ] (IMP-1) dns-wildcard — detección de DNS wildcard antes de la fuerza bruta y permutaciones (evita miles de falsos positivos) — modules/dns/
- [ ] (IMP-1) security-headers — auditoría de cabeceras (CSP, HSTS, XFO, CORS permisivo, cookies sin Secure/HttpOnly) con severidad — modules/web/headers_audit.py
- [ ] (IMP-1) tls-audit — versión TLS, cifrados débiles, caducidad y cadena del certificado con ssl de la stdlib — modules/certs/tls_audit.py
- [ ] (IMP-1) email-security — DKIM (selectores comunes), MTA-STS, TLS-RPT, BIMI y puntuación de spoofing junto a SPF/DMARC — modules/dns/

### IMP-2 — Interfaz

- [ ] (IMP-2) progreso-por-modulo — barra/tabla de progreso en vivo por módulo (estado, duración, nº de hallazgos, errores) — ui/rich_cli.py
- [ ] (IMP-2) wizard-scope — el asistente pregunta scope/exclusiones y confirma autorización antes de módulos activos — ui/wizard.py
- [ ] (IMP-2) wizard-validacion-target — el wizard valida formato de target (dominio/IP/CIDR) con reintentos y avisa si parece una URL antes de continuar — ui/wizard.py (propuesta IMP-2, ronda 2)
- [ ] (IMP-2) dashboard-export — botón de descarga JSON/CSV/MD del escaneo abierto en el dashboard — ui/

### PUL-1 — Repo y documentación

- [ ] (PUL-1) pyproject — pyproject.toml con metadatos, extras ([ui], [pdf], [dev]) y entry point osint-eye; pip install -e . funciona — pyproject.toml, requirements*.txt
- [ ] (PUL-1) dockerignore-real — .dockerignore correcto (hoy está en .gitignore y no se versiona), imagen más pequeña — .dockerignore, .gitignore, Dockerfile
- [ ] (PUL-1) ci-lint-cov — job de ruff y cobertura (pytest --cov) en CI; badge de cobertura — .github/workflows/ci.yml
- [ ] (PUL-1) changelog-unreleased — sección ## [Unreleased] y convención documentada — CHANGELOG.md

### PUL-2 — Calidad de código

- [ ] (PUL-2) trocear-tests — dividir tests/test_core.py (1800 líneas) en tests/test_<zona>_*.py + conftest.py con fixtures comunes, sin cambiar ningún test — tests/
- [ ] (PUL-2) ruff-config — configurar ruff (pyflakes, isort, pyupgrade, bugbear) y dejar el repo en 0 avisos sin cambios de comportamiento — pyproject.toml, **/*.py
- [ ] (PUL-2) partir-rich-cli — ui/rich_cli.py (1200 líneas) en submódulos por panel, misma salida byte a byte — ui/
- [ ] (PUL-2) type-hints-core — tipado completo de core/ y graph/, mypy --strict limpio en esas rutas — core/, graph/

### SEG / TEST

- [ ] (SEG) ssrf-redirects — revisar que los colectores web no siguen redirecciones a IP privadas/metadatos cloud (169.254.169.254) — modules/web/, modules/osint/
- [ ] (SEG) dashboard-api-hardening — el dashboard ya escucha en 127.0.0.1: revisar path traversal en la carga de JSON por <target>, cabeceras de seguridad (CSP sin inline) y límites de tamaño — ui/dashboard.py
- [ ] (SEG) audit-deps — pip-audit sobre requirements y fijar mínimos seguros — requirements.txt (vía Peticiones a PUL-1)
- [ ] (TEST) e2e-smoke — e2e offline: --help, --modules, escaneo --depth quick contra servidor DNS/HTTP local de fixtures — tests/e2e/

## 🟡 Siguiente (v2.3 — «Inteligencia»)

### IMP-1

- [ ] (IMP-1) shodan-censys — integración Shodan/Censys/FOFA opcional con clave del usuario por variable de entorno; se salta sin clave — modules/osint/
- [ ] (IMP-1) asn-ip-ranges — ASN, rangos IP y netblocks de la organización (RDAP/ipwhois) para ampliar la superficie — modules/network/asn.py
- [ ] (IMP-1) js-secrets — extracción de secretos/endpoints/claves en ficheros JS (regex + entropía) con verificación de falsos positivos — modules/web/
- [ ] (IMP-1) favicon-hash — hash mmh3 del favicon para pivotar tecnologías y hosts relacionados — modules/web/
- [ ] (IMP-1) screenshots — capturas de los hosts web vivos (Playwright opcional, extra [shots]) para el informe y el dashboard — modules/web/screenshots.py
- [ ] (IMP-1) reverse-ip-vhosts — vecinos en la misma IP y descubrimiento de virtual hosts — modules/network/
- [ ] (IMP-1) leak-check — comprobación de dominios en fuentes públicas de brechas sin API key (solo metadatos, nunca credenciales) — modules/osint/
- [ ] (IMP-1) social-footprint — cuentas de la organización en GitHub/GitLab/Docker Hub/npm/PyPI — modules/osint/
- [ ] (IMP-1) async-collectors — migrar colectores I/O-bound al core/async_engine.py (medir antes/después) — modules/

### IMP-2

- [ ] (IMP-2) timeline-historico — vista de evolución de la superficie entre escaneos (nuevos/desaparecidos por fecha) — ui/
- [ ] (IMP-2) grafo-avanzado — filtros por tipo de nodo, búsqueda, resaltar caminos de ataque, exportar PNG/SVG — ui/dashboard_template.html
- [ ] (IMP-2) tui-completa — TUI Textual navegable con los resultados (tablas, detalle por activo, atajos) — ui/tui_app.py
- [ ] (IMP-2) i18n — textos de CLI/dashboard en ES/EN con --lang — ui/
- [ ] (IMP-2) tema-claro — tema claro/oscuro en el dashboard respetando prefers-color-scheme — ui/dashboard_template.html
- [ ] (IMP-2) informe-html-interactivo — informe HTML autónomo (un archivo) con tablas ordenables y grafo — ui/ + Peticiones a IMP-3

### IMP-3

- [ ] (IMP-3) risk-scoring-v2 — puntuación explicable: cada punto de riesgo enlaza a la evidencia que lo genera; pesos configurables — core/correlator.py
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
- [ ] (PUL-1) demo-assets — regenerar GIF/capturas con la UI actual (coordinar con IMP-2) — docs/assets/

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
- (IMP-1) metadata-files — metadatos de documentos públicos enlazados desde el dominio (PDF/DOCX/XLSX: autor, software, rutas internas) — modules/web/metadata.py
- (IMP-2) dashboard-detalle-activo — ficha de cada activo en el dashboard: módulos que lo reportan, evidencia y primera/última vez visto — ui/dashboard.py, ui/dashboard_template.html
- (IMP-3) informe-integridad — sello de integridad (SHA-256 de resultados + timestamp UTC + versión de esquema) en todos los exportadores — reporting/
- (IMP-3) monitor-metrics — métricas del modo monitor en formato Prometheus servidas por el dashboard local (127.0.0.1) — core/monitor.py, ui/dashboard.py
- (IMP-3) export-cli-flags — --export sarif,stix,csv,... con exportadores selectivos en lugar de exportar todo con --output — osint_eye.py, reporting/ (propuesta IMP-3, ronda 2)
- (IMP-1) reputacion-blocklists — consultar blocklists públicas sin API key (URLhaus, OpenPhish, PhishTank) para marcar dominio/IP como malicioso conocido — modules/osint/blocklists.py
- (IMP-2) dashboard-autorefresco — auto-refresco del dashboard en modo monitor (polling de la API cada N s, respeta --monitor-interval) — ui/dashboard.py, ui/dashboard_template.html
- (IMP-3) cache-ttl-por-fuente — TTLs distintos por fuente en la caché SQLite (DNS corto, wayback largo) en lugar de TTL global — core/session_cache.py

### Pulimiento

- (PUL-1) Paquete en PyPI y pipx install osint-eye.
- (PUL-1) Pre-commit hooks (ruff, end-of-file, trailing whitespace).
- (PUL-1) Matriz CI con Windows/macOS.
- (PUL-2) Benchmarks reproducibles por módulo (tests/bench/) para evitar regresiones de rendimiento.
- (PUL-2) Eliminar estado global/singletons y pasar dependencias explícitas.
- (PUL-1) version-unica — única fuente de __version__ en core/ leída por banner CLI y CHANGELOG (hoy el banner dice v2.1 y el repo va por 2.1.1) — core/__init__.py, osint_eye.py
- (PUL-1) gitignore-output — garantizar output/, .agent-tmp/ y volcados de escaneo en .gitignore (petición de IMP-1) — .gitignore
- (PUL-2) excepciones-propias — jerarquía de errores (OsintEyeError/ModuleError) para sustituir los ~40 except Exception genéricos detectados — core/errors.py, core/, modules/
- (PUL-1) usage-sync — docs/USAGE.md sincronizado con los flags actuales (--profile, --monitor, exports) con ejemplos probados — docs/USAGE.md
- (PUL-2) tipado-modules — tipado completo de modules/ (mypy) como segunda fase tras type-hints-core de core/ y graph/ — modules/

## ✅ Hecho (DIR mueve aquí lo verificado; se poda cada fase)

- v2.1.1 — dashboard rediseñado, 15 fixes de QA, 118 tests offline.
- v2.2 ronda 1 — dashboard-filtros: buscador y filtros por severidad/tipo/módulo, sin CDN; verificado por DIR en código (commit a3d61bf, suite en 128 tests en verde).
- v2.2 ronda 2 — results-schema: core/schema.py con SCHEMA_VERSION 2.0, TypedDicts y validate_results(); verificado por DIR (suite 179 en verde).
- v2.2 ronda 2 — dashboard-multiscan: selector de escaneos + vista diff reutilizando core/scan_diff.py; verificado por DIR (test_ui_dashboard_diff.py).
- v2.2 ronda 2 — readme-fiel: badges v2.1.1, árbol y enlaces al ROADMAP; verificado por DIR (nota: badge de tests quedó en 118, suite actual 179 — refrescar en próxima pasada PUL-1).
