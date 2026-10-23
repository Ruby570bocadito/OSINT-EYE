# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/), versionado según [SemVer](https://semver.org/lang/es/).

Reglas del equipo (PROTOCOLO §3):
- Toda funcionalidad visible para el usuario lleva su línea bajo `## [Unreleased]` en el mismo commit que la introduce.
- Añadir líneas bajo `[Unreleased]` está permitido a todos los agentes; reordenar, editar o consolidar la sección es tarea exclusiva de PUL-1.
- Al preparar un release, `[Unreleased]` pasa a `## [x.y.z] - fecha` y se abre un `[Unreleased]` vacío.

## [Unreleased]

### Añadido
- **Extractor canónico de hallazgos (`core/findings.py`)**: una sola capa de "qué ha encontrado el scan"
  (takeover, buckets públicos, secretos de GitHub, CVEs, ficheros sensibles, paneles admin/login) con
  `Finding` inmutable, severidad normalizada (CVSS por nombre o score), evidencia, fingerprint estable,
  ordenación determinista y resúmenes por severidad/regla. `reporting/sarif.py` delega en él (reglas
  OE001-OE007, ahora con `properties.evidence`/`sourceModule` por resultado) — base para exit-codes y
  risk-scoring.
- **Códigos de salida para CI (`--fail-on low|medium|high`)**: el peor `attack_surface_score.severity`
  entre los escaneos se compara con el umbral y fija el exit code — `0` dentro del umbral, `1` umbral
  alcanzado/superado, `2` error de uso, `3` ningún target escaneado (todo fuera de scope); códigos
  documentados en `--help` y pensados para pipelines.
- **Exportación SARIF 2.1 (`<base>.sarif`)**: hallazgos de takeover, buckets públicos, secretos de GitHub,
  CVEs y ficheros sensibles como resultados SARIF (niveles error/warning/note según severidad, con
  `partialFingerprints` estables) listos para GitHub Code Scanning; shapes corruptos se saltan sin romper
  el log. Cableado en `export_all` y `SarifExporter` en `reporting/sarif.py`.
- **CI de lint y cobertura**: job `lint` (ruff, gate de sintaxis E9) y job `coverage` (pytest-cov sobre `core/modules/graph/reporting/ui/ai`, `coverage.xml` como artifact y subida a Codecov); badge de cobertura en el README.
- **`.dockerignore` versionado**: contexto de build limpio (sin `.git`, venvs, `output/`, `docs/`, `tests/`) — deja de estar ignorado en `.gitignore`; la imagen de Docker es más pequeña y el build más rápido.
- **`.agent-tmp/` ignorado en git** (borradores y volcados de agentes, PROTOCOLO §3).
- **Empaquetado estándar**: `pyproject.toml` con metadatos completos, dependencias en paridad con `requirements.txt`, extras (`[ui]`, `[pdf]`, `[dev]`), entry point `osint-eye` y `pip install -e .` verificado desde cero.
- **Control de scope (`--scope FILE` / `--exclude`)**: autorización explícita por dominio, wildcard
  (`*.dominio`), IP o CIDR (IPv4/IPv6); los excludes siempre ganan; targets y candidatos fuera de scope
  se omiten y quedan registrados en `results["scope"]["discarded"]` (target, módulo, motivo, timestamp).
  Gateo activo en el orquestador (targets de CLI, candidatos de permutación y sondas de takeover);
  archivo de scope inválido = error de uso limpio antes de escanear.
### Seguridad
- **Verificación TLS nunca desactivada**: `SecurityHeadersAuditor` y el fallback HTML de `ScreenshotCapture`
  ya no usan `verify=False`; un certificado inválido se reporta como hallazgo (score 0, grado F) en vez de
  degradar la sonda ante objetivos hostiles (riesgo MITM).
- **Guard SSRF en redirecciones**: nuevo `modules/web/ssrf_guard.py`; `TechDetector`, `SensitiveDataDetector`,
  `CDNDetector` y `SubdomainTakeoverDetector` ya no siguen redirecciones a IP privadas/loopback/link-local
  (metadatos cloud 169.254.169.254 incluidos): cada hop se valida por esquema y direcciones resueltas, y el
  hop rechazado se reporta como error sin interrumpir el escaneo.
- **Dashboard API endurecido**: cabeceras de seguridad en todas las respuestas (CSP que bloquea toda carga
  externa y frames, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`), `Cache-Control: no-store`
  en `/api/*`, límite de 64 MB por fichero de escaneo cargado y rechazo controlado de JSON con anidamiento
  profundo; la plantilla se sirve verbatim sin pasar por el motor Jinja.
- **Logging real de librería (`--log-level`, `--log-file`)**: `core/`, `graph/` y `reporting/` ya no usan
  `print()` — registran por el árbol `osint_eye` (`core/logging_config.py`, idempotente, stderr + fichero
  en modo append); Rich sigue siendo la única salida de usuario. Nivel por defecto INFO; nivel inválido es
  error de uso limpio. La salida del monitor (alertas, ciclos) pasa a `logging` y desaparece de stdout.
- **Cliente HTTP compartido (`modules/_http.py`)**: todos los colectores salen ahora por un único
  `HTTPClient` con timeout por defecto (nunca peticiones colgadas), reintentos con backoff exponencial
  en errores de conexión y respuestas transitorias (429/5xx, respetando `Retry-After`), User-Agent
  identificable `OSINT-EYE/…` configurable (`OSINT_EYE_USER_AGENT`), rate-limit por host
  (`OSINT_EYE_RATE_LIMIT`) y proxy opcional (`OSINT_EYE_PROXY`); migrados los `requests` sueltos de
  `modules/` (web, wayback, certs, nvd, github, google, cloud, dns avanzado, takeover).
- **Contrato de resultados versionado (`core/schema.py`)**: `SCHEMA_VERSION` ("2.0") embebido en cada
  escaneo (`results.schema_version`), TypedDicts (`ScanResults`, `ModuleResult`), `validate_results()`
  con validadores por módulo y `require_valid_results()`; validación no fatal en `run_all()` y
  `export_all()` (avisa sin perder el escaneo). Tests nuevos en `tests/test_core_schema.py`.
- **Dashboard — explorador de hallazgos con búsqueda y filtros**: nueva tabla unificada de activos
  (subdominios, puertos, tecnologías, emails, CVEs, buckets y técnicas MITRE) con búsqueda de texto,
  filtros por severidad, tipo de activo y módulo de origen; API `GET /api/scan/<target>/assets`
  tolerante a datos malformados (nunca 500) y renderizado 100 % offline vía `textContent`.
- **Dashboard — comparación entre escaneos**: panel "Scan Comparison" con selector From/To sobre los
  escaneos cargados y API `GET /api/scan/<target>/diff?against=<otro>` (reutiliza `core/scan_diff.ScanDiff`);
  muestra subdominios/puertos/servicios/tecnologías/emails/CVEs/buckets añadidos o eliminados, servicios
  con versión cambiada y evolución del score de superficie, con entrada sanitizada (nunca 500).
- **CLI — progreso en vivo por módulo**: tabla `Module Progress` (Rich Live) con estado
  (pending/running/done/error), duración, nº de hallazgos y errores de cada módulo durante el escaneo
  (`run_all` y `--modules`); la salida impresa de los módulos se re-renderiza sobre la tabla sin
  corromperse y en tuberías/CI el tracker degrada a impresión normal.
- **Subdominios pasivos sin API key (`modules/dns/passive_sources.py`)**: 5 fuentes públicas
  (HackerTarget, AlienVault OTX, Anubis/jldc, RapidDNS, CertSpotter) consultadas en paralelo con
  deduplicación y validación estricta de cada hostname (entrada remota hostil); integradas en el
  escaneo DNS en modo `full` (merge con fuerza bruta/CT, detalle por fuente en
  `results["modules"]["dns"]["passive_subdomains"]`); cualquier fuente caída degrada a `status=error`
  sin romper el escaneo.
- **Detección de DNS wildcard (`modules/dns/wildcard.py`)**: antes de la enumeración por fuerza bruta
  y permutaciones se resuelven sondas aleatorias inexistentes; si responden, la zona tiene wildcard y
  los candidatos cuya única respuesta es el set de IPs wildcard se descartan (con contador
  `wildcard.skipped`) en vez de reportar miles de falsos positivos; detalle en
  `results["modules"]["dns"]["wildcard"]` (confianza high/medium, IPs de la huella).
- **Auditoría de email security (`modules/dns/email_security.py`)**: junto a SPF/DMARC comprueba DKIM
  (18 selectores comunes), MTA-STS, TLS-RPT, BIMI y presencia de MX, y produce una puntuación de
  spoofing 0-100 explicable (desglose por componente con deducciones y recomendaciones accionables) en
  `results["modules"]["dns"]["email_security"]` (modo `full`); cada consulta DNS degrada a "no
  encontrado" sin romper el escaneo.
- **Wizard — scope, exclusiones y confirmación de autorización**: el asistente pregunta límites de
  alcance (dominios/wildcards/CIDR) y exclusiones, descarta de verdad los targets que no aplican y
  exige una confirmación explícita de autorización antes de continuar; rechazarla cancela el escaneo.
- **Dashboard — exportación del escaneo abierto**: botones JSON/CSV/MD en la barra superior que
  descargan el escaneo activo (`GET /api/scan/<target>/export?format=…`); el CSV usa las filas del
  explorador de hallazgos con neutralización de fórmulas, el MD reutiliza `MarkdownReporter` y los
  nombres de descarga están saneados (sin path traversal ni inyección de cabeceras).

### Documentación
- README fiel: badges de versión (2.1.1) y de tests sincronizados con el recuento real de la suite, árbol actualizado y sección Roadmap que resume la fase v2.2 enlazando `docs/agentes/ROADMAP.md`.

## [2.1.1] - 2026-09-11

### Dashboard rediseñado
- **Interfaz nueva minimalista y profesional**: sistema de diseño oscuro con un solo acento,
  tipografía del sistema con numerales tabulares, micro-labels en mayúsculas, bordes de 1px,
  sin gradientes ni brillos.
- **Grafo de superficie 100% autónomo**: layout de fuerzas propio en vanilla SVG (d3 y CDN
  eliminados) con arrastre, tooltips, leyenda por tipo y etiquetas solo en hubs de alto grado
  (los grafos densos vuelven a ser legibles).
- **A prueba de inyección**: todo dato del escaneo se renderiza vía `textContent`; cero
  `innerHTML` con datos (cierra los hallazgos XSS de la auditoría).
- **API defensiva por diseño**: `/summary`, `/ports`, `/subdomains`, `/graph`, `/mitre` y
  `/chains` toleran shapes null/list/dict/escalar — nunca devuelven 500 con datos malformados.

### Corregido (segunda ronda de QA — 15 bugs con tests nuevos)
- `modules/dns/subdomain_permutator.py`: `enumerate()` devolvía el acumulado de TODAS las
  llamadas — el monitor compartía estado entre targets y reportaba subdominios ajenos como
  nuevos (falsas alertas).
- `modules/cve/nvd.py`: scores CVE `null` (NVD los envía a veces) rompían `analyze_service`
  y `prioritize_cves` con TypeError.
- `reporting/export.py`: el informe HTML no mostraba NUNCA los sensitive files de
  `modules["endpoints"]` (el shape real); paridad restaurada con MD/PDF/Burp.
- `graph/builder.py`: el grafo ignoraba `modules["permutation"]` — hosts verificados por
  permutación ausentes del HTML interactivo y del export Cypher.
- `osint_eye.py`: worker crashes silenciosos en las fases paralelas (`concurrent.futures.wait`
  descartaba las excepciones) — ahora se imprimen y registran; `--pdf` con targets URL
  reventaba por nombre sin sanear; `export_all` no creaba el directorio padre.
- `osint_eye.py` + `ui/wizard.py`: MarkupError real de Rich con targets hostiles tipo
  `x[/bold]y.com` (escape en panel de monitor, webhook y resumen).
- `core/correlator.py`, `core/monitor.py`, `reporting/mitre_mapper.py`, `ui/rich_cli.py`,
  `ui/tui_app.py`: crashes con shapes borde (None, listas, strings, contadores no numéricos).
- Suite: **118 tests offline** (27 nuevos), pyflakes 0 warnings.


## [2.1.0] - 2026-09-11

### Corregido
- **Crash al arrancar sin nmap**: `NetworkScanner()` ya no revienta en `__init__` si el binario no está; el módulo se degrada con `status: unavailable` y mensaje accionable.
- **Crash con buckets en la correlación**: `ingest_cloud` acepta dicts (`{url, provider, public}`) y strings.
- **Deadlock visual de fases**: los `console.status()` que envolvían hilos que imprimen directamente corrompían la salida → reglas de fase simples.
- **Monitor duplicado**: `main()` y `scan_targets()` lanzaban dos daemons en conflicto; ahora hay una única fuente de verdad (`SubdomainMonitor.run_daemon`) con parada elegante.
- **Dashboard con fichero inexistente**: `--dashboard` sin `-o` cargaba un JSON que nunca se guardó; ahora persiste el JSON antes de abrir el dashboard y `load_scan_results` normaliza rutas (con fallback a demo seguro).
- **crt.sh**: parseo de `name_value` (multi-SAN) que perdía subdominios; matching de dominio exacto (antes `notexample.com` matcheaba `example.com`).
- **WHOIS**: `registrant`/`admin` siempre devolvían `None`; emails validados con formato.
- **Emails por substring**: `x@badexample.com` matcheaba `example.com` → matching exacto/subdominio.
- **Cloudflare**: header `x-cache` comprobado por nombre+valor (antes nunca matcheaba).
- **NVD**: rango de fechas ISO-8601 válido (≤120 días), pacing automático (6s sin API key), backoff 403/429.
- **Wordlists**: rutas relativas al módulo (no al CWD); carga tolerante a formato de una línea con comas.
- **aiohttp**: sesiones por-llamada (fugas y crash en 2ª llamada); `asyncio.get_event_loop` deprecado eliminado.
- **Plugin system**: un builtin que falla ya no mata `load_builtin()`; stubs `unavailable` mantienen el contrato.
- **async engine**: `ClientSession(proxy=...)` inválido, headers perdidos en retry, `result[0]` sobre excepciones.
- **Neo4j exporter**: ids no-string, nodos con id `0` saltados, edges `from`/`to` ignorados.
- **MITRE Navigator**: layer inválido (versión y subID) → layer válido `4.9/4.5`; técnica inexistente sustituida por T1593.003.
- **PDF**: KeyError con datos mínimos, unicode/control chars, paginación con `repeatRows`.
- **Burp XML**: control chars invalidaban el XML.
- **Tests**: 61 tests 100% offline (antes dependían de google.com/example.com).

### Añadido
- **Attack surface score ponderado**: buckets públicos, subdomain takeovers y ficheros sensibles ahora puntúan (antes un scan con 37 buckets públicos daba 0/100).
- **Ingest de correlación**: `ingest_cloud`, `ingest_emails`, `ingest_endpoints`, `ingest_takeover` conectados al orquestador.
- **`--modules` sin valores**: catálogo interactivo con tabla Rich (como prometía el README).
- **`--modules <lista>`**: ejecución selectiva de módulos con validación.
- **`--depth quick`**: fase mínima (dns/certs/wayback/whois/web/análisis).
- **Validación de `--monitor-interval`** (entero positivo).
- **CI en GitHub Actions**: pytest offline × Python 3.10-3.12 + build Docker + smoke test.
- **Docker non-root** con `nmap`/`whois` incluidos y volúmenes correctos.

### Cambiado
- **CLI renovada**: banner con gradiente, resumen tipo dashboard (gauge de riesgo, cobertura por módulo, top findings con chips de severidad), paneles por módulo en `--rich`, wizard reestilizado.
- **requirements.txt**: eliminado `asyncio` (stdlib) del pin.
- **.gitignore**: dejaba de ignorar `.github/` y con globales `*.json`/`*.md`/`*.html`; ahora patrones acotados a artefactos de scan.
- **README**: reescrito con demo GIF, capturas reales y matriz honesta de capacidades.

### Eliminado
- `lib/` (740 KB de JS vendido sin ninguna referencia — 61% del repo).
- `ui/tui.py` (código muerto, nunca importado).
- `__init__.py` raíz (paquete incorrecto).

## [2.0.0] - 2025
- Rediseño completo: async engine, caché SQLite, correlador, grafo, MITRE, dashboard, IA local.

## [1.0.0] - 2024
- Release inicial: DNS, certs, wayback, WHOIS.
