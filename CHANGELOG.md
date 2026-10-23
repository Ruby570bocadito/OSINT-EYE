# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/), versionado según [SemVer](https://semver.org/lang/es/).

Reglas del equipo (PROTOCOLO §3):
- Toda funcionalidad visible para el usuario lleva su línea bajo `## [Unreleased]` en el mismo commit que la introduce.
- Añadir líneas bajo `[Unreleased]` está permitido a todos los agentes; reordenar, editar o consolidar la sección es tarea exclusiva de PUL-1.
- Al preparar un release, `[Unreleased]` pasa a `## [x.y.z] - fecha` y se abre un `[Unreleased]` vacío.

## [Unreleased]

### Añadido
- **Módulo `shodan_censys`**: inteligencia de hosts desde Shodan/Censys/FOFA, totalmente opcional
  (claves del usuario vía `OSINT_EYE_SHODAN_KEY`, `OSINT_EYE_CENSYS_API_ID/SECRET`,
  `OSINT_EYE_FOFA_EMAIL/KEY`): sin clave cada proveedor se marca `skipped` y el escaneo sigue;
  con clave fusiona IPs/puertos/servicios/subdominios en `results["modules"]["shodan_censys"]`.
  Disponible vía `--modules shodan_censys` (o en el catálogo `--modules`).

### Cambiado
- **README.es.md**: la galería Demo apunta al nuevo set de capturas regeneradas con fixtures 100 % offline
  (`demo-scan.gif`, `wizard-auth`, `cli-progress`, `dashboard-dark`, `graph-view`, `report-pdf`); los
  `demo_*.png`/`demo.gif` legacy (solo referenciados desde README.es.md) se eliminan del repo.

### Corregido
- **Dashboard**: el contador y el panel de tecnologías vuelven a reflejar el escaneo (el doble
  envoltorio `_as_dict()` en `get_summary()` convertía la lista de tecnologías detectadas en un
  dict vacío: "0 Technologies" / "No technologies fingerprinted" pese a datos presentes).
- **Dashboard (normalizador único)**: `_tech_names()` unifica summary y `_collect_assets` — aceptan
  todas las formas en la naturaleza (lista directa, wrapper dict/lista y el payload real de
  web_scanner con url/status_code, cuyas claves ya no se filtran como nombres); un dict de
  metadatos sin la clave `technologies` sigue devolviendo vacío (contrato de la regresión SEG).
  El TUI hereda el fix al reutilizar `_collect_assets`.

### Seguridad
- **fix-h011 (DKIM p= vacío)**: la auditoría email-security ya no da por protegido un dominio cuyo
  registro DKIM publica `p=` vacío (clave revocada, RFC 6376 §3.6.1.1): esos selectores quedan en
  `dkim.revoked` con su motivo (`revoked`/`malformed`), no cuentan como evidencia, el score aplica
  la deducción por ausencia de DKIM (-15) y se sugiere republicar una clave válida.
- **fix-h002 (validación de targets CLI)**: la CLI normaliza targets sucios en vez de dejarlos llegar
  a los motores: `HTTPS://Example.COM` → `https://example.com`, `https://example.com/ruta` y
  `example.com/path?x=1` → `example.com` (se conservan scheme y host:port para el módulo web y los
  fixtures loopback), espacios/puntos finales fuera, host en minúsculas. Lo no explicable
  (`not_a_domain!!`, `*.example.com`, puerto inválido) se rechaza con usage error accionable (exit 2)
  usando las reglas del wizard (dominio/IP/CIDR, wildcards a scope).
- **fix-h010 (módulos con comas)**: `--modules dns,web` ya funciona (la forma natural de listar): el
  flag acepta comas y espacios a la vez, recorta espacios, descarta fragmentos vacíos y deduplica.
  Un nombre desconocido produce un error corto y accionable (lista de módulos válidos + hint
  `--modules dns,web`) en lugar del volcado de ~40 líneas de usage que dejaba `choices=[...]`.
- **fix-h008 (PDF duplicado)**: `-o base --pdf` ya no genera dos PDFs. Si 'pdf' está entre los
  formatos de exportación, la rama `--pdf` no renderiza (export_all produce `base.pdf`); si no está,
  la rama deriva la ruta de la base `-o` (sufijo saneado por target en multi-target). Sin `-o` se
  mantiene el nombre por defecto en CWD.
- **fix-h001 (persistencia)**: el quickstart del README ya deja fichero reutilizable: sin `--output`,
  cada escaneo auto-guarda `osint_eye_<target>_<ts>.json` en el directorio actual (misma convención
  que el PDF por defecto) e imprime dónde quedó y que la caché vive en `~/.osint_eye/cache`. La rama
  `--dashboard` reutiliza ese fichero en vez de generar un duplicado con otro timestamp.
- **fix-h007 (Ctrl+C)**: interrumpir un escaneo ya no termina en traceback crudo: el bucle de targets
  captura `KeyboardInterrupt`, reúne los resultados parciales (targets completados + el en vuelo) en
  `ScanInterrupted`, imprime mensaje de aborto con el resumen por target y sale con código propio
  `130` (convención POSIX 128+SIGINT), documentado junto al resto de exit codes.
- **fix-h006 (cache corrupta)**: una `scan_cache.db` corrupta ya no crashea el escaneo con
  `sqlite3.DatabaseError: file is not a database`: `ScanCache` detecta el fallo al inicializar,
  pone el fichero en cuarentena (`<db>.corrupt`, con timestamp si el nombre está ocupado — nunca se
  destruye), avisa al operador por el logger de osint_eye y recrea una caché vacía; el escaneo
  continúa sin datos previos.
- **fix-h004 (escape injection)**: los targets y las rutas de salida suministradas por el usuario se
  neutralizan antes de llegar al terminal — `_neutralize_console_text()` elimina los bytes de control
  (ESC/OSC/DEL) en la entrada de `scan_targets`, en `OSINTEye.__init__` (target y results heredan la
  forma limpia) y en el choke point `_print()` de los 49 mensajes del motor. Un target tipo
  `$'\x1b]0;pwned\x07evil.com'` ya no puede reescribir el título del terminal; los ficheros de
  resultados nunca contienen los bytes crudos.
- **fix-h003 (path traversal)**: toda ruta de salida suministrada por el usuario (`--output/-o`,
  `--export-cypher`, `--log-file`) debe resolver dentro del directorio de trabajo; las que escapan
  se rechazan con usage error (exit 2) antes de escanear, escribir logs o crear ficheros. `export_all()`
  aplica la misma barrera a cualquier llamador no-CLI. Reproducido por TEST: `-o ../../x` escribía
  dos niveles por encima del repo.
- **webhook-guard**: `--webhook` valida la URL antes de arrancar el monitor (exige https y host
  público; loopback, IPs privadas y metadatos cloud bloqueados reutilizando ssrf_guard); el
  handler del monitor rechaza también en runtime — un typo nunca filtra datos del escaneo hacia
  la red interna.

### Añadido
- **Quickstart en el dashboard vacío/demo (dashboard-vacio-guiado)**: cuando el dashboard no tiene
  escaneos o solo muestra datos demo, un panel «No scan data yet» ofrece los 3 comandos exactos del
  CLI con botón de copiado (`--dashboard`, `--dashboard --monitor`, `--rich`); se oculta en cuanto
  hay datos reales. Solo textContent/addEventListener (compatible CSP), sin recursos externos,
  funciona en ambos temas.
- **Tema claro en el dashboard**: el dashboard sigue `prefers-color-scheme` — paleta clara completa
  (tokens redefinidos en `@media (prefers-color-scheme: light)`, `color-scheme` coherente) con el
  oscuro como estado por defecto intacto; el topbar deja su rgba fijo por `--topbar-bg`, el anillo
  del timeline usaba una variable inexistente (`--panel-bg`) que caía siempre a oscuro y ahora usa
  `--surface`, y el export SVG/PNG del grafo lee los tokens computados del tema activo (con
  fallback oscuro). Sin toggle, sin recursos externos.
- **ASN y netblocks de la organización (`asn-ip-ranges`)**: resuelve el target a IP y enumera el ASN
  de origen, el titular y todos los prefijos anunciados vía RIPEstat (API pública sin clave), más el
  objeto de red RDAP (nombre, país, rango start/end, tipo) vía rdap.org; cada fuente degrada de forma
  independiente y los prefijos se reportan como inteligencia (nunca se sondean). Respeta el scope y
  degrada sin red (`modules/network/asn.py`).
- **Hash de favicon para pivotar (`favicon-hash`)**: descarga el icono del objetivo (primero el
  `<link rel="icon">` declarado, con fallback a `/favicon.ico`) y calcula el hash favicon estándar
  de los motores de búsqueda de activos — MurmurHash3 x86_32 firmado sobre el base64, implementado
  en Python puro (cero dependencias nuevas, paridad con la librería de referencia verificada) —
  junto a md5/sha256, tamaño y content-type; las respuestas que no son imagen (por content-type o
  magic bytes) se reportan pero nunca se hashean. Respeta el scope y degrada sin red
  (`modules/web/favicon_hash.py`).
- **TUI completa (`--tui`)**: la TUI Textual es navegable de verdad — pestañas Overview / Assets /
  DNS / Network / Findings (atajos 1-5), tabla de activos con la vista canónica del dashboard y
  filtro en vivo (`ctrl+f`), y ficha modal por activo (módulos que lo reportan, severidad por
  módulo y evidencia) abierta con Enter y cerrada con esc/q; footer con los atajos. Cableada como
  `--tui` tras el escaneo (mismo patrón que `--dashboard`); 100 % offline y degradación grácil sin
  el extra ui.
- **Secretos y endpoints en ficheros JS (`js-secrets`)**: descarga los .js del objetivo (tope 20
  ficheros / 2 MB) y extrae claves AWS/Google/GitHub/Slack, JWT, cabeceras Bearer, claves Firebase,
  contraseñas hardcodeadas, claves privadas y endpoints (absolutos y `/api|/rest|/graphql`), más un
  pase de entropía de Shannon para tokens sin patrón conocido; verificación de falsos positivos
  (ejemplos de documentación, plantillas `${...}`/`process.env`, líneas comentadas y cadenas de
  baja diversidad se descartan) con confianza y línea de origen por hallazgo. Respeta el scope y
  degrada sin red (`modules/web/js_secrets.py`).
- **Benchmarks offline reproducibles (`tests/bench/`)**: runner standalone (`python tests/bench/bench_runner.py`,
  sin dependencias nuevas, sin red, no se recolecta por pytest) que mide 8 casos de core sobre datos
  sintéticos — `Scope.allows()`/`filter_targets()`, ingest y consultas del `AssetCorrelator`,
  `extract_findings` sobre ~1 500 hallazgos, `validate_results`, ciclo completo de `ScanCache` en
  SQLite y parseo de `osint_eye.toml` — y compara cada caso contra su suelo en `floors.json`
  (márgenes generosos): una caída por debajo del suelo sale con código 1 para pillar regresiones
  groseras de rendimiento antes del release.
- **Auditoría TLS (`tls_audit`, `--modules tls_audit`)**: sondeo exacto de protocolos aceptados
  (TLS 1.0/1.1 obsoletos, ausencia de 1.3), familias de cifrado débiles que el servidor aún acepta
  (RC4, 3DES, CBC-SHA1, anónimos), certificado (caducidad con días restantes, SANs, autofirmado,
  firma SHA-1) y cadena verificada contra el almacén del sistema; hallazgos explicables con
  severidad, score 0-100 y nota A-F. Solo stdlib (`ssl`/`socket`), degradación grácil sin conexión
  y respetando el scope (`modules/certs/tls_audit.py`).
- **Capturas demo reales de la UI actual (docs/assets/)**: `dashboard-dark.png` (dashboard con el
  fixture cargado: grafo, filtros del explorer, timeline), `cli-progress.png` (tracker real de
  progreso-por-módulo), `wizard-auth.png` (gate de autorización del wizard), `report-pdf.png`
  (primera página del PDF), `graph-view.png` (grafo de superficie), y demo animada
  `demo-scan.gif`/`demo-scan.mp4` (14 s: CLI → navegación del dashboard). Todo generado 100 %
  offline contra 127.0.0.1 con fixture example.com (dashboard Flask local + navegador headless,
  wizard real abortado en el gate de autorización, PDF con reporting/pdf_reporter); sustituirá a
  los assets antiguos cuando PUL-1 los cablee en los README.
- **Grafo avanzado**: la leyenda del grafo es ahora una barra de filtros por tipo de nodo (chips
  que atenúan lo excluido), búsqueda de nodos con resaltado, botón «Attack paths» que ilumina los
  caminos más cortos del target hacia los nodos de riesgo (CVEs/buckets, fallback puertos) vía BFS,
  y exportación del grafo a SVG y PNG (estilos inline en el SVG serializado, canvas con data: URL
  permitido por la CSP, descarga por Blob) — todo cliente, sin CDN ni recursos externos.
- **Surface Timeline (evolución entre escaneos)**: nuevo panel del dashboard con la línea temporal
  de la superficie — `GET /api/timeline` (global) y `GET /api/scan/<target>/timeline` (por target)
  encadenan deltas por fecha sobre la vista canónica de activos: cuántos activos son nuevos, cuántos
  desaparecieron y listas top con nombres, puntuación de riesgo y profundidad de cada escaneo.
  Los estados históricos se archivan por `(target, scan_date)` (un nuevo escaneo añade evento; la
  recarga del mismo escaneo reemplaza su entrada) — sin CDN, todo por `textContent`, nunca 500.
- **Imports perezosos de reportlab (extra `[pdf]` real)**: `import osint_eye` y `import reporting` ya no
  cargan reportlab hasta generar un PDF de verdad (`PDFReporter` perezoso vía PEP 562 y propiedad
  diferida en el orquestador); arranque más ligero y empaquetado coherente (petición PUL-1).
- **Scope aplicado dentro de los colectores**: los objetivos derivados (candidatos de brute-force
  DNS por wordlist, permutaciones de subdominios, virtual hosts derivados, ficheros JS de terceros,
  URLs de páginas para emails, enumeración de buckets cloud y endpoints web) pasan por
  `Scope.allows()`/`filter_targets()` vía `modules/_scope.py` antes de cualquier resolución o
  petición; cada rechazo queda en el log de auditoría (`results["scope"]["discarded"]`) con etiqueta
  del módulo de origen (`dns_bruteforce`, `dns_permutations`, `vhost_bruteforce`, `js_endpoints`,
  `email_web`, `cloud_buckets`, `web_endpoints`, `web`). Sin scope definido el comportamiento es
  idéntico al anterior.
- **Auto-refresco del dashboard (modo monitor)**: el dashboard puede vivir actualizándose —
  `GET /api/dashboard/config` entrega la configuración al cliente; con `--monitor --dashboard` la
  página hace polling de la API cada `--monitor-interval` (límites 5–3600 s), muestra un badge
  «LIVE · Ns» con pausa/reanudar, se detiene tras 3 fallos seguidos («OFFLINE») y se pausa con la
  pestaña oculta. El servidor recarga los ficheros vigilados solo cuando cambian en disco
  (`reload_scan_results` actualiza la entrada del historial con `refreshed_at`, sin duplicados) y
  el refresco suave preserva el target seleccionado. Todo sin CDN y vía `textContent`.
- **Configuración TOML (`osint_eye.toml`, `--config`, `--profile`)**: `[scan]` (depth, stealth, no_ai,
  no_cache, módulos por defecto), `[timeouts]`, `[scope]` (includes/excludes) y `[exports].formats`
  (subconjunto de exportadores); perfiles `[profiles.<nombre>]` que sobreescriben secciones; precedencia
  flags CLI > perfil > fichero; claves/secciones desconocidas = error de uso limpio (con tomllib stdlib,
  Python 3.11+; en 3.10 todo sigue funcionando sin TOML). `export_all()` acepta `formats=` para exportar
  un subconjunto.
- **Validación de targets en el wizard**: cada objetivo debe ser un dominio (etiquetas RFC,
  punycode incluido), IP v4/v6 o CIDR (`192.0.2.0/24`); la entrada inválida lista el motivo por
  token y reintenta. Si parece una URL (`https://…`, `host:puerto`, `usuario@host`) se avisa y se
  ofrece usar el host extraído; los CIDR válidos no se marcan como URL. El texto del wizard escapa
  siempre el input del usuario (sin Rich MarkupError con targets hostiles).
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
- **Auditoría de cabeceras ampliada (`modules/web/headers_audit.py`)**: ubicación canónica para
  `SecurityHeadersAuditor` (re-exportada desde `modules/dns` por compatibilidad) con análisis de CORS
  (wildcard y credenciales, con severidad), cookies sin `Secure`/`HttpOnly`/`SameSite` y severidad en
  todos los hallazgos; las deducciones previas no cambian y el resultado se integra en
  `results["modules"]["web"]["headers_audit"]` (modo web completo).
- **Wizard — scope, exclusiones y confirmación de autorización**: el asistente pregunta límites de
  alcance (dominios/wildcards/CIDR) y exclusiones, descarta de verdad los targets que no aplican y
  exige una confirmación explícita de autorización antes de continuar; rechazarla cancela el escaneo.
- **Dashboard — exportación del escaneo abierto**: botones JSON/CSV/MD en la barra superior que
  descargan el escaneo activo (`GET /api/scan/<target>/export?format=…`); el CSV usa las filas del
  explorador de hallazgos con neutralización de fórmulas, el MD reutiliza `MarkdownReporter` y los
  nombres de descarga están saneados (sin path traversal ni inyección de cabeceras).
- **Makefile de desarrollo**: atajos `make help/install/test/coverage/lint/docker/clean` que
  reflejan los comandos del protocolo y del CI (venv, suite offline, ruff, build + smoke test de la
  imagen), para onboarding de un solo comando.
- **Hooks de pre-commit**: `.pre-commit-config.yaml` con ruff (misma puerta E9 que el CI), fixer de
  EOF y de espacios finales; activación opcional con `pip install pre-commit && pre-commit install`
  (documentado en CONTRIBUTING.md; `pre-commit` añadido al extra `[dev]`).
- **Badges dinámicos de tests y versión**: un job de CI regenera `.github/badges/tests.json` y
  `version.json` en cada push a `main` (endpoint JSON de shields.io servido desde el propio repo);
  los badges del README dejan de derivarse a mano (fin del desfase tipo «706 vs 767»).
- **Release automático**: al pushear un tag `vX.Y.Z` (que debe coincidir con `__version__` de
  `core/__init__.py`) el workflow `.github/workflows/release.yml` construye sdist/wheel, publica la
  imagen en GHCR con el build-arg de versión y abre el GitHub Release con las notas extraídas de la
  sección correspondiente del CHANGELOG (fallo limpio si la sección no existe).

### Cambiado
- **Fuente única de versión**: `core/__init__.py` define `__version__` (2.1.1); el banner de la CLI
  lo importa (antes decía "v2.1" fijo), `pyproject.toml` lo deriva vía `setuptools.dynamic` y el job
  de badges del CI lo lee de ahí — la versión ya no puede divergir entre banner, paquete y badges.
- **Dependencias depuradas**: se eliminan `nvdlib`, `waybackpy`, `beautifulsoup4` y `lxml`
  (cero imports en producto, verificado con venv limpio y suite completa) y se declara `urllib3`
  (import directo en `modules/_http.py`) — installs más ligeros y contrato honesto.

### Documentación
- README canónico reescrito en inglés desde cero (19 módulos, exit codes de CI, SARIF, scope/autorización, TOML, dashboard, monitor, plugins, suite offline); el README en español se conserva como `README.es.md` con enlaces cruzados.
- README fiel: badges de versión (2.1.1) y de tests sincronizados con el recuento real de la suite, árbol actualizado y sección Roadmap que resume la fase v2.2 enlazando `docs/agentes/ROADMAP.md`.
- docs/USAGE.md sincronizada con la CLI real: scope y autorización, modo CI con exit codes,
  logging de librería, configuración TOML, dashboard y variables de entorno `OSINT_EYE_*`.
- Guías de contribución: `CONTRIBUTING.md` (setup con Makefile, reglas de suite offline y de
  escaneo autorizado, checklist de PR), `SECURITY.md` (divulgación privada vía GitHub) y
  plantillas de issue (bug/feature) y de pull request.

### Corregido
- **Permutador DNS sondeaba FQDN duplicados**: los candidatos de `generate_*` ya son FQDN completos
  y los resolutores les añadían el dominio otra vez (`www.example.com.example.com`, siempre
  NXDOMAIN); ahora `enumerate()` normaliza los candidatos (tolerando etiquetas desnudas de
  llamantes externos) y sondea el FQDN real.
- **Targets con `/` inalcanzables en el dashboard (H-005)**: las rutas `/api/scan/...` usan el
  converter `<path:target>` (el cliente ya codificaba con `encodeURIComponent`, Werkzeug decodifica
  `%2F` tras el routing), así escaneos con target tipo URL (`http://127.0.0.1:8599`) o JSON hostil
  con barras sirven por todos los endpoints. `merge_slashes` desactivado (sin 308 a otra clave) y
  handler 404 con JSON uniforme en `/api/*` — nunca HTML de error ni 500; residuales documentados
  (targets que empiezan por `/`, colisión con ancla de subruta).

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
