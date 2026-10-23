# Changelog

## [Unreleased]

### Seguridad
- **Verificación TLS nunca desactivada**: `SecurityHeadersAuditor` y el fallback HTML de `ScreenshotCapture`
  ya no usan `verify=False`; un certificado inválido se reporta como hallazgo (score 0, grado F) en vez de
  degradar la sonda ante objetivos hostiles (riesgo MITM).

### Añadido
- **Dashboard — explorador de hallazgos con búsqueda y filtros**: nueva tabla unificada de activos
  (subdominios, puertos, tecnologías, emails, CVEs, buckets y técnicas MITRE) con búsqueda de texto,
  filtros por severidad, tipo de activo y módulo de origen; API `GET /api/scan/<target>/assets`
  tolerante a datos malformados (nunca 500) y renderizado 100 % offline vía `textContent`.
### Documentación
- README fiel: badges de versión (2.1.1) y tests (118 passing) reales, árbol sincronizado y sección Roadmap que resume la fase v2.2 enlazando `docs/agentes/ROADMAP.md`.

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
