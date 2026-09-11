# Changelog

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
