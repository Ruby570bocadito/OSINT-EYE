# Referencia de uso — OSINT EYE

Guía extendida de la CLI. Para instalación y quickstart ver el [README](../README.md). El mapa completo de la documentación (arquitectura, módulos, plugins, FAQ) vive en el [hub de docs](index.md).

## Profundidades de escaneo

| Depth | Qué ejecuta |
|-------|-------------|
| `quick` | Fase 1 (dns, certs, wayback, whois) + web + correlación, grafo, MITRE y IA. Sin red, sin dorking, sin endpoints. |
| `normal` | quick + network + cdn_waf + dorking (github/google salvo `--stealth`) + CVE. |
| `deep` | normal + permutation + takeover + endpoints + cloud + emails. |
| `full` | igual que `deep` (alias histórico). |

Las fases 1-3 ejecutan sus módulos concurrentemente (pools acotados); la fase 4 (correlación, grafo, MITRE, chains, IA) es secuencial porque cada análisis depende del anterior.

## Seleccionar módulos

```bash
# Ver el catálogo (tabla Rich con la descripción de cada clave)
python osint_eye.py --modules

# Ejecutar solo estos módulos, en este orden
python osint_eye.py example.com --modules dns certs cloud correlation graph mitre

# Comas y espacios son equivalentes (y se pueden mezclar); se deduplica
python osint_eye.py example.com --modules dns,web
```

Una clave desconocida es un error de uso limpio (exit 2) con mensaje accionable: lista de módulos válidos + hint `--modules dns,web` (nada del volcado de usage de ~40 líneas).

Catálogo completo de claves `--modules` (los 12 colectores built-in más los pasos de motor y análisis):

| Clave | Qué hace |
|-------|----------|
| `dns` | Enumeración de registros DNS (A/AAAA/MX/NS/TXT/CNAME/SOA) + bruteforce de subdominios |
| `certs` | Descubrimiento de subdominios por certificate transparency (crt.sh) |
| `tls_audit` | Versiones de protocolo TLS, cifrados débiles, caducidad y cadena del certificado (stdlib ssl) |
| `shodan_censys` | Inteligencia de hosts vía Shodan/Censys/FOFA (claves opcionales por env `OSINT_EYE_*`; se salta sin ellas) |
| `reverse_ip` | Vecinos por reverse-IP (fuente pública sin clave, solo inteligencia) + virtual hosts por probing del Host-header |
| `social_footprint` | Cuentas de la organización en GitHub/GitLab/Docker Hub/npm/PyPI vía APIs públicas sin clave |
| `leak_check` | Catálogo público de brechas (solo metadatos, nunca credenciales): brechas del dominio exacto + menciones del nombre |
| `wayback` | Histórico de URLs y timeline de snapshots de Wayback Machine |
| `network` | Descubrimiento de puertos y servicios vía nmap (skip grácil si nmap no está) |
| `whois` | Datos de registro y propiedad del dominio |
| `github` | Dorking de código en GitHub para secretos y configs filtrados |
| `google` | Dorking de Google para paneles, ficheros y backups expuestos |
| `cve` | Búsqueda NVD/CVE para los servicios descubiertos por network |
| `web` | Fingerprinting HTTP de tecnologías del target |
| `endpoints` | Descubrimiento de endpoints JS/HTML + sondeo de ficheros sensibles |
| `cloud` | Descubrimiento de buckets cloud (S3/GCP/Azure) y exposición pública |
| `emails` | Enumeración de emails desde WHOIS y fuentes públicas |
| `permutation` | Generación y resolución de permutaciones de subdominios |
| `takeover` | Detección de subdomain takeover (fingerprints de CNAME colgantes) |
| `cdn_waf` | Fingerprinting de CDN y WAF |
| `correlation` | Correlación entre módulos + attack surface score |
| `graph` | Grafo de relaciones (export HTML interactivo) |
| `mitre` | Mapeo a técnicas MITRE ATT&CK + export Navigator |
| `chains` | Constructor de cadenas de ataque (hipótesis multi-paso) |

Dependencias entre módulos a tener en cuenta:
- `cve` consume los servicios del módulo `network` (sin network, no hay CVEs que buscar).
- `takeover` consume subdominios de `permutation` o `dns`.
- `correlation`/`graph`/`mitre`/`chains` funcionan con lo que haya en `results.modules`, así que da igual qué módulos corrieron antes.

## Scope y autorización

Nada fuera del scope declarado se toca. Dos mecanismos complementarios:

```bash
# Scope desde archivo: un patrón por línea (# comentarios)
python osint_eye.py example.com --scope scope.txt

# Exclusiones puntuales (repetibles; SIEMPRE ganan al --scope)
python osint_eye.py example.com --scope scope.txt --exclude sub.example.com --exclude 10.0.0.0/8
```

`scope.txt` acepta dominios (`example.com`), wildcards (`*.example.com`), IPs y CIDR IPv4/IPv6 (`192.0.2.0/24`). Los targets y candidatos fuera de scope (permutaciones, sondas de takeover) se omiten y quedan registrados en `results["scope"]["discarded"]` con target, módulo, motivo y timestamp. Un archivo de scope inválido es un error de uso limpio antes de empezar a escanear.

El asistente interactivo (sin argumentos) también pregunta scope/exclusiones y exige autorización explícita antes de lanzar módulos activos.

## Modo CI (`--fail-on`)

```bash
python osint_eye.py example.com --fail-on medium
```

Compara la peor severidad del `attack_surface_score` con el umbral y fija el exit code, pensado para pipelines:

| Exit | Significado |
|------|-------------|
| `0` | Escaneo terminado dentro del umbral |
| `1` | Umbral `--fail-on` alcanzado o superado (`high` falla también con `critical`) |
| `2` | Error de uso (argumentos, archivo de scope inválido…) |
| `3` | Ningún target escaneado (todo fuera de scope) |
| `130` | Interrumpido por el operador (Ctrl+C; POSIX 128+SIGINT). Reúne los resultados parciales, imprime el resumen de los targets completados y sale limpio — nunca traceback crudo |

## Configuración TOML (`--config` / `--profile`)

```bash
python osint_eye.py example.com --config mi_config.toml
python osint_eye.py example.com --config mi_config.toml --profile deep
```

Si existe `osint_eye.toml` en el directorio actual se lee por defecto. Documento soportado:

```toml
[scan]
depth = "normal"            # quick | normal | deep | full
stealth = false
no_ai = false
no_cache = false
modules = ["dns", "certs"]  # set de módulos por defecto (como --modules)

[timeouts]
monitor_interval = 3600     # segundos entre ciclos del monitor

[scope]
includes = ["example.com"]  # misma sintaxis que --scope
excludes = ["10.0.0.0/8"]

[exports]
formats = ["json", "sarif"] # subconjunto del catálogo de exportadores

[profiles.deep]             # perfiles con nombre
[profiles.deep.scan]
depth = "full"
```

Precedencia: los flags CLI ganan siempre al fichero; dentro del fichero, el perfil seleccionado sobreescribe las tablas de primer nivel. Secciones o claves desconocidas se rechazan al cargar (los typos nunca se ignoran en silencio). Requiere `tomllib` (Python 3.11+); en 3.10 el resto de la herramienta funciona igual sin TOML.

## Logging de librería

```bash
# Nivel DEBUG en consola (stderr) para diagnosticar
python osint_eye.py example.com --log-level DEBUG

# Logs de librería a fichero (append); la consola sigue intacta
python osint_eye.py example.com --log-file scan.log
```

`core/`, `graph/` y `reporting/` registran por el árbol `osint_eye` (nunca `print()`); Rich sigue siendo la única salida de usuario. El nivel por defecto es `INFO`; un nivel inválido es error de uso limpio. La salida del monitor (alertas, ciclos) también va por `logging`.

## Monitor daemon

```bash
python osint_eye.py example.com --monitor --monitor-interval 300 \
    --webhook "https://discord.com/api/webhooks/..."
```

- El daemon establece una **baseline** de subdominios conocidos en el primer ciclo y solo alerta de **novedades** en los siguientes.
- `--webhook` envía un mensaje por cada nueva superficie detectada (compatible Discord/Slack: payload `{"text": ...}`).
- `Ctrl+C` para la parada elegante (el sleep del intervalo es interruptible, no espera el ciclo completo).
- La caché (`~/.osint_eye/` o `--no-cache`) guarda el histórico para los diffs.
- El guard de webhook valida la URL antes de arrancar: exige `https` y host público (loopback, IPs privadas y metadatos cloud bloqueados, reutilizando la lógica anti-SSRF) y se re-verifica en runtime — un typo nunca filtra datos del escaneo hacia la red interna.

## Plugins

```python
# mi_plugin.py — contrato recomendado: BaseModule (core/plugins.py)
from core.plugins import BaseModule

class MiPlugin(BaseModule):
    name = "mi_plugin"          # clave única en el registro
    description = "Qué recolecta, en una línea"
    author = "yo"
    requires_api_key = False

    async def run(self, target: str, **kwargs) -> dict:
        # tu lógica OSINT
        return {"target": target, "hallazgos": ["ejemplo"]}
```

```bash
python osint_eye.py example.com --plugin-dir ./plugins --modules mi_plugin
```

Reglas de carga: todos los `*.py` del directorio (ordenados, se ignoran los que empiezan por `_`); cada subclase de `BaseModule` se instancia y registra; los plugins rotos (sintaxis, imports, falta de `name`/`run`) se reportan con `[!]` y se omiten sin abortar el escaneo. El dict devuelto pasa por `core/schema.py` (los nombres de módulo desconocidos nunca rompen la validación). Contrato completo, reglas del PluginManager y ejemplo offline-testable en [docs/plugins.md](plugins.md).

## IA local (Ollama)

```bash
ollama pull llama3.2
python osint_eye.py example.com --agent      # playbook de análisis
python osint_eye.py example.com --no-ai      # desactiva el análisis IA
```

- El motor solo habla con `http://localhost:11434` (sin nube, sin claves).
- Sin Ollama instalado, `analyze()` devuelve `{"status": "unavailable"}` en milisegundos — el escaneo sigue.
- `--agent` genera además un playbook accionable a partir de los hallazgos.

## Caché y resultados

- Caché SQLite por defecto en `~/.osint_eye/cache/` (`--no-cache` para desactivar). Una caché corrupta no tira el escaneo: se detecta al inicializar, el fichero se pone en cuarentena (`<db>.corrupt`, sin destruirse nunca) y se recrea vacía con un aviso al operador.
- **Sin `-o`** cada escaneo auto-guarda `osint_eye_<target>_<ts>.json` en el directorio actual (misma convención que el PDF por defecto) e imprime dónde quedó — el quickstart del README ya deja fichero reutilizable, y la rama `--dashboard` reutiliza ese fichero en vez de generar un duplicado con otro timestamp.
- **`-o BASE`** se genera: `BASE.json`, `BASE.md`, `BASE.html`, `BASE.pdf` (`--pdf`), `BASE.sarif`, `BASE_subdomains.csv`, `BASE_ports.csv`, `BASE_emails.csv`, `BASE_cves.csv`, `BASE_mitre.json`, `BASE_navigator.json`, `BASE_graph.html`, `BASE_burp.xml`, `BASE_msf.json` y `bounty_report_<target>.md`. Si `pdf` está entre los formatos de export, la rama `--pdf` no duplica el render.
- **Toda ruta de salida suministrada por el usuario** (`-o`, `--export-cypher`, `--log-file`) debe resolver dentro del directorio de trabajo: las que escapan se rechazan con error de uso (exit 2) antes de escanear o escribir nada.
- `--export-cypher BASE.cypher` vuelca el grafo a un dump compatible con Neo4j (literals escapados, labels sanitizados).
- El `.sarif` es SARIF 2.1 (takeover, buckets públicos, secretos, CVEs y ficheros sensibles) listo para subir a GitHub Code Scanning.
- El grafo HTML es autónomo (JS inline): ábrelo sin conexión y sin servidor.

## Dashboard web y TUI

```bash
python osint_eye.py example.com --dashboard      # escanea y abre el dashboard
python ui/dashboard.py output/mi_scan.json       # → http://127.0.0.1:5000
python osint_eye.py example.com --tui            # escanea y explora en la TUI
```

Escucha solo en `127.0.0.1` y funciona 100% offline (sin CDN). Incluye selector multiescaneo con vista diff, explorador de hallazgos con búsqueda y filtros, y exportación JSON/CSV/MD del escaneo abierto vía `GET /api/scan/<target>/export`. Ver la lista completa de endpoints en el [README](../README.md#-dashboard-web).

La **TUI** (`--tui`, Textual) muestra los resultados en pestañas navegables con filtro y ficha por activo, sin salir de la terminal. Ambas interfaces cargan cualquier JSON de resultados con `schema_version` 2.x.

## Variables de entorno

| Variable | Efecto |
|----------|--------|
| `OSINT_EYE_HTTP_TIMEOUT` | Timeout del cliente HTTP compartido, en segundos (float; default 10) |
| `OSINT_EYE_RATE_LIMIT` | Rate-limit por host:puerto, en segundos entre peticiones (float; 0 = sin límite) |
| `OSINT_EYE_USER_AGENT` | User-Agent personalizado (por defecto `OSINT-EYE/…`) |
| `OSINT_EYE_PROXY` | Proxy opcional para todo el tráfico de colectores |
| `NVD_API_KEY` | Clave NVD opcional: sube el rate limit y reduce el pacing a 0.7 s |
| `NO_COLOR` | Desactiva el color de la CLI (estándar NO_COLOR) |
