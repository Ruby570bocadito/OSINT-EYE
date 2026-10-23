# Referencia de uso — OSINT EYE

Guía extendida de la CLI. Para instalación y quickstart ver el [README](../README.md).

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
# Ver el catálogo
python osint_eye.py --modules

# Ejecutar solo estos módulos, en este orden
python osint_eye.py example.com --modules dns certs cloud correlation graph mitre
```

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

## Plugins

```python
# mi_plugin.py
class PluginTemplate:
    name = "mi_plugin"
    author = "yo"

    async def run(self, target: str) -> dict:
        # tu lógica OSINT
        return {"hallazgo": "ejemplo"}
```

```bash
python osint_eye.py example.com --plugin-dir ./plugins
```

Requisitos del plugin: clase con `name`, `author` distinto de `"built-in"` y `async def run(target)`. Los plugins rotos se reportan y se omiten sin abortar el escaneo.

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

- Caché SQLite por defecto en `~/.osint_eye/cache/` (`--no-cache` para desactivar).
- Con `-o BASE` se generan: `BASE.json`, `BASE.md`, `BASE.html`, `BASE.pdf`, `BASE.sarif`, `BASE_subdomains.csv`, `BASE_ports.csv`, `BASE_emails.csv`, `BASE_cves.csv`, `BASE_mitre.json`, `BASE_navigator.json`, `BASE_graph.html`, `BASE_burp.xml`, `BASE_msf.json` y `bounty_report_<target>.md`.
- El `.sarif` es SARIF 2.1 (takeover, buckets públicos, secretos, CVEs y ficheros sensibles) listo para subir a GitHub Code Scanning.
- El grafo HTML es autónomo (JS inline): ábrelo sin conexión y sin servidor.

## Dashboard web

```bash
python ui/dashboard.py output/mi_scan.json   # → http://127.0.0.1:5000
```

Escucha solo en `127.0.0.1` y funciona 100% offline (sin CDN). Incluye selector multiescaneo con vista diff, explorador de hallazgos con búsqueda y filtros, y exportación JSON/CSV/MD del escaneo abierto vía `GET /api/scan/<target>/export`. Ver la lista completa de endpoints en el [README](../README.md#-dashboard-web).

## Variables de entorno

| Variable | Efecto |
|----------|--------|
| `OSINT_EYE_HTTP_TIMEOUT` | Timeout del cliente HTTP compartido, en segundos (float; default 10) |
| `OSINT_EYE_RATE_LIMIT` | Rate-limit por host:puerto, en segundos entre peticiones (float; 0 = sin límite) |
| `OSINT_EYE_USER_AGENT` | User-Agent personalizado (por defecto `OSINT-EYE/…`) |
| `OSINT_EYE_PROXY` | Proxy opcional para todo el tráfico de colectores |
| `NVD_API_KEY` | Clave NVD opcional: sube el rate limit y reduce el pacing a 0.7 s |
| `NO_COLOR` | Desactiva el color de la CLI (estándar NO_COLOR) |
