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
- `correlation`/`graph`/`mitre`/`chains` funcionan con lo que haya en `results.modules`, así que da igual qué módulos corríeron antes.

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
- Con `-o BASE` se generan: `BASE.json`, `BASE.md`, `BASE.html`, `BASE.pdf`, `BASE_subdomains.csv`, `BASE_ports.csv`, `BASE_emails.csv`, `BASE_cves.csv`, `BASE_mitre.json`, `BASE_navigator.json`, `BASE_graph.html`, `BASE_burp.xml`, `BASE_msf.json` y `bounty_report_<target>.md`.
- El grafo HTML es autónomo (JS inline): ábrelo sin conexión y sin servidor.

## Variables de entorno

| Variable | Efecto |
|----------|--------|
| `NVD_API_KEY` | Clave NVD opcional: sube el rate limit y reduce el pacing a 0.7 s |
| `NO_COLOR` | Desactiva el color de la CLI (estándar NO_COLOR) |
