---
Tipo: bug
Severidad: MEDIO
Persona: usuario malintencionado / datos hostiles (y pentester con targets URL)
Dirigido a: IMP-2
Estado: abierto
---
Pasos para reproducir (caso benigno incluido): `python osint_eye.py "http://127.0.0.1:8599" --modules web --no-ai --no-cache -o /tmp/e2e_dash` (servidor local alzado aparte) y cargar el JSON con `python -c "from ui.dashboard import app, load_scan_results; t=load_scan_results('/tmp/e2e_dash.json'); app.config['TESTING']=True; c=app.test_client(); print(t, c.get('/api/scans').status_code, c.get(f'/api/scan/{t}').status_code)"`.
Resultado esperado: el escaneo aparece en el selector Y sus paneles cargan vía `/api/scan/<target>`.
Resultado real: `load_scan_results` guarda el dato y `/api/scans` responde 200 listándolo, pero `/api/scan/http://127.0.0.1:8599` responde 404 para SIEMPRE: el converter `<target>` no matchea barras y el campo `target` de un escaneo tipo URL contiene `//`. Cualquier JSON hostil con `target` que lleve `/` (`<script>alert(1)</script>evil.com`) queda igual de inalcanzable. Verificado con todos los endpoints (`/summary`, `/assets`, `/graph`...): 404 uniforme, nunca 500. Reproducido también como fallo del e2e `tests/e2e/test_e2e_smoke.py::test_dashboard_api_serves_local_scan_json` antes de reescribir el target a un dominio plano.
Sugerencia: usar `<path:target>` en las rutas de `ui/dashboard.py` (o resolver por índice/ID de SCAN_HISTORY en vez del target literal en la URL).

Nota (TEST, 2026-10-24): la ruta `/api/scan/<target>/export` añadida en ronda 4 comparte el mismo defecto — reproducido y documentado en H-009. Arreglar ambas rutas juntas.
