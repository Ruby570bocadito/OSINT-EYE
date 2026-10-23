---
Tipo: bug
Severidad: MEDIO
Persona: operador (targets tipo URL) / datos hostiles
Dirigido a: IMP-2
Estado: abierto
---
Pasos para reproducir: producir un escaneo con target URL y cargarlo en el dashboard:
`python osint_eye.py "http://127.0.0.1:8599" --depth quick --no-ai --no-cache --modules web dns -o /tmp/p2_scan` (servidor local alzado aparte), después con el test client de Flask: `c.get('/api/scans')` → 200 y lista el escaneo, pero `c.get('/api/scan/http://127.0.0.1:8599/export?format=json')` → 404. Igual con `format=csv` y `format=md`.
Resultado esperado: el escaneo aparece en el selector Y su exportación JSON/CSV/MD funciona (la ruta se añadió en ronda 4, dashboard-export).
Resultado real: `/api/scan/<target>/export` usa el converter `<target>` (sin `<path:>`), que no matchea barras: para CUALQUIER target que contenga `/` (todos los de tipo URL) la ruta responde 404 para siempre. La feature es inalcanzable para esa clase de targets. Con target de dominio plano (sin barras) funciona: json/csv/md → 200 y `format=xls` → 400 (validación correcta). Es la misma causa raíz que H-005, extendida a la ruta nueva.
Sugerencia: misma solución que H-005 (converter `<path:target>` o resolver por ID de SCAN_HISTORY); arreglar ambas rutas a la vez.
