# Estado TEST — Tester por personas

Actualizado: 2026-10-23 16:30 UTC · Ronda 1 v2.2 · **Semáforo: 🟡 AMARILLO** (8 hallazgos abiertos, 1 MEDIO en dashboard y 2 MEDIO en CLI; núcleo estable)

## Hecho (últimas 24 h)

- Instalación desde cero siguiendo SOLO README.md en venv limpio: OK (`pip install -r requirements.txt` + `--help` EXIT=0). Nota: la primera instalación dejó `python-whois` sin importar (falla silenciosa transitoria de pip en este entorno; tras reinstalar funciona — no reproducible, sin hallazgo).
- 5 personas probadas · flujos: quick scan example.com, exportaciones completas (-o JSON/MD/HTML/PDF/Burp/MSF/CSVs/mitre/graph), targets malformados (5 casos), ESC en target, `-o` traversal, JSON hostil en los 10 endpoints del dashboard, caché SQLite corrupta, Ctrl+C a mitad, fixture HTTP local e2e (con y sin redirect a metadatos).
- e2e-smoke (ROADMAP) entregado: `tests/e2e/test_e2e_smoke.py`, 9 tests 100 % offline (subprocess + fixtures loopback): `--help`, `--modules`, targets malformados sin traceback, quick scan contra fixture local (detecta `Nginx`), regresión e2e del guard SSRF (302 a 169.254.169.254 bloqueado y el escaneo sigue), dashboard sirve el JSON producido. Suite completa: 279 passed.
- Hallazgos resuelto-pendiente-verificación al abrir la sesión: ninguno (directorio vacío).
- Hallazgos abiertos por destinatario: **IMP-3: 7** (H-001 sin persistencia, H-002 validación targets, H-003 `-o` traversal, H-004 ESC injection, H-006 caché corrupta crash, H-007 Ctrl+C crudo, H-008 PDF duplicado) · **IMP-2: 1** (H-005 targets con `/` inalcanzables en dashboard, reproduce con targets tipo URL).

## En curso

- (nada)

## Bloqueado

- (nada)

## Sin probar (próxima ronda)

- TUI Textual, wizard interactivo (TTY real), `--diff` multi-target (el intento con `--depth full` excedió el time-box), `--monitor` largo con webhook, plugins `--plugin-dir`, `--agent` con Ollama, `--export-cypher`, Docker, Windows/macOS, red lenta/DNS caído/disco lleno.

## Peticiones a otras zonas

- (PUL-1) `.gitignore`: patrón `venv*/` (los venvs por-agente no quedan cubiertos por `venv/`).
- (DIR) El foco de la próxima ronda IMP-3 debería ser H-006 (caché corrupta = crash con EXIT=1) y H-002 (validación de targets): son los que más confunden a un usuario nuevo.

## Propuestas para el roadmap

- (IMP-3) dry-run-modules — `--dry-run` lista los módulos que tocarían el target y qué fuentes externas consultarían, sin ejecutar nada — osint_eye.py
- (IMP-2) dashboard-vacio-guiado — cuando el dashboard carga datos demo, panel con los 3 comandos exactos para generar un escaneo real (hoy solo dice "demo") — ui/dashboard_template.html
