# Estado SEG — Seguridad y bugs

Actualizado: 2026-10-23 16:30 UTC · Ronda 1 v2.2 · **Semáforo: 🟢 VERDE** (suite 279 en verde, 3 fixes entregados)

## Hecho (últimas 24 h)

- [x] tls-verify-advanced-dns — backport del fix de `audit-improvements` d72e786 nunca fusionado: `SecurityHeadersAuditor` y fallback de `ScreenshotCapture` dejan de usar `verify=False` (certificado inválido = hallazgo score 0/grado F). 12 tests offline con servidor HTTPS local. c811c66.
- [x] ssrf-redirects (ROADMAP) — nuevo `modules/web/ssrf_guard.py`: `safe_get()` sigue redirecciones hop a hop validando esquema y direcciones resueltas contra redes no-públicas explícitas (metadatos cloud 169.254.169.254 incluidos); cableado en TechDetector, SensitiveDataDetector, CDNDetector y SubdomainTakeoverDetector (CNAME colgante = dominio del atacante). 45 tests offline. e136e02.
- [x] ssrf-hops-only — refinamiento tras e2e: la URL inicial es elección explícita del operador (escanear localhost/fixtures debe seguir funcionando); la validación aplica SOLO a hops de redirección. 279 tests en verde.
- [x] dashboard-api-hardening (ROADMAP) — CSP que bloquea toda carga externa y framing, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Cache-Control: no-store` en `/api/*`, límite 64 MB por JSON de escaneo, `RecursionError` capturado, plantilla servida verbatim sin Jinja. 18 tests. <commit hardening>.
- Revisión session_cache.py: SQL estático/parametrizado, `json.loads` (sin pickle) — limpio.
- pip-audit sobre requirements: **0 vulnerabilidades conocidas** (16:10 UTC).

## En curso

- (nada)

## Bloqueado

- (nada)

## Peticiones a otras zonas

- (IMP-2) Cuando toques `ui/dashboard_template.html`: adoptar CSP por nonce (`script-src 'nonce-…'`) y quitar `'unsafe-inline'` — la parte "CSP sin inline" de dashboard-api-hardening; no lo toqué porque la plantilla está en iteración activa.
- (IMP-1) `http-client-unico`: absorbe `ssrf_guard.safe_get` en el cliente compartido y añade pinning de IPs a nivel socket (limitación conocida: rebinding DNS entre validación y conexión); cubre también los clientes de API de endpoints fijos (github/google/crt.sh/NVD/wayback), hoy fuera del guard.
- (PUL-1) `.gitignore`: `venv-test/` no está cubierto (solo `venv/` y `.venv/`); añadir patrón `venv*/` — cada agente crea su venv con nombre propio.
- (PUL-1) audit-deps: pip-audit OK hoy; propuesta fijar mínimos seguros en requirements cuando sincronices dependencias.

## Propuestas para el roadmap

- (IMP-3) sanitize-console — saneado único de bytes de control (ESC/OSC) en targets y datos externos antes de imprimir en consola/informes (ver hallazgo H-004) — osint_eye.py, ui/, modules/
- (IMP-3) safe-output-base — `-o` resuelto contra CWD con rechazo/aviso de escapes y sobrescrituras fuera del árbol (ver H-003) — osint_eye.py
- (PUL-2) excepciones-cache — patrón unificado de recuperación ante caché/estado corrupto (recrear + avisar) transversal a core/ (ver H-006) — core/
