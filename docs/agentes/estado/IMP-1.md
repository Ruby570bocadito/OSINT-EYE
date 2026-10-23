# Estado IMP-1 — Colectores

Actualizado: 2026-10-23 (sesión v2.2, ronda 1 — cerrada, 5/5 tareas)

## Hecho (últimas 24 h)

- Bootstrap: docs/agentes/ (PROTOCOLO, OWNERSHIP, ROADMAP, PROMPTS) no existía en el repo; materializado con el texto exacto de la especificación. A partir de ahora el ROADMAP solo lo edita DIR.
- Baseline verificada: compileall OK, 118 tests en verde (v2.1.1, a2dba92). Al cerrar sesión: 506 tests en verde.
- (IMP-1) http-client-unico — HECHA: modules/_http.py (HTTPClient: timeout, retries+backoff, UA identificable, rate-limit por host, proxy, env vars) + migración de los 9 archivos con requests sueltos en modules/; 38 tests (test_modules_http.py). Integrado con el ssrf_guard de SEG (safe_get sobre el cliente compartido).
- (IMP-1) passive-subdomains — HECHA: modules/dns/passive_sources.py (HackerTarget, OTX, Anubis, RapidDNS, CertSpotter; paralelo, validación estricta de hostnames, dedupe) + integración en DNSScanner "full" (results["dns"]["passive_subdomains"]); 47 tests.
- (IMP-1) dns-wildcard — HECHA: modules/dns/wildcard.py (sondas aleatorias, confianza high/medium, huella de IPs) + filtro opt-in en SubdomainEnumerator y SubdomainPermutator + results["dns"]["wildcard"] con contador "skipped"; 32 tests.
- (IMP-1) email-security — HECHA: modules/dns/email_security.py (DKIM 18 selectores, MTA-STS, TLS-RPT, BIMI, MX, puntuación de spoofing explicable con desglose y recomendaciones) + results["dns"]["email_security"]; 28 tests.
- (IMP-1) security-headers — HECHA: modules/web/headers_audit.py (SecurityHeadersAuditor ampliada: CORS wildcard/credenciales, cookies Secure/HttpOnly/SameSite, severidad en todos los hallazgos; deducciones previas intactas), re-export desde modules/dns por compatibilidad, cableada en WebScanner.scan (results["web"]["headers_audit"]); 22 tests.

## En curso

- (nada — sesión cerrada)

## Bloqueado

- (nada)

## Peticiones a otras zonas

- PUL-1/DIR: la rama `main` está por detrás de `master` (default branch). Se ha trabajado sobre master/HEAD; los commits "chore: sync" posteriores sugieren que ya se está sincronizando — verificar que main == master al abrir la siguiente ronda.
- IMP-3: resultados nuevos del contrato en results["modules"]: dns.passive_subdomains, dns.wildcard (con skipped), dns.email_security (spoofing_score/risk/recommendations), web.headers_audit (score/grade/cors_findings/cookie_findings). Si core/schema.py quiere validarlos, son todos dicts lenientes; avísame si necesitas cambios de forma.
- IMP-2: el dashboard/CLI puede mostrar wildcard.skipped, email_security.risk y headers_audit.grade (datos ya en results).
- PUL-2: en modules/dns/advanced_dns.py queda el re-export de SecurityHeadersAuditor; si mueves el módulo, actualiza el comentario de compatibilidad (no romper from modules.dns import SecurityHeadersAuditor: lo usan tests históricos).

## Propuestas para el roadmap

- [ ] (IMP-1) well-known-analysis — análisis de robots.txt, sitemap.xml, security.txt y .well-known/* (detección, no fuerza bruta) — modules/web/wellknown.py
- [ ] (IMP-1) exposed-repos — detección de .git/.svn/.env expuestos solo por HEAD/existencia con códigos de estado, sin descargar contenido — modules/web/exposed_files.py
- [ ] (IMP-1) api-discovery — descubrimiento de swagger.json/openapi.yaml/GraphQL introspection (solo detección pasiva) — modules/web/api_discovery.py
- [ ] (IMP-1) http-client-metrics — contadores agregados por host (peticiones, reintentos, 429) en results para visibilidad de rate limiting — modules/_http.py, results
- [ ] (PUL-2) aiohttp-hygiene — las sesiones aiohttp de modules/dns/advanced_dns.py (VirtualHostBruteforcer, JavaScriptEndpointDiscovery) no pasan por modules/_http.py; unificar timeout/UA si el guard lo permite — modules/dns/advanced_dns.py
