# Estado IMP-1 — Colectores

Actualizado: 2026-10-24 (sesión v2.2, ronda 5 — cerrada, 5/5 tareas)

## Hecho (últimas 24 h)

- (IMP-1) asn-ip-ranges — HECHA: modules/network/asn.py: resuelve target a IP y enumera ASN/holder/prefijos anunciados vía RIPEstat (API pública sin clave) + objeto de red RDAP (nombre, país, rango, tipo) vía rdap.org; degradación por fuente; prefijos solo inteligencia (nunca sondeados); scope-aware; 11 tests (test_modules_asn.py).
- (IMP-1) favicon-hash — HECHA: modules/web/favicon_hash.py (stdlib): MurmurHash3 x86_32 en Python puro (paridad con la librería de referencia: 52/52 casos, cero dependencias nuevas), base64 del icono declarado (<link rel=icon> con fallback /favicon.ico), md5/sha256/tamaño/content-type; respuestas no-imagen nunca se hashean; scope-aware y degradación sin red; 19 tests (test_modules_favicon_hash.py).
- (IMP-1) js-secrets — HECHA: modules/web/js_secrets.py (stdlib): regex (AWS/Google/GitHub/Slack, JWT, Bearer, Firebase, passwords, private keys) + pase de entropía de Shannon + verificación de falsos positivos (placeholders, ${...}/process.env, comentarios, baja diversidad); tope 20 ficheros/2 MB, endpoints /api|rest|graphql; scope-aware y degradación sin red; 16 tests (test_modules_js_secrets.py).
- (IMP-1) tls-audit — HECHA: modules/certs/tls_audit.py (solo stdlib ssl/socket): sondeo por versión (1.0/1.1/1.2/1.3), familias débiles (RC4/3DES/CBC-SHA1/aNULL), certificado (caducidad, SANs, autofirmado, SHA-1), cadena verificada; hallazgos con severidad, score 0-100 y nota A-F; degradación sin conexión y gate de scope. Cableado mínimo en osint_eye.py (catálogo, module_map, --modules, run_tls_audit con scope). 30 tests (test_modules_tls_audit.py).
- (IMP-1) scope-collectores — HECHA: modules/_scope.py (helpers duck-typed; scope=None = comportamiento previo) + gate de scope en objetivos derivados: brute-force DNS de wordlist, permutaciones, vhosts derivados, ficheros JS de terceros, URLs de páginas de email, buckets cloud y endpoints web; descartes auditables en results["scope"]["discarded"] con etiqueta por módulo. Incluye fix del permutador, que sondeaba FQDN duplicados (www.example.com.example.com). 22 tests (test_modules_scope.py), suite en 767 verde.

## En curso

- (nada — sesión cerrada)

## Bloqueado

- (nada)

## Peticiones a otras zonas

- IMP-3: cuando el orquestador construya el Scope (core/scope.py), pásalo a los colectores — todos aceptan scope como kwarg opcional (None = sin filtro): SubdomainEnumerator.enumerate/enumerate_with_resolve, SubdomainPermutator.enumerate, VirtualHostBruteforcer.bruteforce, JavaScriptEndpointDiscovery.scan, CloudBucketDetector.scan, EmailEnumerator.extract_from_web/scan, EndpointDiscovery.discover/discover_sensitive/discover_apis, WebScanner.scan. Los descartes ya caen en Scope.discarded → results["scope"].
- IMP-2: nota de contrato — endpoint discovery ahora pre-filtra antes del pool: "total_tested" cuenta solo peticiones realmente intentadas cuando hay scope (antes contaba futuros encolados).

## Propuestas para el roadmap

- [ ] (IMP-1) well-known-analysis — análisis de robots.txt, sitemap.xml, security.txt y .well-known/* (detección, no fuerza bruta) — modules/web/wellknown.py
- [ ] (IMP-1) exposed-repos — detección de .git/.svn/.env expuestos solo por HEAD/existencia con códigos de estado, sin descargar contenido — modules/web/exposed_files.py
- [ ] (IMP-1) api-discovery — descubrimiento de swagger.json/openapi.yaml/GraphQL introspection (solo detección pasiva) — modules/web/api_discovery.py
- [ ] (IMP-1) http-client-metrics — contadores agregados por host (peticiones, reintentos, 429) en results para visibilidad de rate limiting — modules/_http.py, results
