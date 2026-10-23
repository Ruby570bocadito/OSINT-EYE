# Estado IMP-1 — Colectores

Actualizado: 2026-10-24 (sesión v2.3, ronda 6 — cerrada, 5/5 tareas; suite en 1055 verde)

## Hecho (últimas 24 h)

- (IMP-1) fix-h011-dkim-p-vacio — HECHA (b43d184): check_dkim ya no da por protegido un dominio con `p=` vacío (clave revocada, RFC 6376 §3.6.1.1): selectores en dkim.revoked con motivo (revoked/malformed), present solo con clave real, score conserva la deducción -15 y recomendación de republicar. 6 tests; hallazgo H-011 a resuelto-pendiente-verificación.
- (IMP-1) shodan-censys — HECHA (31c4dcc): modules/osint/shodan_censys.py; Shodan/Censys v2/FOFA con claves del usuario por env (OSINT_EYE_SHODAN_KEY, OSINT_EYE_CENSYS_API_ID/SECRET, OSINT_EYE_FOFA_EMAIL/KEY); sin clave cada proveedor status "skipped" y el escaneo sigue; degradación por proveedor (HTTP/JSON/red con motivo corto); claves nunca entran en results; resumen fusionado (puertos/servicios/subdominios). Cableado mínimo --modules shodan_censys. 16 tests.
- (IMP-1) reverse-ip-vhosts — HECHA (729ae55): modules/network/reverse_ip.py + data/wordlists/vhosts.txt; vecinos vía HackerTarget sin clave (solo inteligencia, nunca se contacta a los vecinos; mensajes del fuente jamás se vuelven datos) + vhosts sondando la IP del objetivo con Host headers (derivados del dominio o explícitos; baseline status/Server/título/longitud >25%); scope-aware con descartes auditables. 17 tests.
- (IMP-1) social-footprint — HECHA (ef47d86): modules/osint/social_footprint.py; GitHub/GitLab/Docker Hub/npm/PyPI con APIs públicas sin clave; nombre de cuenta derivado del dominio (o explícito, 2ª ronda si la 1ª no encuentra nada); degradación por plataforma; payloads malformados tolerados. 19 tests.
- (IMP-1) leak-check — HECHA (452e995): modules/osint/leak_check.py; catálogo público de brechas HIBP sin clave, solo metadatos (nunca credenciales): dominio exacto (campo Domain) + mención heurística del nombre de la org en título/descripción (reportada como heurística, nombres <4 chars ignorados); catálogo 1 request por escaneo, 429/403/red degradan. 14 tests.

## En curso

- (nada — sesión cerrada)

## Bloqueado

- (nada)

## Peticiones a otras zonas

- TEST: H-011 marcado resuelto-pendiente-verificación (commit b43d184) — lista para verificación.
- IMP-3: los 4 módulos nuevos añaden claves aditivas en results["modules"] con bloque summary de counts listos para fichas; el contrato results["modules"][<nombre>] no cambia de forma.
- IMP-2: si el dashboard quiere fichas de estos módulos, summary.platforms_found/neighbors/vhosts_found/exact_domain_breaches ya vienen normalizados.
- PUL-2: modules/network/scanner.py y modules/dns/advanced_dns.py siguen siendo los grandes pendientes de trocear; mis módulos nuevos ya están en piezas separadas.

## Propuestas para el roadmap

- [ ] (IMP-1) hibp-verified-domain — verificación de brechas por dominio con HIBP key de pago opcional (env OSINT_EYE_HIBP_KEY) completando el leak-check público; se salta sin clave — modules/osint/leak_check.py
- [ ] (IMP-1) vhosts-from-subdomains — reutilizar los subdominios ya descubiertos (dns/certs/caché) como candidatos de Host-header probing en reverse_ip en vez de solo la wordlist — modules/network/reverse_ip.py, core
- [ ] (IMP-1) source-health-metrics — métricas por fuente (latencia, tasa de error, reintentos) agregadas en results para diagnosticar fuentes caídas entre escaneos — modules/_http.py, transversal
