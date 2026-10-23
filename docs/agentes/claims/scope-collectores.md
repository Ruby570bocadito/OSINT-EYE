# Claim: scope-collectores

- ID: IMP-1
- Fecha: 2026-10-24 08:20 UTC
- Rutas: modules/dns/dns_scanner.py, modules/dns/subdomain_permutator.py, modules/dns/advanced_dns.py, modules/osint/cloud_email.py, modules/web/web_scanner.py, tests/test_modules_scope.py
- Tarea: aplicar Scope.allows()/filter_targets() (core/scope.py) a los objetivos derivados dentro de cada módulo (brute-force DNS de wordlist, permutaciones, endpoints JS/vhosts, cloud, URLs de web); scope opcional, sin scope = comportamiento actual.
