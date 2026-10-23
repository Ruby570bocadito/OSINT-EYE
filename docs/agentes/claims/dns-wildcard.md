# Claim: dns-wildcard

- **Agente:** IMP-1
- **Fecha/hora UTC:** 2026-10-23 10:20 UTC
- **Tarea (ROADMAP):** (IMP-1) dns-wildcard — detección de DNS wildcard antes de la fuerza bruta y permutaciones (evita miles de falsos positivos)
- **Rutas que voy a tocar:**
  - `modules/dns/wildcard.py` (nuevo: WildcardDetector)
  - `modules/dns/dns_scanner.py` (detección previa en scan + filtro en SubdomainEnumerator)
  - `modules/dns/subdomain_permutator.py` (filtro opt-in en enumerate)
  - `modules/dns/__init__.py` (export WildcardDetector)
  - `tests/test_modules_wildcard.py` (nuevo, offline con resolve_fn inyectado)
  - `CHANGELOG.md` (solo añadir línea bajo `## [Unreleased]`)
- **Diseño:** detector opt-in por parámetro (cero resolución DNS oculta en tests existentes); IPs comparadas con las de las sondas aleatorias; los candidatos cuya resolución es subconjunto de las IPs wildcard se descartan y se contabilizan.
