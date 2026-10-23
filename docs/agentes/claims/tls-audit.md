# Claim: tls-audit

- ID: IMP-1
- Fecha: 2026-10-24 09:05 UTC
- Rutas: modules/certs/tls_audit.py (nuevo), tests/test_modules_tls_audit.py (nuevo), osint_eye.py (solo cableado mínimo: import + registro en catálogo/module_map/choices + run_tls_audit, excepción §2 del protocolo)
- Tarea: tls-audit — versión TLS, cifrados débiles, caducidad y cadena del certificado con ssl de la stdlib; scope opcional en la conexión; degradación grácil si el host no responde.
