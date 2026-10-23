# claim: fix-h011-dkim-p-vacio

- Agente: IMP-1
- Fecha: 2026-10-23 18:00 UTC
- Tarea: H-011 de TEST (BAJO) — registro DKIM con p= vacío produce falso positivo; tratar p= vacío como clave revocada (RFC 6376 §3.6.1.1), no como evidencia válida.
- Rutas: modules/dns/email_security.py, tests/test_modules_email_security.py
