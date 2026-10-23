---
Tipo: mejora
Severidad: MEDIO
Persona: usuario torpe
Dirigido a: IMP-3
Estado: resuelto-pendiente-verificación
---
Pasos para reproducir: para cada caso ejecutar `python osint_eye.py "<target>" --depth quick --no-ai --no-cache --modules dns` con target = `HTTPS://Example.COM`, `example.com ` (con espacio final), `not_a_domain!!`, `https://example.com/ruta`, `example.com/path?x=1` y revisar el JSON con `-o /tmp/x`.
Resultado esperado: aviso accionable (o aborto) para targets que no son dominio/IP válidos; o normalización visible (host extraído, minúsculas).
Resultado real: los cinco casos terminan con EXIT=0, sin traceback y sin ningún aviso; `osint_eye.py example.com/path?x=1 --modules dns` llega a ejecutar `Getting DNS records for example.com/path?x=1...`; el JSON guarda `target: "HTTPS://Example.COM"` tal cual, `dns.error` está ausente y `dns.subdomains` es `[]`. El usuario cree que escaneó algo cuando en realidad no se resolvió nada.
Sugerencia: validar dominio/IP/CIDR al inicio de run() (dominios con regex + ipaddress) y normalizar (strip, lowercase, extraer netloc de URLs); abortar con mensaje accionable si no encaja (la propuesta wizard-validacion-target de IMP-2 cubre el wizard, esto es la CLI directa).

Resolución (IMP-3): `_normalize_cli_target()` en osint_eye.py + validación de args.targets en main()
antes de cualquier escaneo. Normaliza (strip, rstrip '.'/'/', minúsculas, scheme+netloc de URLs —
el scheme se conserva para el módulo web y el host:port para los fixtures loopback del e2e; IPv6
reconstruye corchetes; token con path → host; userinfo '@' y '[v6]:port' soportados) y valida el
host con las reglas del wizard (ui/wizard._validate_target, gemelo CLI de wizard-validacion-target).
Los 5 casos del hallazgo: 4 se normalizan (visibles en results.target), `not_a_domain!!` aborta con
exit 2 y mensaje accionable. Regresión: tests/test_target_validation.py (10 tests).
