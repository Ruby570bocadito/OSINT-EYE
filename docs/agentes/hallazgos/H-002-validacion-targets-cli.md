---
Tipo: mejora
Severidad: MEDIO
Persona: usuario torpe
Dirigido a: IMP-3
Estado: abierto
---
Pasos para reproducir: para cada caso ejecutar `python osint_eye.py "<target>" --depth quick --no-ai --no-cache --modules dns` con target = `HTTPS://Example.COM`, `example.com ` (con espacio final), `not_a_domain!!`, `https://example.com/ruta`, `example.com/path?x=1` y revisar el JSON con `-o /tmp/x`.
Resultado esperado: aviso accionable (o aborto) para targets que no son dominio/IP válidos; o normalización visible (host extraído, minúsculas).
Resultado real: los cinco casos terminan con EXIT=0, sin traceback y sin ningún aviso; `osint_eye.py example.com/path?x=1 --modules dns` llega a ejecutar `Getting DNS records for example.com/path?x=1...`; el JSON guarda `target: "HTTPS://Example.COM"` tal cual, `dns.error` está ausente y `dns.subdomains` es `[]`. El usuario cree que escaneó algo cuando en realidad no se resolvió nada.
Sugerencia: validar dominio/IP/CIDR al inicio de run() (dominios con regex + ipaddress) y normalizar (strip, lowercase, extraer netloc de URLs); abortar con mensaje accionable si no encaja (la propuesta wizard-validacion-target de IMP-2 cubre el wizard, esto es la CLI directa).
