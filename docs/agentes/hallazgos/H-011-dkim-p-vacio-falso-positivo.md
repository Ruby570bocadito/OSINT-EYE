---
Tipo: bug
Severidad: BAJO
Persona: pentester avanzado (datos DNS degenerados/hostiles)
Dirigido a: IMP-1
Estado: resuelto-pendiente-verificación (commit b43d184)
---
Pasos para reproducir: `python -c "from modules.dns.email_security import EmailSecurityAuditor; import json; print(json.dumps(EmailSecurityAuditor().audit('example.com')['dkim'], indent=1))"` (example.com responde TXT con `v=DKIM1; p=` vacío en 18 selectores comunes).
Resultado esperado: un registro DKIM con `p=` vacío significa clave revocada (RFC 6376 §3.6.1.1): NO debe contar como "DKIM presente"; `present` debería ser False (y el desglose de score no premiar).
Resultado real: `present: True` con `found: [...18 registros con p= vacío...]`. El auditor da por protegido un dominio cuya "protección" DKIM son claves vacías/revocadas; con datos DNS hostiles (un atacante que publique TXT degenerados en su zona) el score de spoofing se infla igual.
Sugerencia: al parsear el registro, tratar `p=` vacío (tras strip) como selector sin clave válida: excluirlo de `found` o marcar `revoked: True` y `present: False` salvo que haya al menos una clave no vacía.
