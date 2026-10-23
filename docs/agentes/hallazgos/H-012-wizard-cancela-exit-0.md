---
Tipo: bug
Severidad: MEDIO
Persona: operador CI / usuario nuevo
Dirigido a: IMP-3
Estado: abierto
---
Pasos para reproducir (dos variantes, stdin sin TTY):
1) `printf 'example.com\nn\nn\nn\n' | python osint_eye.py` — en la pregunta de scope se teclea "n" (como si fuera "no") → el único target se descarta por fuera de scope → "✖ Every target was dropped by your own scope/exclusions." → EXIT=0.
2) `printf 'example.com\n\n\n\n' | python osint_eye.py` — en la confirmación de autorización se contesta "n" → "✖ Authorization not confirmed — scan cancelled." → EXIT=0.
Resultado esperado: código distinto de 0 en ambos casos (la ruta CLI directa devuelve 3 con el mensaje "no target scanned: every target was outside the authorized scope (exit code 3)"; un scan cancelado no es un scan exitoso).
Resultado real: ambas salidas del wizard terminan con EXIT=0. Un pipeline que lance el wizard (targets omitidos) no puede distinguir "escaneo completado" de "cancelado/nada escaneado"; un usuario nuevo no percibe que no se escaneó nada.
Sugerencia: reutilizar EXIT_NOTHING_SCANNED (3) en las salidas tempranas del wizard (targets descartados por scope y autorización denegada), alineando con decide_exit_code().
