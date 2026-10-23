---
Tipo: mejora
Severidad: BAJO
Persona: usuario torpe
Dirigido a: IMP-3
Estado: resuelto-pendiente-verificación
---
Pasos para reproducir: `timeout -s INT 5 python osint_eye.py example.com --depth quick --no-ai --no-cache --modules dns certs wayback` (el INT cae a mitad del escaneo).
Resultado esperado: mensaje limpio de aborto ("Escaneo interrumpido; resultados parciales en X" o equivalente) y salida ordenada con código != 0.
Resultado real: traceback crudo que termina en `KeyboardInterrupt` (`sock.connect(sa)`), sin mensaje de aborto ni indicación de resultados parciales. Verificado `grep -c Traceback` = 1 en la salida.
Sugerencia: capturar `KeyboardInterrupt` en el bucle principal de osint_eye.py, imprimir un resumen de lo completado (los resultados parciales ya viven en `engine.results`) y salir con código propio.

Resolución (IMP-3): el bucle de targets de `scan_targets()` va dentro de try/except `KeyboardInterrupt`;
`engine` se resetea a None al inicio de cada iteración (un Ctrl+C durante la cabecera del target N+1
nunca atribuye el engine del target N). Al abortar: los parciales del target en vuelo (vía
`engine.results`) se suman a los completados y se lanza `ScanInterrupted(partials)`; `main()` imprime
"[x] Scan interrupted by user (Ctrl+C)" con la lista de targets, el resumen por target y el código
`130` (128+SIGINT, documentado en el bloque de exit codes). Regresión: tests/test_cli_interrupt.py
(8 tests: completado+en vuelo, sin atribución errónea, primer target, run limpio intacto, main→130,
decide_exit_code intacto).
