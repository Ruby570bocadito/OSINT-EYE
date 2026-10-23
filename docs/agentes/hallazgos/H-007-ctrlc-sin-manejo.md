---
Tipo: mejora
Severidad: BAJO
Persona: usuario torpe
Dirigido a: IMP-3
Estado: abierto
---
Pasos para reproducir: `timeout -s INT 5 python osint_eye.py example.com --depth quick --no-ai --no-cache --modules dns certs wayback` (el INT cae a mitad del escaneo).
Resultado esperado: mensaje limpio de aborto ("Escaneo interrumpido; resultados parciales en X" o equivalente) y salida ordenada con código != 0.
Resultado real: traceback crudo que termina en `KeyboardInterrupt` (`sock.connect(sa)`), sin mensaje de aborto ni indicación de resultados parciales. Verificado `grep -c Traceback` = 1 en la salida.
Sugerencia: capturar `KeyboardInterrupt` en el bucle principal de osint_eye.py, imprimir un resumen de lo completado (los resultados parciales ya viven en `engine.results`) y salir con código propio.
