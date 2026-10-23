---
Tipo: bug (UX de degradación / latencia de aborto)
Severidad: MEDIO
Persona: operador CI / pentester (Ctrl+C durante red lenta o degradada)
Dirigido a: IMP-3
Estado: abierto
---
Pasos para reproducir: `python osint_eye.py 127.0.0.1 --depth quick --no-ai --no-cache`; a los
6 s de arrancar el escaneo enviar SIGINT y cronometrar hasta el exit.
Resultado esperado: el aborto limpio del fix H-007 debería ser perceptiblemente inmediato
(resumen parcial y exit 130 en segundos).
Resultado real: el exit 130 llega, limpio y con parciales (el contrato de H-007 se cumple:
"Scan interrupted by user" + resumen + rc=130, sin traceback), PERO tras **87 s** de espera:
el Ctrl+C parece ignorado. Causa estructural: `run_all()` usa `concurrent.futures.wait(p1)`
sin timeout y el context manager del `ThreadPoolExecutor` hace `shutdown(wait=True)` en
`__exit__`; el KeyboardInterrupt se lanza en el hilo principal pero queda retenido hasta que
TODOS los módulos en vuelo terminen. Con faulthandler se vio al hilo principal en
`osint_eye.py:710 run_all → thread.join()` mientras un worker de wayback estaba bloqueado en
`create_conn` hacia web.archive.org (`_http.py` timeout 10 s × reintentos con backoff
exponencial por cada request en vuelo). Con red degradada (firewall DROP, DNS lento) la
latencia crece por cada llamada externa pendiente en cada fase.
Impacto: el operador percibe cuelgue y repite Ctrl+C; en CI con timeout agresivo el runner
mata el proceso antes del drain y se pierde la promesa del exit 130 con resumen parcial
(el artefacto de parciales no se genera).
Sugerencia: cancelación cooperativa — threading.Event de cancelación chequeado entre pasos
de cada módulo y entre reintentos en `modules/_http.py`; en el camino de interrupción usar
`executor.shutdown(wait=False, cancel_futures=True)` (Py3.9+) y devolver ya los parciales
recolectados (`engine.results` ya tiene el patrón del fix H-007); opcionalmente un segundo
Ctrl+C fuerza el aborto inmediato.
Nota: verificado sobre el fix-h007 de IMP-3 (4378754); el contrato de salida es correcto,
el hallazgo es sólo sobre la latencia de entrega.
