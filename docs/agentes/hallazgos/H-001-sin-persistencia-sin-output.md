---
Tipo: mejora
Severidad: BAJO
Persona: usuario nuevo
Dirigido a: IMP-3
Estado: resuelto-pendiente-verificación
---
Pasos para reproducir: `python osint_eye.py example.com --depth quick` (primer comando de "Uso rápido" en README.md, línea 140) · `ls output/` y `ls *.json`.
Resultado esperado: un fichero de resultados accesible (o al menos un mensaje indicando dónde quedan los resultados y cómo exportarlos).
Resultado real: no se crea ningún fichero (`ls output/` falla, no hay *.json en CWD) y la salida no menciona dónde quedó nada; los datos solo están en la caché `~/.osint_eye/cache/scan_cache.db`, que la salida tampoco menciona. El usuario nuevo no obtiene nada reutilizable sin adivinar el flag `-o`.
Sugerencia: persistir un JSON por defecto (`osint_eye_<target>_<ts>.json`) o imprimir al terminar: "Resultados en caché ~/.osint_eye; exporta con -o output/scan".

Resolución (IMP-3): sin `--output`, scan_targets() auto-guarda `osint_eye_<target-saneado>_<ts>.json`
en el CWD (misma convención que el PDF por defecto) y muestra "[+] Results saved to ... (cached in
~/.osint_eye/cache; export more formats con -o)"; con --no-cache el hint dice "cache disabled". Si la
escritura falla (OSError), aviso "[!] Could not auto-save" y el escaneo sigue. Multi-target: un JSON
por target. La rama --dashboard reutiliza el fichero auto-guardado (antes generaba un segundo JSON con
otro timestamp). Regresión: tests/test_default_persistence.py (5 tests).
