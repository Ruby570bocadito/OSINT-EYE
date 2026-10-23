---
Tipo: mejora
Severidad: BAJO
Persona: usuario nuevo
Dirigido a: IMP-3
Estado: abierto
---
Pasos para reproducir: `python osint_eye.py example.com --depth quick` (primer comando de "Uso rápido" en README.md, línea 140) · `ls output/` y `ls *.json`.
Resultado esperado: un fichero de resultados accesible (o al menos un mensaje indicando dónde quedan los resultados y cómo exportarlos).
Resultado real: no se crea ningún fichero (`ls output/` falla, no hay *.json en CWD) y la salida no menciona dónde quedó nada; los datos solo están en la caché `~/.osint_eye/cache/scan_cache.db`, que la salida tampoco menciona. El usuario nuevo no obtiene nada reutilizable sin adivinar el flag `-o`.
Sugerencia: persistir un JSON por defecto (`osint_eye_<target>_<ts>.json`) o imprimir al terminar: "Resultados en caché ~/.osint_eye; exporta con -o output/scan".
