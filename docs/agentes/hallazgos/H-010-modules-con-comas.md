---
Tipo: mejora
Severidad: BAJO
Persona: usuario torpe
Dirigido a: IMP-3
Estado: abierto
---
Pasos para reproducir: `python osint_eye.py example.com --depth quick --no-ai --no-cache --modules dns,web` (separados por comas, la forma natural de escribir una lista).
Resultado esperado: que funcione (aceptar comas) o un error corto que diga cómo separar los módulos.
Resultado real: argparse aborta con EXIT=2 y vuelca el usage completo (~40 líneas con la lista de los 19 choices) porque `--modules` es nargs="+"; no hay pista de que la separación es por espacios. El usuario nuevo interpreta el muro de texto como fallo grave.
Sugerencia: `type=lambda s: s.split(",")` sobre `--modules` (compatibiliza ambas formas), o un mensaje corto tipo "separa los módulos con espacios: --modules dns web".
