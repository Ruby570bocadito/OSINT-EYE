---
Tipo: mejora
Severidad: BAJO
Persona: usuario torpe
Dirigido a: IMP-3
Estado: resuelto-pendiente-verificación
---
Pasos para reproducir: `python osint_eye.py example.com --depth quick --no-ai --no-cache --modules dns,web` (separados por comas, la forma natural de escribir una lista).
Resultado esperado: que funcione (aceptar comas) o un error corto que diga cómo separar los módulos.
Resultado real: argparse aborta con EXIT=2 y vuelca el usage completo (~40 líneas con la lista de los 19 choices) porque `--modules` es nargs="+"; no hay pista de que la separación es por espacios. El usuario nuevo interpreta el muro de texto como fallo grave.
Sugerencia: `type=lambda s: s.split(",")` sobre `--modules` (compatibiliza ambas formas), o un mensaje corto tipo "separa los módulos con espacios: --modules dns web".

Resolución (IMP-3): `--modules` pierde `choices=[...]` (origen del muro de texto) y gana
`type=_split_modules_token`, que divide cada token por comas (acepta `dns web`, `dns,web` y mixto,
recorta espacios y descarta fragmentos vacíos); main() aplana, deduplica (orden estable) y valida
contra MODULE_CATALOG con `parser.error` compacto: "unknown module(s): X; valid modules: ... (separate
them with commas or spaces: --modules dns,web)". `--modules` sin valores sigue imprimiendo el
catálogo. Regresión: tests/test_modules_flag.py (9 tests).
