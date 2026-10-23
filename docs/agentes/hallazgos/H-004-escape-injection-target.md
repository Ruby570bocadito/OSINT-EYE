---
Tipo: seguridad
Severidad: BAJO
Persona: usuario malintencionado / datos hostiles
Dirigido a: IMP-3
Estado: resuelto-pendiente-verificación
---
Pasos para reproducir: `python osint_eye.py $'\x1b[31m\x1b]0;pwned\x07evil.com' --depth quick --no-ai --no-cache --modules dns` en una terminal interactiva y observar la línea de progreso.
Resultado esperado: el target se imprime neutralizado (secuencias ESC invisibles o escapadas), sin efectos en el terminal del operador.
Resultado real: las secuencias ANSI pasan crudas a stdout (se cuentan 5 líneas de salida que contienen el byte `\x1b[31m` literal); el título del terminal puede ser reescrito por el OSC `\x1b]0;pwned\x07`. Rich escapa el markup `[...]` pero no los bytes ESC; el valor del target se interpola tal cual en los mensajes `[*]`/paneles.
Sugerencia: sanear targets y cualquier dato externo que vaya a la consola eliminando bytes de control (`re.sub(r"[\x00-\x1f\x7f]", "", s)` o `s.isprintable()` guard) en un punto único previo a los prints.

Resolución (IMP-3): `_neutralize_console_text()` en osint_eye.py (`re.sub(r"[\x00-\x1f\x7f]", "")`,
según la sugerencia) aplicado en los puntos de entrada y render: targets en `scan_targets()` y en
`OSINTEye.__init__` (results heredan la forma limpia), mensajes del motor en `_print()` (choke point
de los 49 mensajes con datos externos) y rutas --output/--export-cypher/--log-file en main() (primero
se limpia, después se valida la cadena exacta que se usará). Queda texto remanente inerte visible
(p. ej. `]0;pwned`) sin efecto de terminal. Regresión: tests/test_console_neutralization.py (12 tests).
Pendiente para IMP-2 (petición en estado/IMP-3.md): endurecimiento equivalente en las tablas Rich de
ui/rich_cli.py para datos externos no-target (banners, records).
