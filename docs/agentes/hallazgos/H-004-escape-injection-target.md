---
Tipo: seguridad
Severidad: BAJO
Persona: usuario malintencionado / datos hostiles
Dirigido a: IMP-3
Estado: abierto
---
Pasos para reproducir: `python osint_eye.py $'\x1b[31m\x1b]0;pwned\x07evil.com' --depth quick --no-ai --no-cache --modules dns` en una terminal interactiva y observar la línea de progreso.
Resultado esperado: el target se imprime neutralizado (secuencias ESC invisibles o escapadas), sin efectos en el terminal del operador.
Resultado real: las secuencias ANSI pasan crudas a stdout (se cuentan 5 líneas de salida que contienen el byte `\x1b[31m` literal); el título del terminal puede ser reescrito por el OSC `\x1b]0;pwned\x07`. Rich escapa el markup `[...]` pero no los bytes ESC; el valor del target se interpola tal cual en los mensajes `[*]`/paneles.
Sugerencia: sanear targets y cualquier dato externo que vaya a la consola eliminando bytes de control (`re.sub(r"[\x00-\x1f\x7f]", "", s)` o `s.isprintable()` guard) en un punto único previo a los prints.
