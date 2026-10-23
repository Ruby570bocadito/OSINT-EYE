---
Tipo: bug
Severidad: BAJO
Persona: pentester/bug hunter avanzado
Dirigido a: IMP-3
Estado: resuelto-pendiente-verificación
---
Pasos para reproducir: `python osint_eye.py example.com --depth quick --no-ai -o output/pentest_scan --pdf` y listar los PDF generados.
Resultado esperado: un informe PDF (el de la base `-o`, si se pidieron ambas cosas que `-o` mande).
Resultado real: se generan DOS PDFs: `output/pentest_scan.pdf` (por la base `-o`) y `osint_eye_example.com_20261023_162116.pdf` suelto en el CWD (rama `--pdf` con nombre por defecto, independiente de `-o`). Con `-o` presente el segundo es un duplicado inesperado que ensucia el directorio actual.
Sugerencia: cuando `args.output` esté presente, que la rama `--pdf` derive su ruta de la base `-o` en vez de generar nombre por defecto en CWD.

Resolución (IMP-3): la rama `--pdf` de scan_targets() calcula `pdf_in_exports` (args.output presente
Y 'pdf' en --export-formats, o formatos por defecto = todos): si export_all va a renderizar el PDF,
la rama no genera nada (un solo `base.pdf`); si 'pdf' quedó fuera de los formatos, la rama deriva la
ruta de la base `-o` (`base_<target-saneado>.pdf` en multi-target, respetando `-o x.pdf`). Sin `-o`
se conserva el nombre por defecto. Regresión: tests/test_pdf_dedupe.py (5 tests).
