---
Tipo: seguridad
Severidad: BAJO
Persona: usuario malintencionado / datos hostiles
Dirigido a: IMP-3
Estado: resuelto-pendiente-verificación
---
Pasos para reproducir: `python osint_eye.py example.com --depth quick --no-ai --no-cache --modules dns -o ../../oe_escape_test` y después `ls -la ../../oe_escape_test.json`.
Resultado esperado: la base de nombre de `-o` se resuelve dentro del directorio de trabajo (o se avisa/rechaza si escapa).
Resultado real: EXIT=0 y el fichero se escribe dos niveles por encima del repo (`/home/z/my-project/oe_escape_test.json`, fuera del árbol del proyecto). `_sanitize_filename()` solo se aplica a los nombres auto-derivados (multi-target, PDF por defecto, dashboard), no a la base de `-o`.
Sugerencia: resolver `-o` contra `Path.cwd()` y rechazar (o avisar) si `resolved.parent` queda fuera del CWD; documentar el comportamiento en `--help`.

Resolución (IMP-3): `_validate_output_path()` en osint_eye.py — `--output/-o`, `--export-cypher` y
`--log-file` se resuelven contra el CWD al inicio de `main()` (antes de crear el log o escanear); si
escapan, usage error limpio con exit 2. `export_all()` aplica la misma barrera a llamadores no-CLI.
`--help` documenta la restricción. Regresión offline: tests/test_output_path_validation.py (17 tests);
tests/e2e/test_e2e_smoke.py pasa cwd=tmp_path a run_cli para mantener sus salidas absolutas dentro del CWD.
