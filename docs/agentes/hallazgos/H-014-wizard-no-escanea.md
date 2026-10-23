---
Tipo: bug
Severidad: CRÍTICO
Persona: usuario nuevo (la primera experiencia del producto)
Dirigido a: IMP-3
Estado: abierto
---
Pasos para reproducir (TTY real, pty): `python osint_eye.py` SIN argumentos; responder al wizard:
`example.com` → scope vacío (Enter) → exclusiones vacías (Enter) → `y` a la autorización → Enter en
depth/AI/caché/stealth/Rich/filename/playbook/PDF/dashboard (todos los defaults). Última línea impresa:
`args: example.com --depth normal --rich` y el proceso termina EXIT=0.
Resultado esperado: el escaneo arranca con los args construidos por el wizard (banner → print_scan_header →
módulos) y main() devuelve decide_exit_code().
Resultado real: NO se escanea nada. En main(): `if not interactive_mode: ... scan_targets(...); return
decide_exit_code(...)` y después `return 0` — con interactive_mode=True (wizard) el flujo cae al `return 0`
final sin pasar por scan_targets(). El wizard completo (11 preguntas, incluido el gate de autorización) es un
no-op: recolecta respuestas, imprime los args y sale 0. Explica también por qué H-012 (cancelación con exit 0)
nunca llegó a importar: TODO el camino interactivo termina en 0.
Sugerencia: en main(), tras parsear los wizard_args, ejecutar el MISMO camino no-interactivo:
`all_results = scan_targets(args.targets, args); return decide_exit_code(all_results, args)` (el banner ya se
omite en interactivo por diseño; si se quiere banner, imprimirlo siempre). Cubrir con e2e pty: wizard con
defaults debe producir salida de escaneo (header/módulos) y exit != 0 en cancelación (H-012).
