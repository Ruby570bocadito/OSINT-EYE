"""e2e: el camino feliz del wizard escanea de verdad (H-014, CRÍTICO).

Antes del fix, main() caía al ``return 0`` final cuando
interactive_mode=True: el wizard recolectaba las 11 respuestas + el gate
de autorización, imprimía los args construidos y salía SIN llamar a
scan_targets() — toda la experiencia interactiva era un no-op.

La regresión corre el wizard real en un pty (los Prompt/Confirm de Rich
exigen TTY para leer línea a línea) contra el target loopback y exige
los efectos del camino no interactivo: fases de escaneo en la salida,
export JSON vía --output y exit code del contrato decide_exit_code().
100 % offline (target 127.0.0.1, sin fixtures externos).
"""

import json
import os
import pty
import select
import subprocess
import sys
import time
from threading import Thread

import pytest

pytestmark = pytest.mark.skipif(
    not hasattr(os, "openpty"), reason="requiere pty (POSIX)"
)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CLI = os.path.join(REPO_ROOT, "osint_eye.py")

# (marcador del prompt tal como llega al pty, respuesta a enviar).
# Los marcadores viven dentro de un span de Rich, sin códigos ANSI en medio.
_WIZARD_STEPS = [
    ("Target domain(s) or IP(s)", "127.0.0.1"),
    ("Scope limit", ""),
    ("Exclusions", ""),
    ("I am authorized to test", "y"),
    ("Scan depth", "quick"),
    ("Use local AI analysis", "n"),
    ("Use scan cache", "n"),
    ("Stealth mode", ""),
    ("Spectacular Rich output", ""),
    # Nombre custom: el wizard sólo pasa --output si difiere del default
    # (con el default delega en la auto-persistencia de H-001), y un
    # export con nombre fijo da un artefacto determinista para asertar.
    ("Output base filename", "wiz_scan"),
    ("Red Team Playbook", ""),
    ("Executive PDF report", ""),
    ("web dashboard after scan", ""),
    ("Neo4j Cypher", ""),
]


def _run_wizard_in_pty(cwd: str):
    master, slave = pty.openpty()
    proc = subprocess.Popen(
        [sys.executable, CLI],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        close_fds=True,
        cwd=cwd,
    )
    os.close(slave)

    chunks: list = []

    def _reader():
        while True:
            try:
                ready, _, _ = select.select([master], [], [], 0.3)
            except (OSError, ValueError):
                break
            if not ready:
                continue
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            if not data:
                break
            chunks.append(data)

    reader = Thread(target=_reader, daemon=True)
    reader.start()

    # Ventana sólo para la INTERACCIÓN (los prompts son instantáneos);
    # el escaneo posterior tiene su propio wait(timeout=300).
    interaction_deadline = time.monotonic() + 150
    for marker, answer in _WIZARD_STEPS:
        buf = b"".join(chunks)
        while marker.encode() not in buf:
            if proc.poll() is not None:
                raise AssertionError(
                    f"el proceso terminó antes del prompt {marker!r}: el "
                    "wizard no llegó a preguntar lo esperado. Última "
                    f"salida: {buf[-600:]!r}"
                )
            if time.monotonic() > interaction_deadline:
                proc.kill()
                raise AssertionError(
                    f"el prompt {marker!r} no apareció en 150 s. Última "
                    f"salida: {buf[-600:]!r}"
                )
            time.sleep(0.1)
            buf = b"".join(chunks)
        time.sleep(0.15)  # margen para que Rich consuma la línea previa
        try:
            os.write(master, (answer + "\n").encode())
        except OSError:
            break

    try:
        rc = proc.wait(timeout=300)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise AssertionError("el escaneo post-wizard no terminó en 300 s")
    reader.join(timeout=5)
    try:
        os.close(master)
    except OSError:
        pass
    return rc, b"".join(chunks)


def test_wizard_happy_path_actually_scans(tmp_path):
    """H-014: tras el wizard, main() ejecuta scan_targets + decide_exit_code."""
    rc, out = _run_wizard_in_pty(str(tmp_path))

    assert b"Interactive Setup" in out, "el wizard no llegó a arrancar"
    assert rc in (0, 1, 3), (
        f"exit {rc} inesperado: el camino interactivo no respeta el "
        "contrato decide_exit_code (0 ok / 1 umbral / 3 nada escaneado)"
    )

    export = tmp_path / "wiz_scan.json"
    assert export.exists(), (
        "sin wiz_scan.json: el wizard completó sus preguntas pero el "
        "flujo cayó al return 0 sin escanear ni exportar (regresión "
        f"H-014). Contenido del CWD: {sorted(p.name for p in tmp_path.iterdir())}"
    )
    data = json.loads(export.read_text())
    assert data.get("target") == "127.0.0.1"
    assert "modules" in data, "el JSON exportado no tiene sección de módulos"

    # Evidencia de escaneo real en la salida: las fases del motor.
    assert b"Phase" in out, (
        "la salida del wizard no muestra fases de escaneo: main() no "
        "llegó a scan_targets()"
    )
