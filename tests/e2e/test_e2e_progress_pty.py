"""e2e: la tabla live "Module Progress" refleja estados reales (H-013).

La tabla solo se renderiza en un TTY (Rich degrada a prints planos en
pipes), así que la regresión corre la CLI en un pty contra el fixture
HTTP local y exige ver "running" o "done" en la salida. 100 % offline.
"""

import os
import pty
import select
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

pytestmark = pytest.mark.skipif(
    not hasattr(os, "openpty"), reason="requiere pty (POSIX)"
)


class _NginxFixture(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Server", "nginx/1.24.0")
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>local fixture for e2e</body></html>")

    def log_message(self, *args):
        pass


def _serve():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _NginxFixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _run_cli_in_pty(cmd: list) -> bytes:
    master, slave = pty.openpty()
    proc = subprocess.Popen(
        cmd,
        stdin=slave,
        stdout=slave,
        stderr=slave,
        close_fds=True,
    )
    os.close(slave)

    chunks: list = []

    def _reader():
        while True:
            try:
                ready, _, _ = select.select([master], [], [], 0.5)
            except (OSError, ValueError):
                break
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            if not data:
                break
            chunks.append(data)

    reader = Thread(target=_reader, daemon=True)
    reader.start()
    try:
        proc.wait(timeout=180)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise
    reader.join(timeout=5)
    try:
        os.close(master)
    except OSError:
        pass
    return b"".join(chunks)


def test_progress_table_shows_running_or_done_states():
    """H-013: el dispatch ya no llama a los métodos sin instrumentar."""
    server, _thread = _serve()
    port = server.server_address[1]
    try:
        cmd = [
            sys.executable,
            "osint_eye.py",
            f"http://127.0.0.1:{port}",
            "--depth",
            "quick",
            "--rich",
            "--no-ai",
            "--no-cache",
            "--modules",
            "dns",
            "web",
        ]
        out = _run_cli_in_pty(cmd)
    finally:
        server.shutdown()
        server.server_close()
    assert b"Module Progress" in out, "la tabla de progreso no se renderizó"
    assert (b"running" in out) or (b"done" in out), (
        "la tabla nunca mostró estados running/done: el dispatch sigue "
        "llamando a los métodos sin instrumentar (H-013)"
    )
