"""Regression tests for SecurityHeadersAuditor TLS handling fixes."""

import http.server
import os
import ssl
import subprocess
import tempfile
import threading
import unittest

from modules.dns.advanced_dns import SecurityHeadersAuditor


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>ok</body></html>")

    def log_message(self, *args):
        pass


def _serve(server):
    server.serve_forever()


class TestTLSHandling(unittest.TestCase):
    def setUp(self):
        self.auditor = SecurityHeadersAuditor(timeout=5)

    def test_audit_plain_http_reports_missing_headers(self):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _QuietHandler)
        thread = threading.Thread(target=_serve, args=(server,), daemon=True)
        thread.start()
        try:
            result = self.auditor.audit(
                f"http://127.0.0.1:{server.server_address[1]}/"
            )
            self.assertNotIn("error", result)
            self.assertTrue(
                result["missing_headers"], "HTTP response should miss many headers"
            )
        finally:
            server.shutdown()
            thread.join(timeout=5)

    def test_audit_self_signed_https_never_bypasses_verification(self):
        tmpdir = tempfile.mkdtemp()
        cert = os.path.join(tmpdir, "cert.pem")
        key = os.path.join(tmpdir, "key.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key, "-out", cert, "-days", "1", "-nodes",
                "-subj", "/CN=localhost",
            ],
            check=True, capture_output=True,
        )
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _QuietHandler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=_serve, args=(server,), daemon=True)
        thread.start()
        try:
            result = self.auditor.audit(
                f"https://127.0.0.1:{server.server_address[1]}/"
            )
            # The audit must report the TLS failure instead of silently
            # disabling certificate verification (regression for verify=False).
            self.assertIn("error", result)
            self.assertIn("TLS certificate verification failed", result["error"])
            self.assertEqual(result["grade"], "F")
        finally:
            server.shutdown()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
