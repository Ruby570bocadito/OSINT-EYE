"""OSINT EYE - TLS configuration audit (stdlib only).

Audits one host:port with the standard ``ssl`` module — no external
tools, no third-party libraries:

* negotiated protocol/cipher and which protocol versions the endpoint
  still accepts (TLS 1.0/1.1 = obsolete, 1.2 = fine, 1.3 = best);
* weak cipher families the server still agrees to (RC4, 3DES, legacy
  CBC-SHA1, anonymous) probed with targeted cipher strings;
* leaf certificate: subject/issuer, validity window, days left, SANs,
  self-signed detection and signature hash;
* chain: a verified handshake against the system trust store decides
  ``chain_valid``; the unverified peer chain (when the runtime exposes
  it) is summarised for the report;
* explicable findings with severity, a 0-100 score and a letter grade.

Degradation contract: ``audit()`` ALWAYS returns the full result shape
("connected": False plus "error" when the endpoint is unreachable), so
callers and reports never break on partial results.

Contract consumed by osint_eye.py:
    TLSAuditor().audit(target) -> dict (see shape above; also stored in
    results["modules"]["tls_audit"] via the engine wiring).
"""

import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from modules._scope import allowed as _scope_allowed

#: Ports probed when the target carries no explicit port.
DEFAULT_PORTS = (443,)

#: Protocol versions probed with exact min/max contexts.
PROBED_VERSIONS = (
    ("TLSv1.0", ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
)

#: Weak cipher families probed with targeted OpenSSL cipher strings.
WEAK_CIPHER_PROBES = (
    ("RC4", "RC4-SHA:RC4-MD5", "high"),
    ("3DES", "DES-CBC3-SHA", "high"),
    ("CBC-SHA1", "AES128-SHA:AES256-SHA", "medium"),
    ("anónimos (aNULL)", "aNULL", "high"),
)

#: Deductions applied per finding severity.
SEVERITY_DEDUCTION = {"critical": 40, "high": 30, "medium": 15, "low": 5}

#: Validity window (days) that flags a certificate as expiring soon.
EXPIRING_SOON_DAYS = 30

#: Timeout (seconds) for every connect/handshake attempt.
DEFAULT_TIMEOUT = 10


def _normalise_host_port(target: str) -> Tuple[str, int]:
    """Reduce "host", "host:port" or a URL to (host, port).

    Raises ``ValueError`` for empty/unparseable input; callers translate
    that into the degradation shape.
    """
    raw = (target or "").strip()
    if not raw:
        raise ValueError("target vacío")
    if "://" in raw:
        # Reuse the stdlib parser: URL -> (hostname, port or scheme default).
        from urllib.parse import urlparse

        parsed = urlparse(raw)
        host = parsed.hostname
        if not host:
            raise ValueError(f"URL sin hostname: {target!r}")
        port = parsed.port or (443 if parsed.scheme in ("https", "") else 443)
        return host, int(port)
    if "/" in raw:
        raw = raw.split("/", 1)[0]
    if raw.count(":") == 1:
        host, _, tail = raw.partition(":")
        if tail.isdigit():
            return host, int(tail)
        raise ValueError(f"puerto no válido: {target!r}")
    # Bare IPv6 literal or plain hostname.
    return raw.strip("[]"), 443


def _classify_cipher(name: str) -> bool:
    """True when the cipher suite name is considered weak.

    Conservative classification: RC4, DES/3DES, NULL, EXPORT, MD5 and
    anonymous key exchange. AEAD suites (GCM/CHACHA20) are never weak.
    """
    upper = name.upper()
    if "GCM" in upper or "CHACHA20" in upper:
        return False
    weak_markers = ("RC4", "DES", "NULL", "EXP-", "EXPORT", "MD5", "ADH", "AECDH")
    return any(marker in upper for marker in weak_markers)


class TLSAuditor:
    """Audit TLS protocol versions, ciphers, certificate and chain."""

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = timeout

    # ── probing primitives (patch points for offline tests) ────────────
    def _handshake_versions(self, host: str, port: int) -> Dict[str, Optional[bool]]:
        """Probe each protocol version; ``None`` = unknowable on this runtime."""
        supported: Dict[str, Optional[bool]] = {}
        for label, min_ver, max_ver in PROBED_VERSIONS:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = min_ver
                ctx.maximum_version = max_ver
            except (ValueError, OverflowError, AttributeError):
                # Runtime/OpenSSL refuses to build that version context.
                supported[label] = None
                continue
            supported[label] = self._try_handshake(host, port, ctx)
        return supported

    def _try_handshake(self, host: str, port: int, ctx: ssl.SSLContext) -> bool:
        """One connect+handshake with ``ctx``; True when it succeeds."""
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                with ctx.wrap_socket(sock, server_hostname=host):
                    return True
        except (OSError, ssl.SSLError, ValueError):
            return False

    def _handshake_weak_ciphers(self, host: str, port: int) -> List[Dict]:
        """Probe targeted weak cipher families; only accepted ones return."""
        accepted: List[Dict] = []
        for label, cipher_string, severity in WEAK_CIPHER_PROBES:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.set_ciphers(cipher_string)
            except (ssl.SSLError, ValueError):
                # Cipher string not compiled into this OpenSSL: unknowable.
                continue
            if self._try_handshake(host, port, ctx):
                accepted.append(
                    {"family": label, "ciphers": cipher_string, "severity": severity}
                )
        return accepted

    def _fetch_certificate(
        self, host: str, port: int
    ) -> Tuple[Optional[Dict], bool, List[Dict], Optional[str]]:
        """Verified handshake: leaf cert info, chain validity, peer chain.

        Returns ``(leaf, chain_valid, chain, error)``. ``leaf`` is None
        when the connection fails; ``chain_valid`` is False whenever the
        system trust store rejects the chain.
        """
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    leaf = self._describe_cert(tls.getpeercert())
                    chain = self._describe_chain(tls)
                    return leaf, True, chain, None
        except ssl.SSLCertVerificationError as e:
            # Untrusted/self-signed/hostname mismatch: fetch the leaf
            # without verification so the report still has the details.
            leaf, chain = self._fetch_certificate_unverified(host, port)
            return leaf, False, chain, str(e.reason if hasattr(e, "reason") else e)
        except (OSError, ssl.SSLError, ValueError) as e:
            return None, False, [], str(e)

    def _fetch_certificate_unverified(
        self, host: str, port: int
    ) -> Tuple[Optional[Dict], List[Dict]]:
        """Leaf + chain without verification (for rejected chains)."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    return self._describe_cert(tls.getpeercert()), self._describe_chain(tls)
        except (OSError, ssl.SSLError, ValueError) as e:
            return None, [{"error": str(e)}]

    @staticmethod
    def _describe_chain(tls_sock) -> List[Dict]:
        """Summarise the unverified peer chain when the runtime exposes it.

        ``SSLSocket.get_unverified_chain()`` is not available on every
        CPython release; when missing the chain is reported as unknown
        ([]) instead of failing the audit. Decoding reuses the stdlib
        certificate decoder on a temp PEM file per entry.
        """
        getter = getattr(tls_sock, "get_unverified_chain", None)
        if getter is None:
            return []
        try:
            entries = getter() or []
        except (OSError, ssl.SSLError, ValueError):
            return []
        decoder = getattr(ssl._ssl, "_test_decode_cert", None)
        if decoder is None:
            return []

        import os
        import tempfile

        chain: List[Dict] = []
        for der in entries:
            fd, path = tempfile.mkstemp(suffix=".pem")
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(der)
                info = decoder(path)
            except Exception:
                continue
            finally:
                try:
                    os.unlink(path)
                except OSError:
                    pass
            chain.append(
                {
                    "subject": _dn(info.get("subject")),
                    "issuer": _dn(info.get("issuer")),
                    "not_after": info.get("notAfter"),
                }
            )
        return chain

    @staticmethod
    def _describe_cert(cert: Optional[Dict]) -> Optional[Dict]:
        """Leaf certificate summary from ``getpeercert()`` (verified mode)."""
        if not cert:
            return None
        subject = _dn(cert.get("subject"))
        issuer = _dn(cert.get("issuer"))
        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")
        days_left = _days_until(not_after)
        san = []
        for kind, value in cert.get("subjectAltName", ()) or []:
            if kind == "DNS":
                san.append(value)
        sig = cert.get("signatureAlgorithm") or ""
        return {
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before,
            "not_after": not_after,
            "days_left": days_left,
            "expired": days_left is not None and days_left < 0,
            "expiring_soon": (
                days_left is not None and 0 <= days_left <= EXPIRING_SOON_DAYS
            ),
            "self_signed": bool(subject) and subject == issuer,
            "signature_algorithm": sig,
            "sha1_signature": "sha1" in sig.lower() if sig else False,
            "san": san[:50],
        }

    # ── public API ──────────────────────────────────────────────────────
    def audit(self, target: str, scope=None) -> Dict:
        """Full TLS audit of ``target`` (host, host:port or URL).

        ``scope`` is optional (``core.scope.Scope``): a target outside it
        is never connected and the empty shape is returned (module label
        "tls_audit", discard logged).
        """
        host, port = ("", DEFAULT_PORTS[0])
        try:
            host, port = _normalise_host_port(target)
        except ValueError as e:
            return self._empty(target, error=str(e))

        if scope is not None and not _scope_allowed(scope, target, "tls_audit"):
            print(f"[!] {target} out of scope: skipping TLS audit")
            return self._empty(target, error="fuera de scope")

        leaf, chain_valid, chain, chain_error = self._fetch_certificate(host, port)
        if leaf is None:
            result = self._empty(target, error=chain_error or "sin conexión")
            # Connection failed at the TCP/TLS layer: report it honestly.
            result["chain_valid"] = False
            return result

        versions = self._handshake_versions(host, port)
        weak_ciphers = self._handshake_weak_ciphers(host, port)
        negotiated = self._negotiated(host, port)

        findings = self._build_findings(
            leaf, versions, weak_ciphers, chain_valid, negotiated.get("cipher")
        )
        score = self._score(findings)

        result = {
            "target": target,
            "host": host,
            "port": port,
            "connected": True,
            "error": None,
            "protocol": negotiated.get("protocol"),
            "cipher": negotiated.get("cipher"),
            "versions": versions,
            "weak_ciphers": weak_ciphers,
            "certificate": leaf,
            "chain_valid": chain_valid,
            "chain": chain,
            "findings": findings,
            "score": score,
            "grade": self._grade(score),
        }
        return result

    # ── helpers ─────────────────────────────────────────────────────────
    def _negotiated(self, host: str, port: int) -> Dict:
        """Protocol/cipher of a default verified handshake (informational)."""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    cipher = tls.cipher() or (None, None, None)
                    return {
                        "protocol": tls.version(),
                        "cipher": cipher[0],
                        "cipher_bits": cipher[2],
                    }
        except (OSError, ssl.SSLError, ValueError):
            return {"protocol": None, "cipher": None, "cipher_bits": None}

    @staticmethod
    def _empty(target: str, error: str) -> Dict:
        """Degradation shape: same keys, nothing claimed."""
        return {
            "target": target,
            "host": None,
            "port": None,
            "connected": False,
            "error": error,
            "protocol": None,
            "cipher": None,
            "versions": {},
            "weak_ciphers": [],
            "certificate": None,
            "chain_valid": False,
            "chain": [],
            "findings": [],
            "score": None,
            "grade": None,
        }

    def _build_findings(
        self,
        leaf: Dict,
        versions: Dict[str, Optional[bool]],
        weak_ciphers: List[Dict],
        chain_valid: bool,
        negotiated_cipher: Optional[str] = None,
    ) -> List[Dict]:
        """Turn raw probe results into explicable, sorted findings."""
        findings: List[Dict] = []

        if negotiated_cipher and _classify_cipher(negotiated_cipher):
            findings.append(
                {
                    "severity": "medium",
                    "title": f"Cifrado negociado débil: {negotiated_cipher}",
                    "detail": "El handshake por defecto elige una suite considerada débil.",
                }
            )

        if versions.get("TLSv1.0"):
            findings.append(
                {
                    "severity": "high",
                    "title": "TLS 1.0 aceptado",
                    "detail": "El extremo todavía completa handshakes TLS 1.0 (PCI DSS lo prohíbe).",
                }
            )
        if versions.get("TLSv1.1"):
            findings.append(
                {
                    "severity": "medium",
                    "title": "TLS 1.1 aceptado",
                    "detail": "TLS 1.1 está obsoleto (RFC 8996); desactívalo salvo compatibilidad legada.",
                }
            )
        if versions.get("TLSv1.3") is False:
            findings.append(
                {
                    "severity": "low",
                    "title": "TLS 1.3 no disponible",
                    "detail": "El extremo no negocia TLS 1.3; sin ello pierdes 1-RTT y suites AEAD modernas.",
                }
            )

        for weak in weak_ciphers:
            findings.append(
                {
                    "severity": weak["severity"],
                    "title": f"Cifrado débil aceptado: {weak['family']}",
                    "detail": f"El servidor completa handshakes con {weak['ciphers']}.",
                }
            )

        if leaf.get("expired"):
            findings.append(
                {
                    "severity": "critical",
                    "title": "Certificado caducado",
                    "detail": f"notAfter = {leaf.get('not_after')}; los navegadores lo rechazan.",
                }
            )
        elif leaf.get("expiring_soon"):
            days = leaf.get("days_left")
            findings.append(
                {
                    "severity": "medium" if days is not None and days <= 15 else "low",
                    "title": "Certificado próximo a caducar",
                    "detail": f"Quedan {days} días (notAfter = {leaf.get('not_after')}).",
                }
            )

        if leaf.get("self_signed"):
            findings.append(
                {
                    "severity": "high",
                    "title": "Certificado autofirmado",
                    "detail": "subject == issuer: sin tercera parte de confianza; los clientes verán aviso.",
                }
            )
        if leaf.get("sha1_signature"):
            findings.append(
                {
                    "severity": "medium",
                    "title": "Firma SHA-1",
                    "detail": f"signatureAlgorithm = {leaf.get('signature_algorithm')}; SHA-1 está roto para certificados.",
                }
            )
        if not chain_valid:
            findings.append(
                {
                    "severity": "high",
                    "title": "Cadena no verificable",
                    "detail": "El handshake verificado contra el almacén del sistema falló (cadena incompleta, CA desconocida o nombre que no coincide).",
                }
            )

        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings.sort(key=lambda f: order.get(f["severity"], 9))
        return findings

    @staticmethod
    def _score(findings: List[Dict]) -> int:
        """100 minus deductions; floor 0."""
        score = 100
        for finding in findings:
            score -= SEVERITY_DEDUCTION.get(finding["severity"], 0)
        return max(0, score)

    @staticmethod
    def _grade(score: int) -> str:
        if score >= 90:
            return "A"
        if score >= 75:
            return "B"
        if score >= 50:
            return "C"
        return "F"


def _dn(name) -> str:
    """Flatten an X.509 DN (list of RDN tuples) to a readable string."""
    if not name:
        return ""
    parts = []
    for rdn in name:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def _days_until(ssl_time: Optional[str]) -> Optional[int]:
    """Days from now until an ssl notBefore/notAfter string (UTC)."""
    if not ssl_time:
        return None
    try:
        when = datetime.strptime(ssl_time, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None
    return (when - datetime.now(timezone.utc)).days
