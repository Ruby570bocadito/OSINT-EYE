"""TLS audit suite (100% offline).

The network-facing primitives (handshake probes, certificate fetch) are
monkeypatched; the assertions cover the analysis logic: result shape,
finding derivation, scoring, grades, scope gate and graceful degradation.
"""

from datetime import datetime, timedelta, timezone

import pytest

from core.scope import Scope
from modules.certs.tls_audit import (
    TLSAuditor,
    _classify_cipher,
    _days_until,
    _normalise_host_port,
)


def _ssl_time(dt: datetime) -> str:
    return dt.strftime("%b %d %H:%M:%S %Y GMT")


def _peer_cert(subject_cn="example.com", issuer_cn="Example CA", days_left=365):
    """A getpeercert()-shaped dict (verified handshake output)."""
    now = datetime.now(timezone.utc)
    return {
        "subject": ((("commonName", subject_cn),),),
        "issuer": ((("commonName", issuer_cn),),),
        "notBefore": _ssl_time(now - timedelta(days=30)),
        "notAfter": _ssl_time(now + timedelta(days=days_left)),
        "subjectAltName": (
            ("DNS", "example.com"),
            ("DNS", "www.example.com"),
            ("IP Address", "93.184.216.34"),
        ),
        "signatureAlgorithm": "sha256WithRSAEncryption",
    }


def _patch_probes(monkeypatch, auditor, leaf, chain_valid=True, versions=None,
                  weak=None, negotiated=None):
    monkeypatch.setattr(
        auditor, "_fetch_certificate", lambda host, port: (leaf, chain_valid, [], None)
    )
    monkeypatch.setattr(
        auditor,
        "_handshake_versions",
        lambda host, port: versions
        or {"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True},
    )
    monkeypatch.setattr(auditor, "_handshake_weak_ciphers", lambda host, port: weak or [])
    monkeypatch.setattr(
        auditor,
        "_negotiated",
        lambda host, port: negotiated
        or {"protocol": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256", "cipher_bits": 128},
    )


class TestNormaliseHostPort:
    def test_plain_host(self):
        assert _normalise_host_port("example.com") == ("example.com", 443)

    def test_host_port(self):
        assert _normalise_host_port("example.com:8443") == ("example.com", 8443)

    def test_url_default_port(self):
        assert _normalise_host_port("https://example.com/path") == ("example.com", 443)

    def test_url_explicit_port(self):
        assert _normalise_host_port("https://example.com:9443/") == ("example.com", 9443)

    def test_ipv6_literal(self):
        assert _normalise_host_port("::1") == ("::1", 443)

    def test_empty_rejected(self):
        with pytest.raises(ValueError):
            _normalise_host_port("")


class TestClassifyCipher:
    @pytest.mark.parametrize(
        "name",
        ["RC4-SHA", "DES-CBC3-SHA", "NULL-MD5", "EXP-RC4-MD5", "AECDH-AES128-SHA"],
    )
    def test_weak(self, name):
        assert _classify_cipher(name) is True

    @pytest.mark.parametrize(
        "name",
        [
            "ECDHE-RSA-AES128-GCM-SHA256",
            "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
            "ECDHE-RSA-AES256-SHA384",
        ],
    )
    def test_strong(self, name):
        assert _classify_cipher(name) is False


class TestDaysUntil:
    def test_future_date_positive(self):
        future = datetime.now(timezone.utc) + timedelta(days=100)
        days = _days_until(_ssl_time(future))
        assert days in (99, 100)

    def test_past_date_negative(self):
        past = datetime.now(timezone.utc) - timedelta(days=10)
        assert _days_until(_ssl_time(past)) < 0

    def test_none_and_garbage(self):
        assert _days_until(None) is None
        assert _days_until("no es una fecha") is None


class TestDescribeCert:
    def test_valid_certificate_summary(self):
        cert = TLSAuditor._describe_cert(_peer_cert(days_left=365))
        assert cert["subject"] == "commonName=example.com"
        assert cert["issuer"] == "commonName=Example CA"
        assert cert["expired"] is False
        assert cert["expiring_soon"] is False
        assert cert["self_signed"] is False
        assert cert["sha1_signature"] is False
        assert cert["san"] == ["example.com", "www.example.com"]

    def test_expired_certificate(self):
        cert = TLSAuditor._describe_cert(_peer_cert(days_left=-5))
        assert cert["expired"] is True
        assert cert["days_left"] < 0

    def test_expiring_soon_window(self):
        cert = TLSAuditor._describe_cert(_peer_cert(days_left=10))
        assert cert["expiring_soon"] is True

    def test_self_signed_detection(self):
        cert = TLSAuditor._describe_cert(
            _peer_cert(subject_cn="example.com", issuer_cn="example.com")
        )
        assert cert["self_signed"] is True

    def test_no_cert_returns_none(self):
        assert TLSAuditor._describe_cert(None) is None


class TestAuditOffline:
    def test_clean_host_scores_high(self, monkeypatch):
        auditor = TLSAuditor()
        leaf = TLSAuditor._describe_cert(_peer_cert(days_left=365))
        _patch_probes(monkeypatch, auditor, leaf)

        result = auditor.audit("example.com:443")

        assert result["connected"] is True
        assert result["error"] is None
        assert result["protocol"] == "TLSv1.3"
        assert result["certificate"]["subject"] == "commonName=example.com"
        assert result["chain_valid"] is True
        assert result["grade"] in ("A", "B")
        assert result["score"] >= 75
        # No weak ciphers, no obsolete protocols: nothing to report.
        assert result["findings"] == []

    def test_obsolete_protocols_and_weak_ciphers_scored(self, monkeypatch):
        auditor = TLSAuditor()
        leaf = TLSAuditor._describe_cert(_peer_cert(days_left=365))
        _patch_probes(
            monkeypatch,
            auditor,
            leaf,
            versions={"TLSv1.0": True, "TLSv1.1": True, "TLSv1.2": True, "TLSv1.3": False},
            weak=[{"family": "RC4", "ciphers": "RC4-SHA", "severity": "high"}],
        )

        result = auditor.audit("example.com")
        titles = [f["title"] for f in result["findings"]]

        assert any("TLS 1.0" in t for t in titles)
        assert any("TLS 1.1" in t for t in titles)
        assert any("RC4" in t for t in titles)
        assert any("TLS 1.3" in t for t in titles)
        # 100 - 30 (TLS1.0 high) - 15 (TLS1.1 medium) - 30 (RC4 high) - 5 (low)
        assert result["score"] == 20
        assert result["grade"] == "F"

    def test_expired_certificate_is_critical(self, monkeypatch):
        auditor = TLSAuditor()
        leaf = TLSAuditor._describe_cert(_peer_cert(days_left=-3))
        _patch_probes(monkeypatch, auditor, leaf)

        result = auditor.audit("example.com")
        severities = [f["severity"] for f in result["findings"]]

        assert "critical" in severities
        assert result["findings"][0]["severity"] == "critical"
        assert result["score"] <= 60

    def test_self_signed_and_broken_chain(self, monkeypatch):
        auditor = TLSAuditor()
        leaf = TLSAuditor._describe_cert(
            _peer_cert(subject_cn="example.com", issuer_cn="example.com")
        )
        _patch_probes(monkeypatch, auditor, leaf, chain_valid=False)

        result = auditor.audit("example.com")
        titles = [f["title"] for f in result["findings"]]

        assert any("autofirmado" in t for t in titles)
        assert any("Cadena no verificable" in t for t in titles)

    def test_unreachable_endpoint_degrades(self, monkeypatch):
        auditor = TLSAuditor()
        monkeypatch.setattr(
            auditor,
            "_fetch_certificate",
            lambda host, port: (None, False, [], "connection refused"),
        )

        result = auditor.audit("down.example.com")

        assert result["connected"] is False
        assert result["error"] == "connection refused"
        assert result["score"] is None
        assert result["certificate"] is None
        assert result["findings"] == []

    def test_out_of_scope_never_connects(self, monkeypatch):
        auditor = TLSAuditor()

        def must_not_connect(host, port):
            raise AssertionError("out-of-scope target must not be probed")

        monkeypatch.setattr(auditor, "_fetch_certificate", must_not_connect)

        scope = Scope(includes=["other.com"])
        result = auditor.audit("example.com", scope=scope)

        assert result["connected"] is False
        assert result["error"] == "fuera de scope"
        assert scope.discarded[0]["module"] == "tls_audit"

    def test_empty_target_degrades_without_network(self, monkeypatch):
        auditor = TLSAuditor()
        monkeypatch.setattr(
            auditor,
            "_fetch_certificate",
            lambda host, port: (_ for _ in ()).throw(AssertionError("must not connect")),
        )

        result = auditor.audit("")
        assert result["connected"] is False
        assert result["error"]
