"""SEG regression: webhook-guard — SSRF en --webhook (AlertManager).

La URL del webhook es elección del operador pero sigue siendo un fetch
saliente de la máquina del operador: exige https y host público
(loopback, RFC1918, link-local/metadatos y ULA bloqueados), reutilizando
modules/web/ssrf_guard.
"""

import pytest

from core.monitor import AlertManager
from modules.web import ssrf_guard
from modules.web.ssrf_guard import is_safe_webhook_url


@pytest.mark.parametrize(
    "url",
    [
        "https://hooks.example.com/x",
        "https://discord.com/api/webhooks/1/2",
        "https://93.184.216.34/hook",  # IP literal pública
    ],
)
def test_acepta_https_publico(url, monkeypatch):
    monkeypatch.setattr(
        ssrf_guard, "_resolve", lambda host: {"93.184.216.34"}
    )
    assert is_safe_webhook_url(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.example.com/x",          # esquema no https
        "ftp://hooks.example.com/x",           # esquema no http(s)
        "https://127.0.0.1/hook",              # loopback
        "https://169.254.169.254/latest",      # metadatos cloud
        "https://10.0.0.1/hook",               # RFC1918
        "https://192.168.1.1/hook",            # RFC1918
        "https://172.16.0.1/hook",             # RFC1918
        "https://[::1]/hook",                  # IPv6 loopback
        "https://fc00::1/hook",                # ULA IPv6 (sin corchetes: inválida)
        "https://0.0.0.0/hook",                # unspecified
        "",                                    # vacía
        "not a url",                           # sin esquema ni host
        "https://",                            # sin host
    ],
)
def test_rechaza_no_https_y_espacio_privado(url):
    assert is_safe_webhook_url(url) is False


def test_rechaza_hostname_que_resuelve_privado(monkeypatch):
    monkeypatch.setattr(ssrf_guard, "_resolve", lambda host: {"10.1.2.3"})
    assert is_safe_webhook_url("https://internal.corp/hook") is False


def test_rechaza_hostname_no_resoluble(monkeypatch):
    monkeypatch.setattr(ssrf_guard, "_resolve", lambda host: set())
    assert is_safe_webhook_url("https://no-existe-osint-eye.invalid/hook") is False


def test_webhook_handler_url_insegura_es_noop(monkeypatch):
    monkeypatch.setattr(ssrf_guard, "_resolve", lambda host: {"127.0.0.1"})
    handler = AlertManager.webhook_handler("https://127.0.0.1/hook")
    # No debe lanzar ni hacer red: no-op callable.
    handler("tipo", "mensaje", "ALTO", {"k": "v"})


def test_webhook_handler_url_segura_devuelve_handler(monkeypatch):
    monkeypatch.setattr(ssrf_guard, "_resolve", lambda host: {"93.184.216.34"})
    handler = AlertManager.webhook_handler("https://93.184.216.34/hook")
    assert callable(handler)
