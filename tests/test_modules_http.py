"""Offline tests for the shared HTTP client (modules/_http.py).

No network access: every request goes through a mocked
``requests.Session.request``; configuration (timeout, retries, rate
limit, proxy, User-Agent) is verified against the client internals.
"""

import os
import sys
import time
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from modules._http import (
    DEFAULT_TIMEOUT,
    HTTPClient,
    _client_params_from_env,
    get_client,
)


# ─────────────────────────────────────────────────────────────────────────────
# User-Agent
# ─────────────────────────────────────────────────────────────────────────────
class TestUserAgent:
    def test_default_user_agent_is_identifiable(self):
        client = HTTPClient()
        assert "OSINT-EYE" in client.user_agent
        assert "https://github.com/Ruby570bocadito/OSINT-EYE" in client.user_agent
        assert client.session.headers["User-Agent"] == client.user_agent

    def test_custom_user_agent_argument_wins(self):
        client = HTTPClient(user_agent="OSINT-EYE/9.9 (custom-agent-test)")
        assert client.user_agent == "OSINT-EYE/9.9 (custom-agent-test)"
        assert client.session.headers["User-Agent"] == client.user_agent

    def test_env_user_agent_used_when_no_argument(self, monkeypatch):
        monkeypatch.setenv("OSINT_EYE_USER_AGENT", "OSINT-EYE/7.7 (env-agent)")
        params = _client_params_from_env()
        client = HTTPClient(**params)
        assert client.user_agent == "OSINT-EYE/7.7 (env-agent)"

    def test_env_user_agent_ignored_when_argument_given(self, monkeypatch):
        monkeypatch.setenv("OSINT_EYE_USER_AGENT", "OSINT-EYE/7.7 (env-agent)")
        client = HTTPClient(user_agent="OSINT-EYE/1.0 (arg-agent)")
        assert client.user_agent == "OSINT-EYE/1.0 (arg-agent)"


# ─────────────────────────────────────────────────────────────────────────────
# Timeout policy
# ─────────────────────────────────────────────────────────────────────────────
class TestTimeout:
    @staticmethod
    def _client_with_captured_request():
        client = HTTPClient(timeout=7)
        captured = {}

        def fake_request(method, url, **kwargs):
            captured["method"] = method
            captured["url"] = url
            captured.update(kwargs)
            return MagicMock(status_code=200)

        client.session.request = fake_request
        return client, captured

    def test_default_timeout_applied_when_omitted(self):
        client, captured = self._client_with_captured_request()
        client.get("https://example.invalid/path")
        assert captured["timeout"] == 7

    def test_explicit_timeout_honoured(self):
        client, captured = self._client_with_captured_request()
        client.get("https://example.invalid/path", timeout=3)
        assert captured["timeout"] == 3

    def test_timeout_none_falls_back_to_default(self):
        """timeout=None must never disable the ceiling."""
        client, captured = self._client_with_captured_request()
        client.get("https://example.invalid/path", timeout=None)
        assert captured["timeout"] == 7
        assert captured["timeout"] is not None

    def test_default_timeout_constant_is_bounded(self):
        assert 0 < DEFAULT_TIMEOUT <= 30


# ─────────────────────────────────────────────────────────────────────────────
# Retry configuration
# ─────────────────────────────────────────────────────────────────────────────
class TestRetryConfiguration:
    def test_adapter_retries_with_backoff(self):
        client = HTTPClient(retries=3, backoff_factor=0.75)
        adapter = client.session.get_adapter("https://example.invalid")
        assert adapter.max_retries.total == 3
        assert adapter.max_retries.backoff_factor == 0.75

    def test_transient_statuses_are_retried(self):
        client = HTTPClient()
        adapter = client.session.get_adapter("https://example.invalid")
        for status in (429, 500, 502, 503, 504):
            assert status in adapter.max_retries.status_forcelist

    def test_post_is_never_retried(self):
        client = HTTPClient()
        adapter = client.session.get_adapter("https://example.invalid")
        assert "POST" not in adapter.max_retries.allowed_methods
        assert "GET" in adapter.max_retries.allowed_methods

    def test_retry_after_header_respected(self):
        client = HTTPClient()
        adapter = client.session.get_adapter("https://example.invalid")
        assert adapter.max_retries.respect_retry_after_header

    def test_exhausted_retries_return_last_response_not_raise(self):
        client = HTTPClient()
        adapter = client.session.get_adapter("https://example.invalid")
        assert not adapter.max_retries.raise_on_status


# ─────────────────────────────────────────────────────────────────────────────
# Rate limiting
# ─────────────────────────────────────────────────────────────────────────────
class TestRateLimit:
    def test_same_host_is_throttled(self):
        client = HTTPClient(rate_limit=0.05)
        start = time.monotonic()
        client._throttle("https://host-a.invalid/x")
        client._throttle("https://host-a.invalid/y")
        elapsed = time.monotonic() - start
        assert elapsed >= 0.045

    def test_different_hosts_are_independent(self):
        client = HTTPClient(rate_limit=0.2)
        start = time.monotonic()
        client._throttle("https://host-a.invalid/x")
        client._throttle("https://host-b.invalid/x")
        assert time.monotonic() - start < 0.1

    def test_disabled_by_default(self):
        client = HTTPClient()
        assert client.rate_limit == 0.0
        start = time.monotonic()
        for _ in range(3):
            client._throttle("https://host-c.invalid/x")
        assert time.monotonic() - start < 0.1

    def test_negative_rate_limit_clamped_to_zero(self):
        client = HTTPClient(rate_limit=-5)
        assert client.rate_limit == 0.0

    def test_env_rate_limit_via_params(self, monkeypatch):
        monkeypatch.setenv("OSINT_EYE_RATE_LIMIT", "1.5")
        params = _client_params_from_env()
        assert params["rate_limit"] == 1.5
        client = HTTPClient(**params)
        assert client.rate_limit == 1.5


# ─────────────────────────────────────────────────────────────────────────────
# Proxy
# ─────────────────────────────────────────────────────────────────────────────
class TestProxy:
    def test_proxy_argument_configures_session(self):
        client = HTTPClient(proxy="http://127.0.0.1:9999")
        assert client.session.proxies["http"] == "http://127.0.0.1:9999"
        assert client.session.proxies["https"] == "http://127.0.0.1:9999"

    def test_no_proxy_by_default(self):
        client = HTTPClient()
        assert client.session.proxies == {}

    def test_env_proxy_via_params(self, monkeypatch):
        monkeypatch.setenv("OSINT_EYE_PROXY", "http://127.0.0.1:8888")
        params = _client_params_from_env()
        assert params["proxy"] == "http://127.0.0.1:8888"

    def test_malformed_env_rate_limit_ignored(self, monkeypatch):
        monkeypatch.setenv("OSINT_EYE_RATE_LIMIT", "not-a-number")
        assert _client_params_from_env() == {}


# ─────────────────────────────────────────────────────────────────────────────
# Shared client + pass-through behaviour
# ─────────────────────────────────────────────────────────────────────────────
class TestSharedClientAndPassThrough:
    def test_get_client_returns_same_instance(self):
        assert get_client() is get_client()
        assert isinstance(get_client(), HTTPClient)

    def test_response_passthrough_and_kwargs(self):
        client = HTTPClient()
        sentinel = MagicMock(status_code=200)
        client.session.request = MagicMock(return_value=sentinel)

        resp = client.get(
            "https://example.invalid/api", params={"q": "test"}, timeout=2
        )
        assert resp is sentinel
        args, kwargs = client.session.request.call_args
        assert args[0] == "GET"
        assert args[1] == "https://example.invalid/api"
        assert kwargs["params"] == {"q": "test"}
        assert kwargs["timeout"] == 2

    def test_head_and_post_methods(self):
        client = HTTPClient()
        client.session.request = MagicMock(return_value=MagicMock())
        client.head("https://example.invalid/")
        client.post("https://example.invalid/", data={"a": "b"})
        assert client.session.request.call_args_list[0][0][0] == "HEAD"
        assert client.session.request.call_args_list[1][0][0] == "POST"

    def test_cookies_property_delegates_to_session(self):
        client = HTTPClient()
        assert client.cookies is client.session.cookies
        client.cookies.set("CONSENT", "YES+")
        assert client.session.cookies.get("CONSENT") == "YES+"

    def test_set_header(self):
        client = HTTPClient()
        client.set_header("apiKey", "test-key-123")
        assert client.session.headers["apiKey"] == "test-key-123"

    def test_close_closes_session(self):
        client = HTTPClient()
        client.session.close = MagicMock()
        client.close()
        client.session.close.assert_called_once()
