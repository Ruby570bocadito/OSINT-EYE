"""OSINT EYE - Shared HTTP client for every collector.

All ``modules/`` collectors go through :class:`HTTPClient` so that every
outbound request gets, by default:

* a bounded timeout (explicit ``timeout=None`` is not honoured: it falls
  back to the client default, a stuck request must never hang a scan),
* retries with exponential backoff on connection errors and transient
  server answers (429/500/502/503/504), honouring ``Retry-After``,
* an identifiable ``User-Agent`` (``OSINT-EYE/<version> (+repo url)``)
  instead of spoofed browser strings, configurable per client or via the
  ``OSINT_EYE_USER_AGENT`` environment variable,
* an optional per-host rate limit (minimum seconds between two requests
  to the same ``host:port``, thread-safe) so polite scanning against one
  target is a constructor argument away,
* optional proxy support (``proxy`` argument or ``OSINT_EYE_PROXY``).

The class exposes the underlying :class:`requests.Session` (``.session``,
``.cookies``) so advanced callers keep full control; convenience
``get``/``head``/``post`` proxies cover the collector use cases.

Contract: ``HTTPClient.get(...)`` returns a ``requests.Response`` and only
raises when the caller explicitly asks for it (``raise_for_status`` is the
caller's job). Connection-level errors still bubble up after the retries
are exhausted — collectors are expected to catch and degrade gracefully.
"""

import os
import threading
import time
from typing import Dict, Optional
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_TIMEOUT = 10.0
DEFAULT_RETRIES = 2
DEFAULT_BACKOFF = 0.5
DEFAULT_USER_AGENT = "OSINT-EYE/2.2 (+https://github.com/Ruby570bocadito/OSINT-EYE)"

# Statuses worth retrying for a recon tool: transient server-side issues
# and rate limiting (429 honours Retry-After via respect_retry_after_header).
RETRY_STATUS_FORCELIST = (429, 500, 502, 503, 504)


class HTTPClient:
    """requests.Session wrapper with timeout, retries, rate limit and proxy."""

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        backoff_factor: float = DEFAULT_BACKOFF,
        rate_limit: float = 0.0,
        user_agent: Optional[str] = None,
        proxy: Optional[str] = None,
    ):
        self.timeout = float(timeout) if timeout else DEFAULT_TIMEOUT
        self.retries = max(0, int(retries))
        self.backoff_factor = max(0.0, float(backoff_factor))
        self.rate_limit = max(0.0, float(rate_limit))
        self.user_agent = user_agent or os.environ.get("OSINT_EYE_USER_AGENT") or DEFAULT_USER_AGENT

        self.session = requests.Session()
        self.session.headers["User-Agent"] = self.user_agent

        retry = Retry(
            total=self.retries,
            connect=self.retries,
            read=self.retries,
            status=self.retries,
            backoff_factor=self.backoff_factor,
            status_forcelist=RETRY_STATUS_FORCELIST,
            # POST is not idempotent: never replayed automatically.
            allowed_methods=frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"}),
            respect_retry_after_header=True,
            # Return the last response instead of raising once retries run
            # out; collectors decide what to do with a 5xx answer.
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        if not proxy:
            proxy = os.environ.get("OSINT_EYE_PROXY") or None
        if proxy:
            self.session.proxies.update({"http": proxy, "https": proxy})

        self._lock = threading.Lock()
        self._last_hit: Dict[str, float] = {}

    # ── conveniences ────────────────────────────────────────────────────────
    @property
    def cookies(self):
        """Direct access to the session cookie jar (e.g. Google CONSENT)."""
        return self.session.cookies

    def set_header(self, name: str, value: str) -> None:
        """Set a default header on the underlying session (e.g. apiKey)."""
        self.session.headers[name] = value

    def set_default_timeout(self, timeout: float) -> None:
        self.timeout = float(timeout) if timeout else DEFAULT_TIMEOUT

    # ── rate limiting ───────────────────────────────────────────────────────
    def _throttle(self, url: str) -> None:
        """Sleep just enough to keep ``rate_limit`` seconds per host:port."""
        if self.rate_limit <= 0:
            return
        parts = urlsplit(url)
        key = f"{parts.scheme}://{parts.netloc}" if parts.netloc else url
        with self._lock:
            now = time.monotonic()
            earliest = self._last_hit.get(key, 0.0) + self.rate_limit
            wait = earliest - now
            # Reserve the slot while holding the lock so concurrent worker
            # threads queue up instead of all sleeping for the same instant.
            self._last_hit[key] = max(now, earliest)
        if wait > 0:
            time.sleep(wait)

    # ── request core ────────────────────────────────────────────────────────
    def request(self, method: str, url: str, **kwargs):
        self._throttle(url)
        # An explicit timeout=None must never disable the ceiling.
        if kwargs.get("timeout") is None:
            kwargs["timeout"] = self.timeout
        return self.session.request(method, url, **kwargs)

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs):
        return self.request("HEAD", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self.request("POST", url, **kwargs)

    def close(self) -> None:
        self.session.close()


def _client_params_from_env() -> dict:
    """Read optional HTTP tuning from the environment (no secrets required)."""
    params: dict = {}

    def _float(name: str):
        raw = os.environ.get(name)
        if not raw:
            return None
        try:
            return float(raw)
        except ValueError:
            return None

    timeout = _float("OSINT_EYE_HTTP_TIMEOUT")
    if timeout:
        params["timeout"] = timeout
    rate = _float("OSINT_EYE_RATE_LIMIT")
    if rate:
        params["rate_limit"] = rate
    if os.environ.get("OSINT_EYE_USER_AGENT"):
        params["user_agent"] = os.environ["OSINT_EYE_USER_AGENT"]
    if os.environ.get("OSINT_EYE_PROXY"):
        params["proxy"] = os.environ["OSINT_EYE_PROXY"]
    return params


_shared_client: Optional[HTTPClient] = None
_shared_lock = threading.Lock()


def get_client() -> HTTPClient:
    """Process-wide shared client (env-tuned, lazily created, thread-safe)."""
    global _shared_client
    if _shared_client is None:
        with _shared_lock:
            if _shared_client is None:
                _shared_client = HTTPClient(**_client_params_from_env())
    return _shared_client
