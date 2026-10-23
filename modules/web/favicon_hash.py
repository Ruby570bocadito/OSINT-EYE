"""OSINT EYE - Favicon hashing for technology/asset pivoting.

Downloads a target's favicon and computes the MurmurHash3 x86_32 of its
base64 encoding — the same "favicon hash" widely used by asset-search
engines to pivot from one hash to every host serving the same icon.

MurmurHash3 x86_32 is implemented here in pure Python (the canonical
algorithm, ~30 lines): no new dependency, deterministic across runtimes,
and the module stays stdlib-only per project policy. The result is the
SIGNED 32-bit integer the search engines expect.

Detection order: ``<link rel="icon">`` / ``rel="shortcut icon"`` on the
page first, falling back to the conventional ``/favicon.ico``. A response
that is not an image (content-type or magic bytes) is reported but never
hashed, so an HTML error page can't poison the pivot value.

Degradation contract: ``scan()`` always returns the full result shape;
network failures degrade to ``error`` entries instead of raising.

Contract consumed by osint_eye.py:
    FaviconHasher().scan(target) -> dict (see shape below).
"""

import base64
import hashlib
import re
from typing import Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

from modules._http import HTTPClient
from modules._scope import allowed as _scope_allowed

#: Conventional fallback when the page declares no icon.
DEFAULT_FAVICON_PATH = "/favicon.ico"

#: Never hash payloads larger than this (bounded runtime).
MAX_BYTES = 1_000_000

_LINK_ICON_RE = re.compile(
    r"<link[^>]+rel=[\"'][^\"']*(?:shortcut\s+icon|icon|apple-touch-icon)[^\"']*"
    r"[\"'][^>]*>",
    re.I,
)
_LINK_HREF_RE = re.compile(r"href=[\"']([^\"']+)[\"']", re.I)

_MAGIC_SIGNATURES = (
    b"\x89PNG\r\n\x1a\n",  # PNG
    b"GIF87a",  # GIF
    b"GIF89a",
    b"\xff\xd8\xff",  # JPEG
    b"\x00\x00\x01\x00",  # ICO
)


def mmh3_x86_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32 over ``data`` (signed 32-bit result).

    Canonical algorithm; matches the well-known favicon-hash recipe
    (mmh3.hash over the base64-encoded icon bytes).
    """
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded = length - (length % 4)

    for i in range(0, rounded, 4):
        k1 = int.from_bytes(data[i : i + 4], "little")
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail = data[rounded:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    return h1 - 0x100000000 if h1 >= 0x80000000 else h1


def favicon_hash(content: bytes) -> int:
    """Signed mmh3 of the base64-encoded icon bytes (pivot value)."""
    return mmh3_x86_32(base64.encodebytes(content))


def looks_like_image(content: bytes, content_type: str = "") -> bool:
    """True when the payload is plausibly an image (type or magic bytes)."""
    ctype = (content_type or "").split(";", 1)[0].strip().lower()
    if ctype.startswith("image/"):
        return True
    if not content:
        return False
    return any(content.startswith(sig) for sig in _MAGIC_SIGNATURES)


def pick_favicon_url(html: str, base_url: str) -> Optional[str]:
    """Resolve the declared icon URL from a page, else None.

    Relative hrefs resolve against ``base_url``; protocol-relative
    (``//host/x``) becomes https. The first declared icon wins.
    """
    for link in _LINK_ICON_RE.findall(html or ""):
        href_match = _LINK_HREF_RE.search(link)
        if not href_match:
            continue
        href = href_match.group(1).strip()
        if not href or href.startswith("#"):
            continue
        if href.startswith("//"):
            return f"https:{href}"
        if href.startswith("http"):
            return href
        prefix = base_url if base_url.endswith("/") else base_url + "/"
        return urljoin(prefix, href)
    return None


def _split_target(target: str) -> Tuple[str, str]:
    """Reduce target to (origin, base_url) for fallback construction."""
    raw = (target or "").strip()
    if not raw:
        raise ValueError("target vacío")
    if "://" not in raw:
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    if not parsed.netloc:
        raise ValueError(f"target no reconocible: {target!r}")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return origin, raw


class FaviconHasher:
    """Fetch a target's favicon and compute its pivot hash."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = HTTPClient(timeout=timeout)

    @staticmethod
    def _result(target: str) -> Dict:
        """Full result shape (nothing claimed yet)."""
        return {
            "target": target,
            "favicon_url": None,
            "status": None,
            "content_type": None,
            "size_bytes": None,
            "md5": None,
            "sha256": None,
            "favicon_hash": None,
            "error": None,
        }

    def scan(self, base_url: str, scope=None) -> Dict:
        """Compute the favicon pivot hash for ``base_url``.

        ``scope`` is optional (``core.scope.Scope``): both the page and
        the favicon URL are checked before being requested (module label
        "favicon_hash"); out-of-scope URLs are never fetched.
        """
        results = self._result(base_url)

        try:
            origin, page_url = _split_target(base_url)
        except ValueError as e:
            results["error"] = str(e)
            return results

        if scope is not None and not _scope_allowed(scope, base_url, "favicon_hash"):
            print(f"[!] {base_url} out of scope: skipping favicon hash")
            return results

        # Page first: a declared <link rel="icon"> beats the fallback.
        favicon_url: Optional[str] = None
        try:
            response = self.session.get(page_url, timeout=self.timeout)
            status = getattr(response, "status_code", None)
            if status is None or status < 400:
                favicon_url = pick_favicon_url(
                    getattr(response, "text", "") or "", page_url
                )
        except Exception as e:
            # Page unreachable: still try the conventional fallback path.
            results["error"] = str(e)

        if favicon_url is None:
            favicon_url = origin + DEFAULT_FAVICON_PATH

        if scope is not None and not _scope_allowed(
            scope, favicon_url, "favicon_hash"
        ):
            results["favicon_url"] = favicon_url
            return results

        try:
            response = self.session.get(favicon_url, timeout=self.timeout)
        except Exception as e:
            results["favicon_url"] = favicon_url
            results["error"] = results["error"] or str(e)
            return results

        content = getattr(response, "content", b"") or b""
        content_type = getattr(response, "headers", {}).get("Content-Type", "")
        status = getattr(response, "status_code", None)

        results["favicon_url"] = favicon_url
        results["status"] = status
        results["content_type"] = content_type

        if status is not None and status >= 400:
            results["error"] = f"HTTP {status}"
            return results
        if len(content) > MAX_BYTES:
            results["error"] = "favicon demasiado grande"
            return results
        if not looks_like_image(content, content_type):
            results["error"] = "la respuesta no parece una imagen"
            return results

        results["size_bytes"] = len(content)
        results["md5"] = hashlib.md5(content).hexdigest()
        results["sha256"] = hashlib.sha256(content).hexdigest()
        results["favicon_hash"] = favicon_hash(content)
        return results
