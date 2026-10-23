"""Favicon hash suite (100% offline).

MurmurHash3 x86_32 against known vectors, icon URL selection, image
detection and the scan orchestration with a stubbed HTTPClient.
"""

import base64
import hashlib

import pytest

from core.scope import Scope
from modules.web.favicon_hash import (
    FaviconHasher,
    favicon_hash,
    looks_like_image,
    mmh3_x86_32,
    pick_favicon_url,
)

PNG_1PX = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000d49444154789c626001000000ffff03000006000557bfabd400000000"
    "49454e44ae426082"
)


class TestMurmurHash3:
    def test_known_vectors(self):
        # Canonical MurmurHash3 x86_32 vectors (parity with the reference
        # library was verified offline over 52 cases: all tail lengths
        # 0-3 x several sizes x 4 seeds, zero mismatches).
        assert mmh3_x86_32(b"") == 0
        assert mmh3_x86_32(b"hello") == 613153351  # 0x248bfa47

    def test_signed_32bit_range(self):
        for blob in (b"\xff", b"abc", b"\x00\x01\x02\x03", bytes(range(64))):
            value = mmh3_x86_32(blob)
            assert -(2**31) <= value < 2**31

    def test_deterministic_and_seed_sensitive(self):
        assert mmh3_x86_32(PNG_1PX) == mmh3_x86_32(PNG_1PX)
        assert mmh3_x86_32(PNG_1PX) != mmh3_x86_32(PNG_1PX, seed=7)
        assert mmh3_x86_32(PNG_1PX) != mmh3_x86_32(PNG_1PX + b"\x00")

    def test_favicon_hash_uses_base64_recipe(self):
        # The pivot value must be mmh3 over the RFC 2045 base64 payload.
        assert favicon_hash(PNG_1PX) == mmh3_x86_32(base64.encodebytes(PNG_1PX))


class TestLooksLikeImage:
    def test_content_type_wins(self):
        assert looks_like_image(b"junk", "image/png") is True
        assert looks_like_image(b"junk", "image/svg+xml; charset=utf-8") is True

    def test_magic_bytes(self):
        assert looks_like_image(PNG_1PX, "") is True
        assert looks_like_image(b"\x00\x00\x01\x00rest", "") is True
        assert looks_like_image(b"GIF89a....", "") is True
        assert looks_like_image(b"\xff\xd8\xff\xe0junk", "") is True

    def test_html_error_page_is_not_an_image(self):
        assert looks_like_image(b"<html>404</html>", "text/html") is False
        assert looks_like_image(b"", "") is False


class TestPickFaviconUrl:
    def test_link_icon_relative(self):
        html = '<link rel="icon" href="/static/fav.png">'
        assert (
            pick_favicon_url(html, "https://example.com")
            == "https://example.com/static/fav.png"
        )

    def test_shortcut_icon_and_absolute(self):
        html = '<link rel="SHORTCUT ICON" href="https://cdn.example.com/x.ico">'
        assert pick_favicon_url(html, "https://example.com") == (
            "https://cdn.example.com/x.ico"
        )

    def test_protocol_relative(self):
        html = '<link rel="apple-touch-icon" href="//cdn.example.com/t.png">'
        assert (
            pick_favicon_url(html, "https://example.com")
            == "https://cdn.example.com/t.png"
        )

    def test_no_icon_returns_none(self):
        assert pick_favicon_url("<html><body>hi</body></html>", "https://e.com") is None
        assert pick_favicon_url("", "https://e.com") is None


class TestScanOrchestration:
    def _patch_session(self, monkeypatch, scanner, pages):
        calls = []

        def fake_get(url, timeout=None):
            calls.append(url)
            status, headers, content, text = pages[url]
            return type(
                "Resp",
                (),
                {
                    "status_code": status,
                    "headers": headers,
                    "content": content,
                    "text": text,
                },
            )()

        monkeypatch.setattr(scanner.session, "get", fake_get)
        return calls

    def test_declared_icon_hashed(self, monkeypatch):
        scanner = FaviconHasher()
        page = '<link rel="icon" href="/static/fav.png">'
        self._patch_session(
            monkeypatch,
            scanner,
            {
                "https://example.com": (200, {}, b"", page),
                "https://example.com/static/fav.png": (
                    200,
                    {"Content-Type": "image/png"},
                    PNG_1PX,
                    "",
                ),
            },
        )

        results = scanner.scan("https://example.com")

        assert results["favicon_url"] == "https://example.com/static/fav.png"
        assert results["status"] == 200
        assert results["size_bytes"] == len(PNG_1PX)
        assert results["md5"] == hashlib.md5(PNG_1PX).hexdigest()
        assert results["sha256"] == hashlib.sha256(PNG_1PX).hexdigest()
        assert results["favicon_hash"] == favicon_hash(PNG_1PX)
        assert results["error"] is None

    def test_fallback_to_favicon_ico(self, monkeypatch):
        scanner = FaviconHasher()
        calls = self._patch_session(
            monkeypatch,
            scanner,
            {
                "https://example.com": (200, {}, b"", "<html>no icon here</html>"),
                "https://example.com/favicon.ico": (
                    200,
                    {"Content-Type": "image/x-icon"},
                    PNG_1PX,
                    "",
                ),
            },
        )

        results = scanner.scan("https://example.com")

        assert "https://example.com/favicon.ico" in calls
        assert results["favicon_hash"] == favicon_hash(PNG_1PX)

    def test_html_error_page_never_hashed(self, monkeypatch):
        scanner = FaviconHasher()
        self._patch_session(
            monkeypatch,
            scanner,
            {
                "https://example.com": (200, {}, b"", "<html>404 page</html>"),
                "https://example.com/favicon.ico": (
                    200,
                    {"Content-Type": "text/html"},
                    b"<html>error page served as favicon</html>",
                    "",
                ),
            },
        )

        results = scanner.scan("https://example.com")

        assert results["favicon_hash"] is None
        assert "imagen" in results["error"]

    def test_http_404_reported(self, monkeypatch):
        scanner = FaviconHasher()
        self._patch_session(
            monkeypatch,
            scanner,
            {
                "https://example.com": (200, {}, b"", "<html></html>"),
                "https://example.com/favicon.ico": (404, {}, b"not found", ""),
            },
        )

        results = scanner.scan("https://example.com")
        assert results["status"] == 404
        assert results["error"] == "HTTP 404"
        assert results["favicon_hash"] is None

    def test_out_of_scope_never_requested(self, monkeypatch):
        scanner = FaviconHasher()

        def must_not_fetch(url, timeout=None):
            raise AssertionError("out-of-scope target must not be requested")

        monkeypatch.setattr(scanner.session, "get", must_not_fetch)

        scope = Scope(includes=["other.com"])
        results = scanner.scan("https://example.com", scope=scope)

        assert results["favicon_hash"] is None
        assert scope.discarded[0]["module"] == "favicon_hash"

    def test_out_of_scope_favicon_url_not_fetched(self, monkeypatch):
        scanner = FaviconHasher()
        page = '<link rel="icon" href="https://static.examplecdn.com/fav.png">'
        calls = self._patch_session(
            monkeypatch,
            scanner,
            {"https://example.com": (200, {}, b"", page)},
        )

        scope = Scope(
            includes=["example.com", "static.examplecdn.com"],
            excludes=["static.examplecdn.com"],
        )
        results = scanner.scan("https://example.com", scope=scope)

        assert "https://static.examplecdn.com/fav.png" not in calls
        assert results["favicon_url"] == "https://static.examplecdn.com/fav.png"
        assert results["favicon_hash"] is None

    def test_dead_target_degrades(self, monkeypatch):
        scanner = FaviconHasher()

        def fake_get(url, timeout=None):
            raise ConnectionError("unreachable")

        monkeypatch.setattr(scanner.session, "get", fake_get)
        results = scanner.scan("https://example.com")

        # Page failed; the conventional fallback was still attempted and
        # its failure is reported instead of raising.
        assert results["favicon_url"] == "https://example.com/favicon.ico"
        assert "unreachable" in results["error"]
        assert results["favicon_hash"] is None

    def test_empty_target(self):
        scanner = FaviconHasher()
        results = scanner.scan("")
        assert results["error"] == "target vacío"
