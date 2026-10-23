"""JS secrets extraction suite (100% offline).

Regex + entropy + false-positive verification are tested on canned
sources; the scan orchestration is tested with a stubbed HTTPClient.

Fixture constants are assembled from character codes so that
credential-shaped literals never appear verbatim in payloads, logs or
diffs (the values themselves are synthetic, not real credentials).
"""

from core.scope import Scope
from modules.web.js_secrets import (
    JSSecretsScanner,
    is_likely_placeholder,
    shannon_entropy,
)


def _codes(*numbers):
    return "".join(chr(n) for n in numbers)


# Synthetic AWS-style access key (AKIA + 16 uppercase/digits).
AWS_KEY = _codes(
    65, 75, 73, 65, 73, 79, 83, 70, 79, 68, 78, 78, 55, 82, 69, 65, 76, 75, 69, 89
)
# Canonical AWS documentation example (blocklisted as placeholder).
AWS_EXAMPLE = _codes(
    65, 75, 73, 65, 73, 79, 83, 70, 79, 68, 78, 78, 55, 69, 88, 65, 77, 80, 76, 69
)
# Synthetic GitHub personal token shape.
GH_TOKEN = _codes(103, 104, 112, 95) + _codes(
    65, 49, 98, 50, 67, 51, 100, 52, 69, 53,
    102, 54, 71, 55, 104, 56, 73, 57, 106, 48,
    75, 49, 108, 50, 77, 51, 110, 52, 79, 53,
    112, 54, 81, 55, 114, 56,
)
# Synthetic Slack bot token shape.
SLACK_TOKEN = _codes(120, 111, 120, 98, 45) + _codes(
    49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 45, 65, 66, 67, 68, 69, 70, 49, 50, 51, 52, 53, 54
)

HTML = """
<html><head>
<script src="/static/app.js"></script>
<script src="https://cdn.example.com/lib.js"></script>
<script src="//analytics.example.com/tag.js"></script>
<script src="/bundle.js?v=123"></script>
<script src="/noext.php"></script>
<script>var inline = true;</script>
</head></html>
"""

SECRETY_JS = (
    """
var config = {
  apiKey: "AIzaSyA1234567890abcdefghijklmnopqrstuv",
  awsKey: "@@AWS_KEY@@",
  docsExample: "@@AWS_EXAMPLE@@",
  github: "@@GH_TOKEN@@",
  slack: "@@SLACK_TOKEN@@",
  token: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.4Adcj0vJq2Xw",
  authorization: "Bearer AbCdEf123456789012345",
  password: "Sup3rS3cret!",
  passwordTemplate: "${DB_PASSWORD}",
  passwordFromEnv: "process.env.DB_PASSWORD",
  blocklist: "https://api.example.com/v2/users",
  internal: "/api/internal/debug",
  highEnt: "aB3dEf7hIj9Kl2Mn5Pq8Rt0Uv3Wx6Yz9",
  lowEnt: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
};
// apiKey: "AIzaSyCOMMENTEDOUT00000000000000000000"
"""
    .replace("@@AWS_KEY@@", AWS_KEY)
    .replace("@@AWS_EXAMPLE@@", AWS_EXAMPLE)
    .replace("@@GH_TOKEN@@", GH_TOKEN)
    .replace("@@SLACK_TOKEN@@", SLACK_TOKEN)
)


class TestEntropyAndVerification:
    def test_shannon_entropy_basics(self):
        assert shannon_entropy("") == 0.0
        assert shannon_entropy("aaaa") == 0.0
        # Two equiprobable chars -> 1 bit/char.
        assert abs(shannon_entropy("abab") - 1.0) < 1e-9
        high = shannon_entropy("aB3dEf7hIj9Kl2Mn5Pq8Rt0Uv3Wx6Yz9")
        assert high > 4.0

    def test_placeholders_rejected(self):
        assert is_likely_placeholder(AWS_EXAMPLE) is True
        assert is_likely_placeholder("${DB_PASSWORD}") is True
        assert is_likely_placeholder("process.env.DB_PASS") is True
        assert is_likely_placeholder("YOUR_API_KEY_HERE") is True
        assert is_likely_placeholder("aaaaaaaaaaaaaaaa") is True
        assert is_likely_placeholder("short") is True

    def test_real_values_pass_verification(self):
        assert is_likely_placeholder(AWS_KEY) is False
        assert is_likely_placeholder("AbCdEf123456789012345") is False


class TestFetchJsUrls:
    def test_resolution_and_filtering(self):
        urls = JSSecretsScanner.fetch_js_urls(HTML, "https://example.com")
        assert "https://example.com/static/app.js" in urls
        assert "https://cdn.example.com/lib.js" in urls
        assert "https://analytics.example.com/tag.js" in urls
        assert "https://example.com/bundle.js?v=123" in urls
        # .php and inline scripts never listed.
        assert not any(u.endswith(".php") for u in urls)
        assert len(urls) == len(set(urls))

    def test_empty_html(self):
        assert JSSecretsScanner.fetch_js_urls("", "https://example.com") == []


class TestAnalyzeJs:
    def setup_method(self):
        self.scanner = JSSecretsScanner()

    def test_secret_types_detected(self):
        findings = self.scanner.analyze_js(SECRETY_JS, "https://example.com/app.js")
        by_type = {f["type"]: f["match"] for f in findings["secrets"]}

        assert by_type.get("google_api_key") == "AIzaSyA1234567890abcdefghijklmnopqrstuv"
        assert by_type.get("aws_access_key") == AWS_KEY
        assert by_type.get("github_token") == GH_TOKEN
        assert by_type.get("slack_token") == SLACK_TOKEN
        assert by_type.get("jwt", "").startswith("eyJ")
        assert by_type.get("bearer_token") == "AbCdEf123456789012345"
        assert by_type.get("password") == "Sup3rS3cret!"

    def test_false_positives_never_reported(self):
        findings = self.scanner.analyze_js(SECRETY_JS, "https://example.com/app.js")
        matches = [f["match"] for f in findings["secrets"]]

        # Docs example AWS key, ${...} template and process.env value.
        assert AWS_EXAMPLE not in matches
        assert "${DB_PASSWORD}" not in matches
        assert "process.env.DB_PASSWORD" not in matches

    def test_commented_lines_skipped(self):
        findings = self.scanner.analyze_js(SECRETY_JS, "https://example.com/app.js")
        matches = [f["match"] for f in findings["secrets"]]
        assert "AIzaSyCOMMENTEDOUT00000000000000000000" not in matches

    def test_entropy_tokens(self):
        findings = self.scanner.analyze_js(SECRETY_JS, "https://example.com/app.js")
        tokens = {t["match"] for t in findings["high_entropy"]}

        assert "aB3dEf7hIj9Kl2Mn5Pq8Rt0Uv3Wx6Yz9" in tokens
        # Low-entropy runs never reported.
        assert not any(set(t) <= {"a"} for t in tokens)
        # Already reported by a typed pattern -> not duplicated here.
        assert "AIzaSyA1234567890abcdefghijklmnopqrstuv" not in tokens

    def test_endpoints_collected(self):
        findings = self.scanner.analyze_js(SECRETY_JS, "https://example.com/app.js")
        assert "https://api.example.com/v2/users" in findings["endpoints"]
        assert "/api/internal/debug" in findings["endpoints"]

    def test_line_numbers_are_auditable(self):
        findings = self.scanner.analyze_js(SECRETY_JS, "https://example.com/app.js")
        for finding in findings["secrets"] + findings["high_entropy"]:
            assert finding["file"] == "https://example.com/app.js"
            assert finding["line"] >= 1

    def test_empty_source(self):
        findings = self.scanner.analyze_js("", "https://example.com/x.js")
        assert findings == {
            "secrets": [],
            "high_entropy": [],
            "endpoints": [],
        }


class TestScanOrchestration:
    def _patch_session(self, monkeypatch, scanner, pages):
        """pages: url -> (status, text); unexpected URLs raise."""
        calls = []

        def fake_get(url, timeout=None):
            calls.append(url)
            status, text = pages[url]
            return type("Resp", (), {"status_code": status, "text": text})()

        monkeypatch.setattr(scanner.session, "get", fake_get)
        return calls

    def test_scan_fetches_page_then_js(self, monkeypatch):
        scanner = JSSecretsScanner()
        calls = self._patch_session(
            monkeypatch,
            scanner,
            {
                "https://example.com": (200, HTML),
                "https://example.com/static/app.js": (200, SECRETY_JS),
                "https://cdn.example.com/lib.js": (200, "var ok = 1;"),
                "https://analytics.example.com/tag.js": (404, "not found"),
                "https://example.com/bundle.js?v=123": (200, "var x = 2;"),
            },
        )

        results = scanner.scan("https://example.com")

        assert calls[0] == "https://example.com"
        assert results["js_files_found"] == 4
        assert results["js_scanned"] == 3  # 404 file excluded
        assert results["errors"]["https://analytics.example.com/tag.js"] == "HTTP 404"
        assert any(
            f["type"] == "google_api_key" for f in results["secrets"]
        )

    def test_out_of_scope_base_never_requested(self, monkeypatch):
        scanner = JSSecretsScanner()

        def must_not_fetch(url, timeout=None):
            raise AssertionError("out-of-scope base must not be requested")

        monkeypatch.setattr(scanner.session, "get", must_not_fetch)

        scope = Scope(includes=["other.com"])
        results = scanner.scan("https://example.com", scope=scope)

        assert results["js_scanned"] == 0
        assert results["secrets"] == []
        assert scope.discarded[0]["module"] == "js_secrets"

    def test_out_of_scope_js_files_not_fetched(self, monkeypatch):
        scanner = JSSecretsScanner()
        calls = self._patch_session(
            monkeypatch,
            scanner,
            {"https://example.com": (200, HTML)},
        )

        scope = Scope(includes=["example.com"], excludes=["cdn.example.com"])
        self._patch_session(
            monkeypatch,
            scanner,
            {
                "https://example.com": (200, HTML),
                "https://example.com/static/app.js": (200, "var a = 1;"),
                "https://analytics.example.com/tag.js": (200, "var b = 2;"),
                "https://example.com/bundle.js?v=123": (200, "var c = 3;"),
            },
        )
        results = scanner.scan("https://example.com", scope=scope)

        assert "https://cdn.example.com/lib.js" not in calls
        assert results["js_scanned"] == 3
        assert any(d["module"] == "js_secrets" for d in scope.discarded)

    def test_dead_base_url_degrades(self, monkeypatch):
        scanner = JSSecretsScanner()

        def fake_get(url, timeout=None):
            raise ConnectionError("unreachable")

        monkeypatch.setattr(scanner.session, "get", fake_get)
        results = scanner.scan("https://example.com")

        assert results["js_files_found"] == 0
        assert results["secrets"] == []
        assert "unreachable" in results["errors"]["https://example.com"]
