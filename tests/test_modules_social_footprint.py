"""Offline tests for the social footprint scanner
(modules/osint/social_footprint.py).

HTTP is a fake client keyed by (host, path); the platform APIs answer
canned JSON. No network anywhere.
"""

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from modules.osint.social_footprint import SocialFootprintScanner, derive_names

DOMAIN = "example.com"


class FakeHTTP:
    """Routes (host, path-prefix) -> canned response."""

    def __init__(self, routes):
        self.routes = routes  # list of (host, path_prefix, response)
        self.calls = []

    def get(self, url, params=None, timeout=None, **kwargs):
        self.calls.append((url, params))
        resp = MagicMock()
        # Longest matching (host, path-prefix) wins, so /users/example/repos
        # is not shadowed by /users/example.
        best = None
        best_len = -1
        for host, prefix, answer in self.routes:
            if not url.startswith(f"https://{host}"):
                continue
            path = url[len(f"https://{host}"):]
            if path == prefix or path.startswith(prefix.rstrip("/") + "/"):
                if len(prefix) > best_len:
                    best, best_len = answer, len(prefix)
        if best is not None:
            if callable(best):
                return best(url, params)
            status, payload = best
            resp.status_code = status
            resp.json.return_value = payload
            resp.text = payload if isinstance(payload, str) else ""
            resp.headers = {}
            return resp
        resp.status_code = 404
        resp.json.return_value = {}
        resp.text = ""
        return resp


def _scanner(routes):
    return SocialFootprintScanner(http=FakeHTTP(routes), timeout=5)


GITHUB_PROFILE = {
    "login": "example",
    "html_url": "https://github.com/example",
    "name": "Example Corp",
    "company": None,
    "blog": "https://example.com",
    "public_repos": 12,
    "followers": 40,
    "created_at": "2015-01-01T00:00:00Z",
}
GITHUB_REPOS = [
    {
        "name": "tool",
        "html_url": "https://github.com/example/tool",
        "description": "A tool",
        "language": "Python",
        "stargazers_count": 5,
        "updated_at": "2026-01-01T00:00:00Z",
    }
]


class TestDeriveNames:
    def test_first_label_cleaned(self):
        assert derive_names("www.example.com") == ["www"]
        assert derive_names("example.com") == ["example"]

    def test_strips_non_platform_chars(self):
        assert derive_names("my-org.co.uk") == ["my-org"]

    def test_extra_names_appended_and_deduped(self):
        names = derive_names("example.com", extra=["Example", "ex!"])
        assert names == ["example"]

    def test_extra_valid_name(self):
        names = derive_names("example.com", extra=["examplehq"])
        assert names == ["example", "examplehq"]

    def test_junk_domain_yields_nothing(self):
        assert derive_names("!@$.com") == []
        assert derive_names("") == []


class TestPlatforms:
    def test_github_found_with_repos(self):
        routes = [
            ("api.github.com", "/users/example", (200, GITHUB_PROFILE)),
            ("api.github.com", "/users/example/repos", (200, GITHUB_REPOS)),
        ]
        result = _scanner(routes).scan(DOMAIN)
        gh = result["platforms"]["github:example"]
        assert gh["status"] == "ok"
        assert gh["found"] is True
        assert gh["public_repos"] == 12
        assert gh["recent_repos"][0]["name"] == "tool"
        assert result["summary"]["platforms_found"] == ["github:example"]

    def test_github_404_is_ok_not_found(self):
        routes = [("api.github.com", "/users/example", (404, {}))]
        result = _scanner(routes).scan(DOMAIN)
        gh = result["platforms"]["github:example"]
        assert gh["status"] == "ok" and gh["found"] is False

    def test_github_rate_limit_is_error(self):
        routes = [("api.github.com", "/users/example", (403, {}))]
        result = _scanner(routes).scan(DOMAIN)
        gh = result["platforms"]["github:example"]
        assert gh["status"] == "error"
        assert "rate limited" in gh["reason"]

    def test_gitlab_found_with_projects(self):
        routes = [
            ("gitlab.com", "/api/v4/users", (200, [{"id": 7, "name": "Example", "web_url": "https://gitlab.com/example", "created_at": "2016-01-01"}])),
            ("gitlab.com", "/api/v4/users/7/projects", (200, [{"name": "proj", "web_url": "https://gitlab.com/example/proj", "description": None, "star_count": 1, "last_activity_at": "2026-02-02"}])),
        ]
        result = _scanner(routes).scan(DOMAIN)
        gl = result["platforms"]["gitlab:example"]
        assert gl["found"] is True
        assert gl["recent_projects"][0]["name"] == "proj"

    def test_gitlab_user_list_empty_is_not_found(self):
        routes = [("gitlab.com", "/api/v4/users", (200, []))]
        result = _scanner(routes).scan(DOMAIN)
        assert result["platforms"]["gitlab:example"]["found"] is False

    def test_dockerhub_found_with_repos(self):
        routes = [
            ("hub.docker.com", "/v2/users/example/", (200, {"full_name": "Example", "company": "Example Corp", "date_joined": "2017-01-01"})),
            ("hub.docker.com", "/v2/repositories/example/", (200, {"count": 3, "results": [{"name": "app", "description": None, "pull_count": 100, "star_count": 2, "last_updated": "2026-03-03"}]})),
        ]
        result = _scanner(routes).scan(DOMAIN)
        dh = result["platforms"]["dockerhub:example"]
        assert dh["found"] is True
        assert dh["repo_count"] == 3
        assert dh["recent_repos"][0]["name"] == "app"

    def test_npm_scope_packages(self):
        routes = [
            (
                "registry.npmjs.org",
                "/-/v1/search",
                (200, {
                    "objects": [
                        {"package": {"name": "@example/lib", "description": "lib", "version": "1.0.0", "date": "2026-01-01", "links": {"npm": "https://npmjs.com/package/@example/lib"}}},
                        {"package": {"name": "@other/pkg", "description": None, "version": "0.0.1", "date": None, "links": {}}},
                    ]
                }),
            )
        ]
        result = _scanner(routes).scan(DOMAIN)
        npm = result["platforms"]["npm:example"]
        assert npm["found"] is True
        assert npm["packages"] == [
            {"name": "@example/lib", "description": "lib", "version": "1.0.0", "date": "2026-01-01", "links": "https://npmjs.com/package/@example/lib"}
        ]

    def test_pypi_profile_scraped(self):
        html = '<a href="/project/sample-pkg/">sample-pkg</a><a href="/project/other/">x</a>'
        routes = [("pypi.org", "/user/example/", (200, html))]
        result = _scanner(routes).scan(DOMAIN)
        pypi = result["platforms"]["pypi:example"]
        assert pypi["found"] is True
        assert pypi["packages"] == ["sample-pkg", "other"]

    def test_pypi_404_not_found(self):
        routes = [("pypi.org", "/user/example/", (404, ""))]
        result = _scanner(routes).scan(DOMAIN)
        assert result["platforms"]["pypi:example"]["found"] is False


class TestScan:
    def test_full_footprint_summary(self):
        routes = [
            ("api.github.com", "/users/example", (200, GITHUB_PROFILE)),
            ("api.github.com", "/users/example/repos", (200, GITHUB_REPOS)),
            ("gitlab.com", "/api/v4/users", (200, [])),
            ("hub.docker.com", "/v2/users/example/", (404, {})),
            ("registry.npmjs.org", "/-/v1/search", (200, {"objects": []})),
            ("pypi.org", "/user/example/", (404, "")),
        ]
        result = _scanner(routes).scan(DOMAIN)
        assert result["names_checked"] == ["example"]
        assert result["summary"]["platforms_found"] == ["github:example"]
        assert result["summary"]["total_packages"] == 1
        assert len(result["platforms"]) == 5

    def test_nothing_found_tries_second_candidate(self):
        routes = [
            # round 1: example -> nothing anywhere
            ("api.github.com", "/users/example", (404, {})),
            ("gitlab.com", "/api/v4/users", (200, [])),
            ("hub.docker.com", "/v2/users/example/", (404, {})),
            ("registry.npmjs.org", "/-/v1/search", (200, {"objects": []})),
            ("pypi.org", "/user/example/", (404, "")),
            # round 2: examplehq -> GitHub hit
            ("api.github.com", "/users/examplehq", (200, GITHUB_PROFILE)),
            ("api.github.com", "/users/examplehq/repos", (200, [])),
        ]
        scanner = _scanner(routes)
        result = scanner.scan(DOMAIN, names=["example", "examplehq"])
        assert result["names_checked"] == ["example", "examplehq"]
        assert "github:examplehq" in result["summary"]["platforms_found"]
        assert len(scanner.http.calls) > 5  # second round really ran

    def test_network_failure_degrades_per_platform(self):
        http = MagicMock()
        http.get.side_effect = OSError("network down")
        result = SocialFootprintScanner(http=http).scan(DOMAIN)
        statuses = {b["status"] for b in result["platforms"].values()}
        assert statuses == {"error"}
        assert result["summary"]["platforms_found"] == []

    def test_scope_denies_entry(self):
        class Scope:
            def allows(self, target):
                return False

            def discard(self, target, module=""):
                pass

        http = MagicMock()
        http.get.side_effect = AssertionError("must not be called")
        result = SocialFootprintScanner(http=http).scan(DOMAIN, scope=Scope())
        assert result["names_checked"] == []
        assert result["platforms"] == {}

    def test_weird_target_notes_error_but_runs(self):
        routes = [("api.github.com", "/users/ex", (404, {})), ("gitlab.com", "/api/v4/users", (200, [])),
                  ("hub.docker.com", "/v2/users/ex/", (404, {})), ("registry.npmjs.org", "/-/v1/search", (200, {"objects": []})),
                  ("pypi.org", "/user/ex/", (404, ""))]
        result = _scanner(routes).scan("weird target!!", names=["ex"])
        assert "target" in result["errors"]
        assert result["names_checked"] == ["ex"]
