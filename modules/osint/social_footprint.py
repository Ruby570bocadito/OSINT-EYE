"""OSINT EYE - Organisation footprint on public development platforms.

Checks whether the organisation behind the target holds accounts or
publishes packages on the big developer platforms, using only their
public, key-free APIs:

* GitHub   — REST ``/users/{name}`` (+ pinned public repos, best-effort)
* GitLab   — ``/api/v4/users?username={name}`` (+ public projects)
* Docker Hub — v2 ``/users/{name}/`` and ``/repositories/{name}/``
* npm      — registry search for ``@scope`` packages
* PyPI     — public maintainer profile page (``/user/{name}/``)

Candidate account names are derived from the target domain (first
label, alphanumeric-only) plus whatever the operator passes explicitly.
Username shapes that platforms reject are skipped per-platform; every
platform degrades independently (404 → not found, 403/rate limit or
network failure → ``status: "error"`` with a short reason, never an
exception to the caller).

The platform APIs are third-party lookup services queried *about* the
target identity; no derived host is contacted, so the scope model is
the entry guard only (module label "social_footprint").

Contract consumed by osint_eye.py:
    SocialFootprintScanner().scan(target) -> dict with keys
    "target", "names_checked", "platforms", "summary", "errors".
"""

import re
from typing import Dict, List, Optional

from modules._http import HTTPClient, get_client
from modules._scope import allowed as _scope_allowed

GITHUB_API = "https://api.github.com/users/{name}"
GITHUB_REPOS = "https://api.github.com/users/{name}/repos"
GITLAB_API = "https://gitlab.com/api/v4/users"
GITLAB_PROJECTS = "https://gitlab.com/api/v4/users/{id}/projects"
DOCKERHUB_USER = "https://hub.docker.com/v2/users/{name}/"
DOCKERHUB_REPOS = "https://hub.docker.com/v2/repositories/{name}/"
NPM_SEARCH = "https://registry.npmjs.org/-/v1/search"
PYPI_USER = "https://pypi.org/user/{name}/"

NAME_MAX = 39  # GitHub username hard limit; others are similar
MAX_REPOS = 10
MAX_PACKAGES = 10

_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-_.]*[A-Za-z0-9])?$")
_PROJECT_LINK_RE = re.compile(r'href="/project/([A-Za-z0-9._-]+)/"')


def derive_names(domain: str, extra: Optional[List[str]] = None) -> List[str]:
    """Account-name candidates for a target domain (order preserved).

    First label of the domain, stripped to alphanumerics/dashes; a
    candidate must survive the generic platform username shape.
    """
    names: List[str] = []
    base = (domain or "").strip().lower()
    base = base.split("://")[-1].split("/")[0]
    first_label = base.split(".")[0] if base else ""
    cleaned = re.sub(r"[^a-z0-9-]", "", first_label)
    for candidate in [cleaned] + [str(e).strip() for e in (extra or [])]:
        cand = candidate.lower().lstrip("-_.")
        if cand and len(cand) <= NAME_MAX and _NAME_RE.match(cand) and cand not in names:
            names.append(cand)
    return names[:3]


class SocialFootprintScanner:
    """Detect organisation accounts on public dev platforms (no keys)."""

    def __init__(self, timeout: int = 10, http: Optional[HTTPClient] = None):
        self.timeout = timeout
        self.http = http or get_client()

    # ── low-level helpers ────────────────────────────────────────────────
    def _get(self, url: str, **kwargs):
        """GET returning (response, None) or (None, short_reason)."""
        try:
            resp = self.http.get(url, timeout=self.timeout, **kwargs)
            return resp, None
        except Exception as exc:
            return None, str(exc)[:120] or exc.__class__.__name__

    @staticmethod
    def _json(resp):
        try:
            return resp.json() or {}
        except Exception:
            return {}

    # ── platforms (each: {"status", "found", ...} + platform data) ──────
    def _github(self, name: str) -> Dict[str, object]:
        resp, err = self._get(GITHUB_API.format(name=name))
        if err:
            return {"status": "error", "reason": err}
        if resp.status_code == 404:
            return {"status": "ok", "found": False}
        if resp.status_code != 200:
            reason = "rate limited" if resp.status_code in (403, 429) else f"HTTP {resp.status_code}"
            return {"status": "error", "reason": reason}
        data = self._json(resp)
        profile = {
            "status": "ok",
            "found": True,
            "profile_url": data.get("html_url"),
            "name": data.get("name"),
            "company": data.get("company"),
            "blog": data.get("blog"),
            "public_repos": data.get("public_repos"),
            "followers": data.get("followers"),
            "created_at": data.get("created_at"),
        }
        resp, err = self._get(
            GITHUB_REPOS.format(name=name), params={"sort": "updated", "per_page": MAX_REPOS}
        )
        repos = []
        if not err and resp.status_code == 200:
            rows = self._json(resp)
            if not isinstance(rows, list):
                rows = []
            for repo in rows[:MAX_REPOS]:
                if isinstance(repo, dict):
                    repos.append(
                        {
                            "name": repo.get("name"),
                            "url": repo.get("html_url"),
                            "description": repo.get("description"),
                            "language": repo.get("language"),
                            "stars": repo.get("stargazers_count"),
                            "updated_at": repo.get("updated_at"),
                        }
                    )
        profile["recent_repos"] = repos
        return profile

    def _gitlab(self, name: str) -> Dict[str, object]:
        resp, err = self._get(GITLAB_API, params={"username": name})
        if err:
            return {"status": "error", "reason": err}
        if resp.status_code != 200:
            return {"status": "error", "reason": f"HTTP {resp.status_code}"}
        users = self._json(resp)
        if not isinstance(users, list) or not users:
            return {"status": "ok", "found": False}
        user = users[0] if isinstance(users[0], dict) else {}
        profile = {
            "status": "ok",
            "found": True,
            "profile_url": user.get("web_url"),
            "name": user.get("name"),
            "created_at": user.get("created_at"),
        }
        resp, err = self._get(
            GITLAB_PROJECTS.format(id=user.get("id")), params={"per_page": MAX_REPOS}
        )
        projects = []
        if not err and resp.status_code == 200:
            rows = self._json(resp)
            if not isinstance(rows, list):
                rows = []
            for proj in rows[:MAX_REPOS]:
                if isinstance(proj, dict):
                    projects.append(
                        {
                            "name": proj.get("name"),
                            "url": proj.get("web_url"),
                            "description": proj.get("description"),
                            "stars": proj.get("star_count"),
                            "updated_at": proj.get("last_activity_at"),
                        }
                    )
        profile["recent_projects"] = projects
        return profile

    def _dockerhub(self, name: str) -> Dict[str, object]:
        resp, err = self._get(DOCKERHUB_USER.format(name=name))
        if err:
            return {"status": "error", "reason": err}
        if resp.status_code == 404:
            return {"status": "ok", "found": False}
        if resp.status_code != 200:
            return {"status": "error", "reason": f"HTTP {resp.status_code}"}
        data = self._json(resp)
        profile = {
            "status": "ok",
            "found": True,
            "profile_url": f"https://hub.docker.com/u/{name}",
            "full_name": data.get("full_name"),
            "company": data.get("company"),
            "date_joined": data.get("date_joined"),
        }
        resp, err = self._get(DOCKERHUB_REPOS.format(name=name), params={"page_size": MAX_REPOS})
        repos, count = [], None
        if not err and resp.status_code == 200:
            data = self._json(resp)
            if not isinstance(data, dict):
                data = {}
            count = data.get("count")
            for repo in (data.get("results") or [])[:MAX_REPOS]:
                if isinstance(repo, dict):
                    repos.append(
                        {
                            "name": repo.get("name"),
                            "description": repo.get("description"),
                            "pulls": repo.get("pull_count"),
                            "stars": repo.get("star_count"),
                            "updated_at": repo.get("last_updated"),
                        }
                    )
        profile["repo_count"] = count
        profile["recent_repos"] = repos
        return profile

    def _npm(self, name: str) -> Dict[str, object]:
        resp, err = self._get(
            NPM_SEARCH, params={"text": f"scope:{name}", "size": MAX_PACKAGES}
        )
        if err:
            return {"status": "error", "reason": err}
        if resp.status_code != 200:
            return {"status": "error", "reason": f"HTTP {resp.status_code}"}
        data = self._json(resp)
        objects = data.get("objects") if isinstance(data, dict) else None
        objects = objects or []
        packages = []
        for obj in objects[:MAX_PACKAGES]:
            pkg = (obj.get("package") or {}) if isinstance(obj, dict) else {}
            if pkg.get("name", "").startswith(f"@{name}/"):
                packages.append(
                    {
                        "name": pkg.get("name"),
                        "description": pkg.get("description"),
                        "version": pkg.get("version"),
                        "date": pkg.get("date"),
                        "links": pkg.get("links", {}).get("npm")
                        if isinstance(pkg.get("links"), dict)
                        else None,
                    }
                )
        return {"status": "ok", "found": bool(packages), "packages": packages}

    def _pypi(self, name: str) -> Dict[str, object]:
        resp, err = self._get(PYPI_USER.format(name=name))
        if err:
            return {"status": "error", "reason": err}
        if resp.status_code == 404:
            return {"status": "ok", "found": False}
        if resp.status_code != 200:
            return {"status": "error", "reason": f"HTTP {resp.status_code}"}
        html = getattr(resp, "text", "") or ""
        packages = list(dict.fromkeys(_PROJECT_LINK_RE.findall(html)))[:MAX_PACKAGES]
        return {
            "status": "ok",
            "found": bool(packages),
            "profile_url": PYPI_USER.format(name=name),
            "packages": packages,
        }

    # ── orchestration ────────────────────────────────────────────────────
    def scan(
        self, target: str, names: Optional[List[str]] = None, scope=None
    ) -> Dict[str, object]:
        """Footprint ``target`` across the platforms (entry-guarded).

        ``scope`` is optional (``core.scope.Scope``): the target must be
        in scope (entry guard, label "social_footprint"). The first
        candidate name is probed on every platform; if it yields no
        account at all, the next candidate gets a round too.
        """
        target = (target or "").strip()
        empty = {
            "target": target,
            "names_checked": [],
            "platforms": {},
            "summary": {"platforms_found": [], "total_packages": 0},
            "errors": {},
        }

        if scope is not None and not _scope_allowed(scope, target, "social_footprint"):
            print(f"[!] {target} out of scope: skipping social footprint")
            return empty

        errors: Dict[str, str] = {}
        if target and re.match(r"^[A-Za-z0-9.-]+$", target) is None:
            # Not a domain/IP-shaped target: nothing sensible to derive,
            # only explicitly provided names are probed.
            errors["target"] = "target is not domain-shaped; pass names explicitly"
            names_checked = derive_names("", names)
        else:
            names_checked = derive_names(target, names)
        platforms: Dict[str, Dict[str, object]] = {}
        summary: Dict[str, object] = {"platforms_found": [], "total_packages": 0}

        checks = {
            "github": self._github,
            "gitlab": self._gitlab,
            "dockerhub": self._dockerhub,
            "npm": self._npm,
            "pypi": self._pypi,
        }
        found_any = False
        for name in names_checked:
            for platform, fn in checks.items():
                key = f"{platform}:{name}"
                try:
                    block = fn(name)
                except Exception as exc:  # last-resort guard per platform
                    block = {"status": "error", "reason": str(exc)[:120]}
                platforms[key] = block
                if block.get("found"):
                    summary["platforms_found"].append(key)
                    summary["total_packages"] += len(block.get("recent_repos", []))
                    summary["total_packages"] += len(block.get("recent_projects", []))
                    summary["total_packages"] += len(block.get("packages", []))
                    found_any = True
            if found_any:
                break  # primary identity identified; no extra rounds

        return {
            "target": target,
            "names_checked": names_checked,
            "platforms": platforms,
            "summary": summary,
            "errors": errors,
        }


__all__ = ["SocialFootprintScanner", "derive_names"]
