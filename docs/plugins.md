# Writing plugins

OSINT EYE ships twelve built-in collectors, but the engine treats them exactly
like your own code: everything is a plugin behind the `PluginManager`
(`core/plugins.py`). This page is the complete contract plus a working,
offline-testable example.

## The contract: `BaseModule`

```python
from core.plugins import BaseModule

class MyModule(BaseModule):
    name = "my_module"          # registry key (used in --modules)
    description = "What it collects, one line"
    version = "1.0.0"
    author = "you"
    requires_api_key = False    # set True only if you truly need a key

    async def run(self, target: str, **kwargs) -> dict:
        ...
        return {"target": target, "findings": [...]}
```

Rules that matter:

1. **`run()` is `async`** and returns a plain dict — no bare lists, no console
   side effects beyond logs. Everything the engine needs must be in the dict.
2. **Return the full shape even on failure.** Built-ins degrade gracefully:
   a dead source yields an empty/partial result with an `error` key and a
   warning, never an exception into the scan loop. Reports and the dashboard
   render whatever you return.
3. **Register under a unique `name`.** Names must not collide with the
   built-ins (`dns`, `certs`, `wayback`, `web`, `network`, `whois`, `github`,
   `google`, `cloud`, `emails`, `cdn_waf`, `cve`).
4. **Stay in scope.** Anything you are about to touch must pass
   `core.scope.Scope.allows()`; rejected items should be recorded, not
   silently dropped. Built-ins get this for free through
   `modules/_scope.py`; reuse it.
5. **Fetch through the shared HTTP client** (`modules/_http.py`). It gives you
   timeouts, retries with backoff, per-host rate limiting, a consistent UA and
   proxy support — and it routes through `modules/web/ssrf_guard.py` so a
   hostile target cannot bounce your requests into internal address space.

## Loading your plugin

Drop the file in a directory and point `--plugin-dir` at it:

```bash
python osint_eye.py example.com --plugin-dir ./my_plugins --modules my_module
```

`PluginManager.load_from_directory()`:

- loads every `*.py` in the directory, **sorted**, skipping files that start
  with `_`;
- instantiates **every `BaseModule` subclass** it finds in a file (one file can
  ship several plugins);
- validates each instance on `register()` — a class without a usable `name` or
  a callable `run` is skipped with a `[!]` message instead of crashing the run;
- isolates each file under a unique temporary module name, so a broken plugin
  (syntax error, missing import) is reported and skipped **without aborting the
  remaining plugins**, and never leaks into `sys.modules`;
- broken *built-ins* follow the same philosophy: a collector whose runtime
  dependency is missing (e.g. the `nmap` binary) is replaced by an
  "unavailable built-in" stub so `has_plugin()` stays truthful.

`--modules my_module` runs only your plugin; `python osint_eye.py --modules`
without values prints the catalog of everything registered.

## The results contract

Your dict lands in `results["modules"][name]` and is validated by
`core/schema.py` (`SCHEMA_VERSION 2.0`). The contract is deliberately
permissive:

- **unknown module names never fail validation** — plugins must not break older
  consumers;
- per-module validation only checks keys it knows about, and only when present;
- everything must be JSON round-trip safe (it will be saved, reloaded by the
  dashboard and diffed).

Notable findings are projected onto the canonical layer in
`core/findings.py` — give each finding a stable identity (what, where, why) and
a severity, and it will flow into risk scoring, SARIF, exit codes and the
dashboard automatically.

## A complete example (offline-testable)

```python
"""Example plugin: reports whether the target declares a security.txt."""
from core.plugins import BaseModule
from modules._http import get_client          # shared client: timeouts, retries, rate limit, proxy
from modules.web.ssrf_guard import safe_get   # every fetch validated against SSRF


class SecurityTxtModule(BaseModule):
    name = "security_txt"
    description = "Checks /.well-known/security.txt (RFC 9116)"
    version = "1.0.0"
    author = "you"
    requires_api_key = False

    async def run(self, target: str, **kwargs) -> dict:
        result = {"target": target, "found": False, "url": None, "error": None}
        session = get_client()
        for scheme in ("https", "http"):
            url = f"{scheme}://{target}/.well-known/security.txt"
            try:
                resp = safe_get(session, url, timeout=10)
                if resp.status_code == 200 and "Contact:" in resp.text:
                    result.update(found=True, url=url)
                    return result
            except Exception as exc:            # degrade, never raise
                result["error"] = str(exc)
        return result
```

Test it 100 % offline the way the built-ins are tested: point it at a local
HTTP server fixture (see `tests/e2e/test_e2e_smoke.py` and
`tests/conftest.py` for the loopback pattern), never at a real third party.
The project's test policy is **no network in CI, ever**.

## Checklist before you ship

- [ ] Unique `name`, one-line `description`, honest `requires_api_key`
- [ ] `run()` returns the full shape on every failure path
- [ ] Scope-aware, fetches through `modules/_http.py`
- [ ] Offline tests added under `tests/`
- [ ] One line under `[Unreleased]` in `CHANGELOG.md` in the same commit
