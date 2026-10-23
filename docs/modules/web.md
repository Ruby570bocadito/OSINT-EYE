# Module: Web (`web`)

Source files: `modules/web/web_scanner.py` (orchestrator), `modules/web/headers_audit.py`,
`modules/web/js_secrets.py`, `modules/web/favicon_hash.py`, `modules/web/ssrf_guard.py`.

Runs at depth: **quick** and above (endpoint discovery and the extra audits
intensify at deeper depths).

## What it collects

- **Live host probing**: which known hosts serve HTTP(S), redirects and the
  technologies they expose (fingerprinted locally, no third-party lookup
  service).
- **Security headers audit** (`headers_audit.py`): missing/broken CSP, HSTS,
  X-Frame-Options, X-Content-Type-Options, Referrer-Policy and
  Permissions-Policy, plus **CORS analysis** (wildcard origins and
  credential-revealing combinations) and **per-cookie flag audit**
  (`Secure`, `HttpOnly`, `SameSite`). Every finding carries a severity and
  everything folds into one explicable `score` with a letter `grade`.
- **JS secrets** (`js_secrets.py`): regexes + Shannon entropy over JavaScript
  files, with a false-positive verification pass that rejects placeholder
  values (`YOUR_API_KEY`, `${...}`, `process.env.*`), docs examples,
  comment-only lines and low-diversity strings. Findings carry type,
  confidence and line number — recon material, not verified provider matches.
- **Favicon hashing** (`favicon_hash.py`): the MurmurHash3 x86_32 of the
  target's favicon (pure-Python implementation, stdlib-only) so you can pivot
  on asset-search engines to hosts serving the same icon.
- **Endpoint discovery** at deep depths: paths from Wayback, robots/sitemap
  and wordlists, checked against live hosts.

## Built-in safety

Every HTTP fetch goes through `ssrf_guard.safe_get`: **redirect hops are
validated one by one** (scheme + resolved addresses), and anything pointing at
loopback, RFC1918 or cloud metadata space raises `SSRFBlockedError` — a
`requests.RequestException` subclass — so per-collector error handling keeps
working and the scan continues. A hostile target cannot turn its own redirects
into a probe of your internal network or of `169.254.169.254`.

## Degradation

A dead base URL, a 4xx JS file or a hostile response degrade to error entries
in the result dict instead of raising; the module always returns the full
result shape.
