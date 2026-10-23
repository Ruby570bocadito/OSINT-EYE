# Security Policy

## Reporting a vulnerability

Use **GitHub's private vulnerability reporting**: open the repository's **Security** tab → *Report a vulnerability*. This keeps the report private between you and the maintainers.

Please **do not** open a public issue, discussion or pull request for a security problem.

When reporting, include:

- The version or commit you tested (e.g. output of `pip show osint-eye` or the commit hash)
- A minimal reproduction that runs against `example.com` or `localhost` — no third-party targets
- The affected component (CLI, dashboard, exporter, module) and the impact you believe it has
- Any log/output snippet that shows the problem, with domains/IPs of real targets redacted

## What is in scope

- The CLI (`osint_eye.py`) and everything under `core/`, `modules/`, `reporting/`, `graph/`, `ui/`, `ai/`
- The local dashboard (`ui/dashboard.py`): request handling, path sanitization, upload limits, SSRF guards
- The plugin loading mechanism (`core/plugins.py`) when loading third-party plugins
- Export formats where injection matters (CSV/HTML/PDF/SARIF formula or script injection)

## What is out of scope

- Scanning third-party systems: the tool is for **authorized targets only**; reports describing attacks against systems you do not own will not be processed
- Vulnerabilities in unpatched third-party dependencies that have a public fix — file those upstream and let us know
- Missing hardening for usage explicitly documented as out of the threat model (e.g. serving the dashboard beyond `127.0.0.1`)

## Response targets

- **Triage:** within 7 days of the report
- **Fix:** severity-based; critical issues get a patch release as soon as a fix is ready
- **Credit:** reporters are credited in the release notes by default; say so in the report if you prefer to stay anonymous

## Safe development practice

If you are contributing a fix, keep regression tests offline (fixtures/monkeypatch) and validate against `example.com` or `localhost` only, as described in [CONTRIBUTING.md](CONTRIBUTING.md).
