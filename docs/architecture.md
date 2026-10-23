# Architecture

This page explains how OSINT EYE is put together: the layers, the data flow
through a scan, the results contract and the safety guards. It is written for
contributors and operators who want to understand what happens between
`python osint_eye.py example.com` and the final report.

## The pipeline in one picture

```
CLI / wizard (--rich, --tui, --dashboard)
        │  targets + depth + scope + config
        ▼
Engine (osint_eye.py)          core/: config, scope, session_cache, logging
        │  phase 1-3: collectors in bounded pools
        ▼
Modules (modules/*)  ──►  raw per-module dicts
        │  merge + validate
        ▼
core/schema.py (SCHEMA_VERSION 2.0, validate_results)
        │  phase 4: sequential analysis
        ▼
correlator → graph/builder → mitre_mapper → chains → ai/llm_engine (optional)
        │
        ▼
core/findings.py (canonical Finding records)
        │
        ▼
reporting/ (json, md, html, pdf, csv, sarif, burp, msf, cypher)  +  ui/ views
```

## Repository layout

| Path | Role |
|---|---|
| `osint_eye.py` | CLI entry point: argument parsing, orchestration of scan phases, exit codes. |
| `core/` | Engine internals: `schema.py` (results contract), `findings.py` (canonical findings), `scope.py` (authorization), `session_cache.py` (SQLite cache), `config.py` (TOML), `correlator.py`, `monitor.py`, `async_engine.py`, `plugins.py`, `errors.py`, `logging_config.py`. |
| `modules/` | The twelve built-in collectors plus shared infrastructure: `_http.py` (single HTTP client with timeouts, retries/backoff, per-host rate limit, UA and proxy) and `_scope.py` (scope checks for derived URLs). |
| `graph/` | `builder.py` builds a NetworkX attack-surface graph; `neo4j_exporter.py` emits a Neo4j-compatible `.cypher` dump (`--export-cypher`). |
| `reporting/` | Export layer: `export.py`/`export_tools.py` (JSON/MD/HTML/CSV/Burp/MSF), `markdown_reporter.py`, `pdf_reporter.py`, `sarif.py` (SARIF 2.1), `mitre_mapper.py`. |
| `ui/` | Presentation: `rich_cli.py` (terminal), `wizard.py` (interactive setup), `dashboard.py` + `dashboard_template.html` (Flask, localhost only), `tui_app.py` (Textual). |
| `ai/` | `llm_engine.py`: optional LLM features, talking **only** to a local Ollama server (localhost:11434). No keys, no remote endpoints, no telemetry. |
| `tests/` | The offline test suite (hundreds of tests, 100 % offline by policy). |

## Scan phases and concurrency

The engine splits work into phases so that cheap, passive reconnaissance runs
first and expensive active probing only happens if you asked for it:

1. **Phase 1 (passive)** — `dns`, `certs`, `wayback`, `whois`.
2. **Phase 2 (light active)** — `web`, `network`, `cdn_waf`, dorking
   (`github`, `google`), `cve`.
3. **Phase 3 (expansive)** — subdomain permutations, takeover checks, endpoint
   discovery, `cloud`, `emails`.
4. **Phase 4 (analysis, sequential)** — correlation, graph building, MITRE
   mapping, attack chains, optional AI summary. Sequential because every step
   consumes the previous step's output.

Phases 1–3 run their collectors concurrently in bounded thread pools (the pool
sizes scale with the number of targets, never unbounded). `--stealth` skips the
aggressive dorking modules and throttles requests; `--depth quick` stops after
phase 1's essentials plus analysis.

## The results contract

Every module returns a plain dict. Before analysis, the engine projects the
merged results through `core/schema.py`, the single source of truth for the
`results` shape (`SCHEMA_VERSION = "2.0"`, embedded in every scan):

- **Permissive by design**: unknown top-level keys and unknown module names
  never fail validation — plugins and future collectors must not break older
  consumers (dashboard, diff, reporters).
- **Graceful**: per-module validation only checks keys it knows about, and only
  when present, because modules degrade gracefully and may return partial data
  or an `error` status.
- **JSON round-trip safe**: a scan saved to disk and reloaded validates the
  same way.

On top of the raw module data, `core/findings.py` builds the canonical findings
layer: every result shape (takeovers, public buckets, GitHub leaks, CVEs,
sensitive files, login panels…) becomes a `Finding` with a normalized severity,
a stable fingerprint and the evidence that produced it. SARIF export, CI exit
codes, risk scoring and the dashboard all derive their views from this layer —
a fix in one module shape automatically propagates everywhere.

## Safety and authorization model

OSINT EYE is built for authorized testing, and the code enforces what it can:

- **Scope control** (`core/scope.py`): `--scope FILE` accepts one domain,
  wildcard domain, IP or CIDR per line; `--exclude` (repeatable) always wins.
  Anything a module is about to touch must pass `Scope.allows()`, and rejected
  targets are recorded as auditable discards in `results["scope"]` — nothing is
  silently dropped. Collectors re-check URLs they derive, not just the roots.
- **Wizard authorization check**: the interactive wizard states what passive
  and active reconnaissance means and requires an explicit `[y/n]` confirmation
  before continuing.
- **SSRF guard** (`modules/web/ssrf_guard.py`): redirects are validated hop by
  hop (scheme + resolved addresses); a target pointing at loopback, RFC1918 or
  cloud metadata space gets a `SSRFBlockedError` (a `requests.RequestException`
  subclass), so the scan continues instead of leaking internal responses into
  reports.
- **Output confinement**: user-supplied output paths (`-o`, `--export-cypher`,
  `--log-file`) must resolve inside the current working directory; escaping
  paths are refused with a usage error before anything is written.
- **Webhook guard**: `--webhook` requires HTTPS and a public host, reusing the
  SSRF logic — a typo can never push scan data to an internal service.
- **Dashboard hardening**: the Flask dashboard binds to `127.0.0.1` by default,
  ships a CSP, `X-Content-Type-Options: nosniff` and a 64 MB upload limit, and
  neutralizes formula injection in CSV exports.

## Caching and configuration

`core/session_cache.py` keeps a SQLite cache (`~/.osint_eye/cache`) so repeated
runs skip what has not changed; a corrupted cache file is quarantined (never
destroyed) and rebuilt empty. `--no-cache` disables it. `core/config.py` reads
an `osint_eye.toml` (`--config`), including named `[profiles.<name>]` sections
selectable with `--profile`. Core/graph/reporting logging is routed through
`core/logging_config.py` (`--log-level`, `--log-file`).

## Design principles

1. **Offline-first tests.** The test suite never touches the network: loopback
   servers and fixtures only. Anything that cannot be tested offline needs a
   fake, not a real target.
2. **Graceful degradation.** A module that cannot reach its source returns an
   empty/partial result with a warning instead of raising; reports always get
   the full result shape.
3. **Stdlib preference.** New dependencies need a strong reason; several
   algorithms (MurmurHash3 for favicon pivoting, for example) are implemented
   in pure Python to stay dependency-free.
4. **No keys required.** Every built-in collector works without an API key.
   Optional keys (NVD) only improve throughput.
5. **Single HTTP client.** Collectors fetch through `modules/_http.py` so
   timeouts, retries, rate limiting, UA and proxy behave consistently.
