# Module: Wayback (`wayback`)

Source file: `modules/web/wayback.py`.

Runs at depth: **quick** and above. No API key required.

## What it collects

- **Historical URLs** for the target from the Wayback Machine (web.archive.org
  CDX API): every URL that has ever been archived is a lead — old admin panels,
  retired endpoints, backup files, forgotten staging hosts.
- The URL list feeds downstream endpoint discovery: paths extracted from
  Wayback are checked by the web module's endpoint stage at deep depths.

## Why it matters

Active scanning shows what a host serves *today*; the Wayback Machine shows
what it served *at any point in the past*. For attack-surface work the
difference is often where the interesting findings live: deprecated APIs and
directories that still resolve but no longer appear in the site's navigation.

## Degradation

Queries are best-effort: a timeout, a rate limit or a hostile response degrades
to an empty URL list with a warning — the rest of the scan continues
unaffected. Like every collector, requests go through the shared HTTP client
(`modules/_http.py`) with timeouts, retries and per-host rate limiting, and the
SSRF guard validates every redirect hop before following it.
