# Module: Google dorking (`google`)

Source file: `modules/osint/google.py`.

Runs at depth: **normal** and above (skipped by `--stealth`). No API key.

## What it collects

- **Google dorking**: operator-style queries (`site:`, `filetype:`, `intitle:`,
  directory listings, exposed documents, login pages…) executed against the
  public results page, with the target domain substituted into each dork.

## Honest limitations (by design)

Like the GitHub module, this one scrapes the **public results page** to stay
key-free, so it is inherently best-effort: Google may rate-limit (HTTP 429),
serve a consent/CAPTCHA page or change its markup at any time. Every search
degrades to an empty result with a `[!]` warning and backoff/retry;
`full_scan()` always returns the complete result shape so reports never break.

`--stealth` skips dorking entirely (and throttles everything else); the module
also honours the shared HTTP client's per-host rate limiting to stay polite.

## Result shape

Category-grouped hits (each with the query that produced it and the result
URLs), a total count, and per-category lists that stay present (possibly empty)
under every failure mode — downstream reporters can render without special
cases.
