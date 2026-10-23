# Module: CVE (`cve`)

Source file: `modules/cve/nvd.py`.

Runs at depth: **normal** and above.

## What it collects

- **CVE lookup** against the free NVD REST API 2.0, matched to the
  technologies the web module fingerprinted (product/version pairs) or to
  keywords supplied by the scan. Results carry identifiers, severity
  (CVSS) and references, and flow into the canonical findings layer so they
  surface in the risk score, SARIF and the dashboard.

## Rate limits and the optional API key

The NVD API **works without any key**, but without one you get ~5 requests per
rolling 30-second window, so the module enforces conservative pacing by
default:

- Optional key: pass `api_key` or set the `NVD_API_KEY` environment variable
  for much better throughput. Get a free key at
  https://nvd.nist.gov/developers/request-an-api-key
- Every request has a timeout and honours the rate limit; HTTP 403/429 triggers
  backoff + a single retry.
- On persistent failure the lookup degrades to an empty list with a `[!]`
  warning instead of raising — a scan never dies because NVD is having a bad
  day.

## Notes

- This is the only built-in module with an *optional* key, and it is purely a
  throughput knob: behaviour and result shape are identical with or without
  it.
- Enrichment (EPSS, CISA KEV) is on the idea bank; today the module sticks to
  NVD data.
