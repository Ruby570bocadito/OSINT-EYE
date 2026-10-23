# Module: Certificates (`certs`)

Source files: `modules/certs/cert_scanner.py`, `modules/certs/tls_audit.py`.

Runs at depth: **quick** and above. No API key required.

## What it collects

- **Certificate Transparency subdomains** via the free crt.sh JSON API: every
  certificate ever issued for the domain (and its wildcard forms) is a source
  of real subdomain names — often the fastest way to find hosts no wordlist
  will guess. Parsed certificates carry at least a `domain` key.
- **TLS audit** (`tls_audit.py`): supported protocol versions (flagging SSLv3
  and TLS 1.0/1.1), weak cipher suites, and the certificate itself — validity
  window, issuer, SANs and chain problems.

## Honest limitations

crt.sh is a free community service and is often slow or rate-limited. Every
query degrades gracefully to an empty/partial result with a `[!]` warning
instead of raising; a slow crt.sh day never breaks a scan.

## Result keys

`CertScanner().scan(target)` returns a dict with `subdomains` (list) among
other keys. `TLSAnalyzer().analyze(host)` (used by the web/recon pipeline)
returns `host`, `protocols`, `certificate`.

## Notes

- The TLS audit connects to the hosts the scan already knows about — it does
  not invent new targets, and it respects scope checks.
- For heavily scanned domains, crt.sh may take minutes to respond on first
  query; the module paces itself and falls back to partial data.
