# Module: DNS (`dns`)

Source files: `modules/dns/dns_scanner.py` (orchestrator), `modules/dns/wildcard.py`,
`modules/dns/passive_sources.py`, `modules/dns/subdomain_permutator.py`,
`modules/dns/advanced_dns.py`, `modules/dns/email_security.py`.

Runs at depth: **quick** and above (permutations, takeover and the email-security
audit come with the deeper phases).

## What it collects

- **DNS records** for the target: A/AAAA, MX, NS, TXT, CNAME, SOA and more,
  plus explicit **SPF** and **DMARC** policy parsing (both always present in the
  result, even on partial failures).
- **Subdomain enumeration** via bruteforce with the bundled wordlists
  (`data/wordlists`) at deep depths.
- **Passive sources** in `full` mode, merged and deduplicated:
  HackerTarget, AlienVault OTX, Anubis, RapidDNS and CertSpotter — all
  key-free. Per-source detail is exposed under `passive_subdomains`, and each
  source degrades independently if it is down or rate-limited.
- **Wildcard detection before enumeration**: a handful of random labels that
  cannot legitimately exist are resolved; if they answer, the zone has a
  wildcard and the discovered IP set becomes the fingerprint used to discard
  candidates that only "resolve" through it. Without this step, bruteforce
  against a wildcarded zone would report thousands of false positives.
- **Zone-transfer (AXFR) checks** against the target's name servers.
- **Permutations and takeover**: variant generation (prefix/suffix combos and
  variants of discovered hosts), resolution, and subdomain-takeover detection
  via provider-specific error signatures.
- **Advanced DNS**: DNSSEC status, reverse DNS and virtual-host probing.
- **Email security / anti-spoofing audit** (`modules/dns/email_security.py`),
  DNS-only and key-free: DKIM via common selector names, MTA-STS, TLS-RPT,
  BIMI, MX presence and an explicable spoofing score (0–100) with per-component
  deductions (`score_breakdown`) and human-readable recommendations.

## Result keys

`scan(target, "basic"|"full")` returns a dict with at least: `domain`,
`subdomains` (list), `records` (per record type), `spf`, `dmarc`; in full mode
also `passive_subdomains` and `wildcard`.

## Degradation

Every network step is best-effort: failures are captured in the result dict
(`error` key) instead of propagating. SPF/DMARC are always present; passive
sources that fail simply contribute nothing.
