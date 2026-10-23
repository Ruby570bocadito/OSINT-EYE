# Module: CDN / WAF (`cdn_waf`)

Source file: `modules/osint/cloud_email.py` (`CDNDetector`).

Runs at depth: **normal** and above. No API key.

## What it collects

- **CDN detection**: which hosts are fronted by a CDN (header signatures,
  CNAME patterns and IP ownership against well-known provider ranges).
- **WAF fingerprinting**: evidence of a Web Application Firewall in front of a
  host (signature headers, behavioural cookies), with the provider when
  identifiable.

## Why it matters for the rest of the scan

The CDN/WAF verdict is consumed downstream:

- **Risk scoring**: a WAF in front of a host changes what its exposed findings
  are worth (exploitability drops, surface shifts to the origin).
- **Attack planning**: knowing which hosts are proxied tells you where active
  testing will be noisy and where you may be talking to an edge node instead
  of the application.
- **Asset pivoting**: shared CDN IPs mean the IP alone is not attribution —
  the module marks hosts so the graph does not over-connect unrelated assets.

## Result shape and degradation

Per-host verdicts (`cdn`, `waf`, provider, evidence) in the module result;
each check degrades independently and the full shape is always returned. The
canonical findings layer picks up notable findings (e.g. a WAF that blocks
*you* but not the internet is itself an interesting signal).
