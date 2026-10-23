# Module: Network (`network`)

Source files: `modules/network/scanner.py` (Nmap), `modules/network/asn.py`.

Runs at depth: **normal** and above.

## What it collects

- **Port and service scanning** via Nmap with service/version detection:
  open ports, service names, product/version banners. The external `nmap`
  binary is used when present; install it (https://nmap.org) to enable this
  module.
- **ASN / netblock expansion** (`asn.py`): from the target's resolved IP to the
  organisation's announced infrastructure, using public key-free sources only —
  RIPEstat (origin ASN, holder organisation, every announced prefix of the ASN)
  and RDAP (registration object: name, country, start/end address, type). This
  is how one target domain expands into the rest of the organisation's
  attack surface.

## Resilience contract

Constructing `NetworkScanner` **never raises**, even when the `nmap` Python
package or the `nmap` binary is missing. Availability is checked lazily on
first use (`PortScanner.is_available`), and when unavailable every scan returns
a graceful-degradation dict:

```json
{"host": "target", "status": "unavailable", "services": [],
 "error": "nmap binary not found in PATH - install nmap (https://nmap.org)"}
```

so callers (CLI, reporters, dashboard) always get the keys they expect. The
plugin registry keeps the module listed (as an "unavailable built-in" stub)
instead of aborting the whole load.

## Notes

- Port scanning is **active** reconnaissance — make sure the target is in scope
  and you are authorized before running this module against anything that is
  not yours.
- ASN/RDAP lookups are pure registry queries (passive, no packets to the
  target) and work even without nmap installed.
