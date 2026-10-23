# Module: WHOIS (`whois`)

Source file: `modules/osint/whois.py`.

Runs at depth: **quick** and above. No API key required.

## What it collects

- **Domain registration data**: registrar, creation/expiry dates, name servers,
  registrant organisation and contact fields where the registry exposes them,
  and status codes (client/server hold, transfer lock, etc.).

## Why it matters

Registration data answers a different question than the rest of the modules:
*who holds this domain and since when?* Creation dates help separate an
organisation's main estate from recently registered look-alikes; registrar and
status data feed takedown and abuse workflows; name servers hint at hosting
infrastructure shared across domains.

## Degradation

WHOIS is a best-effort protocol: some registries rate-limit, some hide most
fields behind GDPR redaction, and some require a different query path. Failures
and redactions degrade to a partial result with a warning — the module never
raises into the scan loop, and the report always renders.

## Notes

- The lookup happens once per domain target (IP targets are handled by the
  network module's RDAP pass instead).
- Like every collector, it runs through the engine's scope checks before
  touching anything.
