# Module: Emails (`emails`)

Source file: `modules/osint/cloud_email.py` (`EmailEnumerator`).

Runs at depth: **deep** and above. No API key.

## What it collects

- **Email addresses** referencing the target domain, harvested from public
  surfaces reachable without a key: indexed pages and documents, the wayback
  URL corpus and pattern-derived candidates (common corporate
  `first.last@` shapes built from discovered names).
- The result feeds the **email security audit** on the DNS side
  (`modules/dns/email_security.py`): knowing a domain sends mail, the audit
  checks whether it protects what it sends (SPF/DMARC/DKIM/MTA-STS) — the two
  together answer "can someone impersonate this organisation's mail?".

## Privacy and ethics

Enumerated addresses are **metadata about exposure**, not a mailing list: the
tool is for assessing how much information an organisation leaks about its
people. Do not use it to build contact lists, and never combine it with
credential attacks — that is outside the tool's purpose and outside its
license of trust.

## Degradation

Each source is best-effort and fails to empty; the module always returns the
full result shape so reports and the correlator keep working when a source is
unavailable.
