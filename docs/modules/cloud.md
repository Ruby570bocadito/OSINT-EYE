# Module: Cloud buckets (`cloud`)

Source file: `modules/osint/cloud_email.py` (`CloudBucketDetector`).

Runs at depth: **deep** and above. No API key.

## What it collects

- **Public cloud storage buckets** named after the target: candidate bucket
  names are derived from the organisation/domain name (permutations included)
  across the common providers, and each candidate is **verified** — a bucket
  only counts as a finding if it actually exists and is publicly listable, not
  merely because a DNS name resolves.

## Why it matters

Misconfigured object storage is one of the most common real-world exposure
paths: backups, database dumps and internal documents end up in buckets that
inherit the company name. Verified public listing turns "someone might have
created this bucket" into "this bucket is open right now".

## Degradation and result shape

Each provider check is independent and best-effort: network failures,
auth quirks or a provider being down degrade that provider to "no findings +
warning" without touching the rest. The result keeps the full shape for
reporters; verified buckets carry the evidence (URL, listing status) that
produced the finding, so the canonical findings layer
(`core/findings.py`) can fingerprint and score them.

## Notes

- Only **existence and listing** are checked — the module never downloads or
  dumps bucket contents.
- Candidates are scope-checked before any request leaves the machine.
