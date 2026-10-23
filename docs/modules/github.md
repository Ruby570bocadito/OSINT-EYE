# Module: GitHub dorking (`github`)

Source file: `modules/osint/github.py`.

Runs at depth: **normal** and above (skipped by `--stealth`). No API key.

## What it collects

- **Code-search dorking** against GitHub: targeted queries for leaked secrets,
  configuration files, internal hostnames and credentials that reference the
  target domain — the classic dork families (`"example.com" password`,
  `"api.example.com" Authorization`, filename filters, and so on), grouped into
  categories in the result.

## Honest limitations (by design)

This module scrapes the **public search UI** (`github.com/search`) on purpose:
the tool stays key-free. That makes it inherently best-effort — GitHub can
rate-limit (HTTP 429), require a login for code search, or change its markup at
any time. In all those cases every search degrades to an empty result with a
`[!]` warning, and `scan()` always returns the full result shape
(`total_findings`, category lists, …) so reports never break.

For reliable, higher-volume code search, GitHub's official REST API with a
token is the better path — deliberately **not** implemented here to keep the
tool key-free end to end.

## Ethics and scope

Dorking searches *public* code for references to your target. Findings are
leads, not verified leaks: every hit is recon material for the operator to
review. Do not use the module to harvest third-party secrets; scope it to
domains you are authorized to assess.
