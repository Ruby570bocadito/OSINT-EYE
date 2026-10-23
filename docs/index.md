# OSINT EYE documentation

Welcome to the OSINT EYE documentation hub. OSINT EYE is a modular OSINT and
attack-surface reconnaissance platform: it collects from public sources (DNS,
certificate transparency, Wayback Machine, WHOIS, GitHub/Google dorking, NVD),
correlates the results into an attack-surface score, a relationship graph and
MITRE ATT&CK mappings, and exports everything to the format your workflow needs.

Start with the main [README](../README.md) for installation and a quickstart,
then use this hub to go deeper.

## Documentation map

| Document | What it covers |
|---|---|
| [Architecture](architecture.md) | How the engine is layered: CLI → engine → collectors → schema → analysis → exports/UI. Data flow, concurrency model and safety guards. |
| [Modules](modules/dns.md) | One page per built-in collector (start at DNS; the sidebar-style table below links the rest). What each module collects, its result keys and its degradation behaviour. |
| [Writing plugins](plugins.md) | The `BaseModule` contract, `PluginManager` loading rules and a complete, offline-testable example plugin. |
| [FAQ](FAQ.md) | API keys, targets, scope and authorization, exit codes, where results live, why a module came back empty. |
| [Extended CLI reference (Spanish)](USAGE.md) | The original in-depth CLI guide: depths, profiles, monitor mode, exports. |
| [Roadmap](agentes/ROADMAP.md) | The live development plan, maintained by the fleet. |
| [Changelog](../CHANGELOG.md) | Release history, one entry per user-visible change. |

## The built-in modules at a glance

The twelve built-in collectors below are registered by name and selectable
with `--modules` (e.g. `--modules dns,web,cve`). The catalog is bigger: engine
and analysis steps (`permutation`, `takeover`, `endpoints`, `tls_audit`,
`correlation`, `graph`, `mitre`, `chains`) and intelligence add-ons
(`shodan_censys`, `reverse_ip`, `social_footprint`, `leak_check`) are
selectable too — see the complete table in [USAGE](USAGE.md):

| Key | Collects | Page |
|---|---|---|
| `dns` | DNS records, subdomain enumeration (bruteforce + passive), wildcard detection, AXFR, permutations, takeover, email anti-spoofing audit | [dns](modules/dns.md) |
| `certs` | Certificate Transparency subdomains (crt.sh), TLS protocol/cipher audit | [certs](modules/certs.md) |
| `wayback` | Historical URLs from the Wayback Machine | [wayback](modules/wayback.md) |
| `web` | Web technologies, live endpoints, security headers, JS secrets, favicon hash pivoting | [web](modules/web.md) |
| `network` | Nmap port/service scan, ASN/netblock expansion | [network](modules/network.md) |
| `whois` | Domain registration data | [whois](modules/whois.md) |
| `github` | GitHub code-search dorking (no API key) | [github](modules/github.md) |
| `google` | Google dorking (no API key) | [google](modules/google.md) |
| `cloud` | Public cloud bucket discovery | [cloud](modules/cloud.md) |
| `emails` | Email address enumeration | [emails](modules/emails.md) |
| `cdn_waf` | CDN / WAF fingerprinting | [cdn_waf](modules/cdn_waf.md) |
| `cve` | CVE lookup against the free NVD API 2.0 | [cve](modules/cve.md) |

## Depth availability

Not every module runs at every scan depth (see `--depth`):

| Depth | Modules |
|---|---|
| `quick` | dns, certs, wayback, whois + web + correlation, graph, MITRE, AI |
| `normal` | quick + network, cdn_waf, dorking (github/google unless `--stealth`), cve |
| `deep` / `full` | normal + permutations, takeover, endpoint discovery, cloud, emails |

Phases 1–3 run their collectors concurrently in bounded pools; the analysis
phase (correlation, graph, MITRE, chains, AI) is sequential because each step
consumes the previous one's output.
