# OSINT EYE

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![100% Free](https://img.shields.io/badge/100%25%20Free-No%20API%20Keys-brightgreen)]()
[![Stars](https://img.shields.io/github/stars/Ruby570bocadito/OSINT-EYE)](https://github.com/Ruby570bocadito/OSINT-EYE/stargazers)
[![Forks](https://img.shields.io/github/forks/Ruby570bocadito/OSINT-EYE)](https://github.com/Ruby570bocadito/OSINT-EYE/network)

**AI-Powered Attack Surface Intelligence Engine**

OSINT EYE is an automated reconnaissance platform combining multi-source OSINT, asset correlation, async scanning, and local LLM reasoning to autonomously prioritize attack vectors.

**100% Free - No API Keys Required**

## Quick Start

### Docker (Recommended)
```bash
docker build -t osint-eye .
docker run -v $(pwd)/output:/app/output osint-eye example.com --depth full --output /app/output/results
```

### Local
```bash
git clone https://github.com/Ruby570bocadito/OSINT-EYE.git
cd OSINT-EYE
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
sudo apt install nmap
python osint_eye.py example.com --depth full
```

## Scan Depth

| Level | Modules | Time |
|-------|---------|------|
| `quick` | DNS + CT + Wayback + Nmap | ~1 min |
| `normal` | quick + WHOIS + Web Tech + CVE + CDN/WAF | ~3 min |
| `deep` | normal + Permutation + Takeover + Endpoints + Cloud + Emails | ~10 min |
| `full` | deep + GitHub Dorks + Google Dorks | ~20 min |

## Modules (20+)

### Core Recon
- **DNS** - Records, subdomain bruteforce, zone transfer, SPF/DMARC
- **Permutation** - Advanced subdomain permutation algorithm
- **Takeover** - 15+ cloud service takeover detection
- **Certificate Transparency** - crt.sh public API
- **Network** - Nmap port/service scanning
- **WHOIS** - Domain registration + ASN

### Web Intelligence
- **Tech Detection** - 100+ technologies (headers, patterns, cookies)
- **Endpoint Discovery** - 200+ paths (admin, APIs, configs, backups)
- **Sensitive Data** - API keys, tokens, credentials, PII
- **Cloud Buckets** - AWS S3, GCP, Azure, DigitalOcean
- **CDN/WAF** - Cloudflare, Akamai, Fastly, AWS WAF
- **Email Enumeration** - Extraction + generation + verification

### Advanced
- **DNSSEC Walking** - NSEC/NSEC3 zone enumeration
- **Reverse DNS** - Full /24 PTR enumeration
- **Virtual Host Bruteforce** - Discover hidden vhosts
- **JavaScript Analysis** - Extract endpoints/secrets from JS
- **TLS Analysis** - Cipher suites, cert details, vulnerability check
- **Security Headers** - HSTS, CSP, X-Frame-Options audit
- **Parameter Discovery** - URL parameter fuzzing
- **Screenshot Capture** - Web service screenshots (Playwright)

### Intelligence
- **CVE Lookup** - NVD API vulnerability correlation
- **Asset Correlation** - Cross-module relationship detection
- **Attack Surface Graph** - Interactive NetworkX + Pyvis visualization
- **Attack Surface Scoring** - 0-100 severity score
- **AI Analysis** - Local Ollama LLM reasoning
- **MITRE ATT&CK** - Mapping findings to MITRE framework
- **Attack Chains** - Automated attack chain identification

## Usage

```bash
# Full recon
python osint_eye.py target.com --depth full --output results

# Quick scan
python osint_eye.py target.com --depth quick

# Stealth mode
python osint_eye.py target.com --stealth

# Specific modules
python osint_eye.py target.com --modules dns network web cloud

# No AI
python osint_eye.py target.com --no-ai

# Generate PDF report
python osint_eye.py target.com --depth full --pdf

# AI Agent (Red Team Playbook)
python osint_eye.py target.com --depth full --agent

# Docker
docker run -v $(pwd)/output:/app/output osint-eye target.com --depth deep --output /app/output/results
```

## Features

- **Plugin System** - Extend with custom modules
- **Interactive Graph** - Visualize attack surface relationships
- **Multiple Report Formats** - Markdown, PDF, JSON, HTML
- **Continuous Monitoring** - Run as a daemon with alerts
- **Web Dashboard** - Flask-based GUI
- **Export to Neo4j** - Cypher format for graph databases

## Architecture

```
osint_eye/
├── core/          # Async engine, cache, plugins, correlation
├── modules/       # DNS, certs, web, network, osint, cve
├── ai/            # Ollama LLM integration
├── graph/         # Attack surface graph builder
├── reporting/     # Markdown/PDF report generation
├── ui/            # Rich TUI + Textual interactive app
├── lib/           # Frontend assets for graph visualization
└── tests/         # Unit tests (pytest)
```

## Requirements

- Python 3.11+
- nmap
- Optional: Ollama (for AI analysis)

## Testing

```bash
pip install pytest pytest-cov
pytest tests/ -v --cov=osint_eye
```

## License

MIT

---

*For authorized security assessment only.*