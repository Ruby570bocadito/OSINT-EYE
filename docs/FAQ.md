# FAQ

Short answers to the questions that come up most often. For anything CLI-flag
related in depth, see the [extended reference](USAGE.md) (Spanish) or the main
[README](../README.md).

## Keys, network and privacy

**Does it need API keys?**
No. Every built-in module works key-free. The only *optional* key is
`NVD_API_KEY`, which increases CVE lookup throughput (without it NVD allows
~5 requests per rolling 30 s window and the module paces itself). The optional
AI features talk exclusively to a local Ollama server (localhost:11434) — no
cloud, no keys, no telemetry.

**Is OSINT EYE offline?**
The *test suite* is 100 % offline by project policy (loopback fixtures only).
Scans themselves are a network tool by design: they query public sources
(DNS, crt.sh, Wayback, WHOIS, NVD, search engines). Everything degrades
gracefully when a source is unreachable — you get warnings and partial
results, never a crash.

**Where does my data go?**
Nowhere, except to the sources you query and wherever you point the outputs.
Results are saved locally, the cache lives in `~/.osint_eye/`, the dashboard
binds to `127.0.0.1` by default, and `--webhook` only accepts public HTTPS
hosts (so scan data cannot be pushed to an internal service by accident).

## Targets and authorization

**What is a valid target?**
Domain names and IP addresses (comma/space separated; the wizard also accepts
CIDRs in scope fields). The interactive wizard validates as you type and
refuses things that look like URLs. Run it without arguments to use the wizard.

**How do I make sure I only scan what I'm allowed to?**
Combine three layers: the wizard's explicit authorization confirmation;
`--scope FILE` (one domain / wildcard / IP / CIDR per line) so out-of-scope
items are skipped **and recorded**; and `--exclude` (repeatable, always wins
over `--scope`). Collectors re-check URLs they derive, not just the roots, and
every discard is auditable in `results["scope"]`. See
[architecture](architecture.md#safety-and-authorization-model).

**Is active scanning safe to point anywhere?**
No. Port scanning, endpoint fuzzing and permutation enumeration are active
reconnaissance. Only run OSINT EYE against systems you own or have explicit
permission to test (see the responsible-use section of the README).

## Results and exits

**Where do results end up?**
With `--output/-o base`, the exporters write `base.json`, `base.md`, `base.html`,
`base.pdf` (`--pdf`), CSV, SARIF, Burp/MSF artifacts — all constrained to the
current working directory. Without `-o`, each scan auto-saves
`osint_eye_<target>_<ts>.json` in the current directory and tells you where.
The SQLite cache lives in `~/.osint_eye/cache` (`--no-cache` disables it).

**How do I use it in CI?**
Use exit codes: `0` finished under threshold, `1` `--fail-on low|medium|high`
threshold exceeded, `2` usage error, `3` nothing scanned (everything out of
scope). `--fail-on high` fails on high *and* critical findings. Pair with
`--output` and the SARIF export for code-scanning integration.

**How do I look at results?**
`--rich` (terminal UI with per-module progress), `--tui` (Textual explorer),
`--dashboard` (Flask web UI at http://127.0.0.1:5000 with graph, timeline,
diff and export endpoints), or plain files. Multi-target scans support
`--diff`.

**Why is module X empty?**
Almost always a documented degradation, not a bug: crt.sh slow or
rate-limited (`certs`), Google/GitHub serving a consent page or 429
(`google`/`github`), NVD pacing without a key (`cve`), nmap binary missing
(`network`), or a wildcard DNS zone silently filtering bruteforce candidates
(`dns`). Warnings in the log tell you which source backed off; reruns with
`--no-cache` or at a different time often fill the gaps.

**A scan behaves weirdly — how do I report it?**
Open a bug report via the [issue templates](https://github.com/Ruby570bocadito/OSINT-EYE/issues/new/choose)
(there's an offline-reproduction checkbox — please honor it) or read
[CONTRIBUTING](../CONTRIBUTING.md) to fix it yourself. Security issues go
through [SECURITY.md](../SECURITY.md), never public issues.

## Extending

**Can I add my own collectors?**
Yes — that's the `BaseModule` contract; see [writing plugins](plugins.md).
Unknown module names never break validation, and `--plugin-dir` loads your
code without touching the core.

**Docker?**
`make docker` builds the image (same as CI); the image takes the version as a
build argument. `make install` / `make test` / `make lint` / `make coverage`
mirror the CI pipeline for local development.
