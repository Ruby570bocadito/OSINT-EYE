"""OSINT EYE - Web Dashboard (Flask, minimalist & professional).

Loads scan-result JSON files (tolerating missing/renamed paths) and serves a
local-only web dashboard on 127.0.0.1. Every REST endpoint is defensive and
never raises a 500 on malformed or empty scan data. The frontend is 100%
self-contained (no CDN) and renders all scan data through textContent —
never innerHTML — so scan results can never inject markup.
"""

from flask import Flask, render_template_string, jsonify
import json
from datetime import datetime
from pathlib import Path

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

SCAN_RESULTS = {}
SCAN_HISTORY = []

# Message shown in the web UI when a scan file could not be located.
LAST_LOAD_WARNING = None


# --- shape guards -----------------------------------------------------------

def _as_dict(value):
    return value if isinstance(value, dict) else {}


def _as_list(value):
    return value if isinstance(value, list) else []


def _as_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_str_list(value):
    out = []
    for item in _as_list(value):
        if isinstance(item, str):
            if item and item not in out:
                out.append(item)
        elif isinstance(item, dict):
            name = item.get("subdomain") or item.get("name") or item.get("host")
            if isinstance(name, str) and name and name not in out:
                out.append(name)
    return out


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _norm_sev(value, default="info"):
    """Normalize any severity label to one of the filterable buckets."""
    sev = str(value or "").strip().lower()
    return sev if sev in _SEVERITY_RANK else default


def _collect_assets(results):
    """Flatten a scan into filterable asset rows for the findings explorer.

    Every extraction is defensive: missing keys, wrong types and malformed
    entries are skipped instead of raising. Severity is normalized to
    critical/high/medium/low/info so dashboard filters stay predictable.
    """
    modules = _as_dict(results.get("modules"))
    assets = []
    seen = set()

    def add(atype, name, module, severity, detail=""):
        name = str(name or "").strip()
        if not name:
            return
        key = (atype, name, module)
        if key in seen:
            return
        seen.add(key)
        assets.append(
            {
                "type": atype,
                "name": name,
                "module": module,
                "severity": _norm_sev(severity),
                "detail": str(detail or "").strip(),
            }
        )

    # Subdomains (dns / certs / permutation) — module kept per source.
    for key in ("dns", "certs", "permutation"):
        for sub in _as_str_list(_as_dict(modules.get(key)).get("subdomains")):
            add("subdomain", sub, key, "info")

    # Open ports (network module).
    for svc in _as_list(_as_dict(modules.get("network")).get("services")):
        if not isinstance(svc, dict) or svc.get("state") != "open":
            continue
        if svc.get("port") in (None, ""):
            continue
        name = f"{svc['port']}/{svc.get('protocol') or 'tcp'}"
        detail = " ".join(
            str(part) for part in (svc.get("service"), svc.get("version")) if part
        )
        add("port", name, "network", "info", detail)

    # Technologies (web module) — list of strings or dict keys.
    techs = _as_dict(_as_dict(modules.get("web")).get("technologies")).get("technologies")
    if isinstance(techs, list):
        tech_names = [t for t in techs if isinstance(t, str)]
    elif isinstance(techs, dict):
        tech_names = [str(k) for k in techs]
    else:
        tech_names = []
    for tech in tech_names:
        add("tech", tech, "web", "info")

    # Emails.
    for mail in _as_str_list(_as_dict(modules.get("emails")).get("emails_found")):
        add("email", mail, "emails", "info")

    # CVEs — severity from the first CVSS entry; description kept as detail.
    for cve in _as_list(_as_dict(modules.get("cve")).get("cves")):
        if not isinstance(cve, dict):
            continue
        ident = cve.get("id") or cve.get("cve_id") or cve.get("cve")
        severity_list = _as_list(cve.get("severity"))
        sev, score = "", ""
        if severity_list and isinstance(severity_list[0], dict):
            sev = severity_list[0].get("severity") or ""
            score = severity_list[0].get("score")
        detail = f"CVSS {score}" if score not in ("", None) else ""
        desc = cve.get("description") or cve.get("summary")
        if isinstance(desc, str) and desc.strip():
            short = " ".join(desc.split())[:140]
            if len(" ".join(desc.split())) > 140:
                short += "…"
            detail = f"{detail} — {short}" if detail else short
        add("cve", ident, "cve", sev, detail)

    # Cloud buckets — public exposure ranks high.
    buckets = _as_dict(modules.get("cloud_buckets"))
    for bucket in _as_list(buckets.get("found")):
        if not isinstance(bucket, dict):
            continue
        url = bucket.get("url") or bucket.get("bucket") or bucket.get("name")
        severity = "high" if bucket.get("public") else "info"
        detail = str(bucket.get("provider") or "")
        if bucket.get("listable"):
            detail = (detail + " listable").strip()
        add("bucket", url, "cloud", severity, detail)

    # MITRE ATT&CK mappings.
    for finding in _as_list(_as_dict(results.get("mitre")).get("findings")):
        if not isinstance(finding, dict):
            continue
        name = f"{finding.get('technique_id') or ''} {finding.get('technique_name') or ''}".strip()
        name = name or finding.get("technique") or ""
        add("technique", name, "mitre", finding.get("severity"), finding.get("tactic") or "")

    assets.sort(
        key=lambda a: (_SEVERITY_RANK[a["severity"]], a["type"], a["name"].lower())
    )
    return assets


# --- API --------------------------------------------------------------------

@app.route("/")
def dashboard():
    return render_template_string(_template())


@app.route("/api/scans", methods=["GET"])
def list_scans():
    return jsonify(
        {
            "scans": SCAN_HISTORY,
            "total": len(SCAN_HISTORY),
            "warning": LAST_LOAD_WARNING,
        }
    )


@app.route("/api/scan/<target>", methods=["GET"])
def get_scan(target):
    if target in SCAN_RESULTS:
        return jsonify(SCAN_RESULTS[target])
    return jsonify({"error": "Scan not found"}), 404


@app.route("/api/scan/<target>/subdomains", methods=["GET"])
def get_subdomains(target):
    if target not in SCAN_RESULTS:
        return jsonify({"error": "Scan not found"}), 404

    results = SCAN_RESULTS[target]
    modules = _as_dict(results.get("modules"))
    subs = set()
    for key in ("dns", "certs", "permutation"):
        subs.update(_as_str_list(_as_dict(modules.get(key)).get("subdomains")))

    return jsonify(
        {
            "target": target,
            "subdomains": sorted(subs),
            "count": len(subs),
        }
    )


@app.route("/api/scan/<target>/ports", methods=["GET"])
def get_ports(target):
    if target not in SCAN_RESULTS:
        return jsonify({"error": "Scan not found"}), 404

    results = SCAN_RESULTS[target]
    services = _as_list(_as_dict(_as_dict(results.get("modules")).get("network")).get("services"))
    open_ports = [
        s for s in services
        if isinstance(s, dict) and s.get("state") == "open"
    ]

    return jsonify(
        {
            "target": target,
            "ports": open_ports,
            "count": len(open_ports),
        }
    )


@app.route("/api/scan/<target>/graph", methods=["GET"])
def get_graph(target):
    if target not in SCAN_RESULTS:
        return jsonify({"error": "Scan not found"}), 404

    results = SCAN_RESULTS[target]
    graph = results.get("graph")
    if not isinstance(graph, dict):
        graph = {}
    nodes = _as_list(graph.get("nodes"))
    edges = _as_list(graph.get("edges"))
    return jsonify({"nodes": nodes, "edges": edges})


@app.route("/api/scan/<target>/mitre", methods=["GET"])
def get_mitre(target):
    if target not in SCAN_RESULTS:
        return jsonify({"error": "Scan not found"}), 404

    results = SCAN_RESULTS[target]
    mitre = _as_dict(results.get("mitre"))
    return jsonify(
        {
            "findings": _as_list(mitre.get("findings")),
            "total_findings": _as_int(mitre.get("total_findings"),
                                      len(_as_list(mitre.get("findings")))),
        }
    )


@app.route("/api/scan/<target>/chains", methods=["GET"])
def get_chains(target):
    if target not in SCAN_RESULTS:
        return jsonify({"error": "Scan not found"}), 404

    results = SCAN_RESULTS[target]
    return jsonify(_as_list(results.get("attack_chains")))


@app.route("/api/scan/<target>/assets", methods=["GET"])
def get_assets(target):
    if target not in SCAN_RESULTS:
        return jsonify({"error": "Scan not found"}), 404

    assets = _collect_assets(SCAN_RESULTS[target])
    return jsonify({"target": target, "assets": assets, "count": len(assets)})


@app.route("/api/scan/<target>/summary", methods=["GET"])
def get_summary(target):
    if target not in SCAN_RESULTS:
        return jsonify({"error": "Scan not found"}), 404

    results = SCAN_RESULTS[target]
    modules = _as_dict(results.get("modules"))

    services = _as_list(_as_dict(modules.get("network")).get("services"))
    open_ports = [
        s for s in services
        if isinstance(s, dict) and s.get("state") == "open"
    ]
    techs = _as_dict(_as_dict(_as_dict(modules.get("web")).get("technologies")).get("technologies"))
    if isinstance(techs, list):
        tech_list = [t for t in techs if isinstance(t, str)]
    else:
        tech_list = [str(k) for k in techs.keys()]

    return jsonify(
        {
            "target": target,
            "date": results.get("scan_date"),
            "depth": results.get("depth"),
            "subdomains": len(_as_str_list(_as_dict(modules.get("dns")).get("subdomains"))),
            "open_ports": len(open_ports),
            "technologies": tech_list,
            "emails": len(_as_str_list(_as_dict(modules.get("emails")).get("emails_found"))),
            "cves": len(_as_list(_as_dict(modules.get("cve")).get("cves"))),
            "cloud_buckets": len(_as_list(_as_dict(modules.get("cloud_buckets")).get("public"))),
            "attack_surface_score": _as_dict(
                _as_dict(results.get("correlation")).get("attack_surface_score")
            ),
            "mitre_findings": _as_int(_as_dict(results.get("mitre")).get("total_findings")),
            "attack_chains": len(_as_list(results.get("attack_chains"))),
        }
    )


# --- loading ----------------------------------------------------------------

def _empty_scan_data(target: str = "demo") -> dict:
    """Safe, empty demo payload so the dashboard always renders something."""
    return {
        "target": target,
        "scan_date": datetime.now().isoformat(),
        "depth": "demo",
        "modules": {
            "dns": {"subdomains": [], "records": {}},
            "certs": {"subdomains": []},
            "permutation": {"subdomains": []},
            "network": {"services": []},
            "web": {"technologies": {"technologies": []}},
            "emails": {"emails_found": []},
            "cloud_buckets": {"found": [], "public": []},
            "cve": {"cves": []},
        },
        "correlation": {
            "attack_surface_score": {"score": 0, "severity": "LOW", "factors": []}
        },
        "mitre": {"findings": [], "total_findings": 0},
        "attack_chains": [],
        "graph": {"nodes": [], "edges": []},
        "demo": True,
    }


def _resolve_results_path(filepath: str):
    """Resolve a scan-results path tolerantly.

    Order of attempts:
      1. the path exactly as given,
      2. the path + '.json' (osint_eye.py sometimes passes the base name),
      3. the newest '<stem>*.json' match in the working directory,
      4. the newest 'osint_eye_*.json' file in the working directory.

    Returns a Path or None when nothing usable exists.
    """
    if not filepath:
        return None

    candidates = [Path(filepath)]
    if not str(filepath).endswith(".json"):
        candidates.append(Path(str(filepath) + ".json"))

    for cand in candidates:
        if cand.is_file():
            return cand

    try:
        stem = Path(filepath).stem or ""
        here = Path.cwd()
        for pattern in (f"{stem}*.json" if stem else None, "osint_eye_*.json"):
            if not pattern:
                continue
            matches = sorted(
                (p for p in here.glob(pattern) if p.is_file()),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            if matches:
                return matches[0]
    except OSError:
        pass

    return None


def load_scan_results(filepath: str) -> str:
    """Load scan results from a JSON file — never raises.

    Accepts paths with or without the .json extension; falls back to the most
    recent matching JSON in the working directory; finally loads safe demo
    data so the dashboard still renders (warning shown in the web UI).

    Returns the target key the data was stored under.
    """
    global LAST_LOAD_WARNING
    LAST_LOAD_WARNING = None

    data = None
    resolved = _resolve_results_path(filepath)
    if resolved is not None:
        try:
            with open(resolved, encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                data = loaded
            else:
                LAST_LOAD_WARNING = (
                    f"{resolved} does not contain a JSON object; showing demo data."
                )
        except (OSError, ValueError) as exc:
            LAST_LOAD_WARNING = f"Could not read {resolved}: {exc}"
    else:
        LAST_LOAD_WARNING = (
            f"Scan file '{filepath}' (or any matching .json) not found — "
            "showing empty demo data."
        )

    if data is None:
        data = _empty_scan_data()
        print(f"[!] {LAST_LOAD_WARNING}")
    elif LAST_LOAD_WARNING is None and filepath and not str(filepath).endswith(".json"):
        # Friendly note when the extension had to be guessed.
        if str(resolved) != str(filepath):
            LAST_LOAD_WARNING = f"Loaded {resolved} (requested: '{filepath}')"
            print(f"[*] {LAST_LOAD_WARNING}")

    target = str(data.get("target") or "unknown")
    SCAN_RESULTS[target] = data
    SCAN_HISTORY.append(
        {
            "target": target,
            "date": data.get("scan_date") or datetime.now().isoformat(),
            "depth": data.get("depth") or "unknown",
            "demo": bool(data.get("demo")),
            "warning": LAST_LOAD_WARNING,
        }
    )
    return target


def start_dashboard(host="127.0.0.1", port=5000, debug=False):
    """Start the web dashboard (binds to localhost by default)."""
    print(f"[*] Starting OSINT EYE Dashboard at http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)


def _template() -> str:
    """Return the dashboard HTML, from the sibling template file if present,
    falling back to a minimal inline page so the route never 500s."""
    tpl_path = Path(__file__).parent / "dashboard_template.html"
    try:
        return tpl_path.read_text(encoding="utf-8")
    except OSError:
        return (
            "<!DOCTYPE html><html><head><meta charset='utf-8'>"
            "<title>OSINT EYE</title></head><body style='background:#0A0B0E;"
            "color:#E8EAF0;font-family:system-ui;padding:40px'>"
            "<h1>OSINT EYE Dashboard</h1><p>dashboard_template.html not found — "
            "the REST API is still available under /api/.</p></body></html>"
        )


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        for filepath in sys.argv[1:]:
            target = load_scan_results(filepath)  # tolerates missing .json
            print(f"[*] Loaded '{target}' from: {filepath}")

    if not SCAN_RESULTS:
        print(
            "[*] No scan results loaded. Usage: python dashboard.py <results.json> [results2.json]"
        )
        print("[*] Starting with empty dashboard...")

    start_dashboard()
