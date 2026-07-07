"""OSINT EYE - Web Dashboard (Flask + D3.js)"""

from flask import Flask, render_template_string, jsonify, request, send_from_directory
import json
import os
from datetime import datetime
from pathlib import Path

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

SCAN_RESULTS = {}
SCAN_HISTORY = []


@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/scans", methods=["GET"])
def list_scans():
    return jsonify(
        {
            "scans": SCAN_HISTORY,
            "total": len(SCAN_HISTORY),
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
    subs = set()
    subs.update(results.get("modules", {}).get("dns", {}).get("subdomains", []))
    subs.update(results.get("modules", {}).get("certs", {}).get("subdomains", []))
    subs.update(results.get("modules", {}).get("permutation", {}).get("subdomains", []))

    return jsonify(
        {
            "target": target,
            "subdomains": sorted(list(subs)),
            "count": len(subs),
        }
    )


@app.route("/api/scan/<target>/ports", methods=["GET"])
def get_ports(target):
    if target not in SCAN_RESULTS:
        return jsonify({"error": "Scan not found"}), 404

    results = SCAN_RESULTS[target]
    services = results.get("modules", {}).get("network", {}).get("services", [])
    open_ports = [s for s in services if s.get("state") == "open"]

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
    return jsonify(results.get("graph", {"nodes": [], "edges": []}))


@app.route("/api/scan/<target>/mitre", methods=["GET"])
def get_mitre(target):
    if target not in SCAN_RESULTS:
        return jsonify({"error": "Scan not found"}), 404

    results = SCAN_RESULTS[target]
    return jsonify(results.get("mitre", {}))


@app.route("/api/scan/<target>/chains", methods=["GET"])
def get_chains(target):
    if target not in SCAN_RESULTS:
        return jsonify({"error": "Scan not found"}), 404

    results = SCAN_RESULTS[target]
    return jsonify(results.get("attack_chains", []))


@app.route("/api/scan/<target>/summary", methods=["GET"])
def get_summary(target):
    if target not in SCAN_RESULTS:
        return jsonify({"error": "Scan not found"}), 404

    results = SCAN_RESULTS[target]
    modules = results.get("modules", {})

    return jsonify(
        {
            "target": target,
            "date": results.get("scan_date"),
            "depth": results.get("depth"),
            "subdomains": len(modules.get("dns", {}).get("subdomains", [])),
            "open_ports": len(
                [
                    s
                    for s in modules.get("network", {}).get("services", [])
                    if s.get("state") == "open"
                ]
            ),
            "technologies": modules.get("web", {})
            .get("technologies", {})
            .get("technologies", []),
            "emails": len(modules.get("emails", {}).get("emails_found", [])),
            "cves": len(modules.get("cve", {}).get("cves", [])),
            "cloud_buckets": len(modules.get("cloud_buckets", {}).get("public", [])),
            "attack_surface_score": results.get("correlation", {}).get(
                "attack_surface_score", {}
            ),
            "mitre_findings": results.get("mitre", {}).get("total_findings", 0),
            "attack_chains": len(results.get("attack_chains", [])),
        }
    )


def load_scan_results(filepath: str):
    """Load scan results from JSON file"""
    with open(filepath) as f:
        data = json.load(f)

    target = data.get("target", "unknown")
    SCAN_RESULTS[target] = data
    SCAN_HISTORY.append(
        {
            "target": target,
            "date": data.get("scan_date", datetime.now().isoformat()),
            "depth": data.get("depth", "unknown"),
        }
    )


def start_dashboard(host="127.0.0.1", port=5000, debug=False):
    """Start the web dashboard"""
    print(f"[*] Starting OSINT EYE Dashboard at http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)


DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINT EYE Dashboard</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a1a; color: #e0e0e0; }
        .header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 20px 30px; border-bottom: 2px solid #0f3460; display: flex; align-items: center; justify-content: space-between; }
        .header h1 { color: #00d2ff; font-size: 24px; }
        .header .subtitle { color: #7f8c8d; font-size: 14px; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .stats-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 25px; }
        .stat-card { background: #1a1a2e; border: 1px solid #0f3460; border-radius: 10px; padding: 20px; text-align: center; transition: transform 0.2s; }
        .stat-card:hover { transform: translateY(-3px); border-color: #00d2ff; }
        .stat-value { font-size: 36px; font-weight: bold; color: #00d2ff; }
        .stat-label { font-size: 14px; color: #7f8c8d; margin-top: 5px; }
        .panel { background: #1a1a2e; border: 1px solid #0f3460; border-radius: 10px; padding: 20px; margin-bottom: 20px; }
        .panel h2 { color: #00d2ff; margin-bottom: 15px; font-size: 18px; border-bottom: 1px solid #0f3460; padding-bottom: 10px; }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #0f3460; color: #00d2ff; padding: 10px; text-align: left; font-size: 13px; }
        td { padding: 8px 10px; border-bottom: 1px solid #1a1a3e; font-size: 13px; }
        tr:hover { background: #16213e; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }
        .badge-critical { background: #c0392b; color: white; }
        .badge-high { background: #e74c3c; color: white; }
        .badge-medium { background: #f39c12; color: white; }
        .badge-low { background: #3498db; color: white; }
        .badge-info { background: #95a5a6; color: white; }
        #graph-container { width: 100%; height: 500px; background: #0a0a1a; border-radius: 8px; overflow: hidden; }
        .node { stroke: #fff; stroke-width: 1.5px; }
        .link { stroke: #4a4a6a; stroke-opacity: 0.6; }
        .target-selector { display: flex; gap: 10px; margin-bottom: 20px; }
        .target-btn { background: #0f3460; color: #e0e0e0; border: 1px solid #1a5276; padding: 8px 16px; border-radius: 6px; cursor: pointer; transition: all 0.2s; }
        .target-btn:hover, .target-btn.active { background: #00d2ff; color: #1a1a2e; border-color: #00d2ff; }
        .chain-card { background: #16213e; border-left: 4px solid #e74c3c; padding: 15px; margin-bottom: 10px; border-radius: 0 8px 8px 0; }
        .chain-card h4 { color: #e74c3c; margin-bottom: 8px; }
        .chain-step { padding: 5px 0 5px 15px; border-left: 2px solid #0f3460; margin-left: 10px; font-size: 13px; }
        @media (max-width: 768px) { .grid-2 { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>OSINT EYE Dashboard</h1>
            <div class="subtitle">Attack Surface Intelligence Platform</div>
        </div>
        <div id="scan-count" style="color: #7f8c8d;"></div>
    </div>

    <div class="container">
        <div class="target-selector" id="target-selector"></div>

        <div class="stats-row" id="stats-row">
            <div class="stat-card"><div class="stat-value" id="stat-subs">0</div><div class="stat-label">Subdomains</div></div>
            <div class="stat-card"><div class="stat-value" id="stat-ports">0</div><div class="stat-label">Open Ports</div></div>
            <div class="stat-card"><div class="stat-value" id="stat-techs">0</div><div class="stat-label">Technologies</div></div>
            <div class="stat-card"><div class="stat-value" id="stat-cves">0</div><div class="stat-label">CVEs</div></div>
            <div class="stat-card"><div class="stat-value" id="stat-emails">0</div><div class="stat-label">Emails</div></div>
            <div class="stat-card"><div class="stat-value" id="stat-score">-</div><div class="stat-label">Risk Score</div></div>
        </div>

        <div class="grid-2">
            <div class="panel">
                <h2>Attack Surface Graph</h2>
                <div id="graph-container"></div>
            </div>
            <div class="panel">
                <h2>Open Ports</h2>
                <div id="ports-table"></div>
            </div>
        </div>

        <div class="grid-2">
            <div class="panel">
                <h2>MITRE ATT&CK Findings</h2>
                <div id="mitre-table"></div>
            </div>
            <div class="panel">
                <h2>Attack Chains</h2>
                <div id="chains-container"></div>
            </div>
        </div>
    </div>

    <script>
        let currentTarget = null;

        async function loadTargets() {
            const resp = await fetch('/api/scans');
            const data = await resp.json();
            const selector = document.getElementById('target-selector');
            const countEl = document.getElementById('scan-count');
            countEl.textContent = `${data.total} scan(s) loaded`;

            selector.innerHTML = '';
            data.scans.forEach(s => {
                const btn = document.createElement('button');
                btn.className = 'target-btn';
                btn.textContent = s.target;
                btn.onclick = () => selectTarget(s.target);
                selector.appendChild(btn);
            });

            if (data.scans.length > 0) {
                selectTarget(data.scans[0].target);
            }
        }

        async function selectTarget(target) {
            currentTarget = target;
            document.querySelectorAll('.target-btn').forEach(b => {
                b.classList.toggle('active', b.textContent === target);
            });

            const resp = await fetch(`/api/scan/${target}/summary`);
            const summary = await resp.json();

            document.getElementById('stat-subs').textContent = summary.subdomains;
            document.getElementById('stat-ports').textContent = summary.open_ports;
            document.getElementById('stat-techs').textContent = summary.technologies.length;
            document.getElementById('stat-cves').textContent = summary.cves;
            document.getElementById('stat-emails').textContent = summary.emails;
            document.getElementById('stat-score').textContent = summary.attack_surface_score.score || '-';

            loadPorts(target);
            loadGraph(target);
            loadMitre(target);
            loadChains(target);
        }

        async function loadPorts(target) {
            const resp = await fetch(`/api/scan/${target}/ports`);
            const data = await resp.json();
            const container = document.getElementById('ports-table');

            if (data.ports.length === 0) {
                container.innerHTML = '<p style="color: #7f8c8d;">No open ports found</p>';
                return;
            }

            let html = '<table><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th></tr>';
            data.ports.forEach(p => {
                html += `<tr><td>${p.port}</td><td>${p.protocol}</td><td>${p.service}</td><td>${p.version || ''}</td></tr>`;
            });
            html += '</table>';
            container.innerHTML = html;
        }

        async function loadGraph(target) {
            const resp = await fetch(`/api/scan/${target}/graph`);
            const graph = await resp.json();
            const container = document.getElementById('graph-container');
            container.innerHTML = '';

            if (!graph.nodes || graph.nodes.length === 0) {
                container.innerHTML = '<p style="color: #7f8c8d; text-align: center; padding: 50px;">No graph data available</p>';
                return;
            }

            const width = container.clientWidth;
            const height = 500;

            const svg = d3.select('#graph-container').append('svg')
                .attr('width', width).attr('height', height);

            const simulation = d3.forceSimulation(graph.nodes)
                .force('link', d3.forceLink(graph.edges).id(d => d.id || d.source).distance(100))
                .force('charge', d3.forceManyBody().strength(-300))
                .force('center', d3.forceCenter(width / 2, height / 2));

            const link = svg.append('g').selectAll('line')
                .data(graph.edges).enter().append('line')
                .attr('class', 'link').attr('stroke-width', 1);

            const node = svg.append('g').selectAll('circle')
                .data(graph.nodes).enter().append('circle')
                .attr('class', 'node')
                .attr('r', d => d.size || 10)
                .attr('fill', d => d.color || '#00d2ff')
                .call(d3.drag()
                    .on('start', dragStarted)
                    .on('drag', dragged)
                    .on('end', dragEnded));

            node.append('title').text(d => d.label || d.id);

            node.on('mouseover', function(event, d) {
                d3.select(this).attr('r', (d.size || 10) + 5);
            }).on('mouseout', function(event, d) {
                d3.select(this).attr('r', d.size || 10);
            });

            simulation.on('tick', () => {
                link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
                    .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
                node.attr('cx', d => d.x).attr('cy', d => d.y);
            });

            function dragStarted(event, d) {
                if (!event.active) simulation.alphaTarget(0.3).restart();
                d.fx = d.x; d.fy = d.y;
            }
            function dragged(event, d) { d.fx = event.x; d.fy = event.y; }
            function dragEnded(event, d) {
                if (!event.active) simulation.alphaTarget(0);
                d.fx = null; d.fy = null;
            }
        }

        async function loadMitre(target) {
            const resp = await fetch(`/api/scan/${target}/mitre`);
            const data = await resp.json();
            const container = document.getElementById('mitre-table');

            if (!data.findings || data.findings.length === 0) {
                container.innerHTML = '<p style="color: #7f8c8d;">No MITRE findings</p>';
                return;
            }

            let html = '<table><tr><th>Technique</th><th>Name</th><th>Tactic</th><th>Severity</th></tr>';
            data.findings.forEach(f => {
                const badgeClass = f.severity.toLowerCase();
                html += `<tr><td>${f.technique_id}</td><td>${f.technique_name}</td><td>${f.tactic}</td><td><span class="badge badge-${badgeClass}">${f.severity}</span></td></tr>`;
            });
            html += '</table>';
            container.innerHTML = html;
        }

        async function loadChains(target) {
            const resp = await fetch(`/api/scan/${target}/chains`);
            const chains = await resp.json();
            const container = document.getElementById('chains-container');

            if (chains.length === 0) {
                container.innerHTML = '<p style="color: #7f8c8d;">No attack chains identified</p>';
                return;
            }

            let html = '';
            chains.slice(0, 5).forEach(chain => {
                html += `<div class="chain-card" style="border-left-color: ${chain.risk_score >= 80 ? '#c0392b' : chain.risk_score >= 50 ? '#f39c12' : '#3498db'}">`;
                html += `<h4>${chain.name} (Risk: ${chain.risk_score})</h4>`;
                chain.steps.forEach(step => {
                    html += `<div class="chain-step"><strong>Step ${step.step}:</strong> ${step.action}</div>`;
                });
                html += '</div>';
            });
            container.innerHTML = html;
        }

        loadTargets();
    </script>
</body>
</html>
"""


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        for filepath in sys.argv[1:]:
            if filepath.endswith(".json"):
                load_scan_results(filepath)
                print(f"[*] Loaded: {filepath}")

    if not SCAN_RESULTS:
        print(
            "[*] No scan results loaded. Usage: python dashboard.py <results.json> [results2.json]"
        )
        print("[*] Starting with empty dashboard...")

    start_dashboard()
