"""SEG regression: get_summary() refleja las tecnologías reales del escaneo.

TechDetector produce ``web.technologies.technologies`` como lista de
strings; el doble ``_as_dict()`` anterior la convertía en {} (branch
muerto) y el dashboard mostraba siempre 0 tecnologías.
"""

import json

from ui.dashboard import app, load_scan_results

BASE = {
    "schema_version": "2.0",
    "scan_date": "2026-10-24T12:00:00",
    "depth": "quick",
    "correlation": {"attack_surface_score": {"score": 3, "severity": "LOW"}},
    "modules": {},
}


def _summary(client, modules, tmp_path):
    results = dict(BASE)
    results["modules"] = modules
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(json.dumps(results), encoding="utf-8")
    target = load_scan_results(str(scan_file))
    resp = client.get(f"/api/scan/{target}/summary")
    assert resp.status_code == 200
    return resp.get_json()


def test_tech_list_shape_real_techdetector(tmp_path):
    """Forma real de TechDetector: lista de strings bajo technologies."""
    modules = {
        "web": {
            "technologies": {
                "url": "http://127.0.0.1:8599",
                "technologies": ["Nginx", "PHP"],
            }
        }
    }
    app.config["TESTING"] = True
    data = _summary(app.test_client(), modules, tmp_path)
    assert data["technologies"] == ["Nginx", "PHP"]


def test_tech_dict_shape_tolerada(tmp_path):
    """Forma alternativa (dict nombre->detalle): se listan las claves."""
    modules = {
        "web": {"technologies": {"technologies": {"Nginx": {"version": "1.24"}}}}
    }
    app.config["TESTING"] = True
    data = _summary(app.test_client(), modules, tmp_path)
    assert data["technologies"] == ["Nginx"]


def test_tech_ausente_devuelve_vacia(tmp_path):
    modules = {"web": {"technologies": {"url": "http://127.0.0.1:8599"}}}
    app.config["TESTING"] = True
    data = _summary(app.test_client(), modules, tmp_path)
    assert data["technologies"] == []
