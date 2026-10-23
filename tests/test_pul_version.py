"""Contrato de versión única (tarea version-unica, PUL-1).

La versión vive solo en core/__init__.py; el banner de la CLI la importa.
Offline: subprocess local con --help, sin red.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

from core import __version__

ROOT = Path(__file__).resolve().parent.parent


def test_version_es_semver():
    assert re.fullmatch(r"\d+\.\d+\.\d+", __version__), __version__


def test_pyproject_deriva_la_version_de_core():
    # pyproject.toml ya no lleva version estática: debe declararla dinámica.
    try:
        import tomllib
    except ModuleNotFoundError:  # Python 3.10
        return
    data = tomllib.load(open(ROOT / "pyproject.toml", "rb"))
    assert "version" in data["project"].get("dynamic", []), data["project"].get("dynamic")
    assert "version" not in data["project"], "pyproject duplica la versión de core/"


def test_banner_cli_muestra_la_version_de_core():
    env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONIOENCODING="utf-8")
    res = subprocess.run(
        [sys.executable, "osint_eye.py", "--help"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert res.returncode == 0, res.stderr[-500:]
    assert f"v{__version__}" in res.stdout, f"el banner no muestra v{__version__}"
