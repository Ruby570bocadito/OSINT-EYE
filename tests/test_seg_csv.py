"""SEG regression: neutralización de celdas CSV del dashboard (petición IMP-2).

csv.writer entrecomilla lo necesario para no romper filas, pero Excel/
LibreOffice/Sheets interpretan celdas que empiezan por = + - @ como
fórmulas al ABRIR el fichero. _csv_cell debe prefijarlas todas; el
colapso de whitespace neutraliza tab/CR sobrantes.
"""

from ui.dashboard import _csv_cell, _safe_download_name


def test_formula_prefijos_completos():
    for payload in ("=cmd()", "+1+1", "-1+1", "@SUM(1)", "\t=cmd()", "\r=cmd()"):
        out = _csv_cell(payload)
        assert not out.startswith(_PREFIXES), f"{payload!r} -> {out!r}"


_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def test_celda_normal_intacta():
    assert _csv_cell("example.com") == "example.com"
    assert _csv_cell("sub.example.com") == "sub.example.com"
    assert _csv_cell(None) == ""
    assert _csv_cell("") == ""


def test_saltos_de_linea_colapsados():
    assert "\n" not in _csv_cell("linea1\nlinea2")
    assert "\r" not in _csv_cell("linea1\rlinea2")
    assert _csv_cell("linea1\nlinea2") == "linea1 linea2"


def test_prefix_apostrofe_no_se_duplica_efecto():
    # Un valor que ya empieza con ' no es ejecutable en hojas de cálculo:
    # se deja tal cual (el apostrofe ya neutraliza).
    assert _csv_cell("'=cmd()") == "'=cmd()"


def test_safe_download_name_sin_traversal_ni_injection():
    for hostile in (
        "../../etc/passwd",
        "http://evil.com/path?q=1",
        "..\\..\\win",
        'x"onerror="y',
        "a\r\nb: c",
        ".",
        "",
    ):
        name = _safe_download_name(hostile, "csv")
        assert name.startswith("osint_eye_") and name.endswith(".csv")
        for ch in ("/", "\\", '"', "\r", "\n"):
            assert ch not in name, f"{hostile!r} -> {name!r}"
        assert len(name) <= len("osint_eye_") + 80 + len(".csv")
