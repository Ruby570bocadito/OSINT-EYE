#!/usr/bin/env python3
"""Extrae la sección de una versión del CHANGELOG.md para las notas de release.

Uso: python extract_changelog.py 2.1.1  > notas.md
Fallo limpio (exit != 0) si la sección '## [x.y.z]' no existe: un release sin
changelog no se publica (regla del propio CHANGELOG).
"""

import re
import sys
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parent.parent.parent / "CHANGELOG.md"


def main() -> int:
    if len(sys.argv) != 2:
        print("uso: extract_changelog.py <version>", file=sys.stderr)
        return 2
    version = sys.argv[1].lstrip("v")
    text = CHANGELOG.read_text(encoding="utf-8")

    header = re.compile(r"^## \[" + re.escape(version) + r"\](?:[ \t]- .*)?$", re.M)
    match = header.search(text)
    if not match:
        print(f"ERROR: no existe la sección '## [{version}]' en CHANGELOG.md", file=sys.stderr)
        return 1

    start = match.end()
    nxt = re.search(r"^## \[", text[start:], re.M)
    section = text[start : start + nxt.start()] if nxt else text[start:]
    section = section.strip()

    if not section:
        print(f"ERROR: la sección '## [{version}]' está vacía", file=sys.stderr)
        return 1

    print(f"## OSINT EYE v{version}\n\n{section}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
