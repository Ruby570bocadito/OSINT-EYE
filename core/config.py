"""TOML configuration for OSINT EYE (``osint_eye.toml``).

Loads scan configuration from a TOML file (stdlib ``tomllib`` on Python
3.11+; on 3.10 TOML support is simply unavailable and every other code
path keeps working). Supported document:

.. code-block:: toml

    [scan]
    depth = "normal"            # quick | normal | deep | full
    stealth = false
    no_ai = false
    no_cache = false
    modules = ["dns", "certs"]  # default module set (like --modules)

    [timeouts]
    monitor_interval = 3600     # seconds between monitor checks

    [scope]
    includes = ["example.com"]  # same syntax as --scope entries
    excludes = ["10.0.0.0/8"]

    [exports]
    formats = ["json", "sarif"] # subset of the export_all catalogue

    [profiles.deep]
    [profiles.deep.scan]
    depth = "full"

Precedence: CLI flags always win over the config file; inside the file,
the selected profile overrides top-level tables. Unknown sections/keys
are rejected at load time so typos never silently no-op.
"""

from __future__ import annotations

import copy
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

try:  # stdlib since Python 3.11
    import tomllib  # type: ignore[import-not-found]  # mypy analiza con python_version=3.10
except ModuleNotFoundError:  # Python 3.10: TOML config simply unavailable
    tomllib = None

CONFIG_FILENAME = "osint_eye.toml"

VALID_DEPTH = ("quick", "normal", "deep", "full")

#: Export keys produced by OSINTEye.export_all().
VALID_EXPORT_FORMATS = (
    "json",
    "markdown",
    "html",
    "csv",
    "mitre_json",
    "mitre_navigator",
    "bounty_report",
    "graph",
    "pdf",
    "burp",
    "metasploit",
    "sarif",
)

#: section → allowed keys
VALID_SECTIONS: dict[str, set[str]] = {
    "scan": {"depth", "stealth", "no_ai", "no_cache", "modules"},
    "timeouts": {"monitor_interval"},
    "scope": {"includes", "excludes"},
    "exports": {"formats"},
}

_BOOL_KEYS = {"stealth", "no_ai", "no_cache"}


class ConfigError(ValueError):
    """Raised for unreadable, invalid or mis-typed configuration."""


def _qual(section: str, key: str) -> str:
    return f"{section}.{key}"


def _check_bool(section: str, key: str, value: Any) -> None:
    if not isinstance(value, bool):
        raise ConfigError(
            f"{_qual(section, key)} debe ser booleano (true/false), no {value!r}"
        )


def _check_str_list(section: str, key: str, value: Any) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{_qual(section, key)} debe ser una lista de strings")
    return value


def _check_positive_int(section: str, key: str, value: Any) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ConfigError(f"{_qual(section, key)} debe ser un entero positivo")


class Config:
    """Validated view over an osint_eye.toml document."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = copy.deepcopy(data or {})
        self._validate()

    # ── construction ────────────────────────────────────────────────────
    @classmethod
    def load(cls, path: str | None = None) -> Config | None:
        """Load the config file; ``None`` when none is given nor detected.

        ``path=None`` auto-detects ``osint_eye.toml`` in the CWD. An
        explicit path that does not exist raises ``ConfigError`` (the CLI
        turns it into a clean usage error).
        """
        if tomllib is None:
            raise ConfigError(
                "tomllib requiere Python 3.11+; actualiza Python o usa los flags de CLI"
            )
        if path is None:
            if not Path(CONFIG_FILENAME).exists():
                return None
            path = CONFIG_FILENAME
        try:
            raw = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"no se puede leer {path}: {exc}") from None
        try:
            document = tomllib.loads(raw)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"TOML inválido en {path}: {exc}") from None
        return cls(document)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        """Build a Config directly from a parsed document (tests/API)."""
        return cls(data)

    def _validate(self) -> None:
        profiles = self._data.get("profiles", {})
        if not isinstance(profiles, dict):
            raise ConfigError("profiles debe ser una tabla [profiles.<nombre>]")
        for section, content in self._data.items():
            if section == "profiles":
                for name, body in profiles.items():
                    if not isinstance(body, dict):
                        raise ConfigError(
                            f"profiles.{name} debe ser una tabla de secciones"
                        )
                    for sub, subbody in body.items():
                        if sub not in VALID_SECTIONS:
                            raise ConfigError(
                                f"sección desconocida [profiles.{name}.{sub}]; "
                                f"válidas: {sorted(VALID_SECTIONS)}"
                            )
                        self._validate_body(f"profiles.{name}.{sub}", subbody)
                continue
            self._validate_body(section, content)

    def _validate_body(self, prefix: str, body: Any) -> None:
        if not isinstance(body, dict):
            raise ConfigError(f"{prefix} debe ser una tabla [section]")
        section = prefix.split(".")[-1]
        if section not in VALID_SECTIONS:
            raise ConfigError(
                f"sección desconocida [{prefix}]; válidas: "
                f"{sorted(VALID_SECTIONS)} + [profiles.<nombre>]"
            )
        for key, value in body.items():
            if key not in VALID_SECTIONS[section]:
                raise ConfigError(
                    f"clave desconocida {_qual(section, key)}; válidas: "
                    f"{sorted(VALID_SECTIONS[section])}"
                )
            if key in _BOOL_KEYS:
                _check_bool(prefix, key, value)
            elif key == "depth":
                if value not in VALID_DEPTH:
                    raise ConfigError(
                        f"depth debe ser uno de {VALID_DEPTH}, no {value!r}"
                    )
            elif key == "modules":
                _check_str_list(prefix, key, value)
            elif key == "monitor_interval":
                _check_positive_int(prefix, key, value)
            elif key in ("includes", "excludes", "formats"):
                _check_str_list(prefix, key, value)

    def validate_modules(self, valid_modules: Iterable[str]) -> Config:
        """Cross-check [scan].modules against the module catalogue."""
        for module in self._data.get("scan", {}).get("modules", []) or []:
            if module not in valid_modules:
                raise ConfigError(
                    f"módulo desconocido {module!r}; válidos: {sorted(valid_modules)}"
                )
        return self

    def validate_export_formats(self) -> Config:
        for fmt in self._data.get("exports", {}).get("formats", []) or []:
            if fmt not in VALID_EXPORT_FORMATS:
                raise ConfigError(
                    f"formato de exportación desconocido {fmt!r}; válidos: "
                    f"{sorted(VALID_EXPORT_FORMATS)}"
                )
        return self

    # ── profiles ────────────────────────────────────────────────────────
    def has_profile(self, name: str) -> bool:
        return name in self._data.get("profiles", {})

    def apply_profile(self, name: str) -> Config:
        """Config with ``[profiles.<name>]`` overlaid on the top level.

        ``"default"`` always exists: without a ``[profiles.default]``
        table it simply returns the top-level configuration.
        """
        profiles = self._data.get("profiles", {})
        if name != "default" and name not in profiles:
            raise ConfigError(
                f"perfil {name!r} no existe; definidos: {sorted(profiles) or 'ninguno'}"
            )
        merged = copy.deepcopy(self._data)
        if name == "default":
            return Config(merged)
        overlay = copy.deepcopy(profiles[name])
        for section, body in overlay.items():
            if section in ("scan", "timeouts", "scope", "exports") and isinstance(
                merged.get(section), dict
            ):
                merged[section] = {**merged[section], **body}
            else:
                merged[section] = body
        return Config(merged)

    # ── typed accessors (None = not configured) ─────────────────────────
    @property
    def depth(self) -> str | None:
        return cast("str | None", self._data.get("scan", {}).get("depth"))

    @property
    def stealth(self) -> bool | None:
        return cast("bool | None", self._data.get("scan", {}).get("stealth"))

    @property
    def no_ai(self) -> bool | None:
        return cast("bool | None", self._data.get("scan", {}).get("no_ai"))

    @property
    def no_cache(self) -> bool | None:
        return cast("bool | None", self._data.get("scan", {}).get("no_cache"))

    @property
    def modules(self) -> list[str] | None:
        return cast("list[str] | None", self._data.get("scan", {}).get("modules"))

    @property
    def monitor_interval(self) -> int | None:
        return cast(
            "int | None", self._data.get("timeouts", {}).get("monitor_interval")
        )

    @property
    def scope_includes(self) -> list[str] | None:
        return cast("list[str] | None", self._data.get("scope", {}).get("includes"))

    @property
    def scope_excludes(self) -> list[str] | None:
        return cast("list[str] | None", self._data.get("scope", {}).get("excludes"))

    @property
    def export_formats(self) -> list[str] | None:
        return cast("list[str] | None", self._data.get("exports", {}).get("formats"))

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(self._data)
