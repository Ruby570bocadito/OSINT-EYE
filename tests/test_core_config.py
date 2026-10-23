"""Tests for TOML configuration (core/config.py + CLI wiring) — offline.

Covers: validation (sections, keys, types), loading (auto-detect, explicit
path, invalid TOML), profiles, typed accessors, CLI precedence
(config fills CLI defaults, explicit flags win), [scope] → Scope, and
export format selection in export_all.
"""

import argparse
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.config import (  # noqa: E402
    CONFIG_FILENAME,
    VALID_EXPORT_FORMATS,
    Config,
    ConfigError,
)
from osint_eye import (  # noqa: E402
    MODULE_CATALOG,
    _apply_config_to_args,
    build_scope_from_config,
)


VALID_DOC = {
    "scan": {"depth": "quick", "stealth": True, "modules": ["dns", "certs"]},
    "timeouts": {"monitor_interval": 600},
    "scope": {"includes": ["example.com"], "excludes": ["10.0.0.0/8"]},
    "exports": {"formats": ["json", "sarif"]},
}


class TestValidation:
    def test_valid_document_round_trips(self):
        config = Config.from_dict(VALID_DOC)
        assert config.depth == "quick"
        assert config.stealth is True
        assert config.modules == ["dns", "certs"]
        assert config.monitor_interval == 600
        assert config.export_formats == ["json", "sarif"]

    def test_unset_keys_are_none(self):
        config = Config.from_dict({})
        assert config.depth is None
        assert config.stealth is None
        assert config.modules is None
        assert config.scope_includes is None
        assert config.export_formats is None

    def test_unknown_section_rejected(self):
        with pytest.raises(ConfigError, match="sección desconocida"):
            Config.from_dict({"scann": {"depth": "quick"}})

    def test_unknown_key_rejected(self):
        with pytest.raises(ConfigError, match="clave desconocida scan.tiemout"):
            Config.from_dict({"scan": {"tiemout": 5}})

    def test_invalid_depth_rejected(self):
        with pytest.raises(ConfigError, match="depth"):
            Config.from_dict({"scan": {"depth": "mega"}})

    def test_bool_keys_must_be_bool(self):
        with pytest.raises(ConfigError, match="booleano"):
            Config.from_dict({"scan": {"stealth": "yes"}})

    def test_monitor_interval_must_be_positive(self):
        with pytest.raises(ConfigError, match="entero positivo"):
            Config.from_dict({"timeouts": {"monitor_interval": -5}})
        with pytest.raises(ConfigError):
            Config.from_dict({"timeouts": {"monitor_interval": True}})

    def test_lists_of_strings_only(self):
        with pytest.raises(ConfigError, match="lista de strings"):
            Config.from_dict({"scope": {"includes": ["ok.com", 42]}})

    def test_module_catalogue_crosscheck(self):
        config = Config.from_dict({"scan": {"modules": ["dns", "nope"]}})
        with pytest.raises(ConfigError, match="módulo desconocido"):
            config.validate_modules(MODULE_CATALOG)
        valid = Config.from_dict({"scan": {"modules": ["dns", "web"]}})
        assert valid.validate_modules(MODULE_CATALOG) is valid

    def test_export_format_crosscheck(self):
        config = Config.from_dict({"exports": {"formats": ["json", "docx"]}})
        with pytest.raises(ConfigError, match="formato de exportación"):
            config.validate_export_formats()


class TestLoading:
    def test_no_file_autodetected_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert Config.load(None) is None

    def test_autodetect_reads_cwd_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / CONFIG_FILENAME).write_text(
            '[scan]\ndepth = "deep"\n', encoding="utf-8"
        )
        config = Config.load(None)
        assert config.depth == "deep"

    def test_missing_explicit_path_raises(self, tmp_path):
        with pytest.raises(ConfigError, match="no se puede leer"):
            Config.load(str(tmp_path / "nope.toml"))

    def test_invalid_toml_raises(self, tmp_path):
        bad = tmp_path / "broken.toml"
        bad.write_text("[scan\nbroken", encoding="utf-8")
        with pytest.raises(ConfigError, match="TOML inválido"):
            Config.load(str(bad))


class TestProfiles:
    def test_profile_overrides_sections_and_keeps_rest(self):
        config = Config.from_dict(
            {
                **VALID_DOC,
                "profiles": {
                    "ci": {"scan": {"depth": "full", "stealth": False}},
                },
            }
        )
        merged = config.apply_profile("ci")
        assert merged.depth == "full"
        assert merged.stealth is False  # profile wins over top-level
        assert merged.modules == ["dns", "certs"]  # untouched key survives
        assert merged.export_formats == ["json", "sarif"]
        # the original config object is not mutated
        assert config.depth == "quick"

    def test_unknown_profile_rejected(self):
        config = Config.from_dict(VALID_DOC)
        with pytest.raises(ConfigError, match="perfil 'ci' no existe"):
            config.apply_profile("ci")

    def test_default_profile_needs_no_section(self):
        config = Config.from_dict(VALID_DOC)
        assert config.apply_profile("default").to_dict() == VALID_DOC


class TestCLIPrecedence:
    def _parser(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--depth", default="normal")
        parser.add_argument("--stealth", action="store_true")
        parser.add_argument("--no-ai", dest="no_ai", action="store_true")
        parser.add_argument("--no-cache", dest="no_cache", action="store_true")
        parser.add_argument("--monitor-interval", dest="monitor_interval", type=int, default=3600)
        parser.add_argument("--modules", nargs="*", default=None)
        return parser

    def test_config_fills_untouched_defaults(self):
        parser = self._parser()
        args = parser.parse_args([])
        config = Config.from_dict(VALID_DOC)
        _apply_config_to_args(args, config, parser)
        assert args.depth == "quick"
        assert args.stealth is True
        assert args.modules == ["dns", "certs"]

    def test_explicit_cli_flags_win(self):
        parser = self._parser()
        args = parser.parse_args(["--depth", "full", "--stealth"])
        config = Config.from_dict(VALID_DOC)
        _apply_config_to_args(args, config, parser)
        assert args.depth == "full"  # user flag survives
        assert args.stealth is True  # same value, no harm

    def test_monitor_interval_from_config(self):
        parser = self._parser()
        args = parser.parse_args([])
        config = Config.from_dict({"timeouts": {"monitor_interval": 60}})
        _apply_config_to_args(args, config, parser)
        assert args.monitor_interval == 60

    def test_export_formats_always_applied(self):
        parser = self._parser()
        args = parser.parse_args([])
        config = Config.from_dict({"exports": {"formats": ["json"]}})
        _apply_config_to_args(args, config, parser)
        assert args.export_formats == ["json"]


class TestScopeFromConfig:
    def test_scope_built_from_config(self):
        config = Config.from_dict(VALID_DOC)
        scope = build_scope_from_config(config)
        assert scope.allows("www.example.com")
        assert not scope.allows("10.1.2.3")

    def test_none_when_unconfigured(self):
        assert build_scope_from_config(Config.from_dict({})) is None


class TestExportFormatSelection:
    def test_export_all_honours_subset(self, tmp_path, monkeypatch):
        from osint_eye import OSINTEye

        monkeypatch.chdir(tmp_path)
        engine = OSINTEye(target="example.com", ai=False, cache=False)
        exports = engine.export_all(
            str(tmp_path / "scan"), formats=["json", "sarif"]
        )
        assert set(exports) == {"json", "sarif"}

    def test_export_all_rejects_unknown_format(self, tmp_path, monkeypatch):
        from osint_eye import OSINTEye

        monkeypatch.chdir(tmp_path)
        engine = OSINTEye(target="example.com", ai=False, cache=False)
        with pytest.raises(ValueError, match="formatos de exportación desconocidos"):
            engine.export_all(str(tmp_path / "scan"), formats=["docx"])

    def test_catalogue_matches_config_valid_formats(self):
        from osint_eye import _EXPORT_FORMATS

        assert set(_EXPORT_FORMATS) == set(VALID_EXPORT_FORMATS)


class TestCLIWiring:
    def _run_cli(self, *cli_args, cwd=None):
        import subprocess

        env = dict(os.environ)
        env["PYTHONPATH"] = os.path.join(os.path.dirname(__file__), "..")
        return subprocess.run(
            [sys.executable, "osint_eye.py", *cli_args],
            capture_output=True,
            text=True,
            env=env,
            cwd=cwd or os.path.join(os.path.dirname(__file__), ".."),
            timeout=60,
        )

    def test_missing_config_file_is_usage_error(self, tmp_path):
        result = self._run_cli("example.com", "--config", str(tmp_path / "no.toml"))
        assert result.returncode == 2
        assert "config" in (result.stderr + result.stdout).lower()

    def test_invalid_toml_is_usage_error(self, tmp_path):
        bad = tmp_path / "broken.toml"
        bad.write_text("[scan\ndepth = ", encoding="utf-8")
        result = self._run_cli("example.com", "--config", str(bad))
        assert result.returncode == 2

    def test_profile_without_config_is_usage_error(self):
        result = self._run_cli("example.com", "--profile", "ci")
        assert result.returncode == 2
        assert "--profile" in (result.stderr + result.stdout)

    def test_valid_config_with_profile_accepted(self, tmp_path):
        cfg = tmp_path / "osint_eye.toml"
        cfg.write_text(
            '[scan]\ndepth = "quick"\n\n[profiles.ci]\n[profiles.ci.scan]\n'
            'depth = "full"\nmodules = ["dns"]\n',
            encoding="utf-8",
        )
        # --modules (sin valores) imprime el catálogo y sale 0: cruza la
        # carga de config y el perfil sin tocar la red.
        result = self._run_cli("--config", str(cfg), "--profile", "ci", "--modules")
        assert result.returncode == 0, result.stderr

    def test_config_scope_blocks_out_of_scope_target(self, tmp_path):
        cfg = tmp_path / "osint_eye.toml"
        cfg.write_text('[scope]\nincludes = ["example.com"]\n', encoding="utf-8")
        result = self._run_cli("evil.net", "--config", str(cfg))
        assert result.returncode == 3  # nothing scanned (exit-codes contract)
        assert "no target scanned" in (result.stdout + result.stderr)
