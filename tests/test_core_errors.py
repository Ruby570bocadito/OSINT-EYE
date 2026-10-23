"""Tests for the own exception hierarchy (core/errors.py) — 100% offline.

Covers: subclass topology, catching everything through the OsintEyeError
base, ModuleError attributes (module tag, message formatting, cause
chaining), pickle round-trips (errors cross process boundaries in the
async engine), and that none of the new classes accidentally inherits
from ValueError/KeyError/OSError (which would change existing except
clauses on adoption).
"""

import os
import pickle
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.errors import (  # noqa: E402
    CacheError,
    ConfigurationError,
    ExportError,
    ModuleError,
    NetworkError,
    OsintEyeError,
)

ALL_ERRORS = [ModuleError, NetworkError, ConfigurationError, ExportError, CacheError]


def _make(error_cls):
    """Instancia canónica de cada error (ModuleError lleva etiqueta de módulo)."""
    if error_cls is ModuleError:
        return error_cls("dns", "fallo genérico")
    return error_cls("fallo genérico")


# ── topology ────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("error_cls", ALL_ERRORS)
def test_every_error_is_an_osint_eye_error(error_cls):
    assert issubclass(error_cls, OsintEyeError)


def test_base_is_an_exception_not_valueerror():
    assert issubclass(OsintEyeError, Exception)
    assert not issubclass(OsintEyeError, ValueError)
    assert not issubclass(OsintEyeError, KeyError)
    assert not issubclass(OsintEyeError, OSError)


@pytest.mark.parametrize("error_cls", ALL_ERRORS)
def test_no_accidental_builtin_base(error_cls):
    for builtin in (ValueError, KeyError, OSError, TypeError):
        assert not issubclass(error_cls, builtin), error_cls.__name__


# ── catching through the base ───────────────────────────────────────────────
@pytest.mark.parametrize("error_cls", ALL_ERRORS)
def test_base_catch_allows_one_handler_per_zone(error_cls):
    with pytest.raises(OsintEyeError):
        raise _make(error_cls)


@pytest.mark.parametrize("builtin_handler", [ValueError, TypeError, KeyError, OSError])
def test_own_errors_are_not_caught_by_builtin_handlers(builtin_handler):
    with pytest.raises(OsintEyeError):
        try:
            raise OsintEyeError("error deliberado")
        except builtin_handler:
            pass  # pragma: no cover — solo se llega si la jerarquía está rota


# ── ModuleError specifics ───────────────────────────────────────────────────
def test_module_error_prefixes_the_module_tag():
    error = ModuleError("dns", "resolver agotado")
    assert error.module == "dns"
    assert str(error) == "[dns] resolver agotado"


def test_module_error_without_module_tag():
    error = ModuleError("", "fallo sin zona")
    assert error.module == ""
    assert str(error) == "fallo sin zona"


def test_module_error_chains_the_original_cause():
    original = ConnectionError("connection reset by peer")
    try:
        raise original
    except ConnectionError:
        with pytest.raises(ModuleError) as exc_info:
            # El raise implícito (sin from) es justo lo que se verifica: el
            # encadenamiento automático de __context__ dentro de un handler.
            raise ModuleError("web", "petición fallida", cause=original)  # noqa: B904
    error = exc_info.value
    assert error.__cause__ is original
    assert error.__context__ is original


def test_module_error_is_catchable_as_module_error_and_base():
    with pytest.raises(ModuleError):
        try:
            raise ModuleError("cve", "api sin clave")
        except OsintEyeError:
            raise


# ── messaging ───────────────────────────────────────────────────────────────
def test_plain_errors_keep_the_exact_message():
    for error_cls in (NetworkError, ConfigurationError, ExportError, CacheError):
        assert str(error_cls("mensaje de prueba")) == "mensaje de prueba"


def test_module_error_message_contains_the_zone():
    assert "scope" in str(ModuleError("scope", "entrada rota"))


# ── pickle (errors travel between processes / threads) ─────────────────────
@pytest.mark.parametrize("error_cls", ALL_ERRORS)
def test_pickle_round_trip(error_cls):
    original = _make(error_cls)
    clone = pickle.loads(pickle.dumps(original))
    assert type(clone) is type(original)
    assert str(clone) == str(original)


def test_pickle_preserves_module_error_attributes():
    original = ModuleError("graph", "neo4j caído")
    clone = pickle.loads(pickle.dumps(original))
    assert clone.module == "graph"
    assert str(clone) == "[graph] neo4j caído"
