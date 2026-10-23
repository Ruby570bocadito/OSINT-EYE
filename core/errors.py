"""Own exception hierarchy for OSINT EYE.

One base class for every error the tool raises on purpose, so callers can
distinguish "OSINT EYE said no" (bad config, out-of-scope target, failed
module) from accidental bugs (``TypeError``, ``AttributeError``...) with a
single ``except OsintEyeError``.

Planned adoption (later phases, one zone at a time, each keeping the full
offline suite green):

* :class:`ModuleError` — module wrappers catch transport/parsing noise and
  re-raise as ``ModuleError("dns", ...)``; the orchestrator reports the
  failure and keeps scanning the rest of the modules.
* :class:`NetworkError` — the shared HTTP client turns timeouts, connect
  errors and bad responses into one catchable type per request.
* :class:`ConfigurationError` — CLI/config/wizard usage errors surface with
  a clean message and exit code 2 instead of a traceback.
* :class:`ExportError` — reporters (JSON/MD/HTML/PDF/SARIF/...) wrap write
  failures so a broken export never discards the scan results.
* :class:`CacheError` — the SQLite cache degrades gracefully: read/write
  issues log and continue, never kill a scan.

The existing domain errors (``ConfigError``, ``ScopeError``,
``ResultsSchemaError``) intentionally keep their ``ValueError`` base for
now: re-parenting them would silently change every ``except ValueError``
out there, and that is not a behaviour-neutral refactor.
"""

from __future__ import annotations


class OsintEyeError(Exception):
    """Base class for every deliberate OSINT EYE error."""


class ModuleError(OsintEyeError):
    """One scanner module failed; the scan continues with the rest."""

    def __init__(self, module: str, message: str, cause: BaseException | None = None):
        text = f"[{module}] {message}" if module else message
        super().__init__(text)
        self.module = module
        self.message = message
        if cause is not None:
            self.__cause__ = cause

    def __reduce__(self) -> tuple[type[ModuleError], tuple[str, str]]:
        # Default exception unpickling would replay cls(*args) with the
        # single formatted message and crash on the 2-arg signature. The
        # cause stays behind on purpose: traceback chaining is process-local.
        return (self.__class__, (self.module, self.message))


class NetworkError(OsintEyeError):
    """Transport-level failure (timeout, connect error, bad status)."""


class ConfigurationError(OsintEyeError):
    """Invalid flags, config file or wizard input; clean usage error."""


class ExportError(OsintEyeError):
    """A report/export could not be written; scan results stay intact."""


class CacheError(OsintEyeError):
    """SQLite cache failure; callers must degrade gracefully."""
