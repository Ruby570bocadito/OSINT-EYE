"""Scope enforcement for targets derived inside collector modules.

Collectors derive hostnames and URLs from external data: wordlist
bruteforce, permutation engines, JS file links, bucket name patterns.
Everything a module is about to *touch* (resolve, request, probe) must
pass the operator scope built by ``core.scope``; rejected targets land
in the discard audit log (``Scope.discarded``, surfaced as
``results["scope"]`` by the core) so runs stay auditable.

The scope object is used duck-typed (``allows()`` plus optional
``discard()``) so collector modules stay decoupled from core; a
``None`` scope means "no filter", which keeps every module's public
behaviour unchanged for existing callers and tests.
"""

from typing import List


def allowed(scope, target: str, module: str = "") -> bool:
    """True when ``target`` may be touched; logs the rejection otherwise.

    ``scope=None`` short-circuits to True. A misbehaving scope object
    fails *closed* (target skipped, never touched) instead of crashing
    the scan mid-collection; the rejection is recorded via
    ``scope.discard()`` when that call is available.
    """
    if scope is None:
        return True
    try:
        ok = bool(scope.allows(target))
    except Exception:
        ok = False
    if ok:
        return True
    discard = getattr(scope, "discard", None)
    if callable(discard):
        try:
            discard(target, module)
        except Exception:
            pass
    return False


def apply_scope(scope, targets, module: str = "") -> List[str]:
    """Return the subset of ``targets`` inside scope, order preserved.

    ``scope=None`` returns a copy of ``targets`` unchanged.
    """
    if scope is None:
        return list(targets)
    return [t for t in targets if allowed(scope, t, module)]
