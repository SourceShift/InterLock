"""Policy compilation and signed distribution (C5).

The control plane compiles authored bindings once, stores the artifact by
sha256, and publishes a signed manifest that names it.  The host verifies the
manifest, fetches the artifact by hash and swaps it atomically.  Nothing in
this package imports a rules module at package import time: the compiler and
the host resolve a ``module:attr`` spec only when they actually compile or load
an artifact.

Submodules are exported lazily so ``import interlock.cloud.policy`` stays
cheap and side-effect free.
"""
from __future__ import annotations

import importlib
from typing import Any, List

__all__ = ["compile", "manifest"]


def __getattr__(name: str) -> Any:
    if name in __all__:
        return importlib.import_module("." + name, __name__)
    raise AttributeError("module {!r} has no attribute {!r}".format(__name__, name))


def __dir__() -> List[str]:
    return sorted(list(globals()) + __all__)
