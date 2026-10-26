"""The host-side connector: config, transport, spool and the poll loop.

This package is the *only* part of interlock.cloud that opens a network
connection (FR-008). Nothing in the core guard imports it: the hook, the
review queue and the policy loader stay network-free, and ``interlock.cloud``
itself imports these modules lazily through :mod:`interlock.cli.cloud`.

Imports are kept cheap at package import: the submodules are stdlib-only and
are exported lazily through ``__getattr__`` so ``import
interlock.cloud.connector`` does not construct a spool or read a config.
"""
from __future__ import annotations

import importlib
from typing import Any, List

__all__ = ["config", "runner", "spool", "transport"]


def __getattr__(name: str) -> Any:
    if name in __all__:
        return importlib.import_module("." + name, __name__)
    raise AttributeError("module {!r} has no attribute {!r}".format(__name__, name))


def __dir__() -> List[str]:
    return sorted(list(globals()) + __all__)
