"""The interlock cloud control plane.

The plane is split into three parts:

- the **control plane** -- the ASGI service and its Postgres schema, which
  holds organisations, reviews, policy manifests and audit events;
- the **data plane** -- the host-local hook and sidecar, which never import
  this package and keep enforcing the last good policy while the plane is
  unreachable;
- the **audit plane** -- the receipt chain and its checkpoints, uploaded from
  hosts and verified on arrival.

This package is deliberately dependency-free at import time: ``import
interlock.cloud`` must succeed under ``python3 -I`` with no site-packages, so
the ASGI server and the Postgres driver are imported only inside the functions
that use them. The package is not imported by the core guard; ``app`` and
``config`` are exposed lazily through this module's ``__getattr__``.
"""
from __future__ import annotations

import importlib
from typing import Any, List

__all__ = ["app", "config"]


def __getattr__(name: str) -> Any:
    if name in __all__:
        return importlib.import_module("." + name, __name__)
    raise AttributeError("module {!r} has no attribute {!r}".format(__name__, name))


def __dir__() -> List[str]:
    return sorted(list(globals()) + __all__)
