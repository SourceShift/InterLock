"""Backend registry and auto-selection.

Selection prefers real kernel-enforced isolation and falls back to the soft
backend only when nothing better is present. The order is deliberate: bubblewrap
on Linux, Seatbelt on macOS, and the soft backend last so the API always works,
just with the honest downgrade in what it can enforce.
"""
from __future__ import annotations

from typing import List, Optional, Type

from .base import Backend, WrapPlan
from .bubblewrap import BubblewrapBackend
from .sandbox_exec import SandboxExecBackend
from .soft import SoftBackend

# Highest-isolation first. SoftBackend is always available and always last.
_ORDER: List[Type[Backend]] = [
    BubblewrapBackend,
    SandboxExecBackend,
    SoftBackend,
]

_BY_NAME = {cls.name: cls for cls in _ORDER}


def available_backends() -> List[str]:
    """Names of backends usable on this host, best isolation first."""
    return [cls.name for cls in _ORDER if cls.is_available()]


def select_backend(prefer: Optional[str] = None) -> Backend:
    """Return a backend instance.

    With ``prefer`` set, return that named backend if it exists and is available,
    otherwise raise. With no preference, return the strongest available one.
    """
    if prefer is not None:
        cls = _BY_NAME.get(prefer)
        if cls is None:
            raise ValueError("unknown backend: {}".format(prefer))
        if not cls.is_available():
            raise RuntimeError("backend not available on this host: {}".format(prefer))
        return cls()
    for cls in _ORDER:
        if cls.is_available():
            return cls()
    return SoftBackend()  # unreachable: soft is always available


__all__ = [
    "Backend",
    "WrapPlan",
    "BubblewrapBackend",
    "SandboxExecBackend",
    "SoftBackend",
    "available_backends",
    "select_backend",
]
