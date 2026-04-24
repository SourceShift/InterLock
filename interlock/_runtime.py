"""Process-global engine the @guard decorator consults at call time."""
from __future__ import annotations

from typing import Optional

from .policy.engine import PolicyEngine

_engine: Optional[PolicyEngine] = None


def set_engine(engine: PolicyEngine) -> None:
    global _engine
    _engine = engine


def get_engine() -> PolicyEngine:
    """Return the installed engine, or an empty allow-all engine if none set."""
    global _engine
    if _engine is None:
        _engine = PolicyEngine()
    return _engine
