"""The backend contract.

A backend translates a :class:`~interlock.brace.profile.SandboxProfile` into a
concrete way to launch a command with that confinement. The translation is a
pure function, :meth:`Backend.wrap`, that returns a :class:`WrapPlan`: the argv
to actually exec, the keyword arguments for ``subprocess``, the list of
containment tokens the backend claims it will enforce, and an optional cleanup
callable. Keeping ``wrap`` free of side effects is what lets the tests assert on
the exact flags a backend would use without ever spawning a process.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from ..profile import SandboxProfile


@dataclass
class WrapPlan:
    """The executable form of a profile for one backend.

    exec_argv:    the full argv including any wrapper (``bwrap``, ``sandbox-exec``).
    popen_kwargs: extra kwargs for ``subprocess.run`` (env, cwd, preexec_fn).
    enforced:     containment tokens actually applied, surfaced on the result.
    cleanup:      called after the run to release any resource wrap allocated.
    """

    exec_argv: List[str]
    popen_kwargs: Dict[str, object] = field(default_factory=dict)
    enforced: List[str] = field(default_factory=list)
    cleanup: Optional[Callable[[], None]] = None


class Backend:
    """Base class. Subclasses set ``name`` and implement ``wrap``/``is_available``."""

    name: str = "base"

    @staticmethod
    def is_available() -> bool:
        return False

    def wrap(self, profile: SandboxProfile, argv: List[str]) -> WrapPlan:
        raise NotImplementedError
