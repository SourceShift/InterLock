"""BRACE: the Agent Control Environment facade.

This is the one class a caller touches. Give it a confinement profile (write one
directly, or compile one from a subject's policy with
:func:`~interlock.brace.profile.compile_profile`) and it will:

1. pick the strongest containment backend the host offers, unless you pin one;
2. put the launch through the policy engine as a ``process_spawn`` event, so a
   rule can block or rewrite it before any process starts;
3. run the command under the backend's confinement;
4. hand back a :class:`~interlock.brace.result.SandboxResult` that reports which
   containment guarantees actually held.

A caller that needs real isolation should say so up front with ``require=``:
``run()`` then refuses, before any process starts, when the chosen backend
cannot deliver every required token (a silent downgrade to the soft backend is
the case this exists for). Checking ``result.enforced`` after ``run()`` reports
the same thing, but only once the untrusted code has already run.

Example::

    from interlock.brace import Sandbox, compile_profile

    profile = compile_profile(registry.resolve(("root", "acme", "agent42")))
    result = Sandbox(profile, require=("net", "fs-rw")).run(["python", "worker.py"])
    # raises IsolationUnavailable, without starting worker.py, on a host that
    # can only offer the soft backend
"""
from __future__ import annotations

import subprocess
from typing import FrozenSet, Iterable, List, Optional, Tuple

from ..policy.engine import PolicyEngine
from .backends import select_backend
from .limits import check_limits
from .profile import SandboxProfile
from .result import SandboxResult
from .trace import check_spawn, record_exit

# Every token a backend can report in ``enforced``. ``require=`` is checked
# against this set so a typo ("netw") fails when the Sandbox is built instead of
# refusing every run with a token no backend could ever claim.
KNOWN_TOKENS: FrozenSet[str] = frozenset({"env", "rlimit", "fs-ro", "fs-rw", "pid", "net"})


class IsolationUnavailable(RuntimeError):
    """The backend cannot enforce a token the caller required; nothing was run."""

    def __init__(self, backend: str, missing: List[str], enforced: List[str]):
        self.backend = backend
        self.missing = missing
        self.enforced = enforced
        super().__init__(
            "refusing to run: the {} backend cannot enforce {} for this profile "
            "(it enforces {})".format(backend, missing, sorted(enforced))
        )


class Sandbox:
    def __init__(
        self,
        profile: Optional[SandboxProfile] = None,
        *,
        backend: Optional[str] = None,
        engine: Optional[PolicyEngine] = None,
        enforcement: str = "blocking",
        principal: Optional[str] = None,
        require: Iterable[str] = (),
    ):
        """Build a sandbox for ``profile`` on ``backend`` (the strongest available by default).

        ``require`` lists ``enforced`` tokens that must hold (for example
        ``("net", "fs-rw")``). ``run()`` raises :class:`IsolationUnavailable`
        before spawning anything when the backend can't deliver one of them.

        Raises ``ValueError`` for an unknown ``require`` token, and
        :class:`~interlock.brace.limits.LimitUnsupported` when the profile asks
        for a resource limit this host cannot enforce (``memory_mb`` on macOS,
        any limit on Windows), instead of failing on every launch later.
        """
        self.profile = profile or SandboxProfile.locked()
        self._backend = select_backend(backend)
        self._engine = engine
        self._enforcement = enforcement
        self._principal = principal
        if isinstance(require, str):
            require = (require,)  # a bare token, not its characters
        self.require: Tuple[str, ...] = tuple(require)
        unknown = sorted(set(self.require) - KNOWN_TOKENS)
        if unknown:
            raise ValueError(
                "unknown required token(s) {}; known tokens are {}".format(
                    unknown, sorted(KNOWN_TOKENS)
                )
            )
        check_limits(self.profile)

    @property
    def backend_name(self) -> str:
        return self._backend.name

    def plan(self, argv: List[str]):
        """Return the backend's :class:`WrapPlan` without running anything.

        Useful for inspection and for the tests: you can see the exact wrapped
        argv a run would execute without spawning a process.
        """
        return self._backend.wrap(self.profile, argv)

    def run(
        self,
        argv: List[str],
        *,
        capture_output: bool = True,
        timeout: Optional[float] = None,
    ) -> SandboxResult:
        """Check, confine, and run ``argv``.

        Raises ``Blocked`` if policy denies the launch, and
        :class:`IsolationUnavailable` if a ``require``d token can't be enforced.
        Either way no process is started.
        """
        if not argv:
            raise ValueError("argv must be non-empty")
        check_limits(self.profile)  # the profile may have been swapped since __init__

        checked = check_spawn(
            argv,
            self.profile,
            engine=self._engine,
            enforcement=self._enforcement,
            principal=self._principal,
        )

        plan = self._backend.wrap(self.profile, checked)
        missing = [t for t in self.require if t not in plan.enforced]
        if missing:
            if plan.cleanup is not None:
                plan.cleanup()
            raise IsolationUnavailable(self._backend.name, missing, list(plan.enforced))
        try:
            completed = subprocess.run(
                plan.exec_argv,
                capture_output=capture_output,
                text=True,
                timeout=timeout,
                **plan.popen_kwargs,
            )
        finally:
            if plan.cleanup is not None:
                plan.cleanup()

        record_exit(self._backend.name, checked, completed.returncode)
        return SandboxResult(
            backend=self._backend.name,
            argv=checked,
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
            enforced=plan.enforced,
        )
