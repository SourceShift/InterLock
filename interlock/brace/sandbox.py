"""BRACE: the Agent Control Environment facade.

This is the one class a caller touches. Give it a confinement profile (write one
directly, or compile one from a subject's policy with
:func:`~interlock.brace.profile.compile_profile`) and it will:

1. pick the strongest containment backend the host offers, unless you pin one;
2. put the launch through the policy engine as a ``process_spawn`` event, so a
   rule can block or rewrite it before any process starts;
3. run the command under the backend's confinement;
4. hand back a :class:`~interlock.brace.result.SandboxResult` that reports which
   containment guarantees actually held, so a caller that needs real isolation
   can refuse a silent downgrade to the soft backend.

Example::

    from interlock.brace import Sandbox, compile_profile

    profile = compile_profile(registry.resolve(("root", "acme", "agent42")))
    result = Sandbox(profile).run(["python", "worker.py"])
    if "net" not in result.enforced:
        raise RuntimeError("refusing to run untrusted code with open network")
"""
from __future__ import annotations

import subprocess
from typing import List, Optional

from ..policy.engine import PolicyEngine
from .backends import select_backend
from .profile import SandboxProfile
from .result import SandboxResult
from .trace import check_spawn, record_exit


class Sandbox:
    def __init__(
        self,
        profile: Optional[SandboxProfile] = None,
        *,
        backend: Optional[str] = None,
        engine: Optional[PolicyEngine] = None,
        enforcement: str = "blocking",
        principal: Optional[str] = None,
    ):
        self.profile = profile or SandboxProfile.locked()
        self._backend = select_backend(backend)
        self._engine = engine
        self._enforcement = enforcement
        self._principal = principal

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
        """Check, confine, and run ``argv``. Raises ``Blocked`` if policy denies it."""
        if not argv:
            raise ValueError("argv must be non-empty")

        checked = check_spawn(
            argv,
            self.profile,
            engine=self._engine,
            enforcement=self._enforcement,
            principal=self._principal,
        )

        plan = self._backend.wrap(self.profile, checked)
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
