"""The portable fallback backend.

Every host has this one. It does not create namespaces or bind-mount anything,
so it is emphatically NOT a security boundary: code that wants to escape it can.
What it does buy is real and worth having as defence in depth:

- a scrubbed environment, so secrets in the parent's env do not leak into the
  child unless the profile explicitly grants them;
- CPU and address-space ceilings via ``resource.setrlimit``, so a runaway or a
  fork bomb hits a wall instead of taking the box down;
- a fixed working directory.

Treat it as the "reduce blast radius" tier, used when neither bubblewrap nor the
macOS sandbox is present. The :class:`~interlock.brace.result.SandboxResult` it
produces never claims the ``pid``, ``net``, or ``fs-ro``/``fs-rw`` tokens, so a
caller that requires true isolation can detect the downgrade and refuse.
"""
from __future__ import annotations

import sys
from typing import Callable, List, Optional

from ..profile import SandboxProfile
from .base import Backend, WrapPlan


def _rlimit_preexec(
    cpu_seconds: Optional[int], memory_mb: Optional[int]
) -> Optional[Callable[[], None]]:
    """Build a ``preexec_fn`` that clamps CPU and address space in the child.

    Returns None when no limit is requested, and on platforms without the POSIX
    ``resource`` limits (Windows), so the caller simply gets no preexec hook.
    """
    if cpu_seconds is None and memory_mb is None:
        return None
    try:
        import resource
    except ImportError:  # non-POSIX
        return None

    def _apply() -> None:  # runs in the forked child, before exec
        # The soft limit is the promise (SIGXCPU at ``cpu_seconds``); the hard
        # limit is the backstop for a child that catches or ignores SIGXCPU.
        #
        # They must DIFFER. Linux evaluates the hard limit first and with ``>=``
        # (kernel/time/posix-cpu-timers.c), so with soft == hard the hard branch
        # matches in the same pass and SIGKILL pre-empts the SIGXCPU the token
        # table advertises -- a runaway died by signal 9, not 24. macOS happens
        # to report SIGXCPU for soft == hard, which is why this only showed up
        # under CI. ``hard = soft + 1`` gives the documented SIGXCPU on both,
        # and still ends the child one second later if it swallows the signal.
        if cpu_seconds is not None:
            resource.setrlimit(
                resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1)
            )
        if memory_mb is not None:
            nbytes = memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (nbytes, nbytes))

    return _apply


class SoftBackend(Backend):
    name = "soft"

    @staticmethod
    def is_available() -> bool:
        return True  # always, by definition

    def wrap(self, profile: SandboxProfile, argv: List[str]) -> WrapPlan:
        enforced: List[str] = ["env"]
        popen_kwargs: dict = {"env": dict(profile.env)}

        if profile.workdir is not None:
            popen_kwargs["cwd"] = profile.workdir

        preexec = _rlimit_preexec(profile.cpu_seconds, profile.memory_mb)
        # preexec_fn only runs on POSIX; skip it on Windows to avoid a raise.
        if preexec is not None and sys.platform != "win32":
            popen_kwargs["preexec_fn"] = preexec
            enforced.append("rlimit")

        return WrapPlan(
            exec_argv=list(argv),
            popen_kwargs=popen_kwargs,
            enforced=enforced,
        )
