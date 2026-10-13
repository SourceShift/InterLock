"""Resource ceilings for a sandboxed child, shared by every backend.

``cpu_seconds`` and ``memory_mb`` are POSIX rlimits set in the forked child just
before it execs. rlimits survive ``exec``, so the same hook works whether the
child is the target program itself (soft), ``bwrap``, or ``sandbox-exec``: the
wrapper inherits the ceiling and hands it to the program it launches.

A requested limit is never dropped silently. :func:`check_limits` refuses, up
front and with a reason, any limit the host cannot enforce, instead of letting
every launch fail later with an opaque ``SubprocessError`` (or, worse, run
without the ceiling the policy asked for).

Measured on macOS (Darwin 24, Apple Silicon): ``setrlimit`` on ``RLIMIT_AS``
(an alias of ``RLIMIT_RSS`` there) and on ``RLIMIT_DATA`` fails with EINVAL for
every value below roughly 1 TB, soft-only or soft == hard alike, because a
64-bit process has already reserved more address space than that. A ceiling
the kernel only accepts above 1 TB enforces nothing, so ``memory_mb`` is
refused on macOS rather than approximated.
"""
from __future__ import annotations

import sys
from typing import Callable, Optional

from .profile import SandboxProfile


class LimitUnsupported(RuntimeError):
    """A profile asks for a resource ceiling this host cannot enforce."""


def _platform_label(platform: str) -> str:
    return {"darwin": "macOS", "win32": "Windows"}.get(platform, platform)


def check_limits(profile: SandboxProfile, platform: Optional[str] = None) -> None:
    """Raise :class:`LimitUnsupported` if ``profile`` asks for a limit this host can't enforce.

    ``platform`` defaults to ``sys.platform``; it is a parameter so the decision
    can be tested for every host from any one of them.
    """
    platform = platform or sys.platform
    requested = [
        name for name, value in (
            ("cpu_seconds", profile.cpu_seconds),
            ("memory_mb", profile.memory_mb),
        )
        if value is not None
    ]
    if not requested:
        return
    if platform == "win32":
        raise LimitUnsupported(
            "{} cannot be enforced on Windows: there are no POSIX resource limits. "
            "Remove them from the profile (the sandbox_limits binding).".format(
                " and ".join(requested)
            )
        )
    if profile.memory_mb is not None and platform == "darwin":
        raise LimitUnsupported(
            "memory_mb={} cannot be enforced on {}: the kernel refuses RLIMIT_AS "
            "and RLIMIT_DATA below the ~1 TB of address space a 64-bit process "
            "already reserves. Remove memory_mb from the profile (the "
            "sandbox_limits binding), or run on Linux.".format(
                profile.memory_mb, _platform_label(platform)
            )
        )


def rlimit_preexec(
    cpu_seconds: Optional[int], memory_mb: Optional[int]
) -> Optional[Callable[[], None]]:
    """Build a ``preexec_fn`` that clamps CPU and address space in the child.

    Returns None when no limit is requested, and on platforms without the POSIX
    ``resource`` limits (Windows), so the caller simply gets no preexec hook.
    :func:`check_limits` is what turns that absence into a refusal.
    """
    if cpu_seconds is None and memory_mb is None:
        return None
    if sys.platform == "win32":
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
