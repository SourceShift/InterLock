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
from typing import List

from ..limits import rlimit_preexec
from ..profile import SandboxProfile
from .base import Backend, WrapPlan


# Kept as an alias: the rlimit hook now lives in ``interlock.brace.limits`` and
# is shared by every backend, not only this one.
_rlimit_preexec = rlimit_preexec


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

        preexec = rlimit_preexec(profile.cpu_seconds, profile.memory_mb)
        # preexec_fn only runs on POSIX; skip it on Windows to avoid a raise.
        if preexec is not None and sys.platform != "win32":
            popen_kwargs["preexec_fn"] = preexec
            enforced.append("rlimit")

        return WrapPlan(
            exec_argv=list(argv),
            popen_kwargs=popen_kwargs,
            enforced=enforced,
        )
