"""BRACE: the interlock Agent Control Environment.

A confinement layer that runs an agent's shell-outs and tool subprocesses under
kernel-enforced isolation whose rules are compiled from the same interlock policy
that governs the agent's in-process actions. One policy, two enforcement points:
the detectors intercept the calls interlock can see, and BRACE confines the
processes it cannot.

The backend is chosen for the host at runtime: bubblewrap on Linux, Seatbelt on
macOS, and a soft rlimits-and-scrubbed-env fallback everywhere else. The soft
fallback is honest about not being a security boundary, and the result object
reports which guarantees actually held so a caller can fail closed.
"""
from __future__ import annotations

from .backends import available_backends, select_backend
from .profile import SandboxProfile, compile_profile
from .result import SandboxResult
from .sandbox import Sandbox

__all__ = [
    "Sandbox",
    "SandboxProfile",
    "SandboxResult",
    "compile_profile",
    "available_backends",
    "select_backend",
]
