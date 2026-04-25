"""What a sandboxed run returns."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class SandboxResult:
    """The outcome of running an argv under a backend.

    backend:   which containment backend actually ran the command.
    argv:      the argv as it was executed inside the sandbox (not the wrapper).
    returncode: the child's exit status, or None if it was never started.
    stdout/stderr: captured child output (empty when not captured).
    enforced:  the containment guarantees the backend claims it applied, as
               short tokens ("pid", "net", "fs-ro", "fs-rw", "rlimit", "env").
               A caller can assert on this to fail closed when a backend
               silently degraded to weaker isolation than the profile asked for.
    """

    backend: str
    argv: List[str]
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    enforced: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.returncode == 0
