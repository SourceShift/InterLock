"""The macOS backend: Seatbelt via ``sandbox-exec``.

macOS has no user namespaces, but it does have Seatbelt, the same sandbox
technology that confines App Store apps, reachable from the command line through
``sandbox-exec``. You hand it a policy written in SBPL (a small Scheme-like
language) and it applies that policy to the process it launches.

A caveat stated plainly: Apple has marked ``sandbox-exec`` deprecated for years,
and SBPL is undocumented. It is nonetheless present and working on current macOS,
and it is the only zero-dependency way to get kernel-enforced confinement on a
Mac, so it is worth using while being honest that it is not a supported API.

What this backend actually enforces, and what it does not:

- **Writes are confined.** The profile denies ``file-write*`` by default and
  re-grants it only for the profile's ``write_paths`` (plus the temp dirs a
  runtime needs for scratch). A process cannot write the user's home or system
  config. This is verified: writing outside the grant returns "Operation not
  permitted".
- **Network is confined.** ``network*`` is granted only when the profile allows
  network at all. Host-granular egress is the nftables backend's job.
- **Reads are NOT confined.** dyld on Apple Silicon needs broad read access to
  the shared cache just to start a binary, and narrowing it reliably is not
  practical, so the profile allows ``file-read*``. The result object therefore
  does not claim an ``fs-ro`` token on this backend, so a caller that truly needs
  read confinement can see it is absent and fall back to bubblewrap on Linux.
"""
from __future__ import annotations

import os
import shutil
from typing import List, Tuple

from ..profile import SandboxProfile
from .base import Backend, WrapPlan

# Scratch locations a macOS runtime needs to write to even under confinement.
# /var/folders is where tempfile.mkdtemp lands (as /private/var/folders once the
# /var -> /private/var symlink is resolved).
BASE_WRITE: Tuple[str, ...] = (
    "/private/tmp",
    "/private/var/folders",
    "/dev",
)


def _canonical(paths: Tuple[str, ...]) -> Tuple[str, ...]:
    """Resolve /tmp -> /private/tmp etc. so Seatbelt subpath matching lines up."""
    return tuple(os.path.realpath(p) for p in paths)


def build_profile(profile: SandboxProfile) -> str:
    """Return the SBPL profile string. Pure over the paths it is given.

    Callers that want /tmp-style paths matched should hand in already-canonical
    (realpath'd) ``write_paths``; :class:`SandboxExecBackend` does this.
    """
    writes = BASE_WRITE + tuple(profile.write_paths)
    write_grant = " ".join('(subpath "{}")'.format(p) for p in writes)
    lines = [
        "(version 1)",
        "(deny default)",
        "(allow process*)",
        "(allow sysctl-read)",
        "(allow mach*)",
        "(allow file-read*)",
        "(allow file-map-executable)",
        "(allow file-write* {})".format(write_grant),
    ]
    if profile.allow_network:
        lines.append("(allow network*)")
    return "".join(lines)


def build_argv(profile: SandboxProfile, argv: List[str]) -> Tuple[List[str], List[str]]:
    """Return ``(sandbox_exec_argv, enforced_tokens)``. Pure over its inputs."""
    prof = build_profile(profile)
    exec_argv = ["sandbox-exec", "-p", prof] + list(argv)
    enforced = ["fs-rw", "env"]  # reads are not confined on this backend
    if not profile.allow_network:
        enforced.append("net")
    return exec_argv, enforced


class SandboxExecBackend(Backend):
    name = "sandbox-exec"

    @staticmethod
    def is_available() -> bool:
        return shutil.which("sandbox-exec") is not None

    def wrap(self, profile: SandboxProfile, argv: List[str]) -> WrapPlan:
        # Canonicalize grant paths so /tmp-style inputs match under Seatbelt.
        canon = SandboxProfile(
            read_paths=_canonical(profile.read_paths),
            write_paths=_canonical(profile.write_paths),
            allow_network=profile.allow_network,
            allowed_hosts=profile.allowed_hosts,
            env=dict(profile.env),
            cpu_seconds=profile.cpu_seconds,
            memory_mb=profile.memory_mb,
            unshare_pid=profile.unshare_pid,
            workdir=profile.workdir,
        )
        exec_argv, enforced = build_argv(canon, argv)
        # Seatbelt does not filter env; scrub it ourselves.
        return WrapPlan(
            exec_argv=exec_argv,
            popen_kwargs={"env": dict(profile.env)},
            enforced=enforced,
        )
