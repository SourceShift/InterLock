"""The Linux backend: bubblewrap.

``bwrap`` builds an unprivileged container out of user namespaces. No root, no
daemon, no image: it starts from an empty mount namespace and you bind in exactly
the paths the profile grants. That maps cleanly onto the profile IR, which is why
it is the primary real-isolation backend on Linux.

The confinement this produces:

- a fresh mount namespace with only the bind-mounts below visible;
- ``--unshare-pid`` so the child cannot see or signal host processes;
- ``--unshare-net`` when the profile grants no network, which removes every
  interface but loopback (host-granular egress, when network *is* allowed, is
  the nftables backend's job, not bwrap's);
- ``--clearenv`` so the parent's environment (and its secrets) never crosses in;
- ``--die-with-parent`` so the sandbox cannot outlive the guard that launched it.

``build_argv`` is a pure function of the profile, so the exact flag list is unit
tested without ever needing bwrap installed. The system base paths are bound with
``--ro-bind-try`` (a missing ``/lib64`` on some arches is not fatal), while the
paths the policy explicitly grants use ``--ro-bind`` / ``--bind`` and fail loudly
if absent, which is the fail-closed behaviour we want.
"""
from __future__ import annotations

import shutil
from typing import List, Tuple

from ..profile import SandboxProfile
from .base import Backend, WrapPlan

# Minimal read-only system tree a dynamically linked program needs to start.
# Bound with --ro-bind-try so an arch that lacks one (no /lib64) still works.
BASE_RO: Tuple[str, ...] = (
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/etc/alternatives",
    "/etc/ssl",
)


def build_argv(profile: SandboxProfile, argv: List[str]) -> Tuple[List[str], List[str]]:
    """Return ``(bwrap_argv, enforced_tokens)`` for the given profile.

    Pure: it neither spawns nor touches the filesystem, so a test can assert on
    the flags directly.
    """
    out: List[str] = [
        "bwrap",
        "--die-with-parent",
        "--new-session",
        "--unshare-user-try",
        "--unshare-ipc",
        "--unshare-uts",
        "--clearenv",
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
    ]
    enforced: List[str] = ["fs-ro", "fs-rw", "env"]

    if profile.unshare_pid:
        out += ["--unshare-pid"]
        enforced.append("pid")

    if not profile.allow_network:
        out += ["--unshare-net"]
        enforced.append("net")
    else:
        # DNS needs resolv.conf; the host resolver socket path varies, so bind
        # the file read-only when it is there.
        out += ["--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf"]

    for path in BASE_RO:
        out += ["--ro-bind-try", path, path]

    for path in profile.read_paths:
        out += ["--ro-bind", path, path]
    for path in profile.write_paths:
        out += ["--bind", path, path]

    for key, value in profile.env.items():
        out += ["--setenv", key, value]

    if profile.workdir is not None:
        out += ["--chdir", profile.workdir]

    out += ["--"]
    out += list(argv)
    return out, enforced


class BubblewrapBackend(Backend):
    name = "bubblewrap"

    @staticmethod
    def is_available() -> bool:
        return shutil.which("bwrap") is not None

    def wrap(self, profile: SandboxProfile, argv: List[str]) -> WrapPlan:
        exec_argv, enforced = build_argv(profile, argv)
        return WrapPlan(exec_argv=exec_argv, enforced=enforced)
