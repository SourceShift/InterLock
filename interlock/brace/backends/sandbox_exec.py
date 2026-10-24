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
  re-grants it only for the profile's ``write_paths`` (plus the two device
  nodes a process legitimately writes, ``/dev/null`` and ``/dev/fd``). A
  process cannot write the user's home, the shared temp roots, or any other
  device node. Per-run scratch is a ``write_paths`` grant: :class:`Sandbox`
  creates one private directory and adds it to the profile it runs. This is
  verified: writing outside the grant returns "Operation not permitted".
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

from ..limits import rlimit_preexec
from ..profile import SandboxProfile
from .base import Backend, WrapPlan

# The only device nodes a confined process may write. Device nodes are granted
# as literals, never whole directories: ``(subpath "/dev")`` would reopen
# ``/dev/fd`` and every other device, and the shared temp roots
# (``/private/tmp``, ``/private/var/folders``) must stay closed. A per-run
# scratch directory is added to ``write_paths`` by :class:`Sandbox` instead.
BASE_WRITE_FILES: Tuple[str, ...] = ("/dev/null",)
BASE_WRITE_DIRS: Tuple[str, ...] = ("/dev/fd",)


def _canonical(paths: Tuple[str, ...]) -> Tuple[str, ...]:
    """Resolve /tmp -> /private/tmp etc. so Seatbelt subpath matching lines up."""
    return tuple(os.path.realpath(p) for p in paths)


def _sbpl_string(path: str) -> str:
    """Validate one grant path and escape it for an SBPL string literal.

    A grant must be an absolute, non-empty path with no NUL, carriage return or
    newline: those cannot be represented in SBPL and, left raw, would let a
    path-derived payload close the string and add rules of its own. Backslash
    and quote are escaped so the value stays inside the literal. Parentheses
    are emitted as their octal escapes (``\\050`` / ``\\051``) so the rendered
    profile contains no literal SBPL syntax inside a grant. Seatbelt decodes
    all four escapes, so the escaped path still matches the real file.
    """
    if not path:
        raise ValueError("write path must be non-empty")
    if "\x00" in path:
        raise ValueError("write path must not contain NUL: {!r}".format(path))
    if "\n" in path or "\r" in path:
        raise ValueError("write path must not contain a newline: {!r}".format(path))
    if not os.path.isabs(path):
        raise ValueError("write path must be absolute: {!r}".format(path))
    return (
        path.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("(", "\\050")
        .replace(")", "\\051")
    )


def _validate_write_paths(paths: Tuple[str, ...]) -> None:
    """Reject invalid grants *before* canonicalization.

    ``os.path.realpath`` turns ``""`` into the cwd and a relative path into a
    cwd-relative absolute path, which would silently grant a directory the
    caller never named. Validate the paths as given; :func:`_sbpl_string`
    validates again when rendering.
    """
    for path in paths:
        _sbpl_string(path)


def build_profile(profile: SandboxProfile) -> str:
    """Return the SBPL profile string. Pure over the paths it is given.

    Callers that want /tmp-style paths matched should hand in already-canonical
    (realpath'd) ``write_paths``; :class:`SandboxExecBackend` does this.
    """
    grants = ['(literal "{}")'.format(_sbpl_string(p)) for p in BASE_WRITE_FILES]
    grants += ['(subpath "{}")'.format(_sbpl_string(p)) for p in BASE_WRITE_DIRS]
    grants += ['(subpath "{}")'.format(_sbpl_string(p)) for p in profile.write_paths]
    write_grant = " ".join(grants)
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
        # Reject "" and relative grants before realpath can turn them into a
        # cwd-derived absolute path: a relative path must fail closed, not
        # silently grant something the caller never named.
        _validate_write_paths(tuple(profile.write_paths))
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
        popen_kwargs: dict = {"env": dict(profile.env)}
        # Seatbelt has no chdir of its own: start sandbox-exec in the workdir,
        # and the program it execs inherits it.
        if profile.workdir is not None:
            popen_kwargs["cwd"] = profile.workdir
        # CPU / memory ceilings are set on sandbox-exec before it execs and are
        # inherited by the program it launches. Enforced, but not yet reported
        # as the "rlimit" token (the guarantee table pins that to soft).
        preexec = rlimit_preexec(profile.cpu_seconds, profile.memory_mb)
        if preexec is not None:
            popen_kwargs["preexec_fn"] = preexec
        return WrapPlan(
            exec_argv=exec_argv,
            popen_kwargs=popen_kwargs,
            enforced=enforced,
        )
