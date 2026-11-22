"""The Linux fallback backend: Landlock.

``bwrap`` is stronger - it builds a container out of user namespaces, so the
child cannot see or signal host processes and the network namespace is fresh.
It also needs unprivileged user namespaces, which a locked-down host, an
unprivileged container image, or a hardened kernel may refuse. Landlock needs
none of that: it is a per-process LSM that this process applies to itself, no
root, no namespace, no helper binary. That makes it the backend for a Linux
host where ``bwrap`` is absent but the kernel knows Landlock (5.13+, ABI 1).

What it enforces, honestly:

- **filesystem** - every read, write, create, remove and execute outside the
  granted paths is refused by the kernel, for this process and its children.
  The closed-by-default profile semantics carry over unchanged: grant nothing
  and the child can write nowhere.
- **network** - only on ABI 4+ (Linux 6.7+), and only the *closed* case: the
  profile grants no network, so TCP bind and connect are denied. A profile that
  grants network cannot be confined to hosts here, exactly as with ``bwrap``
  and Seatbelt, so the backend leaves networking alone and says so.
- **environment** - the child gets the profile's env and nothing else.
- **privileged syscalls** - a seccomp denylist (the second self-applied layer)
  answers ``EPERM`` to the calls a sandboxed agent never needs: ``mount`` and
  ``pivot_root``, ``ptrace`` and the ``process_vm_*`` readers, module and
  ``kexec`` loading, ``bpf``, ``perf_event_open``, ``userfaultfd``, key
  management, and clock/swap/reboot. Denied calls fail; everything else runs.

What it does **not** enforce, and never claims: a PID namespace (the child can
see and signal host processes - ``pid`` is not in ``enforced``), mount or IPC
namespaces, and anything below the socket layer (UDP, raw sockets and unix
sockets are untouched). ``require=("pid",)`` therefore refuses a
landlock-backed run rather than pretending. The syscall layer is a denylist,
not an allowlist: a syscall it does not name is permitted, and it is reported
only where the kernel exposes a seccomp denylist for this machine
(``/proc/sys/kernel/seccomp/actions_avail``, Linux 4.14+, x86_64 or aarch64).

Landlock is applied by the process itself, so the launch is
``python -I _landlock_launcher.py <spec> -- <argv>``. The spec - which paths
get which access bits - is built here as a pure function and unit tested
without a Linux host; the launcher only turns those numbers into syscalls.
"""
from __future__ import annotations

import ctypes
import json
import os
import platform
import sys
from typing import Dict, List, Optional, Tuple

from ..limits import rlimit_preexec
from ..profile import SandboxProfile
from .base import Backend, WrapPlan

_SYS_CREATE_RULESET = 444
_LANDLOCK_CREATE_RULESET_VERSION = 1

# LANDLOCK_ACCESS_FS_* (uapi/linux/landlock.h). The first thirteen are ABI 1;
# REFER is ABI 2, TRUNCATE ABI 3, and both matter for a writable grant.
FS_EXECUTE = 1 << 0
FS_WRITE_FILE = 1 << 1
FS_READ_FILE = 1 << 2
FS_READ_DIR = 1 << 3
FS_REMOVE_DIR = 1 << 4
FS_REMOVE_FILE = 1 << 5
FS_MAKE_CHAR = 1 << 6
FS_MAKE_DIR = 1 << 7
FS_MAKE_REG = 1 << 8
FS_MAKE_SOCK = 1 << 9
FS_MAKE_FIFO = 1 << 10
FS_MAKE_BLOCK = 1 << 11
FS_MAKE_SYM = 1 << 12
FS_REFER = 1 << 13
FS_TRUNCATE = 1 << 14

LANDLOCK_ACCESS_NET_BIND_TCP = 1 << 0
LANDLOCK_ACCESS_NET_CONNECT_TCP = 1 << 1
NET_ALL = LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP

READ = FS_EXECUTE | FS_READ_FILE | FS_READ_DIR
WRITE = (FS_WRITE_FILE | FS_REMOVE_DIR | FS_REMOVE_FILE | FS_MAKE_CHAR
         | FS_MAKE_DIR | FS_MAKE_REG | FS_MAKE_SOCK | FS_MAKE_FIFO
         | FS_MAKE_BLOCK | FS_MAKE_SYM)

# The system tree a dynamically linked program needs to start, mirroring the
# bubblewrap backend's BASE_RO. These are best effort: a missing one on a given
# architecture is skipped rather than failing the launch.
BASE_RO: Tuple[str, ...] = (
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/etc/alternatives",
    "/etc/ssl",
    "/proc",
)
# Device nodes: /dev/null and a tty are needed by most programs, and granting
# them is what bwrap's ``--dev /dev`` does.
BASE_RW: Tuple[str, ...] = ("/dev",)

# Audit architectures (linux/audit.h) and the machine names that map to them.
AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_AARCH64 = 0xC00000B7
_MACHINE_ARCH: Dict[str, int] = {
    "x86_64": AUDIT_ARCH_X86_64, "amd64": AUDIT_ARCH_X86_64,
    "aarch64": AUDIT_ARCH_AARCH64, "arm64": AUDIT_ARCH_AARCH64,
}

# The seccomp denylist, by name -> (x86_64 number, aarch64 number, -1 = none).
# Syscall numbers are per architecture and the two tables do not agree, so the
# pair is pinned here from the kernel's own tables
# (arch/x86/entry/syscalls/syscall_64.tbl, include/uapi/asm-generic/unistd.h).
# Every entry is a call a sandboxed agent has no business making: escalating
# privileges, reading another process's memory, loading kernel code, tracing,
# or moving the system clock.
_DENIED_SYSCALLS: Dict[str, Tuple[int, int]] = {
    # mount / namespace topology
    "mount": (165, 40),
    "umount2": (166, 39),
    "pivot_root": (155, 41),
    "chroot": (161, 51),
    "unshare": (272, 97),
    "setns": (308, 268),
    # process inspection
    "ptrace": (101, 117),
    "process_vm_readv": (310, 270),
    "process_vm_writev": (311, 271),
    "kcmp": (312, 272),
    # kernel code
    "init_module": (175, 105),
    "finit_module": (313, 273),
    "delete_module": (176, 106),
    "kexec_load": (246, 104),
    "kexec_file_load": (320, 294),
    "bpf": (321, 280),
    "perf_event_open": (298, 241),
    "userfaultfd": (323, 282),
    # keys
    "add_key": (248, 217),
    "request_key": (249, 218),
    "keyctl": (250, 219),
    # system state
    "reboot": (169, 142),
    "swapon": (167, 224),
    "swapoff": (168, 225),
    "acct": (163, 89),
    "settimeofday": (164, 170),
    "clock_settime": (227, 112),
    "clock_adjtime": (305, 266),
    "adjtimex": (159, 171),
    # filesystem handles
    "name_to_handle_at": (303, 264),
    "open_by_handle_at": (304, 265),
    # port I/O exists only on x86
    "iopl": (172, -1),
    "ioperm": (173, -1),
}


def _audit_arch() -> Optional[int]:
    machine = platform.machine().lower()
    return _MACHINE_ARCH.get(machine)


def denied_numbers(arch: int) -> Tuple[int, ...]:
    """The denylist numbers for *arch*, sorted and de-duplicated."""
    index = 0 if arch == AUDIT_ARCH_X86_64 else 1
    return tuple(sorted({pair[index] for pair in _DENIED_SYSCALLS.values()
                         if pair[index] >= 0}))


def syscall_filter() -> Optional[Tuple[int, Tuple[int, ...]]]:
    """``(audit_arch, denied_numbers)`` for this machine, or ``None``.

    Three conditions, all checked rather than assumed: Linux, a kernel that
    exposes the seccomp denylist (``actions_avail`` exists from 4.14 and
    lists ``errno``), and an architecture whose syscall table is pinned
    above. Any other host honestly reports no ``syscalls`` token instead of
    installing a filter with numbers that mean something else.
    """
    if not sys.platform.startswith("linux"):
        return None
    try:
        with open("/proc/sys/kernel/seccomp/actions_avail") as f:
            available = f.read().split()
    except OSError:
        return None
    if "errno" not in available:
        return None
    arch = _audit_arch()
    if arch is None:
        return None
    return arch, denied_numbers(arch)

_LAUNCHER = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "_landlock_launcher.py")

_ABI_CACHE: Dict[str, Optional[int]] = {}


def _libc() -> Optional[ctypes.CDLL]:
    try:
        lib = ctypes.CDLL(None, use_errno=True)
        lib.syscall.restype = ctypes.c_long
        return lib
    except (OSError, AttributeError):
        return None


def landlock_abi() -> Optional[int]:
    """The Landlock ABI this kernel offers, or ``None`` when there is none.

    ``landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`` is
    the version probe, not a ruleset: it needs no input and creates nothing.
    Cached per process - the answer cannot change - and a kernel without
    Landlock (or a non-Linux host) answers ``None``, never an exception, so
    availability is a plain boolean.
    """
    if "abi" in _ABI_CACHE:
        return _ABI_CACHE["abi"]
    abi: Optional[int] = None
    if sys.platform.startswith("linux"):
        lib = _libc()
        if lib is not None:
            try:
                result = lib.syscall(_SYS_CREATE_RULESET, ctypes.c_void_p(None),
                                     ctypes.c_size_t(0),
                                     ctypes.c_uint32(_LANDLOCK_CREATE_RULESET_VERSION))
                abi = int(result) if result > 0 else None
            except (OSError, ValueError):
                abi = None
    _ABI_CACHE["abi"] = abi
    return abi


def _ancestors(path: str) -> List[str]:
    """Every parent of *path* up to ``/`` (exclusive), outermost last.

    A nested grant is only reachable if its ancestors can be traversed, and
    Landlock charges directory traversal against ``FS_EXECUTE`` on each one.
    """
    out: List[str] = []
    parent = os.path.dirname(path.rstrip("/")) if path not in ("/", "") else ""
    while parent and parent != "/":
        out.append(parent)
        parent = os.path.dirname(parent)
    return out


def build_spec(profile: SandboxProfile, abi: int) -> Dict[str, object]:
    """Turn a profile into the launcher's spec. Pure; no syscall, no spawn.

    Every path is an inode rule: read paths and the base system tree get
    ``READ``, write paths get ``READ | WRITE`` (plus ``REFER``/``TRUNCATE``
    when the ABI has them), and every granted path's ancestors get ``EXECUTE``
    so the kernel can walk to it. ``handled_fs`` is the union of every access
    the ruleset reasons about, so anything not granted is denied rather than
    left unhandled - an unhandled access is allowed by Landlock, which would
    silently reopen the profile.

    One thing this function cannot know: whether a path is a file or a
    directory (it stays pure, and the path may not exist on the building
    host). The kernel rejects directory rights on a file, so the launcher
    masks each rule to what the opened descriptor can carry - see
    ``usable_access`` there.
    """
    grants: Dict[str, Tuple[int, bool]] = {}

    def grant(path: str, access: int, required: bool) -> None:
        current, already_required = grants.get(path, (0, False))
        grants[path] = (current | access, required or already_required)

    for path in BASE_RO:
        grant(path, READ, required=False)
    for path in BASE_RW:
        grant(path, READ | WRITE, required=False)
    for path in profile.read_paths:
        grant(path, READ, required=True)
    write = READ | WRITE
    if abi >= 2:
        write |= FS_REFER
    if abi >= 3:
        write |= FS_TRUNCATE
    for path in profile.write_paths:
        grant(path, write, required=True)
    # Traversal for every granted path, at the lowest access that permits it.
    for path in list(grants):
        for parent in _ancestors(path):
            grant(parent, FS_EXECUTE, required=False)

    handled = 0
    for access, _ in grants.values():
        handled |= access
    # Deny writes everywhere, and the abilities that are not granted nowhere:
    # the union of what any rule can grant, minus nothing, is exactly the set
    # the ruleset decides. REFER/TRUNCATE join only where the ABI knows them.
    handled |= WRITE
    if abi >= 2:
        handled |= FS_REFER
    if abi >= 3:
        handled |= FS_TRUNCATE

    rules = [{"path": path, "access": access, "required": required}
             for path, (access, required) in sorted(grants.items())]
    # TCP is denied by handling it and granting nothing. A profile that allows
    # network is left alone: Landlock cannot express a host allowlist, and
    # handling it would deny traffic the profile grants.
    handled_net = NET_ALL if (abi >= 4 and not profile.allow_network) else 0
    return {
        "abi": abi,
        "handled_fs": handled,
        "handled_net": handled_net,
        "rules": rules,
    }


class LandlockBackend(Backend):
    """Filesystem confinement through the kernel's Landlock LSM."""

    name = "landlock"

    @staticmethod
    def is_available() -> bool:
        return landlock_abi() is not None

    def wrap(self, profile: SandboxProfile, argv: List[str]) -> WrapPlan:
        abi = landlock_abi()
        if abi is None:
            raise RuntimeError("landlock not available on this host")
        spec: Dict[str, object] = build_spec(profile, abi)
        enforced = ["fs-ro", "fs-rw", "env"]
        if abi >= 4 and not profile.allow_network:
            enforced.append("net")
        # The syscall denylist is a host fact, not a profile one, so it joins
        # the spec here rather than in build_spec, which stays pure.
        seccomp = syscall_filter()
        if seccomp is not None:
            spec["syscalls"] = {"arch": seccomp[0], "deny": list(seccomp[1])}
            enforced.append("syscalls")
        spec_json = json.dumps(spec, separators=(",", ":"))
        popen_kwargs: dict = {"env": dict(profile.env)}
        if profile.workdir is not None:
            popen_kwargs["cwd"] = profile.workdir
        preexec = rlimit_preexec(profile.cpu_seconds, profile.memory_mb)
        if preexec is not None and sys.platform != "win32":
            popen_kwargs["preexec_fn"] = preexec
            enforced.append("rlimit")
        return WrapPlan(
            exec_argv=[sys.executable, "-I", _LAUNCHER, spec_json, "--"] + list(argv),
            popen_kwargs=popen_kwargs,
            enforced=enforced,
        )
