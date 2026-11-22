"""The child half of the Landlock backend: restrict, then exec.

Run by :mod:`interlock.brace.backends.landlock` as
``python -I _landlock_launcher.py <spec-json> -- <argv...>``. It imports
nothing outside the standard library, because it runs inside the sandbox it is
about to build and must not depend on anything the profile has not granted.

Landlock is applied by the process itself: the kernel offers no wrapper
program. That makes this file a security boundary in the same sense ``bwrap``
is, so every failure path exits **without** running the command - a launcher
that could not restrict must never fall through to ``exec``.

The second half is seccomp: the same self-applied model, one layer lower. A
classic-BPF program compares the syscall number against a denylist and answers
``EPERM`` for it, so a process that is already filesystem-confined cannot reach
the privileged calls (``mount``, ``ptrace``, ``bpf``, module loading, ...) that
landlock does not reason about. The program is built by
:func:`filter_program`, which is pure and unit tested; the kernel validates
and installs it here.
"""
import ctypes
import errno
import json
import os
import stat
import sys
from typing import List, NoReturn, Tuple

# landlock_* are arch-uniform syscall numbers (444-446) on every architecture
# Python targets in practice (x86_64, aarch64, arm, riscv64).
_SYS_CREATE_RULESET = 444
_SYS_ADD_RULE = 445
_SYS_RESTRICT_SELF = 446
_PR_SET_NO_NEW_PRIVS = 38
_LANDLOCK_RULE_PATH_BENEATH = 1
_EEXIST = 17
# O_PATH is Linux-only and Pyright resolves os against the host platform, so a
# getattr keeps the module importable while staying exact where it runs.
_O_PATH = getattr(os, "O_PATH", 0)
# Fail-closed exit for "could not build the ruleset".
_REFUSED = 126

# The kernel's ACCESS_FILE mask (security/landlock/fs.c): the only rights a
# rule may carry when its parent is not a directory. Anything else is EINVAL.
_ACCESS_FILE = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 14)

# --- seccomp -----------------------------------------------------------------
# Classic BPF opcodes (linux/filter.h) and the seccomp_data field offsets the
# program loads. Only three load/jump shapes are used: absolute word load,
# equality jump, greater-or-equal jump.
OP_LD_ABS = 0x20        # BPF_LD | BPF_W | BPF_ABS
OP_JEQ = 0x15           # BPF_JMP | BPF_JEQ | BPF_K
OP_JGE = 0x35           # BPF_JMP | BPF_JGE | BPF_K
OP_RET = 0x06           # BPF_RET | BPF_K
_OFFSET_NR = 0          # struct seccomp_data.nr
_OFFSET_ARCH = 4        # struct seccomp_data.arch
_X32_BIT = 1 << 30      # x86_64 syscall numbers above this are the x32 ABI
_AUDIT_ARCH_X86_64 = 0xC000003E

# seccomp(2) return values (linux/seccomp.h). ERRNO|EPERM is the same answer the
# kernel gives an unprivileged caller, so a blocked call looks like a policy
# denial to the program rather than a crash.
RET_KILL = 0x80000000
RET_ERRNO = 0x00050000
RET_ALLOW = 0x7FFF0000
RET_EPERM = RET_ERRNO | errno.EPERM

_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2


def filter_program(arch, denied) -> List[Tuple[int, int, int, int]]:
    """The classic-BPF denylist, as ``(code, jt, jf, k)`` instructions.

    Layout: load the audit arch and jump to the kill instruction when it is
    not *arch* (the syscall numbers below only mean anything on the
    architecture they came from); load the syscall number; on x86_64 reject
    the whole x32 range, because ``0x40000000 | nr`` is a different number
    space a per-number denylist would silently miss; then one equality pair
    per denied number; then allow; then the kill target.

    Pure and order-stable, so a host without Linux can still prove the
    answers by interpreting it - see ``tests/test_brace_landlock.py``.
    """
    numbers = sorted({int(nr) for nr in denied})
    program: List[Tuple[int, int, int, int]] = [
        (OP_LD_ABS, 0, 0, _OFFSET_ARCH),
        (OP_JEQ, 0, 0, int(arch)),          # jf patched to the kill below
        (OP_LD_ABS, 0, 0, _OFFSET_NR),
    ]
    if int(arch) == _AUDIT_ARCH_X86_64:
        program.append((OP_JGE, 0, 1, _X32_BIT))
        program.append((OP_RET, 0, 0, RET_EPERM))
    for nr in numbers:
        program.append((OP_JEQ, 0, 1, nr))
        program.append((OP_RET, 0, 0, RET_EPERM))
    program.append((OP_RET, 0, 0, RET_ALLOW))
    program.append((OP_RET, 0, 0, RET_KILL))
    # Jump offsets count from the *next* instruction: from index 2 the kill
    # target sits at kill - 2.
    kill = len(program) - 1
    code, jt, _jf, k = program[1]
    program[1] = (code, jt, kill - 2, k)
    return program


class _SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8),
                ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort),
                ("filter", ctypes.POINTER(_SockFilter))]


def install_filter(lib, arch, denied):
    """Install the denylist on this process. Caller has already set
    ``no_new_privs``, without which the kernel refuses the filter."""
    program = filter_program(arch, denied)
    filters = (_SockFilter * len(program))(
        *[_SockFilter(code, jt, jf, k) for code, jt, jf, k in program])
    prog = _SockFprog(len(program), filters)
    if lib.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER,
                 ctypes.byref(prog), 0, 0) != 0:
        _die("prctl(PR_SET_SECCOMP) failed (errno {})".format(ctypes.get_errno()))


def usable_access(access, handled, is_dir):
    """The bits of *access* the kernel will accept for one rule.

    Two kernel constraints, both EINVAL when violated: a rule may only carry
    bits the ruleset handles, and a rule on a non-directory may only carry
    ``EXECUTE`` / ``WRITE_FILE`` / ``READ_FILE`` / ``TRUNCATE``. A profile path
    can name a file (``read_paths=["/etc/passwd"]``), and the spec builder
    cannot know without stat'ing it, so the mask is applied here, where the
    descriptor the kernel will check is already open.
    """
    access &= handled
    if not is_dir:
        access &= _ACCESS_FILE
    return access


def _libc():
    """The process's libc, or ``None`` where the symbols are absent.

    ``prctl`` is Linux-only, so on any other host this file must fail through
    :func:`_die` (no command run) rather than a traceback.
    """
    try:
        lib = ctypes.CDLL(None, use_errno=True)
        lib.syscall.restype = ctypes.c_long
        lib.prctl.restype = ctypes.c_int
        return lib
    except (OSError, AttributeError):
        return None


def _die(message: str) -> NoReturn:
    sys.stderr.write("interlock landlock: {}\n".format(message))
    sys.exit(_REFUSED)


def _probe(lib):
    """The kernel's own ABI, so a spec built elsewhere cannot overshoot it."""
    return lib.syscall(_SYS_CREATE_RULESET, ctypes.c_void_p(None),
                       ctypes.c_size_t(0), ctypes.c_uint32(1))


def apply(spec):
    """Install the ruleset from *spec* and restrict this process. Exits the
    process without running anything on any failure."""
    lib = _libc()
    if lib is None:
        _die("the libc syscall/prctl entry points are not available on this host")
    probed = _probe(lib)
    if probed < 1:
        _die("landlock is not available (probe errno {})".format(ctypes.get_errno()))
    # Never claim an ABI newer than the kernel's: the attr struct grew to 16
    # bytes (handled_net) at ABI 4, and a larger struct than the kernel knows
    # is E2BIG.
    abi = min(int(spec["abi"]), int(probed))
    attr = (ctypes.c_uint64 * 2)(int(spec["handled_fs"]), int(spec["handled_net"]))
    size = 8 if abi < 4 else 16
    fd = lib.syscall(_SYS_CREATE_RULESET, attr, size, 0)
    if fd < 0:
        _die("landlock_create_ruleset failed (errno {})".format(ctypes.get_errno()))

    for rule in spec["rules"]:
        path = rule["path"]
        required = rule.get("required", True)
        try:
            parent = os.open(path, _O_PATH | os.O_CLOEXEC)
        except OSError as exc:
            if required:
                _die("cannot open {}: {}".format(path, exc))
            continue
        try:
            access = usable_access(int(rule["access"]), int(spec["handled_fs"]),
                                   stat.S_ISDIR(os.fstat(parent).st_mode))
            if not access:
                # Nothing this rule could grant survives the mask; the kernel
                # rejects an empty rule anyway (ENOMSG). Skipping only ever
                # grants less, so it is safe.
                continue
            # struct landlock_path_beneath_attr is packed: u64 allowed_access +
            # s32 parent_fd = 12 bytes, which the 16-byte buffer covers.
            beneath = (ctypes.c_uint64 * 1)(access)
            beneath_fd = (ctypes.c_int32 * 1)(parent)
            packed = ctypes.create_string_buffer(bytes(beneath) + bytes(beneath_fd) + b"\0" * 4, 16)
            rc = lib.syscall(_SYS_ADD_RULE, fd, _LANDLOCK_RULE_PATH_BENEATH, packed, 0)
            if rc == 0:
                continue
            errno = ctypes.get_errno()
            # Two granted paths can resolve to one inode (/lib and /usr/lib on a
            # merged-usr distro): the second rule is already there, not an error.
            # An optional rule (the base system tree, a traversal ancestor) that
            # this filesystem rejects is skipped for the same reason: a missing
            # grant can only confine more, never less.
            if errno == _EEXIST or not required:
                continue
            _die("landlock_add_rule({}) failed (errno {})".format(path, errno))
        finally:
            os.close(parent)

    if lib.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        _die("prctl(PR_SET_NO_NEW_PRIVS) failed (errno {})".format(ctypes.get_errno()))
    if lib.syscall(_SYS_RESTRICT_SELF, fd, 0) != 0:
        _die("landlock_restrict_self failed (errno {})".format(ctypes.get_errno()))
    os.close(fd)

    # seccomp is the same self-applied model one layer down, and it needs the
    # no_new_privs already set above. It is a separate spec key because a host
    # can have Landlock without exposing a seccomp denylist for its machine.
    seccomp = spec.get("syscalls")
    if seccomp:
        install_filter(lib, int(seccomp["arch"]), seccomp["deny"])


def main(argv):
    if len(argv) < 3 or "--" not in argv:
        _die("usage: _landlock_launcher.py <spec-json> -- <argv...>")
    spec = json.loads(argv[1])
    command = argv[argv.index("--") + 1:]
    if not command:
        _die("no command after --")
    apply(spec)
    try:
        os.execvp(command[0], command)
    except OSError as exc:
        # Restriction is in force and the exec failed: report, never retry.
        sys.stderr.write("interlock landlock: cannot exec {}: {}\n".format(command[0], exc))
        sys.exit(_REFUSED)


if __name__ == "__main__":
    main(sys.argv)
