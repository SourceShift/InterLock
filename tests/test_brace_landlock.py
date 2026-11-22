"""The Landlock backend: the spec is pure and unit-tested anywhere; the real
kernel restriction is proved only where Landlock exists (Linux 5.13+).

The syscall denylist is proved the same way in two halves. Its program is a
pure function, so a small classic-BPF interpreter here runs it for synthetic
``(arch, nr)`` pairs on any host. The kernel actually answering EPERM is only
observable on Linux, and only there is the ``syscalls`` token claimed.
"""
import json
import shutil
import sys
import textwrap

import pytest

from interlock.brace import IsolationUnavailable, Sandbox, SandboxProfile
from interlock.brace.backends import select_backend
from interlock.brace.backends._landlock_launcher import (
    OP_JEQ,
    OP_JGE,
    OP_LD_ABS,
    OP_RET,
    RET_ALLOW,
    RET_EPERM,
    RET_KILL,
    filter_program,
    usable_access,
)
from interlock.brace.backends.bubblewrap import BubblewrapBackend
from interlock.brace.backends.landlock import (
    AUDIT_ARCH_AARCH64,
    AUDIT_ARCH_X86_64,
    FS_EXECUTE,
    FS_MAKE_REG,
    FS_READ_DIR,
    FS_READ_FILE,
    FS_REFER,
    FS_TRUNCATE,
    FS_WRITE_FILE,
    NET_ALL,
    READ,
    LandlockBackend,
    build_spec,
    denied_numbers,
    landlock_abi,
    syscall_filter,
)

_ABI = landlock_abi()
_SH = shutil.which("sh") or "/bin/sh"
_NEEDS_LANDLOCK = pytest.mark.skipif(
    _ABI is None, reason="needs Linux with Landlock (kernel 5.13+)")
_NEEDS_SECCOMP = pytest.mark.skipif(
    syscall_filter() is None,
    reason="needs Linux with a seccomp denylist (4.14+, x86_64/aarch64)")


@pytest.fixture
def fake_abi(monkeypatch):
    """Pin the probe so wrap() runs on any host."""
    def pin(value):
        monkeypatch.setattr(
            "interlock.brace.backends.landlock.landlock_abi", lambda: value)
    return pin


@pytest.fixture
def fake_filter(monkeypatch):
    """Pin the seccomp availability probe so wrap() is host-independent."""
    def pin(value):
        monkeypatch.setattr(
            "interlock.brace.backends.landlock.syscall_filter", lambda: value)
    return pin


# --- the probe ----------------------------------------------------------------
def test_the_probe_answers_none_or_a_positive_abi():
    assert _ABI is None or _ABI >= 1
    # Non-Linux hosts have no Landlock, and the probe says so rather than raising.
    if not sys.platform.startswith("linux"):
        assert _ABI is None


# --- the spec is a pure function of (profile, abi) -----------------------------
def test_write_paths_get_the_write_bits_the_abi_knows(tmp_path):
    ws = str(tmp_path)
    spec = build_spec(SandboxProfile(write_paths=(ws,)), abi=3)
    rule = {r["path"]: r for r in spec["rules"]}[ws]
    for bit in (FS_WRITE_FILE, FS_MAKE_REG, FS_READ_FILE, FS_READ_DIR,
                FS_REFER, FS_TRUNCATE):
        assert rule["access"] & bit
    assert rule["required"] is True
    assert spec["handled_fs"] & FS_TRUNCATE and spec["handled_fs"] & FS_REFER


def test_an_older_abi_grants_no_bits_it_does_not_know(tmp_path):
    spec = build_spec(SandboxProfile(write_paths=(str(tmp_path),)), abi=1)
    rule = {r["path"]: r for r in spec["rules"]}[str(tmp_path)]
    assert not rule["access"] & (FS_REFER | FS_TRUNCATE)
    assert not spec["handled_fs"] & (FS_REFER | FS_TRUNCATE)


def test_handled_fs_covers_every_grant():
    spec = build_spec(SandboxProfile(read_paths=("/srv/data",),
                                     write_paths=("/srv/out",)), abi=4)
    handled = spec["handled_fs"]
    for rule in spec["rules"]:
        assert rule["access"] & handled == rule["access"], rule["path"]


def test_a_nested_grant_gets_traversal_on_its_ancestors(tmp_path):
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    spec = build_spec(SandboxProfile(write_paths=(str(nested),)), abi=3)
    rules = {r["path"]: r["access"] for r in spec["rules"]}
    for parent in (str(tmp_path / "a"), str(tmp_path), str(tmp_path.parent)):
        assert rules[parent] == FS_EXECUTE, parent
    assert "/" not in rules  # the root needs no rule of its own


def test_the_base_tree_is_granted_read_only_and_best_effort():
    spec = build_spec(SandboxProfile(), abi=3)
    rules = {r["path"]: r for r in spec["rules"]}
    assert rules["/usr"]["access"] == READ and rules["/usr"]["required"] is False
    assert rules["/dev"]["access"] & FS_WRITE_FILE
    # A profile path is required: the launcher refuses rather than skipping it.
    required = build_spec(SandboxProfile(read_paths=("/srv/data",)), abi=3)
    assert {r["path"]: r for r in required["rules"]}["/srv/data"]["required"] is True


def test_a_file_rule_keeps_only_the_rights_the_kernel_accepts_on_files():
    """A profile path can be a file (``read_paths=["/etc/passwd"]``). The spec
    says READ; the kernel rejects READ_DIR on a non-directory, so the launcher
    masks it down to the file-safe bits instead of failing the launch."""
    access = usable_access(READ | FS_WRITE_FILE, READ | FS_WRITE_FILE, is_dir=False)
    assert access == FS_EXECUTE | FS_READ_FILE | FS_WRITE_FILE
    assert not access & FS_READ_DIR


def test_a_directory_rule_keeps_every_right_it_was_given():
    assert usable_access(READ | FS_MAKE_REG, READ | FS_MAKE_REG, is_dir=True) == (
        READ | FS_MAKE_REG)


def test_bits_the_ruleset_does_not_handle_are_dropped():
    """The kernel also rejects (EINVAL) a rule carrying an access the ruleset
    never handled, so the mask is the handled set too."""
    assert usable_access(READ | FS_TRUNCATE, READ, is_dir=True) == READ


def test_network_is_denied_only_where_the_abi_can_deny_it():
    closed = SandboxProfile()
    assert build_spec(closed, abi=4)["handled_net"] == NET_ALL
    assert build_spec(closed, abi=3)["handled_net"] == 0     # no net attr yet
    # A profile that grants network is left alone: Landlock has no host list,
    # and handling it would deny what the profile granted.
    assert build_spec(SandboxProfile(allow_network=True), abi=4)["handled_net"] == 0


# --- the seccomp program is pure, so interpret it anywhere --------------------
def _evaluate(program, nr, arch):
    """Run a classic-BPF program the way the kernel would for one syscall.

    Only the three opcodes ``filter_program`` emits are implemented; anything
    else fails loudly, because a program the kernel cannot run is exactly the
    defect this interpreter exists to catch.
    """
    data = {0: nr, 4: arch}  # struct seccomp_data: nr at 0, arch at 4
    accumulator = 0
    pc = 0
    while True:
        code, jt, jf, k = program[pc]
        if code == OP_LD_ABS:
            accumulator = data[k]
            pc += 1
        elif code == OP_JEQ:
            pc += 1 + (jt if accumulator == k else jf)
        elif code == OP_JGE:
            pc += 1 + (jt if accumulator >= k else jf)
        elif code == OP_RET:
            return k
        else:
            raise AssertionError("unknown opcode %#x" % code)


def _x86_64_program():
    return filter_program(AUDIT_ARCH_X86_64, denied_numbers(AUDIT_ARCH_X86_64))


def test_a_denied_syscall_is_answered_with_eperm():
    # 165 is mount(2) on x86_64: the call a sandboxed agent must never land.
    assert _evaluate(_x86_64_program(), 165, AUDIT_ARCH_X86_64) == RET_EPERM
    # 101 is ptrace(2).
    assert _evaluate(_x86_64_program(), 101, AUDIT_ARCH_X86_64) == RET_EPERM


def test_a_syscall_off_the_list_is_allowed():
    # read(2) and write(2) are how every useful program does its work.
    assert _evaluate(_x86_64_program(), 0, AUDIT_ARCH_X86_64) == RET_ALLOW
    assert _evaluate(_x86_64_program(), 1, AUDIT_ARCH_X86_64) == RET_ALLOW
    assert _evaluate(_x86_64_program(), 59, AUDIT_ARCH_X86_64) == RET_ALLOW  # execve


def test_a_foreign_architecture_is_killed_rather_than_judged():
    """The numbers in the program mean something else on another ABI, so the
    filter kills instead of answering a denial it cannot justify."""
    assert _evaluate(_x86_64_program(), 165, AUDIT_ARCH_AARCH64) == RET_KILL


def test_the_x32_number_space_is_answered_too():
    """x86_64 syscalls above bit 30 are the x32 ABI: ``0x40000000 | 165`` is a
    different call a per-number denylist would silently let through."""
    assert _evaluate(_x86_64_program(), (1 << 30) | 165,
                     AUDIT_ARCH_X86_64) == RET_EPERM


def test_each_architecture_is_judged_by_its_own_number_table():
    """mount(2) is 165 on x86_64 and 40 on aarch64; a program built for one
    must not answer for the other."""
    arm = filter_program(AUDIT_ARCH_AARCH64, denied_numbers(AUDIT_ARCH_AARCH64))
    assert _evaluate(arm, 40, AUDIT_ARCH_AARCH64) == RET_EPERM
    assert _evaluate(arm, 165, AUDIT_ARCH_AARCH64) == RET_ALLOW


def test_the_denylist_names_privileged_calls_only():
    assert 165 in denied_numbers(AUDIT_ARCH_X86_64)       # mount
    assert 101 in denied_numbers(AUDIT_ARCH_X86_64)       # ptrace
    assert 321 in denied_numbers(AUDIT_ARCH_X86_64)       # bpf
    # Port I/O does not exist on aarch64, so it is not on that list.
    assert 172 in denied_numbers(AUDIT_ARCH_X86_64)
    assert 172 not in denied_numbers(AUDIT_ARCH_AARCH64)
    # An ordinary syscall is never denied by number.
    for table in (AUDIT_ARCH_X86_64, AUDIT_ARCH_AARCH64):
        numbers = denied_numbers(table)
        assert len(numbers) == len(set(numbers))
        assert all(nr > 0 for nr in numbers)
        assert 0 not in numbers and 1 not in numbers  # read / write


def test_the_filter_is_reported_only_where_the_kernel_exposes_one():
    if not sys.platform.startswith("linux"):
        assert syscall_filter() is None
    else:
        assert syscall_filter() is None or syscall_filter()[0] in (
            AUDIT_ARCH_X86_64, AUDIT_ARCH_AARCH64)


# --- the wrap ----------------------------------------------------------------
def test_wrap_launches_the_restricting_child_then_the_command(fake_abi, tmp_path):
    fake_abi(3)
    plan = LandlockBackend().wrap(SandboxProfile(write_paths=(str(tmp_path),)),
                                  ["/bin/echo", "hi"])
    assert plan.exec_argv[:2] == [sys.executable, "-I"]
    assert plan.exec_argv[2].endswith("_landlock_launcher.py")
    spec = json.loads(plan.exec_argv[3])
    assert spec["abi"] == 3
    assert plan.exec_argv[4:] == ["--", "/bin/echo", "hi"]
    assert "fs-ro" in plan.enforced and "fs-rw" in plan.enforced


def test_wrap_claims_net_only_when_it_is_handled(fake_abi):
    fake_abi(3)
    assert "net" not in LandlockBackend().wrap(SandboxProfile(), ["/bin/true"]).enforced
    fake_abi(4)
    assert "net" in LandlockBackend().wrap(SandboxProfile(), ["/bin/true"]).enforced
    granted = LandlockBackend().wrap(SandboxProfile(allow_network=True), ["/bin/true"])
    assert "net" not in granted.enforced


def test_wrap_refuses_without_a_kernel_to_restrict_on(fake_abi):
    fake_abi(None)
    with pytest.raises(RuntimeError):
        LandlockBackend().wrap(SandboxProfile(), ["/bin/true"])
    assert LandlockBackend.is_available() is False


def test_wrap_carries_the_syscall_denylist_into_the_spec(fake_abi, fake_filter):
    fake_abi(3)
    fake_filter((AUDIT_ARCH_X86_64, (101, 165)))
    plan = LandlockBackend().wrap(SandboxProfile(), ["/bin/true"])
    spec = json.loads(plan.exec_argv[3])
    assert spec["syscalls"] == {"arch": AUDIT_ARCH_X86_64, "deny": [101, 165]}
    assert "syscalls" in plan.enforced


def test_wrap_omits_the_syscall_layer_when_the_host_has_none(fake_abi, fake_filter):
    """A host with Landlock but no seccomp denylist for its machine still gets
    filesystem confinement — and is not told it got a syscall layer."""
    fake_abi(3)
    fake_filter(None)
    plan = LandlockBackend().wrap(SandboxProfile(), ["/bin/true"])
    assert "syscalls" not in json.loads(plan.exec_argv[3])
    assert "syscalls" not in plan.enforced


def test_selection_prefers_landlock_over_soft_when_bwrap_is_absent(monkeypatch):
    monkeypatch.setattr(BubblewrapBackend, "is_available", staticmethod(lambda: False))
    monkeypatch.setattr(LandlockBackend, "is_available", staticmethod(lambda: True))
    assert isinstance(select_backend(), LandlockBackend)


# --- real confinement ---------------------------------------------------------
@_NEEDS_LANDLOCK
def test_a_write_outside_the_grant_is_refused_by_the_kernel(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    inside, outside = ws / "ok.txt", tmp_path / "escape.txt"
    script = "echo ok > {i}; echo bad > {o} 2>/dev/null || echo refused".format(
        i=inside, o=outside)
    sh = _SH
    result = Sandbox(SandboxProfile(write_paths=(str(ws),)),
                     backend="landlock").run([sh, "-c", script])
    assert inside.exists(), result.stderr
    assert not outside.exists(), "landlock let a write escape the grant"
    assert "refused" in result.stdout


@_NEEDS_LANDLOCK
def test_a_read_outside_the_grant_is_refused(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    secret = tmp_path / "outside.txt"
    secret.write_text("should not be readable")
    sh = _SH
    result = Sandbox(SandboxProfile(write_paths=(str(ws),)),
                     backend="landlock").run([sh, "-c", "cat {}".format(secret)])
    assert result.returncode != 0
    assert "should not be readable" not in result.stdout


@_NEEDS_LANDLOCK
def test_it_never_claims_a_pid_namespace_it_cannot_build(tmp_path):
    sb = Sandbox(SandboxProfile(write_paths=(str(tmp_path),)),
                 backend="landlock", require=("pid",))
    with pytest.raises(IsolationUnavailable) as caught:
        sb.run([_SH, "-c", "true"])
    assert caught.value.missing == ["pid"]


@_NEEDS_LANDLOCK
def test_a_missing_granted_path_refuses_instead_of_running(tmp_path):
    absent = tmp_path / "never-created"
    result = Sandbox(SandboxProfile(write_paths=(str(absent),)),
                     backend="landlock").run([_SH, "-c", "echo ran"])
    assert result.returncode != 0
    assert "ran" not in result.stdout
    assert "cannot open" in result.stderr


# --- real syscall confinement -------------------------------------------------
# PTRACE_TRACEME is allowed for any unprivileged process, so its success is the
# control and its EPERM is the filter - no capabilities involved either way.
_PTRACE_PROBE = textwrap.dedent(
    """
    import ctypes
    lib = ctypes.CDLL(None, use_errno=True)
    rc = lib.ptrace(0, 0, 0, 0)  # PTRACE_TRACEME
    print("%d %d" % (rc, ctypes.get_errno()))
    """
)


def _interpreter_profile():
    """This interpreter's prefix, read-only: enough to start python."""
    return SandboxProfile().with_paths(read=[sys.prefix])


@_NEEDS_SECCOMP
@_NEEDS_LANDLOCK
def test_a_privileged_syscall_is_refused_by_the_kernel():
    result = Sandbox(_interpreter_profile(), backend="landlock").run(
        [sys.executable, "-I", "-c", _PTRACE_PROBE])
    assert "syscalls" in result.enforced
    assert result.stdout.strip() == "-1 1", result.stderr  # EPERM


@_NEEDS_SECCOMP
def test_the_same_call_succeeds_without_the_filter():
    """Control: the identical probe on the soft backend, which claims no
    syscall layer. It succeeds, so the EPERM above came from the filter."""
    result = Sandbox(_interpreter_profile(), backend="soft").run(
        [sys.executable, "-I", "-c", _PTRACE_PROBE])
    assert "syscalls" not in result.enforced
    assert result.stdout.strip() == "0 0", result.stderr
