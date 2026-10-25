"""Resource ceilings on every backend, workdir everywhere, and ``require=``.

Four promises, each run for real where the host has the backend:

1. ``cpu_seconds`` / ``memory_mb`` are applied under bubblewrap and sandbox-exec
   too, not only soft: a runaway CPU burn dies by SIGXCPU under each available
   backend, and the identical burn with no ceiling survives to the harness
   timeout (the control that proves the kill was the rlimit's doing).
2. A limit the host cannot enforce is refused when the Sandbox is built, with a
   reason, never dropped silently and never a per-launch SubprocessError.
3. ``workdir`` is the child's working directory on every backend.
4. ``require=`` refuses, before any process starts, when the backend can't
   enforce a required token.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile

import pytest

from interlock.brace import (
    KNOWN_TOKENS,
    IsolationUnavailable,
    LimitUnsupported,
    Sandbox,
    SandboxProfile,
    available_backends,
    compile_profile,
)
from interlock.brace.backends import BubblewrapBackend, SandboxExecBackend, SoftBackend
from interlock.brace.limits import check_limits

_BY_NAME = {cls.name: cls for cls in (SoftBackend, BubblewrapBackend, SandboxExecBackend)}

_AVAILABLE = set(available_backends())


def _backends(*names):
    return [
        pytest.param(name, marks=pytest.mark.skipif(
            name not in _AVAILABLE,
            reason="%s is not available on this host" % name,
        ))
        for name in names
    ]


# --- 1. limits reach every backend's child -----------------------------------


@pytest.mark.parametrize("backend", ["bubblewrap", "sandbox-exec"])
def test_os_backends_attach_the_rlimit_hook_when_limits_are_set(backend):
    """Pure: the plan carries the preexec hook that sets the rlimits."""
    plan = _BY_NAME[backend]().wrap(
        SandboxProfile(cpu_seconds=2), ["/bin/echo", "x"]
    )
    assert callable(plan.popen_kwargs.get("preexec_fn"))


@pytest.mark.parametrize("backend", ["bubblewrap", "sandbox-exec"])
def test_os_backends_add_no_hook_without_limits(backend):
    plan = _BY_NAME[backend]().wrap(
        SandboxProfile.locked(), ["/bin/echo", "x"]
    )
    assert "preexec_fn" not in plan.popen_kwargs


@pytest.mark.parametrize("backend", ["bubblewrap", "sandbox-exec"])
def test_os_backends_claim_the_rlimit_token_when_limits_are_set(backend):
    """Enforced and claimed: the token matrix carries an escape row for each
    backend, so ``enforced`` reports what the caller is actually getting."""
    plan = _BY_NAME[backend]().wrap(
        SandboxProfile(cpu_seconds=2), ["/bin/echo", "x"]
    )
    assert "rlimit" in plan.enforced


@pytest.mark.parametrize("backend", ["soft", "bubblewrap", "sandbox-exec"])
def test_no_backend_claims_rlimit_without_a_ceiling(backend):
    plan = _BY_NAME[backend]().wrap(SandboxProfile.locked(), ["/bin/echo", "x"])
    assert "rlimit" not in plan.enforced


@pytest.mark.parametrize("backend", _backends("soft", "bubblewrap", "sandbox-exec"))
def test_cpu_ceiling_kills_a_runaway_under_every_backend(backend):
    result = Sandbox(SandboxProfile(cpu_seconds=1), backend=backend).run(
        ["python3", "-c", "while True: pass"], timeout=20
    )
    assert result.returncode == -signal.SIGXCPU, (
        "expected death by SIGXCPU under %s, got %r" % (backend, result.returncode)
    )


@pytest.mark.parametrize("backend", _backends("bubblewrap", "sandbox-exec"))
def test_cpu_control_no_ceiling_means_no_kill(backend):
    """Control: the same loop with no ceiling is only ended by the harness."""
    with pytest.raises(subprocess.TimeoutExpired):
        Sandbox(compile_profile({}), backend=backend).run(
            ["python3", "-c", "while True: pass"], timeout=3
        )


@pytest.mark.skipif(sys.platform == "darwin", reason="macOS cannot enforce memory_mb")
@pytest.mark.parametrize("backend", _backends("soft", "bubblewrap"))
def test_memory_ceiling_stops_an_oversized_allocation(backend):
    code = "b = bytearray(512 * 1024 * 1024); print('ALLOCATED')"
    capped = Sandbox(SandboxProfile(memory_mb=128), backend=backend).run(
        ["python3", "-c", code], timeout=30
    )
    assert "ALLOCATED" not in capped.stdout
    assert capped.returncode != 0
    # control: the same allocation with no ceiling succeeds
    free = Sandbox(compile_profile({}), backend=backend).run(
        ["python3", "-c", code], timeout=30
    )
    assert free.stdout.strip() == "ALLOCATED"


# --- 2. unenforceable limits are refused up front ----------------------------


def test_memory_limit_is_refused_on_macos_with_a_reason():
    with pytest.raises(LimitUnsupported) as excinfo:
        check_limits(SandboxProfile(memory_mb=256), platform="darwin")
    message = str(excinfo.value)
    assert "memory_mb=256" in message and "macOS" in message


def test_cpu_limit_alone_is_fine_on_macos():
    check_limits(SandboxProfile(cpu_seconds=5), platform="darwin")


def test_any_limit_is_refused_on_windows():
    with pytest.raises(LimitUnsupported, match="Windows"):
        check_limits(SandboxProfile(cpu_seconds=5), platform="win32")


def test_linux_accepts_both_limits():
    check_limits(SandboxProfile(cpu_seconds=5, memory_mb=256), platform="linux")


def test_no_limits_is_fine_everywhere():
    for platform in ("darwin", "win32", "linux"):
        check_limits(SandboxProfile.locked(), platform=platform)


@pytest.mark.skipif(sys.platform != "darwin", reason="the macOS refusal itself")
@pytest.mark.parametrize("backend", _backends("soft", "sandbox-exec"))
def test_sandbox_with_memory_mb_fails_when_built_on_macos(backend):
    """Before the fix every launch raised an opaque SubprocessError. Now the
    Sandbox refuses at construction, so nothing is ever spawned."""
    with pytest.raises(LimitUnsupported, match="memory_mb"):
        Sandbox(SandboxProfile(memory_mb=128), backend=backend)


def test_compiled_limits_binding_is_checked_too():
    profile = compile_profile({"sandbox_limits": {"cpu_seconds": 5, "memory_mb": 64}})
    with pytest.raises(LimitUnsupported):
        check_limits(profile, platform="darwin")


# --- 3. workdir on every backend ---------------------------------------------


def test_sandbox_exec_plan_sets_cwd():
    plan = _BY_NAME["sandbox-exec"]().wrap(
        SandboxProfile(workdir="/some/dir"), ["/bin/pwd"]
    )
    assert plan.popen_kwargs["cwd"] == "/some/dir"


@pytest.mark.parametrize("backend", _backends("soft", "bubblewrap", "sandbox-exec"))
def test_child_starts_in_the_workdir(backend):
    workdir = os.path.realpath(tempfile.mkdtemp(prefix="brace-workdir-"))
    profile = SandboxProfile(workdir=workdir, read_paths=(workdir,))
    result = Sandbox(profile, backend=backend).run(
        ["python3", "-c", "import os; print(os.path.realpath(os.getcwd()))"], timeout=20
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == workdir


# --- 4. require= -------------------------------------------------------------


def test_require_refuses_before_spawning(tmp_path):
    marker = tmp_path / "ran"
    sandbox = Sandbox(SandboxProfile.locked(), backend="soft", require=("net",))
    with pytest.raises(IsolationUnavailable) as excinfo:
        sandbox.run(["python3", "-c", "open(%r, 'w').write('x')" % str(marker)])
    assert not marker.exists(), "the command ran despite the missing isolation"
    err = excinfo.value
    assert err.backend == "soft"
    assert err.missing == ["net"]
    assert "net" in str(err) and "soft" in str(err)
    assert isinstance(err, RuntimeError)


def test_require_lists_every_missing_token():
    sandbox = Sandbox(SandboxProfile.locked(), backend="soft", require=("net", "fs-rw", "env"))
    with pytest.raises(IsolationUnavailable) as excinfo:
        sandbox.run(["/bin/echo", "x"])
    assert excinfo.value.missing == ["net", "fs-rw"]


@pytest.mark.parametrize("backend", _backends("bubblewrap", "sandbox-exec"))
def test_require_met_runs_normally(backend):
    sandbox = Sandbox(SandboxProfile.locked(), backend=backend, require=("net", "fs-rw"))
    result = sandbox.run(["python3", "-c", "print('ok')"], timeout=20)
    assert result.stdout.strip() == "ok"


def test_require_net_fails_when_the_profile_grants_network():
    """Network grants open egress fully at the OS level, so "net" isn't enforced."""
    profile = SandboxProfile(allow_network=True, allowed_hosts=("api.internal",))
    sandbox = Sandbox(profile, require=("net",))
    with pytest.raises(IsolationUnavailable):
        sandbox.run(["/bin/echo", "x"])


def test_unknown_required_token_fails_when_built():
    with pytest.raises(ValueError, match="netw"):
        Sandbox(require=("netw",))


def test_a_bare_string_is_one_token_not_characters():
    sandbox = Sandbox(SandboxProfile.locked(), backend="soft", require="net")
    assert sandbox.require == ("net",)


def test_default_require_keeps_todays_behaviour():
    result = Sandbox(SandboxProfile.locked(), backend="soft").run(["/bin/echo", "hi"])
    assert result.stdout.strip() == "hi"


def test_known_tokens_cover_every_backend_claim():
    claimed = set()
    for backend in ("soft", "bubblewrap", "sandbox-exec"):
        cls = _BY_NAME[backend]
        for profile in (SandboxProfile.locked(), SandboxProfile(cpu_seconds=1),
                        SandboxProfile(allow_network=True), SandboxProfile(unshare_pid=False)):
            claimed.update(cls().wrap(profile, ["/bin/echo"]).enforced)
    assert claimed <= KNOWN_TOKENS
