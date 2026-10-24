"""The Sandbox facade: it runs a command under confinement AND routes the launch
through the policy engine first. These tests cover the portable behaviour on any
host (soft backend, pre-exec block, argv rewrite) and add real-confinement proofs
that only run where a kernel sandbox exists.
"""
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

import pytest

from interlock import Blocked, Decision, PolicyEngine, SensorEvent, deny_tool
from interlock.brace import IsolationUnavailable, Sandbox, SandboxProfile
from interlock.brace.backends.base import WrapPlan

_HAS_SEATBELT = sys.platform == "darwin" and shutil.which("sandbox-exec") is not None


# --- portable behaviour ------------------------------------------------------
def test_soft_run_executes_and_captures():
    r = Sandbox(SandboxProfile.locked(), backend="soft").run(["/bin/echo", "hi there"])
    assert r.ok and r.returncode == 0
    assert r.stdout.strip() == "hi there"
    assert r.backend == "soft"


def test_empty_argv_rejected():
    with pytest.raises(ValueError):
        Sandbox(SandboxProfile.locked(), backend="soft").run([])


def test_policy_blocks_spawn_before_exec():
    eng = PolicyEngine(rules=[deny_tool("process_spawn", "no shelling out")])
    sb = Sandbox(SandboxProfile.locked(), backend="soft", engine=eng)
    with pytest.raises(Blocked) as ei:
        sb.run(["/bin/echo", "should-not-run"])
    assert "no shelling out" in ei.value.decision.reason


def test_monitor_mode_records_but_runs():
    eng = PolicyEngine(rules=[deny_tool("process_spawn", "would-block")])
    sb = Sandbox(
        SandboxProfile.locked(), backend="soft", engine=eng, enforcement="monitor"
    )
    r = sb.run(["/bin/echo", "ran anyway"])
    assert r.ok  # monitor never intervenes


def test_modify_verdict_rewrites_argv():
    # A rule can rewrite the launch: here it forces a safe argv.
    def rewrite(e: SensorEvent):
        if e.action == "process_spawn":
            return Decision.modify({"argv": ["/bin/echo", "rewritten"]})
        return None

    sb = Sandbox(
        SandboxProfile.locked(), backend="soft", engine=PolicyEngine(rules=[rewrite])
    )
    r = sb.run(["/bin/echo", "original"])
    assert r.stdout.strip() == "rewritten"


def test_plan_does_not_execute():
    plan = Sandbox(SandboxProfile.locked(), backend="soft").plan(["/bin/echo", "x"])
    assert plan.exec_argv == ["/bin/echo", "x"]


# --- per-run scratch directory ------------------------------------------------
def test_run_creates_a_private_scratch_dir_and_removes_it_afterward():
    r = Sandbox(SandboxProfile.locked(), backend="soft").run(
        [
            sys.executable,
            "-c",
            "import os, stat; p = os.environ['TMPDIR']; "
            "print(p); print(oct(stat.S_IMODE(os.stat(p).st_mode)))",
        ]
    )
    assert r.returncode == 0, r.stderr
    scratch, mode = r.stdout.split()
    assert os.path.basename(scratch).startswith("interlock-brace-")
    assert mode == "0o700"
    assert not os.path.exists(scratch), "the scratch tree outlived the run"


def test_run_injects_tmpdir_tmp_and_temp():
    r = Sandbox(SandboxProfile.locked(), backend="soft").run(
        [
            sys.executable,
            "-c",
            "import os; print(os.environ['TMPDIR'] == os.environ['TMP'] "
            "== os.environ['TEMP']); print(os.path.basename(os.environ['TMPDIR']))",
        ]
    )
    assert r.returncode == 0, r.stderr
    same, name = r.stdout.split()
    assert same == "True"
    assert name.startswith("interlock-brace-")


def test_run_does_not_mutate_the_shared_frozen_profile():
    profile = SandboxProfile.locked()
    Sandbox(profile, backend="soft").run(["/bin/echo", "x"])
    assert profile.write_paths == ()
    assert dict(profile.env) == {}


def test_plan_creates_no_scratch_directory(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("plan() must not create a scratch directory")

    monkeypatch.setattr("interlock.brace.sandbox.tempfile.mkdtemp", boom)
    plan = Sandbox(SandboxProfile.locked(), backend="soft").plan(["/bin/echo", "x"])
    assert plan.exec_argv == ["/bin/echo", "x"]


def test_require_refusal_happens_before_any_scratch_is_created(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("scratch was created before the require= refusal")

    monkeypatch.setattr("interlock.brace.sandbox.tempfile.mkdtemp", boom)
    sandbox = Sandbox(SandboxProfile.locked(), backend="soft", require=("net",))
    with pytest.raises(IsolationUnavailable):
        sandbox.run(["/bin/echo", "x"])


def test_the_policy_event_does_not_see_the_scratch_path():
    seen = []

    def capture(event):
        seen.append(event)
        return None

    Sandbox(
        SandboxProfile.locked(), backend="soft", engine=PolicyEngine(rules=[capture])
    ).run(["/bin/echo", "x"])
    assert seen
    assert seen[0].args["write_paths"] == []


def test_scratch_is_removed_when_the_final_wrap_raises(monkeypatch):
    created = []
    real_mkdtemp = tempfile.mkdtemp

    def record_mkdtemp(*args, **kwargs):
        path = real_mkdtemp(*args, **kwargs)
        created.append(path)
        return path

    monkeypatch.setattr("interlock.brace.sandbox.tempfile.mkdtemp", record_mkdtemp)
    sandbox = Sandbox(SandboxProfile.locked(), backend="soft")
    real_wrap = sandbox._backend.wrap
    calls = {"n": 0}

    def failing_wrap(profile, argv):
        calls["n"] += 1
        if calls["n"] == 2:  # the probe is call 1
            raise RuntimeError("wrap failed")
        return real_wrap(profile, argv)

    monkeypatch.setattr(sandbox._backend, "wrap", failing_wrap)
    with pytest.raises(RuntimeError, match="wrap failed"):
        sandbox.run(["/bin/echo", "x"])
    assert len(created) == 1
    assert not os.path.exists(created[0])


def test_scratch_is_removed_when_the_run_times_out(tmp_path):
    seen = tmp_path / "tmpdir"
    profile = SandboxProfile.locked().with_paths(write=[str(tmp_path)])
    with pytest.raises(subprocess.TimeoutExpired):
        Sandbox(profile, backend="soft").run(
            ["/bin/sh", "-c", 'echo "$TMPDIR" > %s; sleep 30' % seen], timeout=1
        )
    scratch = seen.read_text().strip()
    assert os.path.basename(scratch).startswith("interlock-brace-")
    assert not os.path.exists(scratch)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process groups")
def test_timeout_kills_the_sandbox_process_group(tmp_path):
    pidfile = tmp_path / "grandchild.pid"
    sandbox = Sandbox(SandboxProfile.locked(), backend="soft")
    with pytest.raises(subprocess.TimeoutExpired):
        sandbox.run(
            ["/bin/sh", "-c", "sleep 30 & echo $! > %s; wait" % pidfile], timeout=1
        )
    pid = int(pidfile.read_text().strip())
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        os.kill(pid, signal.SIGKILL)
        pytest.fail("grandchild %d survived the timeout" % pid)


# --- spawn: sessions, interruption, and the drain deadline --------------------
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process groups")
@pytest.mark.parametrize("creates_session, expected", [(False, True), (True, False)])
def test_start_new_session_is_requested_only_when_the_wrapper_does_not(
    monkeypatch, creates_session, expected
):
    seen = {}

    class FakeProc:
        returncode = 0

        def communicate(self, timeout=None):
            return ("", "")

    def fake_popen(argv, **kwargs):
        seen.update(kwargs)
        return FakeProc()

    monkeypatch.setattr("interlock.brace.sandbox.subprocess.Popen", fake_popen)
    sandbox = Sandbox(SandboxProfile.locked(), backend="soft")
    sandbox._spawn(
        WrapPlan(exec_argv=["cmd"], creates_session=creates_session),
        capture_output=True,
        timeout=None,
    )
    assert seen.get("start_new_session", False) is expected


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process groups")
def test_an_interrupted_spawn_still_kills_the_process_group(monkeypatch):
    killed = []

    class FakeProc:
        pid = 424242
        returncode = None

        def communicate(self, timeout=None):
            raise KeyboardInterrupt

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(
        "interlock.brace.sandbox.subprocess.Popen", lambda *a, **k: FakeProc()
    )
    monkeypatch.setattr(
        Sandbox, "_kill_process_group", staticmethod(lambda proc: killed.append(proc))
    )
    sandbox = Sandbox(SandboxProfile.locked(), backend="soft")
    with pytest.raises(KeyboardInterrupt):
        sandbox._spawn(
            WrapPlan(exec_argv=["cmd"]), capture_output=True, timeout=None
        )
    assert len(killed) == 1


def test_the_child_is_reaped_when_the_drain_deadline_expires(monkeypatch):
    waited = []

    class FakeProc:
        pid = 424243
        returncode = None

        def communicate(self, timeout=None):
            raise subprocess.TimeoutExpired("cmd", timeout)

        def wait(self, timeout=None):
            waited.append(timeout)
            return 0

    monkeypatch.setattr(
        "interlock.brace.sandbox.subprocess.Popen", lambda *a, **k: FakeProc()
    )
    monkeypatch.setattr(Sandbox, "_kill_process_group", staticmethod(lambda proc: None))
    sandbox = Sandbox(SandboxProfile.locked(), backend="soft")
    with pytest.raises(subprocess.TimeoutExpired) as ei:
        sandbox._spawn(
            WrapPlan(exec_argv=["cmd"]), capture_output=True, timeout=1
        )
    assert waited == [None], "the direct child must be reaped after the drain"
    assert getattr(ei.value, "scratch_in_use", False) is True


def test_a_scratch_held_by_an_escapee_is_not_removed(monkeypatch):
    created = []
    real_mkdtemp = tempfile.mkdtemp

    def record_mkdtemp(*args, **kwargs):
        path = real_mkdtemp(*args, **kwargs)
        created.append(path)
        return path

    monkeypatch.setattr("interlock.brace.sandbox.tempfile.mkdtemp", record_mkdtemp)
    sandbox = Sandbox(SandboxProfile.locked(), backend="soft")

    def fake_spawn(plan, *, capture_output, timeout):
        exc = subprocess.TimeoutExpired(plan.exec_argv, timeout)
        exc.scratch_in_use = True
        raise exc

    monkeypatch.setattr(sandbox, "_spawn", fake_spawn)
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            sandbox.run(["/bin/echo", "x"], timeout=1)
        assert len(created) == 1
        assert os.path.isdir(created[0])
    finally:
        for path in created:
            shutil.rmtree(path, ignore_errors=True)


# --- real confinement, macOS only -------------------------------------------
@pytest.mark.skipif(not _HAS_SEATBELT, reason="needs macOS sandbox-exec")
def test_seatbelt_denies_write_outside_grant():
    home_target = os.path.join(os.path.expanduser("~"), "brace_denied.txt")
    if os.path.exists(home_target):
        os.remove(home_target)
    r = Sandbox(SandboxProfile.locked()).run(
        ["/bin/sh", "-c", "echo pwned > %s" % home_target]
    )
    assert r.returncode != 0
    assert not os.path.exists(home_target)
    assert "fs-rw" in r.enforced


@pytest.mark.skipif(not _HAS_SEATBELT, reason="needs macOS sandbox-exec")
def test_seatbelt_allows_write_inside_grant():
    d = tempfile.mkdtemp()
    f = os.path.join(d, "ok.txt")
    r = Sandbox(SandboxProfile.locked().with_paths(write=[d])).run(
        ["/bin/sh", "-c", "echo ok > %s" % f]
    )
    assert r.returncode == 0
    assert os.path.exists(f)


@pytest.mark.skipif(not _HAS_SEATBELT, reason="needs macOS sandbox-exec")
def test_seatbelt_allows_write_inside_the_injected_scratch():
    r = Sandbox(SandboxProfile.locked()).run(
        ["/bin/sh", "-c", 'printf ok > "$TMPDIR/in.txt" && cat "$TMPDIR/in.txt"']
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "ok"


@pytest.mark.skipif(not _HAS_SEATBELT, reason="needs macOS sandbox-exec")
def test_seatbelt_denies_a_sibling_of_the_injected_scratch():
    """Another mkdtemp under the same shared temp root must stay unwritable:
    only the run's own scratch is granted, not /private/var/folders."""
    sibling = tempfile.mkdtemp(prefix="brace-sibling-")
    try:
        target = os.path.join(sibling, "denied.txt")
        r = Sandbox(SandboxProfile.locked()).run(
            ["/bin/sh", "-c", "echo pwned > %s" % target]
        )
        assert r.returncode != 0
        assert not os.path.exists(target)
    finally:
        shutil.rmtree(sibling, ignore_errors=True)
