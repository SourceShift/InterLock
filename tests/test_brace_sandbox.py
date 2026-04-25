"""The Sandbox facade: it runs a command under confinement AND routes the launch
through the policy engine first. These tests cover the portable behaviour on any
host (soft backend, pre-exec block, argv rewrite) and add real-confinement proofs
that only run where a kernel sandbox exists.
"""
import os
import shutil
import sys
import tempfile

import pytest

from interlock import Blocked, Decision, PolicyEngine, SensorEvent, deny_tool
from interlock.brace import Sandbox, SandboxProfile

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
