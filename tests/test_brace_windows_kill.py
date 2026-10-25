"""The Windows timeout kill walks the process tree, not just the child.

Windows has no ``killpg``; without a tree walk a program the sandbox launched
can spawn a child and let the direct child die, leaving the descendant running
after the timeout. ``taskkill /T`` is the portable tree kill; these tests run
the real code path with ``sys.platform`` and ``subprocess.run`` swapped, so they
execute on any host.
"""
from __future__ import annotations

import subprocess

import pytest

from interlock.brace.sandbox import Sandbox


class FakeProc:
    pid = 4321

    def __init__(self):
        self.killed = False

    def kill(self):
        self.killed = True


@pytest.fixture
def windows(monkeypatch):
    monkeypatch.setattr("interlock.brace.sandbox.sys.platform", "win32")


def test_the_tree_is_killed_before_the_direct_child(windows, monkeypatch):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))

    monkeypatch.setattr("interlock.brace.sandbox.subprocess.run", fake_run)
    proc = FakeProc()
    Sandbox._kill_process_group(proc)  # type: ignore[arg-type]

    assert calls, "taskkill was not run"
    argv, kwargs = calls[0]
    assert argv == ["taskkill", "/T", "/F", "/PID", "4321"]
    assert kwargs["timeout"] == 10
    assert kwargs["check"] is False
    assert proc.killed, "the direct child is killed as a backstop"


def test_a_missing_taskkill_still_kills_the_direct_child(windows, monkeypatch):
    assert windows is None  # the fixture's only job is the platform patch

    def fake_run(argv, **kwargs):
        raise FileNotFoundError("taskkill")

    monkeypatch.setattr("interlock.brace.sandbox.subprocess.run", fake_run)
    proc = FakeProc()
    Sandbox._kill_process_group(proc)  # type: ignore[arg-type]
    assert proc.killed


def test_a_hung_taskkill_gives_up_and_kills_the_direct_child(windows, monkeypatch):
    assert windows is None

    def fake_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr("interlock.brace.sandbox.subprocess.run", fake_run)
    proc = FakeProc()
    Sandbox._kill_process_group(proc)  # type: ignore[arg-type]
    assert proc.killed


def test_a_process_that_vanished_is_not_an_error(windows, monkeypatch):
    assert windows is None
    monkeypatch.setattr("interlock.brace.sandbox.subprocess.run",
                        lambda *args, **kwargs: None)

    class Gone(FakeProc):
        def kill(self):
            raise OSError("already gone")

    Sandbox._kill_process_group(Gone())  # type: ignore[arg-type]  # no exception
