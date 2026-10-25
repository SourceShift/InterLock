"""The compatibility contract and the import monitor.

``attach()`` patches another library's class. Two failure modes follow: the
library updates into a shape the hook cannot patch (the contract), or it
changes underneath a process that is already guarded (the monitor). These tests
use a stand-in MCP module, as ``test_attach.py`` does; the contract and the
provenance comparisons are the subject, not the real SDK.
"""
from __future__ import annotations

import asyncio
import importlib
import json
import sys
import types

import pytest

import interlock
from interlock import Blocked, PolicyEngine
from interlock.attach import (MCP_SEAM, attach, check_seam, detach, inspect_surfaces,
                              monitor)

attach_module = importlib.import_module("interlock.attach")


class FakeClientSession:
    def __init__(self):
        self.calls = []

    async def call_tool(self, name, arguments=None, *rest, **kw):
        self.calls.append((name, dict(arguments or {})))
        return {"ok": True, "name": name}


def _module(class_object=None):
    module = types.ModuleType("mcp.client.session")
    setattr(module, "ClientSession", class_object or type("ClientSession", (FakeClientSession,), {}))
    return module


@pytest.fixture
def fake_mcp():
    module = _module()
    previous = sys.modules.get("mcp.client.session")
    sys.modules["mcp.client.session"] = module
    yield module
    detach()
    if previous is not None:
        sys.modules["mcp.client.session"] = previous
    else:
        sys.modules.pop("mcp.client.session", None)


def _reset_engine():
    interlock.install(engine=PolicyEngine())


# --- the compatibility contract ---------------------------------------------


def test_contract_accepts_the_shapes_attach_supports():
    async_shape = _module()
    assert check_seam(async_shape, MCP_SEAM) == []

    sync_shape = types.ModuleType("mcp.client.session")
    setattr(sync_shape, "ClientSession", type("ClientSession", (FakeClientSession,), {}))
    # A sync call_tool is still patchable: the wrapper returns whatever the
    # method returns, and guard_mcp_session supports both.
    sync_shape.ClientSession.call_tool = lambda self, name, arguments=None, *a, **k: None
    assert check_seam(sync_shape, MCP_SEAM) == []

    varargs_shape = types.ModuleType("mcp.client.session")
    setattr(varargs_shape, "ClientSession", type("ClientSession", (object,), {
        "call_tool": lambda self, *args, **kwargs: None}))
    assert check_seam(varargs_shape, MCP_SEAM) == []


@pytest.mark.parametrize("module, expected", [
    (types.ModuleType("mcp.client.session"), "has no ClientSession"),
    (None, "is not a class"),
    ("missing-method", "has no call_tool"),
    ("not-callable", "is not callable"),
    ("too-few", "takes 1 positional parameter"),
])
def test_contract_names_each_break(module, expected):
    if not isinstance(module, types.ModuleType):
        built = types.ModuleType("mcp.client.session")
        if module is None:
            setattr(built, "ClientSession", object())
        elif module == "missing-method":
            setattr(built, "ClientSession", type("ClientSession", (object,), {}))
        elif module == "not-callable":
            setattr(built, "ClientSession", type("ClientSession", (object,), {
                "call_tool": 3}))
        elif module == "too-few":
            setattr(built, "ClientSession", type("ClientSession", (object,), {
                "call_tool": lambda self, name: None}))
        module = built
    problems = check_seam(module, MCP_SEAM)
    assert problems and expected in problems[0]


def test_the_contract_matches_the_installed_mcp_sdk():
    # The fakes above pin the shapes the hook supports; this checks the real
    # package whenever the environment has it, so a client release that breaks
    # the seam is caught where the SDK is installed (CI installs it in the
    # optional-dependency job, if any; otherwise the check is opt-in).
    sdk = pytest.importorskip("mcp.client.session")
    assert check_seam(sdk, MCP_SEAM) == []


def test_attach_refuses_an_incompatible_seam_and_says_why(fake_mcp):
    fake_mcp.ClientSession.call_tool = 3  # a client release that broke the seam
    report = attach()

    assert report.guarded == []
    assert report.missed and "incompatible seam" in report.missed[0]["reason"]
    assert not report
    assert not getattr(fake_mcp.ClientSession.call_tool, "__interlock_attached__", False)


# --- the import monitor ------------------------------------------------------


def test_monitor_is_clean_right_after_attach(fake_mcp):
    assert attach().guarded == ["mcp-session"]
    assert monitor() == []


def test_monitor_sees_a_restored_method_and_attach_repairs_it(fake_mcp):
    original = fake_mcp.ClientSession.call_tool
    attach()
    fake_mcp.ClientSession.call_tool = original  # someone undid the patch

    [drift] = monitor()
    assert drift.kind == "unpatched"
    assert drift.to_dict()["repaired"] is False

    report = attach()
    assert report.drifts[0]["kind"] == "unpatched"
    assert report.drifts[0]["repaired"] is True
    assert not report  # a tamper is still a finding, even when repaired
    assert monitor() == []
    assert getattr(fake_mcp.ClientSession.call_tool, "__interlock_attached__", False)


def test_monitor_sees_a_replaced_class_and_restores_the_guard(fake_mcp):
    _reset_engine()
    attach()
    interlock.install(rules=[interlock.deny_tool("write_file", reason="no writes")])
    replacement = type("ClientSession", (FakeClientSession,), {})
    fake_mcp.ClientSession = replacement

    [drift] = monitor()
    assert drift.kind == "replaced"
    report = attach()
    assert report.drifts[0]["repaired"] is True

    with pytest.raises(Blocked):
        asyncio.run(replacement().call_tool("write_file", {"path": "/etc/passwd"}))
    assert monitor() == []


def test_monitor_sees_a_source_file_changed_on_disk(tmp_path, fake_mcp):
    source = tmp_path / "session.py"
    source.write_text("# original\n")
    fake_mcp.__file__ = str(source)
    attach()

    source.write_text("# tampered after install\n")
    [drift] = monitor()
    assert drift.kind == "modified"
    assert "changed on disk" in drift.detail

    # A second attach must not re-hash the file and call the tamper clean: the
    # running code did not change, so the digest is still evidence.
    report = attach()
    assert report.drifts and report.drifts[0]["kind"] == "modified"
    assert report.drifts[0]["repaired"] is False
    assert monitor()[0].kind == "modified"


def test_monitor_sees_a_removed_module(fake_mcp):
    attach()
    sys.modules.pop("mcp.client.session", None)
    [drift] = monitor()
    assert drift.kind == "missing"


def test_monitor_sees_a_version_change(monkeypatch, fake_mcp):
    monkeypatch.setattr(attach_module, "_distribution_version", lambda module: "1.0")
    attach()
    monkeypatch.setattr(attach_module, "_distribution_version", lambda module: "2.0")
    [drift] = monitor()
    assert drift.kind == "version"
    assert "1.0 to 2.0" in drift.detail


def test_a_guarded_call_still_goes_through_after_a_monitor_pass(fake_mcp):
    _reset_engine()
    attach()
    assert monitor() == []
    interlock.install(rules=[interlock.deny_tool("write_file", reason="no writes")])
    session = fake_mcp.ClientSession()
    with pytest.raises(Blocked):
        asyncio.run(session.call_tool("write_file", {"path": "/etc/passwd"}))
    assert session.calls == []


# --- inspection without attaching -------------------------------------------


def test_inspect_surfaces_runs_the_contract_without_installing(fake_mcp, monkeypatch):
    monkeypatch.setattr(attach_module, "_module_available", lambda module: True)
    entries = {entry["site"]: entry for entry in inspect_surfaces()}
    entry = entries["mcp-session"]
    assert entry["installed"] is True
    assert entry["compatible"] is True
    assert entry["guarded"] is False
    assert not getattr(fake_mcp.ClientSession.call_tool, "__interlock_attached__", False)


def test_inspect_surfaces_reports_an_incompatible_installed_package(fake_mcp, monkeypatch):
    monkeypatch.setattr(attach_module, "_module_available", lambda module: True)
    fake_mcp.ClientSession.call_tool = 3
    entry = {entry["site"]: entry for entry in inspect_surfaces()}["mcp-session"]
    assert entry["compatible"] is False
    assert "not callable" in entry["problems"][0]


def test_the_cli_prints_surfaces_and_passes_when_mcp_is_absent(monkeypatch):
    from interlock.cli import main

    # This test environment does not install mcp; the check must still be a
    # clean 0, not an import crash.
    monkeypatch.setattr(attach_module, "_module_available", lambda module: False)
    assert main(["attach", "--check", "--json"]) == 0


def test_the_cli_json_lists_every_known_surface(capsys):
    from interlock.cli import main

    assert main(["attach", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    sites = {entry["site"] for entry in payload["surfaces"]}
    assert {"mcp-session", "openai", "anthropic", "langchain"} <= sites
    assert payload["ok"] is True
