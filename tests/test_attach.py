"""Opt-in import hooks: one attach, every MCP session guarded from birth.

The tests use a stand-in MCP module rather than the real SDK: the point is the
hook machinery (find, wrap, unguard) and the class-level patch, not whether
``mcp`` is installed in the test environment. The last group runs a denied
call down both paths - ``guard_mcp_session(session)`` and the attached class -
and asserts the identical verdict, which is the property the whole feature
exists to preserve.
"""
from __future__ import annotations

import asyncio
import importlib
import sys
import types

import pytest

import interlock
from interlock import Blocked, PolicyEngine
from interlock.attach import Attachment, attach, detach, uncovered


class FakeClientSession:
    """The shape ``_install_mcp`` expects: a class with an async call_tool."""

    def __init__(self):
        self.calls = []

    async def call_tool(self, name, arguments=None, *rest, **kw):
        self.calls.append((name, dict(arguments or {})))
        return {"ok": True, "name": name}


@pytest.fixture
def fake_mcp_module():
    """A stand-in ``mcp.client.session`` registered before ``attach``.

    Registering it in ``sys.modules`` exercises the "already imported" path;
    the file-based test below exercises the import-time finder.
    """
    module = types.ModuleType("mcp.client.session")
    setattr(module, "ClientSession", type("ClientSession", (FakeClientSession,), {}))
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


def test_attach_guards_a_module_that_is_already_imported(fake_mcp_module):
    report = attach()

    assert report.guarded == ["mcp-session"]
    assert report, "attach() with everything guarded reports success"
    assert getattr(fake_mcp_module.ClientSession.call_tool, "__interlock_attached__", False)


def test_a_session_created_after_attach_is_guarded_on_first_call(fake_mcp_module):
    _reset_engine()
    attach()
    interlock.install(rules=[interlock.deny_tool("write_file", reason="no writes")])
    session = fake_mcp_module.ClientSession()

    with pytest.raises(Blocked) as excinfo:
        asyncio.run(session.call_tool("write_file", {"path": "/etc/passwd"}))

    assert excinfo.value.decision.reason == "no writes"
    assert session.calls == [], "the call reached the server despite the block"


def test_allowed_calls_reach_the_server_exactly_once(fake_mcp_module):
    _reset_engine()
    attach()
    session = fake_mcp_module.ClientSession()

    out = asyncio.run(session.call_tool("read_file", {"path": "notes.txt"}))

    assert out == {"ok": True, "name": "read_file"}
    assert session.calls == [("read_file", {"path": "notes.txt"})]


def test_a_second_attach_does_not_wrap_the_class_twice(fake_mcp_module):
    _reset_engine()
    attach()
    after_first = fake_mcp_module.ClientSession.call_tool
    report = attach()

    assert fake_mcp_module.ClientSession.call_tool is after_first
    assert report.guarded == ["mcp-session"]
    session = fake_mcp_module.ClientSession()
    asyncio.run(session.call_tool("read_file", {"path": "x"}))
    assert len(session.calls) == 1, "the call was delegated twice"


def test_detach_restores_the_original_class_method(fake_mcp_module):
    original = fake_mcp_module.ClientSession.call_tool
    attach()
    detach()

    assert fake_mcp_module.ClientSession.call_tool is original
    assert getattr(original, "__interlock_attached__", False) is False


def test_the_same_decision_reaches_a_wrapped_and_an_attached_session(fake_mcp_module):
    """The whole promise: attach() changes how a session is guarded, never what
    the policy decides."""
    _reset_engine()
    interlock.install(rules=[interlock.deny_tool("write_file", reason="no writes")])
    attach()

    attached = fake_mcp_module.ClientSession()
    manual = FakeClientSession()
    interlock.guard_mcp_session(manual)

    with pytest.raises(Blocked) as via_attach:
        asyncio.run(attached.call_tool("write_file", {"path": "/etc/passwd"}))
    with pytest.raises(Blocked) as via_wrapper:
        asyncio.run(manual.call_tool("write_file", {"path": "/etc/passwd"}))

    assert via_attach.value.decision.verdict == via_wrapper.value.decision.verdict
    assert via_attach.value.decision.reason == via_wrapper.value.decision.reason
    assert attached.calls == [] and manual.calls == []


def test_sync_sessions_are_guarded_too(fake_mcp_module):
    _reset_engine()

    class SyncSession:
        def __init__(self):
            self.calls = []

        def call_tool(self, name, arguments=None, *rest, **kw):
            self.calls.append(name)
            return {"ok": True}

    setattr(fake_mcp_module, "ClientSession", type("ClientSession", (SyncSession,), {}))
    attach()
    interlock.install(rules=[interlock.deny_tool("write_file", reason="no writes")])
    session = fake_mcp_module.ClientSession()

    with pytest.raises(Blocked):
        session.call_tool("write_file", {"path": "/etc/passwd"})
    assert session.calls == []


# --- the import-time path: a module that is not imported yet -----------------


def _write_package(tmp_path):
    pkg = tmp_path / "fakepkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "session.py").write_text(
        "class Client:\n"
        "    def call_tool(self, name):\n"
        "        return {'name': name}\n"
    )
    return pkg


def test_attach_patches_a_module_imported_afterwards(tmp_path):
    _write_package(tmp_path)
    sys.path.insert(0, str(tmp_path))
    seen = []

    def install(module):
        seen.append(module.__name__)
        cls = module.Client
        original = cls.call_tool
        cls.call_tool = lambda self, name: ("guarded", original(self, name))
        return True

    attachment = Attachment(site="fake", module="fakepkg.session", install=install)
    try:
        report = attach([attachment])
        assert report.guarded == [], "nothing is guarded before the import"
        assert report.missed and report.missed[0]["site"] == "fake"

        imported = importlib.import_module("fakepkg.session")  # the import is the act

        assert seen == ["fakepkg.session"]
        assert imported.Client().call_tool("x") == ("guarded", {"name": "x"})
        assert attach([attachment]).guarded == ["fake"]
    finally:
        detach()
        sys.path.remove(str(tmp_path))
        for name in [n for n in sys.modules if n == "fakepkg" or n.startswith("fakepkg.")]:
            del sys.modules[name]


def test_a_broken_install_does_not_break_the_users_import(tmp_path):
    _write_package(tmp_path)
    sys.path.insert(0, str(tmp_path))
    attachment = Attachment(site="fake", module="fakepkg.session",
                            install=lambda module: 1 / 0)
    try:
        attach([attachment])
        importlib.import_module("fakepkg.session")

        assert attachment.guarded is False
        assert "install failed" in attachment.reason
    finally:
        detach()
        sys.path.remove(str(tmp_path))
        for name in [n for n in sys.modules if n == "fakepkg" or n.startswith("fakepkg.")]:
            del sys.modules[name]


# --- the uncovered report ----------------------------------------------------


def test_uncovered_names_the_model_sdks_and_how_to_guard_them():
    detach()
    entries = {entry["site"]: entry for entry in uncovered()}

    for site in ("openai", "anthropic", "langchain", "litellm", "crewai", "google-adk"):
        assert site in entries
        assert entries[site]["attachable"] is False
        assert "interlock." in entries[site]["how"]


def test_uncovered_drops_a_surface_once_it_is_guarded(fake_mcp_module):
    detach()
    assert "mcp-session" in {entry["site"] for entry in uncovered()}

    attach()
    assert "mcp-session" not in {entry["site"] for entry in uncovered()}


def test_uncovered_reports_whether_the_package_is_even_installed():
    detach()
    entries = {entry["site"]: entry for entry in uncovered()}
    # ``available`` is a fact about this process, whatever it happens to be.
    for entry in entries.values():
        assert isinstance(entry["available"], bool)
