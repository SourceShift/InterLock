"""Opt-in import hooks: guard a framework the moment it is imported (R11).

Everything else in interlock is explicit - ``@guard``, ``guard_mcp_session``,
``guard_tool_loop``. Explicit means coverage is a function of discipline, and a
guard that has to be remembered is a guard that is missing from the one script
nobody reviewed. :func:`attach` closes the one gap with a real class-level seam:

* **MCP client sessions.** ``attach()`` patches
  ``mcp.client.session.ClientSession.call_tool`` once, at import time (or
  immediately if the SDK is already imported). Every session created afterwards
  is guarded on its first call, with no per-session wiring. The patch is
  reversible with :func:`detach`.

Everything else stays explicit on purpose. The model SDKs (OpenAI, Anthropic,
LiteLLM, CrewAI, Google ADK) do not execute tools - they return a request, and
the application's own dispatcher runs it. There is no class method to wrap that
would not also wrap the application's code, so the seam is the dispatcher and
the adapters in :mod:`interlock.interceptors` guard it. :func:`uncovered`
reports those surfaces, and whether the package is installed, the same way the
Node.js client reports what its interceptors cannot see: a missing guard should
be visible, not assumed away.

The hook is opt-in for a reason: a library that installs a ``sys.meta_path``
entry on ``import interlock`` would change every process that imports it.
"""
from __future__ import annotations

import functools
import importlib.abc
import importlib.util
import sys
import threading
import types
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

__all__ = ["Attachment", "AttachReport", "Surface", "SURFACES", "attach", "detach", "uncovered"]


@dataclass(frozen=True)
class Surface:
    """An interception point, and what to do when it is not attached."""

    site: str
    module: str
    how: str
    attachable: bool = False


SURFACES: Tuple[Surface, ...] = (
    Surface(
        "mcp-session", "mcp.client.session", attachable=True,
        how="interlock.attach() guards ClientSession.call_tool; without it, call "
            "interlock.guard_mcp_session(session) on each session",
    ),
    Surface(
        "openai", "openai",
        how="the SDK never runs a tool: guard the dispatcher your tool loop calls "
            "with interlock.guard_tool_loop",
    ),
    Surface(
        "anthropic", "anthropic",
        how="the SDK never runs a tool: guard the dispatcher your tool loop calls "
            "with interlock.guard_tool_loop",
    ),
    Surface(
        "langchain", "langchain_core",
        how="wrap each tool with interlock.guard_langchain_tools",
    ),
    Surface(
        "litellm", "litellm",
        how="guard the tool runner with interlock.guard_litellm_tool_loop",
    ),
    Surface(
        "crewai", "crewai",
        how="guard the tool runner with interlock.guard_crewai_tool_loop",
    ),
    Surface(
        "google-adk", "google.adk",
        how="guard the tool runner with interlock.guard_adk_tool_loop",
    ),
)


@dataclass
class Attachment:
    """One module to watch, and the function that guards it once imported."""

    site: str
    module: str
    install: Callable[[types.ModuleType], bool]
    uninstall: Optional[Callable[[], None]] = None
    guarded: bool = False
    reason: str = ""


@dataclass
class AttachReport:
    """What :func:`attach` did: what is guarded now, and what is not."""

    guarded: List[str] = field(default_factory=list)
    missed: List[Dict[str, str]] = field(default_factory=list)

    def __bool__(self) -> bool:
        return not self.missed

    def to_dict(self) -> Dict[str, Any]:
        return {"guarded": list(self.guarded), "missed": list(self.missed)}


class _Loader(importlib.abc.Loader):
    """Delegating loader that runs ``after(module)`` once the module is ready."""

    def __init__(self, inner: Any, after: Callable[[types.ModuleType], None]) -> None:
        self._inner = inner
        self._after = after

    def create_module(self, spec: Any) -> Any:
        create = getattr(self._inner, "create_module", None)
        return create(spec) if create is not None else None

    def exec_module(self, module: types.ModuleType) -> None:
        self._inner.exec_module(module)
        self._after(module)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class _Finder(importlib.abc.MetaPathFinder):
    """A meta-path finder that only observes its watched modules."""

    def __init__(self, targets: Dict[str, Attachment]) -> None:
        self.targets = targets

    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> Any:
        if fullname not in self.targets:
            return None
        spec = None
        for finder in list(sys.meta_path):
            if finder is self:
                continue
            find = getattr(finder, "find_spec", None)
            if find is None:
                continue
            try:
                spec = find(fullname, path, target)
            except (ImportError, AttributeError):
                continue
            if spec is not None:
                break
        if spec is None or spec.loader is None:
            return spec
        spec.loader = _Loader(spec.loader, lambda module: _installed(fullname, module))
        return spec


_lock = threading.RLock()
_finder: Optional[_Finder] = None
_attachments: Dict[str, Attachment] = {}
_restore: Dict[str, Tuple[Any, Any]] = {}


def _module_available(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def _run_install(attachment: Attachment, module: types.ModuleType) -> None:
    try:
        ok = bool(attachment.install(module))
    except Exception as exc:  # a hook must not break the user's import
        attachment.guarded = False
        attachment.reason = "install failed: {}".format(exc)
        return
    attachment.guarded = ok
    if not ok:
        attachment.reason = attachment.reason or "the module has no attachable seam"


def _installed(fullname: str, module: types.ModuleType) -> None:
    attachment = _attachments.get(fullname)
    if attachment is not None:
        _run_install(attachment, module)


def _install_mcp(module: types.ModuleType) -> bool:
    """Guard ``ClientSession.call_tool`` at the class, without recursion.

    The class method becomes a one-line delegate: on the first call on a
    session it hands the *original* bound method to ``guard_mcp_session``,
    which installs the per-instance guard; every later call goes straight to
    that guard. Marking the wrapper keeps a re-import or a second ``attach``
    from wrapping it again.
    """
    from .interceptors.mcp import guard_mcp_session

    cls = getattr(module, "ClientSession", None)
    original = getattr(cls, "call_tool", None)
    if cls is None or original is None:
        return False
    if getattr(original, "__interlock_attached__", False):
        return True

    @functools.wraps(original)
    def call_tool(self: Any, *args: Any, **kwargs: Any) -> Any:
        guard_mcp_session(self, original=original.__get__(self, type(self)))
        return self.call_tool(*args, **kwargs)

    call_tool.__interlock_attached__ = True  # type: ignore[attr-defined]
    cls.call_tool = call_tool
    _restore[module.__name__] = (cls, original)
    return True


def _restore_mcp() -> None:
    for name, (cls, original) in list(_restore.items()):
        cls.call_tool = original
        _restore.pop(name, None)


def _mcp_attachment() -> Attachment:
    return Attachment(site="mcp-session", module="mcp.client.session",
                      install=_install_mcp, uninstall=_restore_mcp)


def attach(attachments: Optional[Sequence[Attachment]] = None) -> AttachReport:
    """Watch the default surfaces (or ``attachments``) and guard them on import.

    Idempotent: a second call adds no second hook and wraps no class twice.
    Returns an :class:`AttachReport`; ``False`` when something could not be
    attached (the report names why). ``attachments`` exists so a caller can
    attach a test double, or a surface interlock does not ship.
    """
    global _finder
    with _lock:
        for attachment in (list(attachments) if attachments is not None
                           else [_mcp_attachment()]):
            _attachments[attachment.module] = attachment
            module = sys.modules.get(attachment.module)
            if module is not None:
                _run_install(attachment, module)
            elif not _module_available(attachment.module):
                attachment.reason = attachment.reason or "the module is not installed here"
        if _finder is None:
            _finder = _Finder(_attachments)
            sys.meta_path.insert(0, _finder)
        else:
            _finder.targets = _attachments
        # A module imported between the check above and the finder going in
        # would otherwise be missed until its next import.
        for attachment in _attachments.values():
            module = sys.modules.get(attachment.module)
            if module is not None and not attachment.guarded:
                _run_install(attachment, module)
        return _report()


def detach() -> None:
    """Remove the hook and restore every patched class."""
    global _finder
    with _lock:
        if _finder is not None:
            try:
                sys.meta_path.remove(_finder)
            except ValueError:
                pass
            _finder = None
        for attachment in _attachments.values():
            if attachment.uninstall is not None:
                attachment.uninstall()
            attachment.guarded = False
        _attachments.clear()


def _report() -> AttachReport:
    report = AttachReport()
    for attachment in _attachments.values():
        if attachment.guarded:
            report.guarded.append(attachment.site)
        else:
            report.missed.append({"site": attachment.site, "module": attachment.module,
                                  "reason": attachment.reason or "not imported yet"})
    return report


def uncovered() -> List[Dict[str, Any]]:
    """The known interception points that are not guarded right now.

    Each entry names the surface, whether this process could have it at all,
    and how to guard it explicitly. Empty means every shipped surface this
    process could use is attached.
    """
    with _lock:
        out: List[Dict[str, Any]] = []
        for surface in SURFACES:
            attachment = _attachments.get(surface.module)
            if attachment is not None and attachment.guarded:
                continue
            out.append({
                "site": surface.site,
                "module": surface.module,
                "attachable": surface.attachable,
                "available": _module_available(surface.module),
                "how": surface.how,
            })
        return out
