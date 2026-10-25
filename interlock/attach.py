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
import hashlib
import importlib.abc
import importlib.metadata
import importlib.util
import inspect
import os
import sys
import threading
import types
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

__all__ = ["Attachment", "AttachReport", "Drift", "Seam", "Surface", "SURFACES",
           "MCP_SEAM", "attach", "check_seam", "detach", "inspect_surfaces", "monitor",
           "uncovered"]

#: A file is re-hashed whole; a dependency source file is small, and a partial
#: digest would miss a tampered tail.
MAX_DIGEST_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class Seam:
    """The exact shape an attachment relies on in someone else's module.

    The fields are deliberately structural rather than a version pin: a client
    release that keeps the class and method but changes an internal helper is
    compatible, while one that renames the class or changes the method to a
    property is not. :func:`check_seam` reads the installed object.
    """

    target: str
    method: str
    #: Parameter names the method must accept positionally. Names beyond these
    #: are its business; a ``*args`` signature satisfies the requirement.
    positional: Tuple[str, ...] = ("name", "arguments")


#: The seam ``attach()`` patches. Kept as data so a compatibility check can run
#: without installing anything, and so the contract is one reviewable object.
MCP_SEAM = Seam("ClientSession", "call_tool", ("name", "arguments"))


@dataclass(frozen=True)
class Surface:
    """An interception point, and what to do when it is not attached."""

    site: str
    module: str
    how: str
    attachable: bool = False
    seam: Optional[Seam] = None


SURFACES: Tuple[Surface, ...] = (
    Surface(
        "mcp-session", "mcp.client.session", attachable=True, seam=MCP_SEAM,
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


@dataclass(frozen=True)
class Drift:
    """A guarded module that no longer matches what was attached.

    ``kind`` is ``missing`` (the module left ``sys.modules``), ``replaced``
    (a different class object now owns the seam), ``unpatched`` (the method is
    no longer the wrapper), ``modified`` (the source file's digest changed),
    ``removed`` (the source file is gone), or ``version`` (the installed
    distribution version changed).
    """

    site: str
    module: str
    kind: str
    detail: str
    repaired: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {"site": self.site, "module": self.module, "kind": self.kind,
                "detail": self.detail, "repaired": self.repaired}


@dataclass(frozen=True)
class Provenance:
    """What the module looked like when it was guarded."""

    target: str
    method_name: str
    class_object: Any = field(repr=False, compare=False)
    method: Any = field(repr=False, compare=False)
    file: Optional[str]
    sha256: Optional[str]
    version: Optional[str]


def check_seam(module: types.ModuleType, seam: Optional[Seam] = None) -> List[str]:
    """Return the ways ``module`` breaks ``seam``; empty means compatible.

    ``seam`` defaults to :data:`MCP_SEAM`. The check is structural on purpose.
    It answers "can this hook patch and delegate without changing behaviour?",
    not "is this the version we tested against": a compatible client release
    should keep working, and an incompatible one should be refused loudly
    instead of half-guarded.
    """
    seam = seam or MCP_SEAM
    problems: List[str] = []
    target = getattr(module, seam.target, None)
    if target is None:
        return ["{} has no {}".format(module.__name__, seam.target)]
    if not isinstance(target, type):
        problems.append("{}.{} is not a class".format(module.__name__, seam.target))
        return problems
    method = getattr(target, seam.method, None)
    if method is None:
        problems.append("{}.{} has no {}".format(
            module.__name__, seam.target, seam.method))
        return problems
    if not callable(method):
        problems.append("{}.{}.{} is not callable".format(
            module.__name__, seam.target, seam.method))
        return problems
    try:
        signature = inspect.signature(method)
    except (TypeError, ValueError):
        return problems  # callable, but opaque (a C method): patchable
    parameters = [p for p in signature.parameters.values() if p.name != "self"]
    positional = [p for p in parameters if p.kind in (
        inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)]
    takes_varargs = any(p.kind is inspect.Parameter.VAR_POSITIONAL for p in parameters)
    if not takes_varargs and len(positional) < len(seam.positional):
        problems.append(
            "{}.{}.{} takes {} positional parameter(s); the hook needs {} ({})".format(
                module.__name__, seam.target, seam.method, len(positional),
                len(seam.positional), ", ".join(seam.positional)))
    return problems


@dataclass
class Attachment:
    """One module to watch, and the function that guards it once imported."""

    site: str
    module: str
    install: Callable[[types.ModuleType], bool]
    uninstall: Optional[Callable[[], None]] = None
    guarded: bool = False
    reason: str = ""
    seam: Optional[Seam] = None
    provenance: Optional[Provenance] = None


@dataclass
class AttachReport:
    """What :func:`attach` did: what is guarded now, and what is not."""

    guarded: List[str] = field(default_factory=list)
    missed: List[Dict[str, str]] = field(default_factory=list)
    drifts: List[Dict[str, Any]] = field(default_factory=list)

    def __bool__(self) -> bool:
        return not self.missed and not self.drifts

    def to_dict(self) -> Dict[str, Any]:
        return {"guarded": list(self.guarded), "missed": list(self.missed),
                "drifts": list(self.drifts)}


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


class _Incompatible(Exception):
    """The installed module no longer has the shape the hook needs."""


def _file_digest(path: str) -> Optional[Tuple[str, int]]:
    """SHA-256 and size of ``path``, or ``None`` when it cannot be read.

    Whole-file on purpose: a partial digest would let a tampered tail pass.
    The cap only guards against pointing this at something enormous; a real
    client source file is far below it.
    """
    try:
        size = os.path.getsize(path)
        if size > MAX_DIGEST_BYTES:
            return None
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest(), size
    except OSError:
        return None


def _distribution_version(module: str) -> Optional[str]:
    top = module.split(".", 1)[0]
    try:
        return importlib.metadata.version(top)
    except importlib.metadata.PackageNotFoundError:
        return None
    except Exception:  # metadata can be broken independently of the import
        return None


def _capture_provenance(attachment: Attachment, module: types.ModuleType) -> None:
    seam = attachment.seam
    if seam is None:
        return
    cls = getattr(module, seam.target, None)
    method = getattr(cls, seam.method, None) if cls is not None else None
    path = getattr(module, "__file__", None)
    digest = None
    if isinstance(path, str) and path:
        path = os.path.realpath(path)
        digested = _file_digest(path)
        digest = digested[0] if digested is not None else None
    else:
        path = None
    attachment.provenance = Provenance(
        target=seam.target, method_name=seam.method, class_object=cls, method=method,
        file=path, sha256=digest, version=_distribution_version(module.__name__))


def _run_install(attachment: Attachment, module: types.ModuleType) -> None:
    try:
        ok = bool(attachment.install(module))
    except _Incompatible as exc:  # refuse the seam, but never break the import
        attachment.guarded = False
        attachment.reason = "incompatible seam: {}".format(exc)
        attachment.provenance = None
        return
    except Exception as exc:  # a hook must not break the user's import
        attachment.guarded = False
        attachment.reason = "install failed: {}".format(exc)
        attachment.provenance = None
        return
    attachment.guarded = ok
    if not ok:
        attachment.reason = attachment.reason or "the module has no attachable seam"
        attachment.provenance = None
        return
    attachment.reason = ""
    _capture_provenance(attachment, module)


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

    problems = check_seam(module, MCP_SEAM)
    if problems:
        raise _Incompatible("; ".join(problems))
    cls = getattr(module, MCP_SEAM.target)
    original = getattr(cls, MCP_SEAM.method)
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
                      install=_install_mcp, uninstall=_restore_mcp, seam=MCP_SEAM)


def _drifts_for(attachment: Attachment) -> List[Drift]:
    if not attachment.guarded or attachment.provenance is None:
        return []
    provenance = attachment.provenance
    module = sys.modules.get(attachment.module)
    if module is None:
        return [Drift(attachment.site, attachment.module, "missing",
                      "the module was removed from sys.modules; no call is guarded now")]
    drifts: List[Drift] = []
    cls = getattr(module, provenance.target, None)
    if cls is not provenance.class_object:
        replacement = "a different {}.{}".format(attachment.module, provenance.target)
        if getattr(cls, "__interlock_attached__", False) is False:
            replacement += " that is not patched"
        drifts.append(Drift(attachment.site, attachment.module, "replaced", replacement))
    elif getattr(cls, provenance.method_name, None) is not provenance.method:
        drifts.append(Drift(attachment.site, attachment.module, "unpatched",
                            "{}.{} is no longer the guard wrapper".format(
                                provenance.target, provenance.method_name)))
    if provenance.file is not None and provenance.sha256 is not None:
        if not os.path.exists(provenance.file):
            drifts.append(Drift(attachment.site, attachment.module, "removed",
                                "{} no longer exists".format(provenance.file)))
        else:
            digested = _file_digest(provenance.file)
            if digested is not None and digested[0] != provenance.sha256:
                drifts.append(Drift(attachment.site, attachment.module, "modified",
                                    "{} changed on disk after the guard was installed".format(
                                        provenance.file)))
    version = _distribution_version(attachment.module)
    if provenance.version and version and version != provenance.version:
        drifts.append(Drift(attachment.site, attachment.module, "version",
                            "installed version changed from {} to {}".format(
                                provenance.version, version)))
    return drifts


def monitor() -> List[Drift]:
    """Check that every guarded module still looks like what was attached.

    This is the import monitor: the hook wraps a class object, so a module
    replaced in ``sys.modules``, a method restored by hand, a dependency file
    edited on disk, or a distribution upgraded underneath the running process
    all leave a guard that is no longer the guard that was installed. Call it
    on a schedule (or before a sensitive session); :func:`attach` runs it too
    and repairs a replaced or unpatched class, but a changed file is reported,
    not silently re-blessed - the running code did not change, so re-hashing it
    would hide exactly the tamper this exists to find.
    """
    with _lock:
        drifts: List[Drift] = []
        for attachment in _attachments.values():
            drifts.extend(_drifts_for(attachment))
        return drifts


def _inspect_module(module: str, seam: Optional[Seam]) -> Dict[str, Any]:
    entry: Dict[str, Any] = {"module": module, "installed": _module_available(module)}
    if not entry["installed"]:
        return entry
    entry["version"] = _distribution_version(module)
    if seam is None:
        return entry
    try:
        imported = importlib.import_module(module)
    except Exception as exc:  # an import error here is itself a finding
        entry["import_error"] = "{}: {}".format(type(exc).__name__, exc)
        return entry
    problems = check_seam(imported, seam)
    entry["compatible"] = not problems
    entry["problems"] = problems
    return entry


def inspect_surfaces() -> List[Dict[str, Any]]:
    """What each known interception point looks like in this process.

    Unlike :func:`uncovered` this does not need a running attachment: it
    imports an attachable package (a compatibility check is about the installed
    object) and reports its version, whether the seam is compatible, and why
    not. ``python -m interlock attach --check`` prints it.
    """
    with _lock:
        entries: List[Dict[str, Any]] = []
        for surface in SURFACES:
            entry = _inspect_module(surface.module, surface.seam if surface.attachable else None)
            entry.update({"site": surface.site, "attachable": surface.attachable,
                          "how": surface.how})
            drifts = []
            attachment = _attachments.get(surface.module)
            if attachment is not None:
                drifts = [drift.to_dict() for drift in _drifts_for(attachment)]
            entry["guarded"] = bool(attachment is not None and attachment.guarded)
            entry["drifts"] = drifts
            entries.append(entry)
        return entries


def attach(attachments: Optional[Sequence[Attachment]] = None) -> AttachReport:
    """Watch the default surfaces (or ``attachments``) and guard them on import.

    Idempotent: a second call adds no second hook and wraps no class twice.
    Returns an :class:`AttachReport`; ``False`` when something could not be
    attached (the report names why). ``attachments`` exists so a caller can
    attach a test double, or a surface interlock does not ship.
    """
    global _finder
    with _lock:
        incoming = list(attachments) if attachments is not None else [_mcp_attachment()]
        for attachment in incoming:
            # Re-calling attach() with the defaults must keep the existing
            # attachment: replacing it would lose the provenance the monitor
            # compares against, and re-installing would re-hash a file that may
            # just have been tampered with.
            if attachments is None and attachment.module in _attachments:
                continue
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
        drifts: List[Drift] = []
        for attachment in _attachments.values():
            module = sys.modules.get(attachment.module)
            if module is None:
                continue
            found = _drifts_for(attachment)
            if not found and not attachment.guarded:
                _run_install(attachment, module)
                continue
            drifts.extend(found)
            if any(drift.kind in ("replaced", "unpatched") for drift in found):
                _run_install(attachment, module)
        report = _report()
        report.drifts = [
            dict(drift.to_dict(),
                 repaired=bool(drift.kind in ("replaced", "unpatched")
                               and _attachments[drift.module].guarded))
            for drift in drifts
        ]
        return report


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
            attachment.provenance = None
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
