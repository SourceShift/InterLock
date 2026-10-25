"""Declarative policies: rules as data, with a safe condition evaluator (R10).

A policy file is JSON (or YAML, when PyYAML is installed - the core stays
dependency-free). It lists rules; each rule says *when* it applies and *what*
happens::

    {
      "version": 1,
      "rules": [
        {"id": "no-force-push", "verdict": "block",
         "reason": "force-push to a default branch",
         "when": {"intent": "git.push.force:default"}},
        {"id": "cap-rows", "verdict": "modify", "set": {"limit": 100},
         "reason": "row limit capped",
         "when": {"all": [{"action": "query_db"}, {"arg": "limit", "gt": 100}]}},
        {"id": "egress", "detector": "data_egress.network_egress_guard",
         "with": {"allowed_hosts": ["api.acme.com"]}, "widenable": ["allowed_hosts"]}
      ]
    }

**The condition language** is a closed set of operators over the event, never
code. A condition is one of:

- ``{"all": [...]}``, ``{"any": [...]}``, ``{"not": {...}}``
- ``{"action": NAME | [NAMES] | {"glob": PATTERN}}``
- ``{"field": F, OP: VALUE}`` where F is an event field (``action``,
  ``principal``, ``phase``, ``span_id``, ``parent_principal``, ``call_id``)
- ``{"arg": NAME, OP: VALUE}`` - a tool argument; ``a.b`` reaches into a
  nested object
- ``{"intent": SELECTOR}`` - a shell intent (see :mod:`interlock.shell`) in
  any string argument, or only in ``"arg"`` when given
- ``{"sql": SELECTOR}`` - what a SQL argument does (see :mod:`interlock.sql`):
  ``"delete"``, ``"ddl"``, ``"write:customers"``, ``"unbounded"`` ... in the
  SQL-named arguments (``sql``, ``query``, ...), or only in ``"arg"``;
  ``"dialect"`` picks the lexing rules
- ``{"a2a": SELECTOR}`` - an agent-to-agent call (see
  :mod:`interlock.detectors.a2a_policy`): ``"peer"`` or ``"peer:<glob>"``
  matches the ``"peer"`` argument, ``"card"`` or ``"card.<field>[:<glob>]``
  matches the ``"card"`` argument; ``"arg"`` reads the peer from one argument

A rule's ``"on"`` key (an action name, a list, or ``{"glob": ...}``) limits it
to those actions; it is how a catalogued detector, which scans every string
argument, is pointed at the shell tool only.

and OP is one of ``eq ne in not_in gt ge lt le contains startswith endswith
matches glob exists``. Lookups only index dicts and lists; nothing reaches an
attribute, so a hostile file cannot walk from an event into the interpreter.

**Guardrails** (learned the hard way by tools that ship rules as data):

- *Typos fail at load.* An unknown event field, operator or key is an error
  naming the valid choices. For actions with a known argument schema (the
  coding-agent tools, or ones the file declares under ``"tools"``), an
  argument name the tool does not have is an error too - a rule that loads
  clean but can never fire is the worst kind.
- *Bad rules are quarantined.* One invalid rule is skipped (and listed in
  ``engine.quarantined``); the rest of the file loads. A file that does not
  parse at all raises :class:`PolicyError`, and a reloading engine keeps its
  last good policy.
- *Locked rules stay on.* ``"locked": true`` rules cannot be disabled by a
  file that ``"extends"`` this one, nor by any overlay.
- *Overlays only tighten.* A project overlay (``.interlock/policy.json``) may
  add blocking or escalating rules and may widen lists a base rule names in
  ``"widenable"``; it may not disable, replace or relax anything, may not
  rewrite (no ``"set"`` or ``"modify"`` and no detector rules, whose verdicts
  are not known at load time), and may not redefine or persist a tool schema.
  It is ignored until trusted by content hash (see
  :mod:`interlock.policy.trust`).

The combining logic is the engine's and is not configurable: a BLOCK wins, an
ESCALATE waits for no-block, rewrites compose.
"""
from __future__ import annotations

import copy
import dataclasses
import difflib
import fnmatch
import hashlib
import importlib
import inspect
import json
import logging
import os
import pkgutil
import re
import threading
import time
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Tuple

from ..enforce import Decision, Verdict
from ..event import SensorEvent
from .engine import PolicyEngine, Rule

_log = logging.getLogger("interlock")

SCHEMA_VERSION = 1

#: Event fields a ``{"field": ...}`` condition may read.
EVENT_FIELDS: FrozenSet[str] = frozenset(
    {"action", "principal", "phase", "span_id", "parent_principal", "call_id"}
)
OPERATORS: FrozenSet[str] = frozenset(
    {"eq", "ne", "in", "not_in", "gt", "ge", "lt", "le", "contains", "startswith",
     "endswith", "matches", "glob", "exists"}
)
VERDICTS: FrozenSet[str] = frozenset({"block", "escalate", "modify"})
#: Mesh facts a rule may carry (see ``interlock.mesh.bundle``): how far the
#: community trusts it, whether this node only observes it, and the strongest
#: verdict it may carry here. A decision above the ceiling becomes an escalate.
RULE_STATUSES: FrozenSet[str] = frozenset({"experimental", "test", "stable", "deprecated"})
RULE_MODES: FrozenSet[str] = frozenset({"enforce", "shadow"})
RULE_CEILINGS: Dict[str, int] = {"escalate": 1, "modify": 2, "block": 3}
_RULE_KEYS = frozenset(
    {"id", "verdict", "reason", "when", "set", "locked", "phase", "detector", "with",
     "widenable", "description", "on", "status", "mode", "ceiling"}
)
_DOC_KEYS = frozenset({"version", "name", "description", "extends", "rules", "disable", "tools",
                       "channel"})
_OVERLAY_KEYS = frozenset({"version", "name", "description", "rules", "widen", "tools"})

#: Longest regex a ``matches`` condition may use, and the longest string it scans.
MAX_PATTERN = 512
MAX_SCAN = 64 * 1024

#: Known argument names per action. Conditions on these actions are checked
#: against them at load. Adapters and policy files can add more.
TOOL_SCHEMAS: Dict[str, FrozenSet[str]] = {}

#: Serialises writes to the process-global ``TOOL_SCHEMAS``. An ``RLock``
#: because a load holds it while compiling, and ``_compile_overlay`` takes it
#: again to scope the tools an overlay declares to its own rules.
_tool_schemas_lock = threading.RLock()

#: Marks an action that was absent when a snapshot was taken, so restoring it
#: removes the key rather than writing a placeholder back.
_MISSING_TOOL = object()


def register_tool_schema(action: str, args: Iterable[str]) -> None:
    """Declare the argument names ``action`` takes, for load-time checking."""
    with _tool_schemas_lock:
        TOOL_SCHEMAS[action] = frozenset(args)


def _snapshot_tools(actions: Iterable[str]) -> Dict[str, Any]:
    """Capture the current schema of ``actions``, missing ones included."""
    return {action: TOOL_SCHEMAS.get(action, _MISSING_TOOL) for action in actions}


def _restore_tools(snapshot: Mapping[str, Any]) -> None:
    """Put back the schemas captured by :func:`_snapshot_tools`, in place."""
    for action, value in snapshot.items():
        if value is _MISSING_TOOL:
            TOOL_SCHEMAS.pop(action, None)
        else:
            TOOL_SCHEMAS[action] = value  # type: ignore[assignment]


class PolicyError(ValueError):
    """A policy document that cannot be used. ``where`` locates the problem."""

    def __init__(self, message: str, where: str = "") -> None:
        super().__init__("{}: {}".format(where, message) if where else message)
        self.where = where


# --- parsing ------------------------------------------------------------------


def parse_policy_text(text: str, *, fmt: str = "json", source: str = "<text>") -> Dict[str, Any]:
    """Parse JSON (always available) or YAML (needs PyYAML) into a document."""
    if fmt == "json":
        try:
            doc = json.loads(text)
        except ValueError as exc:
            raise PolicyError("not valid JSON: {}".format(exc), source)
    elif fmt in ("yaml", "yml"):
        try:
            import yaml  # type: ignore
        except ImportError:
            raise PolicyError("YAML policies need PyYAML (pip install pyyaml); "
                              "or write the policy as JSON", source)
        try:
            doc = yaml.safe_load(text)
        except Exception as exc:
            raise PolicyError("not valid YAML: {}".format(exc), source)
    else:
        raise PolicyError("unknown policy format {!r}".format(fmt), source)
    if not isinstance(doc, dict):
        raise PolicyError("a policy must be an object at the top level", source)
    return doc


def read_policy_file(path: str) -> Tuple[Dict[str, Any], str]:
    """Read and parse a policy file; return (document, sha256 of its bytes)."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise PolicyError("cannot read: {}".format(exc.strerror or exc), path)
    ext = os.path.splitext(path)[1].lower().lstrip(".")
    fmt = "yaml" if ext in ("yaml", "yml") else "json"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise PolicyError("not UTF-8", path)
    return parse_policy_text(text, fmt=fmt, source=path), hashlib.sha256(raw).hexdigest()


# --- the compiled engine --------------------------------------------------------


class DeclarativeEngine(PolicyEngine):
    #: The epoch is a content hash: the same files give the same epoch in
    #: every process, so a review approved in one hook process matches the
    #: retry in the next.
    epoch_is_stable = True

    """A :class:`PolicyEngine` built from policy documents, reloadable.

    ``quarantined`` lists ``"rule-id: why"`` for every rule skipped as invalid.
    ``overlays`` reports each overlay considered and whether it was applied.
    ``epoch`` hashes the effective documents, so it is stable across processes
    for the same files.
    """

    def __init__(self, rules: Sequence[Rule], *, documents: Sequence[Mapping[str, Any]],
                 quarantined: Sequence[str] = (), locked: Iterable[str] = (),
                 overlays: Sequence[Tuple[str, str]] = (),
                 loader: Optional[Callable[[], "DeclarativeEngine"]] = None,
                 watch: Optional[float] = None, files: Sequence[str] = (),
                 shadow_rules: Sequence[Rule] = ()) -> None:
        super().__init__(list(rules))
        #: Rules installed through ``add_rule``. They are part of the running
        #: policy, not of a document, so a reload re-appends them after the
        #: freshly loaded rules instead of silently dropping them.
        self._code_rules: List[Rule] = []
        self.documents = [copy.deepcopy(dict(d)) for d in documents]
        self.quarantined = list(quarantined)
        self.locked = sorted(set(locked))
        self.overlays = list(overlays)
        self.last_error: Optional[str] = None
        self._loader = loader
        self._watch = watch
        self._files = list(files)
        self._stamps = _stamps(self._files)
        self._checked = time.monotonic()
        self._content_epoch = _content_epoch(self.documents)
        # Shadow rules (``"mode": "shadow"``, set by the mesh subscriber for a
        # rule inside its monitor window) are evaluated after the real decision
        # and never change it. What they would have decided is logged, counted
        # in metrics as observed, tallied in ``shadow_counts`` and handed to
        # ``shadow_sink`` when one is set. The engine does this, not the rule,
        # so the invariant that rules never write records holds.
        self._shadow: List[Rule] = list(shadow_rules)
        self.shadow_sink: Optional[Callable[[Dict[str, Any]], None]] = None
        self.shadow_counts: Dict[Tuple[str, str], int] = {}
        #: Wall-clock time after which the policy should be reloaded even if no
        #: file changed: the moment a shadow rule's monitor window ends.
        self.reload_at: Optional[float] = None

    @property
    def epoch(self) -> str:  # type: ignore[override]
        return self._content_epoch

    def add_rule(self, rule: Rule) -> "DeclarativeEngine":
        """Append a rule and remember it: a later file reload keeps it."""
        self._code_rules.append(rule)
        super().add_rule(rule)
        return self

    def reload(self) -> bool:
        """Re-read the files. On any error keep the current policy, log it, and
        return False; ``last_error`` says why."""
        if self._loader is None:
            return False
        try:
            fresh = self._loader()
        except PolicyError as exc:
            self.last_error = str(exc)
            _log.warning("interlock: policy reload failed, keeping the last good policy: %s", exc)
            return False
        # The freshly loaded rules come first; rules added in code are part of
        # the running policy and are re-appended once, in insertion order.
        self._rules = list(fresh._rules) + list(self._code_rules)
        self._shadow = list(fresh._shadow)
        self._epoch = None
        self.documents = fresh.documents
        self.quarantined = fresh.quarantined
        self.locked = fresh.locked
        self.overlays = fresh.overlays
        self._content_epoch = fresh._content_epoch
        self._files = list(fresh._files) or self._files
        self._stamps = _stamps(self._files)
        self.reload_at = fresh.reload_at
        if fresh.shadow_sink is not None:
            self.shadow_sink = fresh.shadow_sink
        self.last_error = None
        return True

    @property
    def shadow_ids(self) -> List[str]:
        """The ``policy_id`` of every rule this engine only observes."""
        from .engine import _rule_label
        return [_rule_label(rule) for rule in self._shadow]

    def evaluate(self, event: SensorEvent) -> Decision:
        if self._watch is not None:
            now = time.monotonic()
            if now - self._checked >= self._watch:
                self._checked = now
                due = self.reload_at is not None and time.time() >= self.reload_at
                if due or _stamps(self._files) != self._stamps:
                    self.reload()
        decision = super().evaluate(event)
        if self._shadow:
            self._observe(event)
        return decision

    def _observe(self, event: SensorEvent) -> None:
        is_result = getattr(event, "phase", "call") == "result"
        for rule in self._shadow:
            if (getattr(rule, "phase", "call") == "result") != is_result:
                continue
            try:
                would = rule(event)
            except Exception as exc:  # a shadow rule's bug is a log line, never a decision
                _log.warning("interlock: shadow rule %s raised %s", getattr(rule, "policy_id", "?"), exc)
                continue
            if would is None or would.verdict == Verdict.ALLOW:
                continue
            policy_id = would.policy_id or getattr(rule, "policy_id", "?")
            verdict = would.verdict.name
            key = (str(policy_id), verdict)
            self.shadow_counts[key] = self.shadow_counts.get(key, 0) + 1
            _log.info("interlock: shadow rule %s would %s action=%s reason=%s",
                      policy_id, verdict, event.action, would.reason)
            try:
                from .. import metrics
                metrics.record(verdict, getattr(event, "phase", "call"), str(policy_id), observed=True)
            except Exception:
                pass
            if self.shadow_sink is not None:
                try:
                    from ..receipt import digest_args
                    self.shadow_sink({
                        "ts": time.time(), "action": event.action, "phase": getattr(event, "phase", "call"),
                        "policy_id": policy_id, "verdict": verdict, "reason": would.reason,
                        "args_digest": digest_args(event.args), "principal": event.principal,
                    })
                except Exception as exc:
                    _log.warning("interlock: shadow sink failed: %s", exc)


def _stamps(files: Sequence[str]) -> Tuple[Tuple[str, float, int], ...]:
    out = []
    for path in files:
        try:
            st = os.stat(path)
            out.append((path, st.st_mtime, st.st_size))
        except OSError:
            out.append((path, -1.0, -1))
    return tuple(out)


def _content_epoch(documents: Sequence[Mapping[str, Any]]) -> str:
    canonical = json.dumps(list(documents), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


# --- loading --------------------------------------------------------------------


def load_policy(doc: Mapping[str, Any], *, source: str = "<policy>",
                overlays: Sequence[Tuple[str, Mapping[str, Any]]] = (),
                base_dir: Optional[str] = None) -> DeclarativeEngine:
    """Compile a policy document (plus already-trusted overlay documents).

    The documents' ``"tools"`` sections register argument schemas in the
    process-global :data:`TOOL_SCHEMAS` so load-time argument checks can run.
    Nothing a load registers outlives it: the map is restored in ``finally``,
    so an overlay's schema cannot poison the next load (and neither can a base
    document's, which is what makes two loads of the same base identical). The
    module lock serialises concurrent loads over that map.
    """
    with _tool_schemas_lock:
        saved_tools = dict(TOOL_SCHEMAS)
        try:
            documents, rules, quarantined, locked = _compile_with_extends(
                doc, source, base_dir, depth=0)
            applied: List[Tuple[str, str]] = []
            for name, overlay in overlays:
                try:
                    extra, widened = _compile_overlay(overlay, name, rules)
                except PolicyError as exc:
                    _log.warning("interlock: overlay ignored: %s", exc)
                    applied.append((name, "ignored: {}".format(exc)))
                    continue
                rules = widened + extra
                documents.append({"overlay": name, **dict(overlay)})
                applied.append((name, "applied"))
            compiled = [r.rule for r in rules if not r.shadow]
            shadow = [r.rule for r in rules if r.shadow]
            return DeclarativeEngine(compiled, documents=documents, quarantined=quarantined,
                                     locked=locked, overlays=applied, shadow_rules=shadow)
        finally:
            TOOL_SCHEMAS.clear()
            TOOL_SCHEMAS.update(saved_tools)


def load_policy_file(path: str, *, overlays: Sequence[str] = (), trust: Any = None,
                     watch: Optional[float] = None) -> DeclarativeEngine:
    """Load a policy file, plus any overlay files that ``trust`` has approved.

    ``trust`` is an :class:`interlock.policy.trust.TrustStore`; with none, no
    overlay is applied. ``watch`` (seconds) re-checks the files at most that
    often on evaluation and hot-reloads a changed, valid policy.
    """
    path = os.path.abspath(path)

    def build() -> DeclarativeEngine:
        doc, _ = read_policy_file(path)
        accepted: List[Tuple[str, Mapping[str, Any]]] = []
        notes: List[Tuple[str, str]] = []
        for overlay_path in overlays:
            overlay_path = os.path.abspath(overlay_path)
            status, overlay_doc = _trusted_overlay(overlay_path, trust)
            if overlay_doc is None:
                notes.append((overlay_path, status))
                _record_overlay(overlay_path, status)
                continue
            accepted.append((overlay_path, overlay_doc))
        engine = load_policy(doc, source=path, overlays=accepted,
                             base_dir=os.path.dirname(path))
        for name, status in engine.overlays:
            _record_overlay(name, status)
        engine.overlays = notes + engine.overlays
        engine._files = [path] + [os.path.abspath(o) for o in overlays]
        _attach_mesh(engine)
        engine._stamps = _stamps(engine._files)
        return engine

    engine = build()
    engine._loader = build
    engine._watch = watch
    engine._stamps = _stamps(engine._files)
    return engine


def _attach_mesh(engine: "DeclarativeEngine") -> None:
    """If any document came from the mesh, watch the mesh cache for changes,
    reload when the next shadow window ends, and record shadow decisions."""
    specs = [d.get("source") for d in engine.documents
             if isinstance(d.get("source"), str) and d["source"].startswith("mesh:")]
    if not specs:
        return
    try:
        from ..mesh.subscriber import install_recorder, watch_info
        files, reload_at, sink = watch_info(specs)
        install_recorder()
    except Exception as exc:  # the mesh is optional plumbing; never fail a load over it
        _log.warning("interlock: mesh watch not attached: %s", exc)
        return
    engine._files = list(engine._files) + [f for f in files if f not in engine._files]
    engine.reload_at = reload_at
    engine.shadow_sink = sink


def _trusted_overlay(path: str, trust: Any) -> Tuple[str, Optional[Mapping[str, Any]]]:
    if not os.path.exists(path):
        return "missing", None
    if trust is None:
        return "ignored: untrusted (no trust store)", None
    try:
        doc, digest = read_policy_file(path)
    except PolicyError as exc:
        return "ignored: {}".format(exc), None
    state = trust.status(path, digest)
    if state != "ok":
        return "ignored: {}".format(state), None
    return "trusted", doc


def _record_overlay(path: str, status: str) -> None:
    """Overlay outcomes are receipts: policy.overlay with the status as reason."""
    from ..receipt import emit_receipt

    verdict = Verdict.ALLOW if status in ("applied", "trusted") else Verdict.BLOCK
    try:
        emit_receipt(SensorEvent(action="policy.overlay", args={"path": path}),
                     Decision(verdict, "overlay {}".format(status), "policy_overlay"))
    except Exception:  # a sink failure must not stop a policy from loading
        _log.warning("interlock: could not record overlay status for %s", path)


class _Compiled:
    __slots__ = ("id", "rule", "doc", "locked", "shadow")

    def __init__(self, rule_id: str, rule: Rule, doc: Mapping[str, Any], locked: bool,
                 shadow: bool = False) -> None:
        self.id = rule_id
        self.rule = rule
        self.doc = doc
        self.locked = locked
        self.shadow = shadow


def _compile_with_extends(doc: Mapping[str, Any], source: str, base_dir: Optional[str],
                          depth: int) -> Tuple[List[Mapping[str, Any]], List[_Compiled], List[str], List[str]]:
    if depth > 8:
        raise PolicyError("'extends' nests deeper than 8 levels", source)
    _check_keys(doc, _DOC_KEYS, source, "policy")
    version = doc.get("version", SCHEMA_VERSION)
    if version != SCHEMA_VERSION:
        raise PolicyError("unsupported version {!r} (this interlock reads {})".format(
            version, SCHEMA_VERSION), source)
    _register_tools(doc.get("tools"), source)

    documents: List[Mapping[str, Any]] = []
    rules: List[_Compiled] = []
    quarantined: List[str] = []
    locked: List[str] = []
    parent = doc.get("extends")
    if parent is not None:
        parent_doc, parent_source, parent_dir = _resolve_extends(parent, source, base_dir)
        documents, rules, quarantined, locked = _compile_with_extends(
            parent_doc, parent_source, parent_dir, depth + 1)

    disabled = doc.get("disable", [])
    if not isinstance(disabled, list) or not all(isinstance(d, str) for d in disabled):
        raise PolicyError("'disable' must be a list of rule ids", source)
    for rule_id in disabled:
        match = [r for r in rules if r.id == rule_id]
        if not match:
            quarantined.append("{}: 'disable' names no inherited rule".format(rule_id))
        elif match[0].locked:
            quarantined.append("{}: locked, cannot be disabled".format(rule_id))
        else:
            rules = [r for r in rules if r.id != rule_id]

    raw_rules = doc.get("rules", [])
    if not isinstance(raw_rules, list):
        raise PolicyError("'rules' must be a list", source)
    seen = {r.id for r in rules}
    for index, raw in enumerate(raw_rules):
        where = "{} rules[{}]".format(source, index)
        try:
            compiled = _compile_rule(raw, where)
        except PolicyError as exc:
            rule_id = raw.get("id") if isinstance(raw, dict) else None
            quarantined.append("{}: {}".format(rule_id or "rules[{}]".format(index), exc))
            _log.warning("interlock: policy rule quarantined: %s", exc)
            continue
        if compiled.id in seen:
            quarantined.append("{}: duplicate rule id".format(compiled.id))
            continue
        seen.add(compiled.id)
        rules.append(compiled)
        if compiled.locked:
            locked.append(compiled.id)
    documents = documents + [{"source": source, **{k: v for k, v in doc.items() if k != "extends"}}]
    return documents, rules, quarantined, locked


def _resolve_extends(parent: Any, source: str, base_dir: Optional[str]) -> Tuple[Mapping[str, Any], str, Optional[str]]:
    if not isinstance(parent, str) or not parent:
        raise PolicyError("'extends' must be a policy name or path", source)
    if parent.startswith("builtin:"):
        from .packs import builtin_pack
        try:
            return builtin_pack(parent[len("builtin:"):]), parent, None
        except KeyError as exc:
            raise PolicyError(str(exc), source)
    if parent.startswith("mesh:"):
        # A community pack from the node's verified mesh cache. Never a network
        # call: ``interlock mesh sync`` fills the cache, this only reads it, so
        # a mirror outage cannot stall a policy load. A pack that is not cached
        # is a load error, which keeps the last good policy in force.
        from ..mesh.subscriber import SubscriberError, resolve_extends
        try:
            doc, spec, _cache_path = resolve_extends(parent)
        except SubscriberError as exc:
            raise PolicyError(str(exc), source)
        return doc, spec, None
    path = parent if os.path.isabs(parent) else os.path.join(base_dir or os.getcwd(), parent)
    doc, _ = read_policy_file(path)
    return doc, path, os.path.dirname(path)


def _register_tools(tools: Any, source: str) -> None:
    if tools is None:
        return
    if not isinstance(tools, dict):
        raise PolicyError("'tools' must map an action to its argument names", source)
    for action, names in tools.items():
        if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
            raise PolicyError("tools[{!r}] must be a list of argument names".format(action), source)
        register_tool_schema(action, names)


def _overlay_tool_schemas(tools: Any, name: str) -> Dict[str, FrozenSet[str]]:
    """Validate an overlay's ``"tools"`` and return the actions to register.

    Only actions the base does not already declare are returned; declaring an
    existing action with the same argument set is a no-op, and with a different
    set is an error - an overlay must not change what the base validates
    against. Everything is checked before anything is registered, so a
    conflicting entry cannot leave an earlier one behind.
    """
    if tools is None:
        return {}
    if not isinstance(tools, dict):
        raise PolicyError("'tools' must map an action to its argument names", name)
    new: Dict[str, FrozenSet[str]] = {}
    for action, names in tools.items():
        if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
            raise PolicyError("tools[{!r}] must be a list of argument names".format(action), name)
        declared = frozenset(names)
        existing = TOOL_SCHEMAS.get(action)
        if existing is None:
            new[action] = declared
        elif existing != declared:
            raise PolicyError("overlay tools may not redefine action {!r}".format(action), name)
    return new


def _reject_overlay_rewrite(raw: Any, where: str) -> None:
    """Refuse an overlay rule that could rewrite the call.

    A rewrite runs before the base rules judge the working copy, so an overlay
    with ``set`` / ``verdict: "modify"`` - or any detector, whose verdict is not
    known at load time and several of which return MODIFY - could change the
    very argument a locked rule inspects. An overlay may only add a rule that
    blocks or escalates.
    """
    if not isinstance(raw, dict):
        return
    if "detector" in raw:
        what = "use a detector (its verdict is not known at load time)"
    elif "set" in raw or raw.get("verdict") == "modify":
        what = "rewrite arguments with set/modify"
    else:
        return
    rule_id = raw.get("id")
    named = " {!r}".format(rule_id) if isinstance(rule_id, str) else ""
    raise PolicyError(
        "overlay rule{} may not {}; overlays may only add blocking or escalating "
        "rules".format(named, what), where)


def _compile_overlay(overlay: Mapping[str, Any], name: str,
                     base: List[_Compiled]) -> Tuple[List[_Compiled], List[_Compiled]]:
    """Return (overlay rules, base rules with widened lists). Raises on anything
    an overlay may not do."""
    _check_keys(overlay, _OVERLAY_KEYS, name, "overlay")
    with _tool_schemas_lock:
        # A new action an overlay declares is visible while its own rules
        # compile and gone afterwards; the base's schemas are untouched.
        new_tools = _overlay_tool_schemas(overlay.get("tools"), name)
        saved_tools = _snapshot_tools(new_tools)
        try:
            for action, names in new_tools.items():
                register_tool_schema(action, names)
            widened = list(base)
            widen = overlay.get("widen", {})
            if not isinstance(widen, dict):
                raise PolicyError("'widen' must map a rule id to the lists it extends", name)
            for rule_id, params in widen.items():
                index = next((i for i, r in enumerate(widened) if r.id == rule_id), None)
                if index is None:
                    raise PolicyError("widen: no base rule {!r}".format(rule_id), name)
                original = widened[index]
                allowed = original.doc.get("widenable", [])
                if not isinstance(params, dict):
                    raise PolicyError("widen[{!r}] must be an object".format(rule_id), name)
                new_doc = copy.deepcopy(dict(original.doc))
                with_args = dict(new_doc.get("with", {}))
                for param, values in params.items():
                    if param not in allowed:
                        raise PolicyError("widen[{!r}]: {!r} is not widenable".format(
                            rule_id, param), name)
                    if not isinstance(values, list) or not isinstance(
                            with_args.get(param, []), list):
                        raise PolicyError("widen[{!r}][{!r}] must extend a list".format(
                            rule_id, param), name)
                    merged = list(with_args.get(param, []))
                    merged.extend(v for v in values if v not in merged)
                    with_args[param] = merged
                new_doc["with"] = with_args
                # The base rule being widened may itself be a detector: that is
                # the documented widen capability, so only the overlay's own
                # rules are screened by _reject_overlay_rewrite below.
                widened[index] = _compile_rule(new_doc, "{} widen[{}]".format(name, rule_id))
            extra: List[_Compiled] = []
            raw_rules = overlay.get("rules", [])
            if not isinstance(raw_rules, list):
                raise PolicyError("'rules' must be a list", name)
            taken = {r.id for r in widened}
            for index, raw in enumerate(raw_rules):
                where = "{} rules[{}]".format(name, index)
                if isinstance(raw, dict) and raw.get("locked"):
                    raise PolicyError("an overlay rule cannot be locked", where)
                _reject_overlay_rewrite(raw, where)
                compiled = _compile_rule(raw, where)
                if compiled.id in taken:
                    raise PolicyError("an overlay cannot replace rule {!r}".format(compiled.id), where)
                taken.add(compiled.id)
                extra.append(compiled)
            return extra, widened
        finally:
            _restore_tools(saved_tools)


# --- rules ----------------------------------------------------------------------


#: Spellings people reach for, mapped to what the language calls them.
_ALIASES = {
    "equals": "eq", "equal": "eq", "is": "eq", "==": "eq", "!=": "ne", "not_equals": "ne",
    ">": "gt", ">=": "ge", "<": "lt", "<=": "le", "regex": "matches", "match": "matches",
    "includes": "contains", "has": "contains", "starts_with": "startswith",
    "ends_with": "endswith", "not in": "not_in", "notin": "not_in", "one_of": "in",
    "and": "all", "or": "any", "condition": "when", "if": "when", "action": "verdict",
}


def _check_keys(obj: Mapping[str, Any], allowed: FrozenSet[str], where: str, what: str) -> None:
    unknown = sorted(set(obj) - allowed)
    if unknown:
        hints = []
        for key in unknown:
            alias = _ALIASES.get(key.lower())
            close = [alias] if alias in allowed else difflib.get_close_matches(key, sorted(allowed), n=1)
            hints.append("{!r}{}".format(key, " (did you mean {!r}?)".format(close[0]) if close else ""))
        raise PolicyError("unknown {} key(s): {}; valid: {}".format(
            what, ", ".join(hints), ", ".join(sorted(allowed))), where)


def _compile_rule(raw: Any, where: str) -> _Compiled:
    if not isinstance(raw, dict):
        raise PolicyError("a rule must be an object", where)
    _check_keys(raw, _RULE_KEYS, where, "rule")
    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not re.match(r"^[A-Za-z0-9_.:/-]{1,128}$", rule_id):
        raise PolicyError("'id' must be 1-128 characters of [A-Za-z0-9_.:/-]", where)
    where = "{} ({})".format(where, rule_id)
    locked = bool(raw.get("locked", False))
    status = raw.get("status")
    if status is not None and status not in RULE_STATUSES:
        raise PolicyError("'status' must be one of {}".format(", ".join(sorted(RULE_STATUSES))), where)
    mode = raw.get("mode", "enforce")
    if mode not in RULE_MODES:
        raise PolicyError("'mode' must be one of {}".format(", ".join(sorted(RULE_MODES))), where)
    ceiling = raw.get("ceiling")
    if ceiling is not None and ceiling not in RULE_CEILINGS:
        raise PolicyError("'ceiling' must be one of {}".format(", ".join(sorted(RULE_CEILINGS))), where)
    scope = _action_condition(raw["on"], where + " on") if "on" in raw else None
    scope_names = _actions_in([{"action": raw["on"]}]) if "on" in raw else None
    if "detector" in raw:
        for key in ("when", "verdict", "set"):
            if key in raw:
                raise PolicyError("a detector rule takes 'with', not {!r}".format(key), where)
        rule = _detector_rule(raw["detector"], raw.get("with", {}), where)
        if scope is not None:
            rule = _scoped(rule, scope)
        return _finish(rule_id, rule, raw, locked, mode, ceiling)

    verdict = raw.get("verdict")
    if verdict not in VERDICTS:
        raise PolicyError("'verdict' must be one of {}".format(", ".join(sorted(VERDICTS))), where)
    reason = raw.get("reason", rule_id)
    if not isinstance(reason, str):
        raise PolicyError("'reason' must be a string", where)
    phase = raw.get("phase", "call")
    if phase not in ("call", "result"):
        raise PolicyError("'phase' must be 'call' or 'result'", where)
    if "when" not in raw:
        raise PolicyError("a rule needs 'when' (or 'detector')", where)
    condition = _compile_condition(raw["when"], where + " when", actions=scope_names)
    if scope is not None:
        condition = _all([scope, condition])
    modified: Optional[Dict[str, Any]] = None
    if verdict == "modify":
        if phase != "call":
            raise PolicyError("'modify' rules rewrite call arguments; use a detector for results", where)
        modified = raw.get("set")
        if not isinstance(modified, dict) or not modified:
            raise PolicyError("'modify' needs a non-empty 'set' object", where)
    elif "set" in raw:
        raise PolicyError("'set' only applies to 'modify' rules", where)

    def rule(event: SensorEvent) -> Optional[Decision]:
        try:
            hit = condition(event)
        except Exception as exc:  # an evaluator bug must not become an allow
            return Decision.block(
                "rule {} failed to evaluate ({}), denied fail-closed".format(
                    rule_id, type(exc).__name__), rule_id)
        if not hit:
            return None
        attributed = getattr(hit, "name", None)
        if verdict == "block":
            return Decision.block(reason, rule_id, attributed_to=attributed)
        if verdict == "escalate":
            return Decision.escalate(reason, rule_id, attributed_to=attributed)
        return Decision.modify(copy.deepcopy(modified or {}), reason, rule_id,
                               attributed_to=attributed)

    rule.phase = phase  # type: ignore[attr-defined]
    return _finish(rule_id, rule, raw, locked, mode, ceiling)


def _finish(rule_id: str, rule: Rule, raw: Mapping[str, Any], locked: bool, mode: str,
            ceiling: Optional[str]) -> _Compiled:
    if ceiling is not None:
        rule = _ceilinged(rule, ceiling)
    return _Compiled(rule_id, _labelled(rule, rule_id, locked), raw, locked, shadow=(mode == "shadow"))


def _ceilinged(rule: Rule, ceiling: str) -> Rule:
    """Cap a rule's verdict: a decision stronger than ``ceiling`` becomes an
    ESCALATE, so a community rule the node does not fully trust yet asks a
    human instead of acting on its own."""
    limit = RULE_CEILINGS[ceiling]

    def capped(event: SensorEvent) -> Optional[Decision]:
        decision = rule(event)
        if decision is None or decision.verdict == Verdict.ALLOW:
            return decision
        rank = RULE_CEILINGS.get(decision.verdict.name.lower())
        if rank is None or rank <= limit:
            return decision
        return Decision.escalate("above the {} ceiling: {}".format(ceiling, decision.reason),
                                 decision.policy_id, attributed_to=decision.attributed_to)

    capped.phase = getattr(rule, "phase", "call")  # type: ignore[attr-defined]
    return capped


def _scoped(rule: Rule, scope: Condition) -> Rule:
    """Run ``rule`` only for events ``scope`` matches (the ``"on"`` key)."""

    def scoped(event: SensorEvent) -> Optional[Decision]:
        return rule(event) if scope(event) else None

    scoped.phase = getattr(rule, "phase", "call")  # type: ignore[attr-defined]
    return scoped


def _labelled(rule: Rule, rule_id: str, locked: bool) -> Rule:
    def labelled(event: SensorEvent) -> Optional[Decision]:
        decision = rule(event)
        if decision is not None and decision.verdict != Verdict.ALLOW and not decision.policy_id:
            decision = dataclasses.replace(decision, policy_id=rule_id)
        return decision

    labelled.phase = getattr(rule, "phase", "call")  # type: ignore[attr-defined]
    labelled.policy_id = rule_id  # type: ignore[attr-defined]
    labelled.locked = locked  # type: ignore[attr-defined]
    return labelled


# --- detectors by name ----------------------------------------------------------


def detector_factories() -> Dict[str, Callable[..., Rule]]:
    """Every catalogued detector factory, by ``module.factory`` and, where the
    module's main factory shares its name, by the bare name too."""
    from .. import detectors as package

    found: Dict[str, Callable[..., Rule]] = {}
    for info in pkgutil.iter_modules(package.__path__):
        module = importlib.import_module("{}.{}".format(package.__name__, info.name))
        for name, fn in inspect.getmembers(module, inspect.isfunction):
            if fn.__module__ != module.__name__ or name.startswith("_"):
                continue
            if "Rule" not in str(inspect.signature(fn).return_annotation):
                continue
            found["{}.{}".format(info.name, name)] = fn
            found.setdefault(name, fn)
    return found


_FACTORIES: Optional[Dict[str, Callable[..., Rule]]] = None


def _find_factory(name: str) -> Optional[Callable[..., Rule]]:
    """Resolve a detector name, importing only the module it names.

    ``module.factory`` imports ``interlock.detectors.module``; a bare name is
    tried as ``name.name`` first. Only an unknown name pays for the full scan
    (which it needs anyway, to suggest a spelling). Hooks start a process per
    tool call, so this is the difference between one import and a hundred.
    """
    module_name, _, factory_name = name.rpartition(".")
    if not module_name:
        module_name, factory_name = name, name
    if re.match(r"^[a-z_][a-z0-9_]*$", module_name) and re.match(r"^[a-z_][a-z0-9_]*$", factory_name):
        try:
            module = importlib.import_module("interlock.detectors." + module_name)
        except ImportError:
            module = None
        if module is not None:
            fn = getattr(module, factory_name, None)
            if (inspect.isfunction(fn) and fn.__module__ == module.__name__
                    and not factory_name.startswith("_")
                    and "Rule" in str(inspect.signature(fn).return_annotation)):
                return fn
    global _FACTORIES
    if _FACTORIES is None:
        _FACTORIES = detector_factories()
    return _FACTORIES.get(name)


def _detector_rule(name: Any, kwargs: Any, where: str) -> Rule:
    factory = _find_factory(name) if isinstance(name, str) else None
    if factory is None:
        global _FACTORIES
        if _FACTORIES is None:
            _FACTORIES = detector_factories()
        close = difflib.get_close_matches(str(name), sorted(_FACTORIES), n=1)
        raise PolicyError("unknown detector {!r}{}".format(
            name, " (did you mean {!r}?)".format(close[0]) if close else ""), where)
    if not isinstance(kwargs, dict):
        raise PolicyError("'with' must be an object of keyword arguments", where)
    try:
        inspect.signature(factory).bind(**kwargs)
    except TypeError as exc:
        raise PolicyError("{} does not accept these arguments: {}".format(name, exc), where)
    try:
        return factory(**copy.deepcopy(kwargs))
    except Exception as exc:
        raise PolicyError("{} rejected its arguments: {}".format(name, exc), where)


# --- conditions -----------------------------------------------------------------


class Hit:
    """A matched condition, carrying the argument name that matched (if any).

    Conditions return a Hit or False; nothing is stored on shared objects, so
    one compiled policy is safe to evaluate from many threads.
    """

    __slots__ = ("name",)

    def __init__(self, name: Optional[str] = None) -> None:
        self.name = name

    def __bool__(self) -> bool:
        return True


Condition = Callable[[SensorEvent], Any]  # returns a Hit or False
_MISSING = object()


def _compile_condition(raw: Any, where: str, actions: Optional[FrozenSet[str]]) -> Condition:
    if not isinstance(raw, dict) or not raw:
        raise PolicyError("a condition must be a non-empty object", where)
    if "all" in raw or "any" in raw:
        key = "all" if "all" in raw else "any"
        _check_keys(raw, frozenset({key}), where, "condition")
        parts = raw[key]
        if not isinstance(parts, list) or not parts:
            raise PolicyError("{!r} needs a non-empty list".format(key), where)
        scoped = _actions_in(parts) if key == "all" else actions
        subs = [_compile_condition(p, "{}.{}[{}]".format(where, key, i), scoped or actions)
                for i, p in enumerate(parts)]
        return _all(subs) if key == "all" else _any(subs)
    if "not" in raw:
        _check_keys(raw, frozenset({"not"}), where, "condition")
        sub = _compile_condition(raw["not"], where + ".not", actions)
        return lambda event: False if sub(event) else Hit()
    if "action" in raw and "field" not in raw and "arg" not in raw:
        _check_keys(raw, frozenset({"action"}), where, "condition")
        return _action_condition(raw["action"], where)
    if "intent" in raw:
        _check_keys(raw, frozenset({"intent", "arg"}), where, "condition")
        return _intent_condition(raw["intent"], raw.get("arg"), where, actions)
    if "sql" in raw:
        _check_keys(raw, frozenset({"sql", "arg", "dialect"}), where, "condition")
        return _sql_condition(raw["sql"], raw.get("arg"), raw.get("dialect", "generic"),
                              where, actions)
    if "a2a" in raw:
        _check_keys(raw, frozenset({"a2a", "arg"}), where, "condition")
        return _a2a_condition(raw["a2a"], raw.get("arg"), where, actions)
    if "field" in raw or "arg" in raw:
        return _test_condition(raw, where, actions)
    raise PolicyError("unknown condition; use all/any/not/action/field/arg/"
                      "intent/sql/a2a", where)


def _all(subs: List[Condition]) -> Condition:
    def condition(event: SensorEvent) -> Any:
        named: Optional[str] = None
        for sub in subs:
            hit = sub(event)
            if not hit:
                return False
            if named is None:
                named = getattr(hit, "name", None)
        return Hit(named)
    return condition


def _any(subs: List[Condition]) -> Condition:
    def condition(event: SensorEvent) -> Any:
        for sub in subs:
            hit = sub(event)
            if hit:
                return hit
        return False
    return condition


def _actions_in(parts: List[Any]) -> Optional[FrozenSet[str]]:
    """The literal action names an ``all`` is scoped to, for argument checks."""
    for part in parts:
        if isinstance(part, dict) and set(part) == {"action"}:
            value = part["action"]
            if isinstance(value, str):
                return frozenset({value})
            if isinstance(value, list) and all(isinstance(v, str) for v in value):
                return frozenset(value)
    return None


def _action_condition(value: Any, where: str) -> Condition:
    if isinstance(value, str):
        return lambda event: Hit() if event.action == value else False
    if isinstance(value, list) and value and all(isinstance(v, str) for v in value):
        names = frozenset(value)
        return lambda event: Hit() if event.action in names else False
    if isinstance(value, dict) and set(value) == {"glob"} and isinstance(value["glob"], str):
        pattern = value["glob"]
        return lambda event: Hit() if fnmatch.fnmatchcase(event.action, pattern) else False
    raise PolicyError("'action' must be a name, a list of names, or {\"glob\": ...}", where)


def _check_arg_name(name: str, where: str, actions: Optional[FrozenSet[str]]) -> None:
    if not actions:
        return
    root = name.split(".", 1)[0]
    known = [TOOL_SCHEMAS[a] for a in actions if a in TOOL_SCHEMAS]
    if len(known) != len(actions):
        return  # an action with no declared schema: nothing to check against
    if any(root in schema for schema in known):
        return
    valid = sorted(set().union(*known))
    close = difflib.get_close_matches(root, valid, n=1)
    raise PolicyError("{} has no argument {!r}{}; it takes: {}".format(
        "/".join(sorted(actions)), root,
        " (did you mean {!r}?)".format(close[0]) if close else "", ", ".join(valid)), where)


def _intent_condition(selector: Any, arg: Any, where: str,
                      actions: Optional[FrozenSet[str]]) -> Condition:
    from ..shell import analyze

    if not isinstance(selector, (str, list)) or (isinstance(selector, list) and not all(
            isinstance(s, str) for s in selector)):
        raise PolicyError("'intent' must be a selector or a list of selectors", where)
    selectors = [selector] if isinstance(selector, str) else list(selector)
    if arg is not None:
        if not isinstance(arg, str):
            raise PolicyError("'arg' must be an argument name", where)
        _check_arg_name(arg, where, actions)

    def condition(event: SensorEvent) -> Any:
        args = event.args if isinstance(event.args, dict) else {}
        items = [(arg, _lookup(args, arg))] if arg else list(args.items())
        for name, value in items:
            if not isinstance(value, str):
                continue
            for intent in analyze(value, cwd=getattr(event, "cwd", None)):
                if any(intent.matches(s) for s in selectors):
                    return Hit(name)
        return False

    return condition


def _sql_condition(selector: Any, arg: Any, dialect: Any, where: str,
                   actions: Optional[FrozenSet[str]]) -> Condition:
    from ..detectors.sql_statement_guard import DEFAULT_KEYS
    from ..sql import DIALECTS, FLAGS, GROUPS, OPERATIONS, analyze_sql

    selectors = [selector] if isinstance(selector, str) else selector
    if not isinstance(selectors, list) or not selectors or not all(
            isinstance(s, str) for s in selectors):
        raise PolicyError("'sql' must be a selector or a list of selectors", where)
    for sel in selectors:
        kind, sep, _ = sel.partition(":")
        if not ((sep and kind in ("read", "write", "table"))
                or sel in OPERATIONS or sel in GROUPS or sel in FLAGS):
            raise PolicyError("unknown sql selector {!r}; use an operation, ddl/dml/write/"
                              "control, a flag (unbounded, opaque, external, multi) or "
                              "read:/write:/table:<glob>".format(sel), where)
    if dialect != "generic" and dialect not in DIALECTS:
        raise PolicyError("'dialect' must be generic or one of {}".format(
            ", ".join(sorted(DIALECTS))), where)
    if arg is not None:
        if not isinstance(arg, str):
            raise PolicyError("'arg' must be an argument name", where)
        _check_arg_name(arg, where, actions)

    def condition(event: SensorEvent) -> Any:
        args = event.args if isinstance(event.args, dict) else {}
        names = [arg] if arg else [k for k in args if k in DEFAULT_KEYS]
        for name in names:
            value = _lookup(args, name)
            if not isinstance(value, str) or not value.strip():
                continue
            analysis = analyze_sql(value, dialect)
            if any(analysis.matches(s) for s in selectors):
                return Hit(name)
        return False

    return condition


def _a2a_condition(selector: Any, arg: Any, where: str,
                   actions: Optional[FrozenSet[str]]) -> Condition:
    """Match an agent-to-agent call on its peer or its advertised agent card.

    Selectors are pure data over the event, never code, and are validated up
    front so a typo fails at load: ``"peer"`` / ``"peer:<glob>"`` read the peer
    argument (normalised to its host through the same helper the A2A detectors
    use, so a rule and a detector agree on what a peer is), and ``"card"`` /
    ``"card.<field>"`` / ``"card.<field>:<glob>"`` read the ``"card"``
    argument, matching any element of a list field so a skill set can be
    tested. ``"arg"`` names the argument the peer travels in, defaulting to
    ``"peer"``. A list of selectors matches when any one of them does, and the
    match is attributed to the argument that carried it.
    """
    from ..detectors.a2a_policy import _CARD_KEY, _PEER_KEY, peer_host

    selectors = [selector] if isinstance(selector, str) else selector
    if not isinstance(selectors, list) or not selectors or not all(
            isinstance(s, str) for s in selectors):
        raise PolicyError("'a2a' must be a selector or a list of selectors", where)
    specs = [_a2a_selector(s, where) for s in selectors]
    if arg is not None:
        if not isinstance(arg, str):
            raise PolicyError("'arg' must be an argument name", where)
        _check_arg_name(arg, where, actions)
    peer_arg = arg or _PEER_KEY

    def condition(event: SensorEvent) -> Any:
        args = event.args if isinstance(event.args, dict) else {}
        host = peer_host(_lookup(args, peer_arg))
        card = _lookup(args, _CARD_KEY)
        for kind, field, pattern in specs:
            if kind == "peer":
                if pattern is None:
                    if host is not None:
                        return Hit(peer_arg)
                elif host is not None and fnmatch.fnmatchcase(host, pattern):
                    return Hit(peer_arg)
                continue
            value = card if field is None else _lookup(card, field)
            if pattern is None:
                if value is not _MISSING and value is not None:
                    return Hit(_CARD_KEY)
            elif _a2a_value_matches(value, pattern):
                return Hit(_CARD_KEY)
        return False

    return condition


def _a2a_selector(selector: str, where: str) -> Tuple[str, Optional[str], Optional[str]]:
    """Validate one a2a selector into ``(kind, field, pattern)``.

    ``kind`` is ``"peer"`` or ``"card"``; ``field`` names a card field for a
    card selector; ``pattern`` is the glob to match, or None for a bare
    presence test. An unrecognised selector is an error naming the valid forms.
    """
    head, sep, rest = selector.partition(":")
    head = head.strip()
    pattern: Optional[str] = None
    if sep:
        rest = rest.strip()
        if not rest:
            raise PolicyError("a2a selector {!r} needs a pattern after ':'".format(selector),
                              where)
        pattern = rest
    if head == "peer":
        # Hosts are case-insensitive, and peer_host lowercases the peer, so a
        # capital in the selector must not silently disable an otherwise-correct
        # rule.
        return ("peer", None, pattern.lower() if pattern is not None else None)
    if head == "card":
        if pattern is not None:
            raise PolicyError("a2a 'card' takes no pattern; use 'card.<field>:<glob>'", where)
        return ("card", None, None)
    if head.startswith("card."):
        field = head[len("card."):].strip()
        if not field:
            raise PolicyError("a2a selector {!r} names no card field".format(selector), where)
        return ("card", field, pattern)
    raise PolicyError(
        "unknown a2a selector {!r}; use 'peer', 'peer:<glob>', 'card', "
        "'card.<field>' or 'card.<field>:<glob>'".format(selector), where)


def _a2a_value_matches(value: Any, pattern: str) -> bool:
    """Test a card field against a glob: a string, or any element of a list.

    A list field (``skills``) matches when any element does; an element is
    matched by its ``name`` when it is an object, else by itself. Any other
    shape - a missing field, a number, a nested list - does not match.
    """
    if value is _MISSING or value is None:
        return False
    if isinstance(value, str):
        return fnmatch.fnmatchcase(value, pattern)
    if isinstance(value, list):
        for item in value:
            name = item if isinstance(item, str) else (
                item.get("name") if isinstance(item, dict) else None)
            if isinstance(name, str) and fnmatch.fnmatchcase(name, pattern):
                return True
    return False


def _test_condition(raw: Mapping[str, Any], where: str,
                    actions: Optional[FrozenSet[str]]) -> Condition:
    subject_key = "field" if "field" in raw else "arg"
    if "field" in raw and "arg" in raw:
        raise PolicyError("use 'field' or 'arg', not both", where)
    name = raw[subject_key]
    if not isinstance(name, str) or not name:
        raise PolicyError("{!r} must be a non-empty name".format(subject_key), where)
    if subject_key == "field" and name not in EVENT_FIELDS:
        close = difflib.get_close_matches(name, sorted(EVENT_FIELDS), n=1)
        raise PolicyError("unknown event field {!r}{}; valid: {}".format(
            name, " (did you mean {!r}?)".format(close[0]) if close else "",
            ", ".join(sorted(EVENT_FIELDS))), where)
    if subject_key == "arg":
        _check_arg_name(name, where, actions)
    ops = [k for k in raw if k != subject_key]
    bad = [k for k in ops if k not in OPERATORS]
    if bad:
        _check_keys({k: 1 for k in bad}, OPERATORS, where, "operator")
    if len(ops) != 1:
        raise PolicyError("a test takes exactly one operator, got {}".format(len(ops)), where)
    op = ops[0]
    test = _operator(op, raw[op], where)
    attributed = name if subject_key == "arg" else None

    def condition(event: SensorEvent) -> Any:
        if subject_key == "field":
            value = getattr(event, name, None)
        else:
            args = event.args if isinstance(event.args, dict) else {}
            value = _lookup(args, name)
        return Hit(attributed) if test(value) else False

    return condition


def _lookup(args: Mapping[str, Any], path: str) -> Any:
    """Follow a dotted path through dicts (and list indices). Never attributes."""
    current: Any = args
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part, _MISSING)
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return _MISSING
        if current is _MISSING:
            return _MISSING
    return current


def _operator(op: str, operand: Any, where: str) -> Callable[[Any], bool]:
    if op == "exists":
        if not isinstance(operand, bool):
            raise PolicyError("'exists' takes true or false", where)
        return lambda v: (v is not _MISSING and v is not None) == operand
    if op in ("eq", "ne"):
        _json_scalar(operand, op, where)
        if op == "eq":
            return lambda v: v is not _MISSING and v == operand
        return lambda v: v is _MISSING or v != operand
    if op in ("in", "not_in"):
        if not isinstance(operand, list):
            raise PolicyError("{!r} takes a list".format(op), where)
        values = list(operand)
        if op == "in":
            return lambda v: v is not _MISSING and _hashable_in(v, values)
        return lambda v: v is _MISSING or not _hashable_in(v, values)
    if op in ("gt", "ge", "lt", "le"):
        if isinstance(operand, bool) or not isinstance(operand, (int, float)):
            raise PolicyError("{!r} takes a number".format(op), where)
        compare = {"gt": lambda a: a > operand, "ge": lambda a: a >= operand,
                   "lt": lambda a: a < operand, "le": lambda a: a <= operand}[op]
        return lambda v: (not isinstance(v, bool)) and isinstance(v, (int, float)) and compare(v)
    if op in ("contains", "startswith", "endswith"):
        if not isinstance(operand, str):
            raise PolicyError("{!r} takes a string".format(op), where)
        if op == "contains":
            return lambda v: (isinstance(v, str) and operand in v) or (
                isinstance(v, list) and operand in v)
        if op == "startswith":
            return lambda v: isinstance(v, str) and v.startswith(operand)
        return lambda v: isinstance(v, str) and v.endswith(operand)
    if op == "glob":
        if not isinstance(operand, str):
            raise PolicyError("'glob' takes a string pattern", where)
        return lambda v: isinstance(v, str) and fnmatch.fnmatchcase(v, operand)
    if op == "matches":
        if not isinstance(operand, str) or len(operand) > MAX_PATTERN:
            raise PolicyError("'matches' takes a regex of at most {} characters".format(
                MAX_PATTERN), where)
        try:
            pattern = re.compile(operand)
        except re.error as exc:
            raise PolicyError("invalid regex: {}".format(exc), where)
        return lambda v: isinstance(v, str) and pattern.search(v[:MAX_SCAN]) is not None
    raise PolicyError("unknown operator {!r}".format(op), where)


def _json_scalar(value: Any, op: str, where: str) -> None:
    if not isinstance(value, (str, int, float, bool)) and value is not None:
        raise PolicyError("{!r} takes a string, number, boolean or null".format(op), where)


def _hashable_in(value: Any, values: List[Any]) -> bool:
    try:
        return value in values
    except Exception:
        return False


# --- checking a file ------------------------------------------------------------


def check_policy_file(path: str, *, overlays: Sequence[str] = (), trust: Any = None) -> Dict[str, Any]:
    """Load a policy for inspection: rule ids, locked ids, quarantined rules,
    overlay status, epoch. Raises :class:`PolicyError` if it does not parse."""
    engine = load_policy_file(path, overlays=overlays, trust=trust)
    return {
        "path": os.path.abspath(path),
        "rules": engine.policy_ids,
        "locked": engine.locked,
        "quarantined": engine.quarantined,
        "overlays": [{"path": p, "status": s} for p, s in engine.overlays],
        "epoch": engine.epoch,
    }
