"""The distributed policy artifact (C5).

An artifact is **data only**.  It carries the declarative documents a policy
was authored from, the scope bindings that say which templates apply where,
and a *reference* to the code that binds them: a ``module:attr`` spec whose
imported attribute is the ``templates`` mapping ``build_scoped_engine``
expects.  Template factories are Python callables and are not serialisable, so
the artifact never embeds code.  The signed manifest's ``minimum_agent`` pins
the agent version that ships those bytes; the artifact's sha256 identifies the
data but not the module's implementation.

This module is deliberately stdlib-only at import time.  The rules module is
imported *inside* :func:`load_artifact`, never here, so importing
``interlock.policy.artifact`` cannot pull a policy module (or the sidecar)
into a process that only needs the format.

Canonical JSON is ``sort_keys=True, separators=(",", ":"), ensure_ascii=False``
encoded as UTF-8 with exactly one trailing newline.  ``epoch`` is
``sha256(canonical body without epoch)[:16]``: the identity of the exact
distributed rule set.  It is independent of ``PolicyEngine.epoch``, which
hashes object identities in some engines and therefore cannot survive a
serialise/deserialise round trip.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping, Optional, Union

_log = logging.getLogger("interlock")

#: The only artifact format this build understands.
ARTIFACT_FORMAT = 1

#: Action classes the artifact carries failure policy for (FR-072).
FAILURE_POLICY_KEYS = (
    "read_only",
    "local",
    "granted_llm",
    "shell",
    "egress",
    "delete",
    "email",
    "payment",
)

#: The spec's defaults: the safe classes fail open, the irreversible ones
#: fail closed.
FAILURE_POLICY_DEFAULTS = {
    "read_only": "open",
    "local": "open",
    "granted_llm": "open",
    "shell": "closed",
    "egress": "closed",
    "delete": "closed",
    "email": "closed",
    "payment": "closed",
}

FAILURE_POLICY_VALUES = ("open", "closed")

#: The artifact's top-level keys. Extra keys are refused: an artifact is a
#: signed contract, and silently ignoring an unknown field would let a newer
#: producer smuggle a field an older host never validates.
ARTIFACT_KEYS = frozenset({
    "format", "epoch", "documents", "scope", "rules_module",
    "template_ids", "catalog", "failure_policy",
})

ACTIVE_POINTER = "active.json"


class ArtifactError(ValueError):
    """The artifact bytes are malformed, inconsistent or unmaterialisable.

    ``code`` is a short machine-readable refusal, matching the connector's
    ``refusals`` map and the plane's ``422 bad_artifact`` responses.
    """

    def __init__(self, code: str, message: str = "") -> None:
        self.code = str(code)
        self.message = message or self.code
        super().__init__(self.message)


def canonical_json(value: Any) -> str:
    """The one canonical serialisation for artifacts and manifests."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def canonical_bytes(value: Any) -> bytes:
    """Canonical artifact bytes: UTF-8 plus exactly one trailing newline."""
    return (canonical_json(value) + "\n").encode("utf-8")


def compute_epoch(body: Mapping[str, Any]) -> str:
    """``sha256(canonical body without epoch)[:16]``.

    ``body`` may already contain an ``epoch``; it is removed before hashing so
    recomputing an existing artifact's epoch is a pure function of its content.
    """
    without = {key: value for key, value in body.items() if key != "epoch"}
    digest = hashlib.sha256(canonical_bytes(without)).hexdigest()
    return digest[:16]


def seal_artifact(body: Mapping[str, Any]) -> dict:
    """Return ``body`` with its computed ``epoch`` inserted."""
    sealed = {key: value for key, value in body.items() if key != "epoch"}
    sealed["epoch"] = compute_epoch(sealed)
    return sealed


def validate_failure_policy(policy: Any) -> dict:
    """Return a normalised failure policy or raise :class:`ArtifactError`.

    Every class and every value is required.  A missing class is a refusal,
    not a default: a host that silently filled one in would be enforcing a
    policy the plane never compiled.
    """
    if not isinstance(policy, Mapping):
        raise ArtifactError("failure_policy", "failure_policy must be an object")
    unknown = sorted(set(policy) - set(FAILURE_POLICY_KEYS))
    if unknown:
        raise ArtifactError(
            "failure_policy",
            "unknown failure-policy class: {}".format(unknown[0]),
        )
    missing = [key for key in FAILURE_POLICY_KEYS if key not in policy]
    if missing:
        raise ArtifactError(
            "failure_policy",
            "missing failure-policy class: {}".format(missing[0]),
        )
    normal = {}
    for key in FAILURE_POLICY_KEYS:
        value = policy[key]
        if value not in FAILURE_POLICY_VALUES:
            raise ArtifactError(
                "failure_policy",
                "failure policy for {} must be one of {}".format(
                    key, ", ".join(FAILURE_POLICY_VALUES)
                ),
            )
        normal[key] = value
    return normal


def _bindings(scope: Any) -> Mapping[str, Any]:
    if not isinstance(scope, Mapping):
        raise ArtifactError("invalid_scope", "scope must be an object")
    bindings = scope.get("bindings") or {}
    if not isinstance(bindings, Mapping):
        raise ArtifactError("invalid_scope", "scope bindings must be an object")
    return bindings


def _resolve_target(target: Union[str, os.PathLike]) -> Path:
    """Resolve a file, or a directory / ``active.json`` pointer, to one path."""
    path = Path(target)
    if path.is_dir() or path.name == ACTIVE_POINTER:
        pointer = path / ACTIVE_POINTER if path.is_dir() else path
        try:
            document = json.loads(pointer.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ArtifactError(
                "missing_artifact", "cannot read {}: {}".format(pointer, exc)
            ) from None
        sha = document.get("sha256") if isinstance(document, dict) else None
        if not isinstance(sha, str) or not sha:
            raise ArtifactError(
                "missing_artifact",
                "{} does not name an artifact sha256".format(pointer),
            )
        return pointer.parent / "{}.json".format(sha)
    return path


def _read_bytes(target: Union[str, os.PathLike, bytes, bytearray]) -> bytes:
    if isinstance(target, (bytes, bytearray)):
        return bytes(target)
    path = _resolve_target(target)
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ArtifactError(
            "missing_artifact", "cannot read {}: {}".format(path, exc)
        ) from None


def parse_artifact(raw: bytes) -> dict:
    """Parse and structurally validate artifact bytes (no module import)."""
    try:
        artifact = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ArtifactError("invalid_json", "artifact is not valid UTF-8 JSON") from None
    if not isinstance(artifact, dict):
        raise ArtifactError("invalid_json", "artifact must be a JSON object")
    if artifact.get("format") != ARTIFACT_FORMAT:
        raise ArtifactError(
            "unsupported_format",
            "artifact format must be {}, got {!r}".format(
                ARTIFACT_FORMAT, artifact.get("format")
            ),
        )
    unknown = sorted(set(artifact) - ARTIFACT_KEYS)
    if unknown:
        raise ArtifactError(
            "unsupported_field", "unknown artifact field: {}".format(unknown[0])
        )
    documents = artifact.get("documents")
    if not isinstance(documents, list):
        raise ArtifactError("invalid_documents", "documents must be a list")
    artifact["failure_policy"] = validate_failure_policy(
        artifact.get("failure_policy")
    )
    rules_module = artifact.get("rules_module")
    if rules_module is not None and not isinstance(rules_module, str):
        raise ArtifactError("module_mismatch", "rules_module must be a string or null")
    if not rules_module and _bindings(artifact.get("scope")):
        raise ArtifactError(
            "missing_rules_module",
            "scope bindings require a rules_module",
        )
    template_ids = artifact.get("template_ids") or []
    if not isinstance(template_ids, list) or any(
        not isinstance(item, str) or not item for item in template_ids
    ):
        raise ArtifactError(
            "invalid_template_ids", "template_ids must be a list of strings"
        )
    expected = compute_epoch(artifact)
    if artifact.get("epoch") != expected:
        raise ArtifactError(
            "epoch_mismatch",
            "artifact epoch {!r} does not match its body ({})".format(
                artifact.get("epoch"), expected
            ),
        )
    return artifact


def build_documents_engine(documents: Any) -> Optional[Any]:
    """Compile the artifact's documents into the unscoped base policy.

    The artifact carries two kinds of rules and both must decide something: the
    scope bindings (templates, per principal) and the declarative documents
    (the org-wide base).  A document-only policy has no bindings at all, so
    without this engine its rules would be inert - an artifact that signs,
    verifies and allows everything.  Returns None when there are no rules.

    A quarantined rule refuses the load.  Quarantine is the engine's
    forward-compatibility valve for a *file* an operator edited; inside a
    signed artifact it means the plane signed a rule set the host does not
    enforce, which is exactly the silent-drop this module must never allow.
    """
    from .declarative import load_policy

    if not isinstance(documents, (list, tuple)):
        raise ArtifactError("invalid_documents", "documents must be a list")
    rules: list = []
    for index, document in enumerate(documents):
        if not isinstance(document, Mapping):
            raise ArtifactError(
                "invalid_documents", "document {} must be an object".format(index)
            )
        declared = document.get("rules")
        if declared is None:
            continue
        if not isinstance(declared, (list, tuple)):
            raise ArtifactError(
                "invalid_documents",
                "document {} rules must be a list".format(index),
            )
        rules.extend(declared)
    if not rules:
        return None
    try:
        engine = load_policy({"version": 1, "rules": rules})
    except Exception as exc:
        raise ArtifactError(
            "invalid_documents", "documents could not be loaded: {}".format(exc)
        ) from None
    if engine.quarantined:
        raise ArtifactError(
            "invalid_rule",
            "document rule refused: {}".format(engine.quarantined[0]),
        )
    return engine


def _combine_layers(floor: Any, scoped: Any) -> Any:
    """Combine the document floor with the scope decision, block always winning.

    Mirrors ``PolicyEngine``'s own combine rule: BLOCK ends evaluation,
    ESCALATE waits for no block, MODIFYs compose in order (the later rewrite
    of a named argument wins) and an ESCALATE keeps the merged rewrites.  The
    documents are a *floor*: a scope binding can add blocks and escalations,
    but it can never turn a document block into an allow.
    """
    from ..enforce import Decision, Verdict

    if scoped.verdict is Verdict.BLOCK:
        return scoped
    if scoped.verdict is Verdict.ALLOW:
        return floor
    if scoped.verdict is Verdict.ESCALATE:
        if floor.verdict is Verdict.MODIFY and floor.modified_args:
            return Decision(
                verdict=Verdict.ESCALATE,
                reason=scoped.reason,
                policy_id=scoped.policy_id,
                modified_args=dict(floor.modified_args),
                attributed_to=scoped.attributed_to,
                mesh_ceiling=scoped.mesh_ceiling,
            )
        if floor.verdict is Verdict.ESCALATE:
            return scoped if scoped.policy_id else floor
        return scoped
    # scoped is MODIFY
    if floor.verdict in (Verdict.ALLOW,):
        return scoped
    merged = {**(floor.modified_args or {}), **(scoped.modified_args or {})}
    if floor.verdict is Verdict.ESCALATE:
        return Decision(
            verdict=Verdict.ESCALATE,
            reason=floor.reason,
            policy_id=floor.policy_id,
            modified_args=merged or None,
            attributed_to=floor.attributed_to,
            mesh_ceiling=floor.mesh_ceiling,
        )
    first = floor
    return Decision(
        verdict=Verdict.MODIFY,
        reason="; ".join(r for r in (floor.reason, scoped.reason) if r),
        policy_id=first.policy_id,
        modified_args=merged or None,
        attributed_to=first.attributed_to,
        masked=floor.masked or None,
    )


def evaluate_layers(base: Any, scoped: Any, event: Any) -> Any:
    """The artifact's evaluation order, shared by the compiler and the host.

    The documents are the org-wide floor and the scope bindings are the
    per-principal refinement; both decide, and the stricter verdict wins.  A
    document-only artifact has no bindings, so its rules are the whole policy -
    without this layering those rules would be carried, signed and never
    evaluated.  A document rewrite is applied before the scope judges the
    call, exactly as ``PolicyEngine`` re-judges after a MODIFY.
    """
    from ..enforce import Verdict

    if base is None:
        return scoped.evaluate(event)
    floor = base.evaluate(event)
    if floor.verdict is Verdict.BLOCK:
        return floor
    if not (scoped.scope_of(event) or scoped.default_scope):
        # No scope path at all: the documents are the whole policy for this
        # subject. Without this, an artifact that ships documents but leaves
        # ``allow_unscoped`` at its fail-closed default would block every
        # event the documents just authorised.
        return floor
    working = event
    if floor.verdict is Verdict.MODIFY and floor.modified_args:
        working = replace(event, args={**(event.args or {}), **floor.modified_args})
    return _combine_layers(floor, scoped.evaluate(working))



class _NativeBase:
    """The document floor, evaluated natively with a Python per-call fallback.

    Only ``evaluate`` is overridden; everything else (``__len__``, ``epoch``,
    the documents) delegates to the Python engine, so callers that introspect
    the base keep seeing the engine that was actually loaded. A native failure
    must never change the answer - the Python engine evaluates the same policy
    - so the exception is logged, counted on the owning policy, and the same
    event is replayed on Python.
    """

    def __init__(self, engine: Any, plan: Any, owner: "CompiledPolicy") -> None:
        self._engine = engine
        self._plan = plan
        self._owner = owner

    def evaluate(self, event: Any) -> Any:
        from . import native as native_policy

        try:
            return native_policy.decide(self._plan, event)
        except Exception as exc:
            self._owner.native_fallbacks += 1
            _log.warning(
                "interlock: native document evaluation failed (%s); using the "
                "Python engine", exc,
            )
            return self._engine.evaluate(event)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._engine, name)

    def __len__(self) -> int:
        return len(self._engine)


class _NativeScoped:
    """A ``ScopedEngine`` that uses a scope's native plan when one was built.

    The scope engine is still the source of truth: a native failure is counted
    and the same event is replayed on Python, and a scope without a plan (or
    whose cached engine has been rebuilt since the plan was made) delegates
    unchanged. Only ``evaluate`` is overridden; ``scope_of``,
    ``default_scope``, ``epoch_for`` and ``registry`` pass through.
    """

    def __init__(self, engine: Any, plans: Mapping[tuple, tuple],
                 owner: "CompiledPolicy") -> None:
        self._engine = engine
        self._plans = plans
        self._owner = owner

    def evaluate(self, event: Any) -> Any:
        from . import native as native_policy

        scope = tuple(self._engine.scope_of(event) or self._engine.default_scope)
        entry = self._plans.get(scope) if scope else None
        if entry is None:
            return self._engine.evaluate(event)
        engine, plan = entry
        try:
            current = self._engine.registry.for_scope(scope)
        except Exception:
            return self._engine.evaluate(event)
        if current is not engine:
            # The registry rebuilt the scope's engine (a rebind), so the plan
            # was compiled from a policy this event must not be judged under.
            return self._engine.evaluate(event)
        try:
            return native_policy.decide(plan, event)
        except Exception as exc:
            self._owner.native_fallbacks += 1
            _log.warning(
                "interlock: native scope evaluation failed (%s); using the "
                "Python engine", exc,
            )
            return self._engine.evaluate(event)

    def __getattr__(self, name: str) -> Any:
        if name in ("_engine", "_plans", "_owner"):
            raise AttributeError(name)
        return getattr(self._engine, name)


def _scope_paths(scope: Mapping[str, Any]) -> list:
    try:
        bindings = _bindings(scope)
    except ArtifactError:
        return []
    return sorted(str(key) for key in bindings)


def _leaf(key: str) -> tuple:
    return tuple(part for part in str(key).split("/") if part)


def native_forced_off() -> bool:
    """Whether ``INTERLOCK_NATIVE=0`` (or false/no/off) forces Python.

    The artifact path is native-on by default, but the operator's documented
    escape hatch must still win: a host that sets ``INTERLOCK_NATIVE=0`` is
    asking for the Python evaluator everywhere, artifacts included.
    """
    return os.environ.get("INTERLOCK_NATIVE", "").strip().lower() in {
        "0", "false", "no", "off",
    }


class CompiledPolicy:
    """A loaded artifact plus the engines it materialised.

    The scope engine, its per-scope cache and the document base are all built
    once, at load/swap time.  A call only evaluates; it never re-parses the
    artifact, re-imports the module or rebuilds a scope.
    """

    def __init__(self, artifact: Mapping[str, Any], engine: Any, *,
                 raw: bytes, rules_module: Optional[str],
                 template_ids: list, base: Any = None,
                 native_enabled: bool = True) -> None:
        self.artifact = dict(artifact)
        self.engine = engine
        self.base = base
        self.artifact_bytes = bytes(raw)
        self.sha256 = hashlib.sha256(self.artifact_bytes).hexdigest()
        self.epoch = str(artifact.get("epoch") or "")
        self.rules_module = rules_module
        self.template_ids = list(template_ids)
        self.catalog = artifact.get("catalog") or ""
        self.failure_policy = dict(artifact.get("failure_policy") or {})
        self.documents = list(artifact.get("documents") or [])
        self.scope = dict(artifact.get("scope") or {})
        # Native evaluation is on by default for an artifact: unlike a local
        # engine, an artifact is an explicitly compiled, parity-gated rule set.
        # ``python_scopes`` records every scope that stays on Python (scope
        # templates are Python callables, so today that is all of them), and
        # ``native_scopes`` the ones a native plan could decide. The documents
        # base and each bound scope are planned once, here, at load time.
        self._native_requested = bool(native_enabled)
        self._native_forced_off = native_forced_off()
        self.native_enabled = self._native_requested and not self._native_forced_off
        self.native_plan: Optional[Any] = None
        self.native_base = False
        self.native_scopes: list = []
        self.python_scopes = _scope_paths(self.scope)
        self.native_unavailable_reason: Optional[str] = None
        self.native_fallbacks = 0
        self._scope_plans: dict = {}
        self._base_eval = base
        self._attach_native(base)
        self._attach_native_scopes()
        self._scope_eval = (
            _NativeScoped(self.engine, self._scope_plans, self)
            if self._scope_plans else self.engine
        )

    def _reason(self, text: str) -> None:
        """Append one refusal reason, keeping every earlier one."""
        if self.native_unavailable_reason:
            self.native_unavailable_reason = (
                self.native_unavailable_reason + "; " + text)
        else:
            self.native_unavailable_reason = text

    def _attach_native(self, base: Any) -> None:
        """Plan the documents base once, recording why it could not be done.

        A missing accelerator, a base with no rules, or a document the planner
        cannot translate whole all leave evaluation on the Python engine. None
        of them is an error: the Python engine is the definition of semantics.
        """
        if not self.native_enabled:
            self.native_unavailable_reason = (
                "INTERLOCK_NATIVE=0 forces Python evaluation"
                if self._native_forced_off else "native evaluation is disabled"
            )
            return
        from . import native as native_policy

        if base is None:
            self.native_unavailable_reason = "artifact has no document rules to plan"
            return
        if not native_policy.available():
            self.native_unavailable_reason = (
                "the native accelerator interlock_scopes is not installed"
            )
            return
        # Artifacts bypass the size gate: the policy was explicitly compiled
        # for the fast path, and a small document set must not silently run on
        # Python only.
        plan = native_policy.build(base, minimum=0)
        if plan is None:
            _, reason = native_policy.plan_for_with_reason(base, minimum=0)
            self.native_unavailable_reason = (
                reason or "the document base is not expressible natively")
            return
        self.native_plan = plan
        self.native_base = True
        self._base_eval = _NativeBase(base, plan, self)

    def _attach_native_scopes(self) -> None:
        """Plan each bound scope's engine once, exactly as the base is planned.

        A scope whose engine is not expressible stays on Python and is listed
        in ``python_scopes``; the per-scope reason is carried in
        ``native_unavailable_reason`` so ``verify``/``doctor`` can explain it.
        """
        keys = list(self.python_scopes)
        if not keys:
            return
        from . import native as native_policy

        if not self.native_enabled or not native_policy.available():
            return
        reasons = []
        for key in keys:
            path = _leaf(key)
            try:
                engine = self.engine.registry.for_scope(path)
            except Exception as exc:
                reasons.append(
                    "scope {!r} could not be resolved: {}".format(key, exc))
                continue
            plan = native_policy.build(engine, minimum=0)
            if plan is None:
                _, why = native_policy.plan_for_with_reason(engine, minimum=0)
                reasons.append("scope {!r}: {}".format(
                    key, why or "not expressible natively"))
                continue
            self._scope_plans[path] = (engine, plan)
            self.native_scopes.append(key)
        self.python_scopes = [key for key in keys if key not in self.native_scopes]
        if self.python_scopes and reasons:
            self._reason(
                "scope templates are Python callables; scope(s) stayed on "
                "Python: " + "; ".join(reasons[:3]))

    def status(self) -> dict:
        """A machine-readable picture of which backend decided what.

        ``native_base`` is the documents floor; ``native_scopes`` and
        ``python_scopes`` partition the bound scopes. ``native_fallbacks``
        counts calls where the native path failed and Python answered instead.
        """
        if self._native_forced_off:
            rule = "INTERLOCK_NATIVE=0 forces Python"
        elif not self._native_requested:
            rule = "native_enabled=False"
        else:
            rule = "artifact default (native-on)"
        return {
            "enabled": self.native_enabled,
            "rule": rule,
            "native_base": self.native_base,
            "native_scopes": list(self.native_scopes),
            "python_scopes": list(self.python_scopes),
            "native_fallbacks": self.native_fallbacks,
            "native_unavailable_reason": self.native_unavailable_reason,
            "epoch": self.epoch,
            "sha256": self.sha256,
            "scope_epochs": self.scope_epochs(),
        }

    def evaluate(self, event: Any) -> Any:
        return evaluate_layers(self._base_eval, self._scope_eval, event)

    def evaluate_with_epoch(self, event: Any) -> tuple:
        """``(Decision, scope_epoch)``; the scope epoch is None when unbound.

        A document-decided event has no scope, so its epoch is None: the
        artifact's own ``epoch`` identifies the rules it was judged under.
        """
        return (
            evaluate_layers(self._base_eval, self._scope_eval, event),
            self.engine.epoch_for(event),
        )

    def scope_epochs(self) -> dict:
        """Each bound scope path's compiled-engine epoch, deterministically."""
        out = {}
        for key in sorted(_bindings(self.scope)):
            path = tuple(part for part in str(key).split("/") if part)
            try:
                out[str(key)] = self.engine.registry.for_scope(path).epoch
            except Exception:
                out[str(key)] = None
        return out

    def rule_count(self) -> int:
        """Rules that can actually decide an event.

        The documents floor plus every bound scope's compiled rules. This is
        the emptiness test a host needs before serving an artifact: a count of
        templates would say a scope exists even when its template carries no
        rule, and an artifact that decides nothing would allow everything.
        """
        total = 0
        if self.base is not None:
            try:
                total += len(self.base)
            except TypeError:
                pass
        for key in sorted(_bindings(self.scope)):
            path = tuple(part for part in str(key).split("/") if part)
            try:
                total += len(self.engine.registry.for_scope(path))
            except Exception:
                continue
        return total


def _load_templates(spec: str) -> Mapping[str, Any]:
    """Import ``module:attr`` lazily; the import is the only side effect."""
    from ..sidecar.rules import RulesError, load_templates

    try:
        return load_templates(spec)
    except RulesError as exc:
        raise ArtifactError("rules_module", str(exc)) from None


def load_artifact(
    path_or_bytes: Union[str, os.PathLike, bytes, bytearray],
    *,
    module: Optional[str] = None,
    native_enabled: bool = True,
) -> CompiledPolicy:
    """Validate artifact bytes and materialise the engine they describe.

    ``module`` pins the ``module:attr`` spec the caller believes it is loading;
    a mismatch with the artifact raises ``ArtifactError("module_mismatch")`` so
    two hosts cannot run different code under one artifact hash.

    ``native_enabled`` plans the documents base and every bound scope for the
    native evaluator. It is on by default because this is the artifact fast
    path; a control-plane validation call that wants a pure Python round-trip
    passes ``False``. ``INTERLOCK_NATIVE=0`` in the environment forces Python
    even when the default is native-on.
    """
    raw = _read_bytes(path_or_bytes)
    artifact = parse_artifact(raw)
    rules_module = artifact.get("rules_module")
    if module is not None and module != rules_module:
        raise ArtifactError(
            "module_mismatch",
            "artifact names rules module {!r}, caller pinned {!r}".format(
                rules_module, module
            ),
        )

    bindings = _bindings(artifact.get("scope"))
    if rules_module:
        templates = _load_templates(rules_module)
    else:
        templates = {}
        if bindings:
            raise ArtifactError(
                "missing_rules_module", "scope bindings require a rules_module"
            )

    declared = list(artifact.get("template_ids") or [])
    missing = sorted(set(declared) - set(templates))
    if missing:
        raise ArtifactError(
            "missing_template",
            "rules module {} no longer declares template id(s): {}".format(
                rules_module, ", ".join(missing)
            ),
        )

    from ..sidecar.rules import RulesError, build_scoped_engine

    scope = artifact.get("scope") or {}
    try:
        engine = build_scoped_engine(scope, templates)
    except RulesError as exc:
        raise ArtifactError("invalid_scope", str(exc)) from None
    base = build_documents_engine(artifact.get("documents"))

    # Bindings are the authority: a module that exports extra ids is fine
    # unless a binding names one, in which case build_scoped_engine already
    # refused above.  Nothing is dropped silently.
    resolved_ids = sorted(set(declared) | {
        str(entry.get("template"))
        for entries in bindings.values()
        if isinstance(entries, (list, tuple))
        for entry in entries
        if isinstance(entry, Mapping) and entry.get("template")
    })
    return CompiledPolicy(
        artifact, engine, raw=raw, rules_module=rules_module,
        template_ids=resolved_ids, base=base, native_enabled=native_enabled,
    )


def materialize(artifact: Union[Mapping[str, Any], bytes, bytearray],
                path: Union[str, os.PathLike]) -> str:
    """Atomically write canonical artifact bytes to ``path``.

    The write is temp file in the destination directory, ``fsync``, ``rename``,
    then a directory ``fsync``: a crash leaves either the old file or the new
    one, never a truncated artifact.
    """
    if isinstance(artifact, (bytes, bytearray)):
        raw = bytes(artifact)
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ArtifactError("invalid_json", "artifact is not valid JSON") from None
        if not isinstance(value, dict):
            raise ArtifactError("invalid_json", "artifact must be a JSON object")
        payload = canonical_bytes(value)
    elif isinstance(artifact, Mapping):
        value = dict(artifact)
        if "epoch" not in value:
            value = seal_artifact(value)
        payload = canonical_bytes(value)
    else:
        raise ArtifactError("invalid_artifact", "materialize needs bytes or an object")

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(destination.parent), prefix="." + destination.name + ".", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, str(destination))
        try:
            dir_fd = os.open(str(destination.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return str(destination)


__all__ = [
    "ACTIVE_POINTER",
    "ARTIFACT_FORMAT",
    "ARTIFACT_KEYS",
    "ArtifactError",
    "CompiledPolicy",
    "FAILURE_POLICY_DEFAULTS",
    "FAILURE_POLICY_KEYS",
    "FAILURE_POLICY_VALUES",
    "build_documents_engine",
    "canonical_bytes",
    "canonical_json",
    "compute_epoch",
    "evaluate_layers",
    "load_artifact",
    "materialize",
    "native_forced_off",
    "parse_artifact",
    "seal_artifact",
    "validate_failure_policy",
]
