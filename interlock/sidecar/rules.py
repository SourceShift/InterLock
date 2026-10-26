"""Resolve a rules module into the one engine the daemon serves.

The policy is a Python module, not a data file: rules are callables
(:mod:`interlock.policy.engine`). Making the policy *portable* is R10's job
(declarative YAML/JSON); until it lands, the daemon ships the rules module and
only the *evaluation* moves across the language boundary. That is why this
daemon does not wait on R10.
"""
from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any, Iterable, Mapping, Union

from ..policy.engine import PolicyEngine, Rule

if TYPE_CHECKING:  # pragma: no cover - the type checker only; the import is lazy at runtime
    # Imported locally in ``build_scoped_engine`` to keep the daemon's import
    # light, so the annotation needs its own name-only import for the linter.
    from ..policy.scopes import ScopedEngine


class RulesError(Exception):
    """The ``module:attr`` spec does not name a usable rule set."""


class EmptyRules(RulesError):
    """The named engine has no rules.

    Its own exception because it is the one failure that must stop the daemon
    from starting rather than warn: an engine with no rules allows everything,
    so serving it would be a guard that reports success while enforcing nothing.
    """


Spec = Union[PolicyEngine, Iterable[Rule]]


def load_rules(spec: str) -> PolicyEngine:
    """Import ``module:attr`` and return it as a non-empty PolicyEngine.

    ``attr`` must be either a :class:`PolicyEngine` or an iterable of rules
    (a list or tuple a rules module exports). Both spellings are accepted
    because a module that exports plain rules is the more natural thing to
    write and the engine is a trivial wrapper around them.

    Raises :class:`RulesError` for a malformed spec, an import that fails, a
    missing attribute, or an attribute of the wrong shape; :class:`EmptyRules`
    when the result has zero rules.
    """
    module = load_rules_module(spec)
    loaded = _named_attr(module, spec)
    engine = _as_engine(loaded, spec)
    if len(engine) == 0:
        raise EmptyRules(
            "{} resolved to an engine with no rules; refusing to serve an "
            "engine that would allow every action".format(spec)
        )
    return engine


def _spec_parts(spec: str) -> "tuple":
    module_name, sep, attr_name = spec.partition(":")
    if not sep or not module_name or not attr_name:
        raise RulesError(
            "rules must be given as module:attr, got {!r}".format(spec)
        )
    return module_name, attr_name


def load_rules_module(spec: str):
    """Import the ``module`` half of a ``module:attr`` spec.

    Split out from :func:`load_rules` so the sidecar can read a rules module's
    scope *templates* (and, when asked, its declared scope document) from the
    same import that supplies its rules, rather than importing it twice.
    """
    module_name, _ = _spec_parts(spec)
    try:
        return importlib.import_module(module_name)
    except Exception as exc:
        raise RulesError("cannot import {!r}: {}".format(module_name, exc))


def _named_attr(module: Any, spec: str) -> Spec:
    _, attr_name = _spec_parts(spec)
    try:
        return getattr(module, attr_name)
    except AttributeError:
        raise RulesError(
            "{} has no attribute {!r}".format(spec.partition(":")[0], attr_name)
        )


def load_templates(spec: str) -> Mapping[str, Any]:
    """Import ``module:attr`` and return its scope-template mapping.

    ``attr`` may be any attribute name, not only ``templates``: the compiler
    and the host both accept the authored spec verbatim. The value must be a
    mapping of template id to :class:`~interlock.policy.scopes.Template`;
    anything else is a refusal rather than an empty registry, because an empty
    registry would make every bound id unknown at resolve time.
    """
    module = load_rules_module(spec)
    loaded = _named_attr(module, spec)
    if not isinstance(loaded, Mapping):
        raise RulesError(
            "{} resolved to a {}, expected a mapping of template id to Template".format(
                spec, type(loaded).__name__
            )
        )
    return loaded


def _as_engine(loaded: Spec, spec: str) -> PolicyEngine:
    if isinstance(loaded, PolicyEngine):
        return loaded
    if isinstance(loaded, (list, tuple)):
        return PolicyEngine(rules=list(loaded))
    raise RulesError(
        "{} resolved to a {}, expected a PolicyEngine or a list of rules".format(
            spec, type(loaded).__name__
        )
    )


# --- scope documents ---------------------------------------------------------
#
# A scope document is pure data: per-scope *bindings* of template ids to params.
# The templates themselves are code and stay in the rules module, which is why a
# scope document is only meaningful next to the module that declares them. The
# document travels signed (see ``interlock.wire.scope_envelope``); this section
# turns a verified document plus a module's templates into the ScopedEngine the
# daemon serves.

SCOPE_DOC_VERSION = 1


def scope_document_of(module: Any) -> Mapping[str, Any]:
    """The scope document a rules module declares, or raise :class:`RulesError`.

    A module declares its scopes with a ``scope_document`` attribute that is
    either a mapping or a callable returning one. A module with neither cannot
    publish a scope document, which is a refusal rather than an empty one: an
    empty document would serve a scoped engine that scopes nothing.
    """
    declared = getattr(module, "scope_document", None)
    if declared is None:
        raise RulesError(
            "the rules module declares no scope_document; --scope-document needs "
            "one to publish, or point it at an existing signed document"
        )
    document = declared() if callable(declared) else declared
    if not isinstance(document, Mapping):
        raise RulesError("scope_document must be a mapping or a callable returning one")
    return document


def _scope_path(key: Any) -> "tuple":
    return tuple(part for part in str(key).split("/") if part)


def build_scoped_engine(
    document: Mapping[str, Any], templates: Mapping[str, Any]
) -> "ScopedEngine":
    """Compile a verified scope document into the ScopedEngine the daemon serves.

    ``templates`` is the module's ``templates`` mapping (id -> Template). A
    binding that names a template the module does not declare is a refusal, not
    a silently dropped rule: a binding dropped here is a policy that never
    exists, and the call it was meant to judge goes through unjudged.
    """
    from ..policy.scopes import Binding, ScopeRegistry, ScopeTree, ScopedEngine

    if not isinstance(document, Mapping):
        raise RulesError("scope document must be a mapping")
    if document.get("version") != SCOPE_DOC_VERSION:
        raise RulesError(
            "scope document version must be {}, got {!r}".format(
                SCOPE_DOC_VERSION, document.get("version")
            )
        )
    templates = dict(templates or {})
    bindings = document.get("bindings") or {}
    if not isinstance(bindings, Mapping):
        raise RulesError("scope document bindings must be a mapping")
    tree = ScopeTree()
    for key, entries in bindings.items():
        if not isinstance(entries, (list, tuple)):
            raise RulesError("scope {!r} bindings must be a list".format(key))
        compiled = []
        for entry in entries:
            if not isinstance(entry, Mapping):
                raise RulesError("scope {!r} binding must be an object".format(key))
            template_id = entry.get("template")
            if template_id not in templates:
                raise RulesError(
                    "scope {!r} binds unknown template {!r}; the rules module "
                    "must export it in `templates`".format(key, template_id)
                )
            params = entry.get("params") or {}
            if not isinstance(params, Mapping):
                raise RulesError("scope {!r} binding params must be an object".format(key))
            raw_delegated = entry.get("delegated_from")
            if "delegated_from" in entry:
                if not isinstance(raw_delegated, str):
                    raise RulesError(
                        "scope {!r} binding delegated_from must be a scope path "
                        "string".format(key)
                    )
                delegated_from = _scope_path(raw_delegated)
            else:
                delegated_from = None
            enabled = entry.get("enabled", True)
            if not isinstance(enabled, bool):
                raise RulesError(
                    "scope {!r} binding enabled must be a boolean".format(key)
                )
            compiled.append(
                Binding(
                    template_id,
                    dict(params),
                    enabled=enabled,
                    delegated_from=delegated_from,
                )
            )
        tree.bind(_scope_path(key), compiled)
    registry = ScopeRegistry(tree, templates)
    default_scope = document.get("default_scope") or []
    if not isinstance(default_scope, (list, tuple)):
        raise RulesError("scope document default_scope must be a list")
    return ScopedEngine(
        registry,
        default_scope=tuple(default_scope),
        allow_unscoped=bool(document.get("allow_unscoped", False)),
    )
