"""Compile authored policy into the deterministic distributed artifact (C5).

``compile_from_source`` is the plane's single compiler entry point.  It

1. normalises every authored declarative document by loading it and
   re-serialising the documents the engine actually kept (so unknown or
   derived fields cannot ride into the artifact),
2. resolves the scope document's bindings through the rules module named by
   ``rules_module`` / ``IL_CLOUD_POLICY_MODULE`` (templates are code and never
   live on the plane),
3. validates the scope by building the same ``ScopedEngine`` a host will
   materialise, and
4. round-trips a corpus through the source engine and the compiled artifact,
   refusing on the first divergent event.

The function is pure apart from importing the named module: it reads no
database, clock or network. Capability checks (``cap_compile``, step-up) live
on the route, not here.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

from ...policy.artifact import (
    FAILURE_POLICY_DEFAULTS,
    ArtifactError,
    build_documents_engine,
    canonical_bytes,
    compute_epoch,
    evaluate_layers,
    load_artifact,
    seal_artifact,
    validate_failure_policy,
)
from ...policy.declarative import PolicyError, load_policy
from ...sidecar.rules import RulesError, build_scoped_engine, load_templates

#: The rules-module spec environment fallback. The plane ships the core
#: package, so a deployment may name one module for every org.
RULES_MODULE_ENV = "IL_CLOUD_POLICY_MODULE"

#: The round-trip corpus. It lives with the test fixtures because it is the
#: same corpus the tests assert over; a plane built without it refuses to
#: compile rather than signing an unverified artifact.
DEFAULT_CORPUS = (
    Path(__file__).resolve().parents[3]
    / "tests" / "fixtures" / "cloud" / "policy_corpus.jsonl"
)

EVENT_FIELDS = (
    "action", "args", "principal", "parent_principal", "span_id",
    "phase", "cwd", "call_id",
)


class CompileError(ValueError):
    """A compile refusal with the short code the route returns.

    ``bad_artifact`` is FR-041's refusal for an invalid binding, an
    unresolvable module or a round-trip divergence; ``module_mismatch`` is the
    separate refusal for two different module specs.
    """

    def __init__(self, code: str, message: str = "") -> None:
        self.code = str(code)
        self.message = message or self.code
        super().__init__(self.message)


@dataclass(frozen=True)
class CompileResult:
    """The compiled artifact and everything the route/report needs."""

    artifact_bytes: bytes
    sha256: str
    epoch: str
    scope_epochs: Mapping[str, Optional[str]] = field(default_factory=dict)
    rules_module: Optional[str] = None
    template_ids: Sequence[str] = field(default_factory=tuple)
    diffs: Mapping[str, Any] = field(default_factory=dict)
    catalog: str = ""
    failure_policy: Mapping[str, str] = field(default_factory=dict)

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def to_dict(self) -> dict:
        return {
            "sha256": self.sha256,
            "epoch": self.epoch,
            "size": len(self.artifact_bytes),
            "rules_module": self.rules_module,
            "template_ids": list(self.template_ids),
            "scope_epochs": dict(self.scope_epochs),
            "diffs": dict(self.diffs),
            "catalog": self.catalog,
            "failure_policy": dict(self.failure_policy),
        }


def _catalog_id() -> str:
    """The installed detector catalog id, or an empty string when unbuilt."""
    try:
        from ...mesh.catalog import catalog_id

        return str(catalog_id())
    except Exception:
        return ""


def _normalise_documents(documents: Any) -> list:
    """Load every authored document and keep only what the engine kept.

    A quarantined rule refuses the compile: signing a rule the host will skip
    is a policy that silently does nothing, and the plane cannot tell the
    admin afterwards.  A file an operator edits may tolerate quarantine; a
    distributed artifact may not.
    """
    if not isinstance(documents, (list, tuple)):
        raise CompileError("bad_artifact", "documents must be a list")
    out: list = []
    for index, document in enumerate(documents):
        if not isinstance(document, Mapping):
            raise CompileError(
                "bad_artifact", "document {} must be an object".format(index)
            )
        try:
            engine = load_policy(document)
        except PolicyError as exc:
            raise CompileError(
                "bad_artifact", "document {}: {}".format(index, exc)
            ) from None
        except Exception as exc:  # a malformed document is a refusal, not a 500
            raise CompileError(
                "bad_artifact",
                "document {} could not be loaded: {}".format(index, type(exc).__name__),
            ) from None
        if engine.quarantined:
            raise CompileError(
                "bad_artifact",
                "document {}: invalid rule: {}".format(index, engine.quarantined[0]),
            )
        out.extend(engine.documents)
    return out


def _normalise_scope(scope: Any) -> dict:
    if not isinstance(scope, Mapping):
        raise CompileError("bad_artifact", "scope must be an object")
    bindings = scope.get("bindings") or {}
    if not isinstance(bindings, Mapping):
        raise CompileError("bad_artifact", "scope bindings must be an object")
    for key, entries in bindings.items():
        if not isinstance(entries, (list, tuple)):
            raise CompileError(
                "bad_artifact", "scope {!r} bindings must be a list".format(key)
            )
    normal = dict(scope)
    normal.setdefault("version", 1)
    normal["bindings"] = {str(key): [dict(entry) if isinstance(entry, Mapping) else entry
                                    for entry in entries]
                          for key, entries in bindings.items()}
    normal.setdefault("default_scope", [])
    normal.setdefault("allow_unscoped", False)
    return normal


def _module_spec(rules_module: Optional[str]) -> Optional[str]:
    explicit = rules_module.strip() if isinstance(rules_module, str) else None
    explicit = explicit or None
    from_env = (os.environ.get(RULES_MODULE_ENV) or "").strip() or None
    if explicit and from_env and explicit != from_env:
        raise CompileError(
            "module_mismatch",
            "rules_module {!r} differs from {} {!r}".format(
                explicit, RULES_MODULE_ENV, from_env
            ),
        )
    return explicit or from_env


def _resolve_templates(spec: Optional[str], bindings: Mapping[str, Any]) -> Mapping[str, Any]:
    if not bindings:
        # A document-only policy needs no code. A named module is still loaded
        # and validated so a caller cannot believe code was resolved when the
        # spec was broken.
        return load_templates(spec) if spec else {}
    if not spec:
        raise CompileError(
            "bad_artifact",
            "scope bindings require a rules module (set rules_module or "
            "IL_CLOUD_POLICY_MODULE)",
        )
    try:
        return load_templates(spec)
    except RulesError as exc:
        raise CompileError("bad_artifact", str(exc)) from None


def _declared_template_ids(bindings: Mapping[str, Any]) -> list:
    ids = set()
    for entries in bindings.values():
        if not isinstance(entries, (list, tuple)):
            continue
        for entry in entries:
            if isinstance(entry, Mapping):
                template_id = entry.get("template")
                if isinstance(template_id, str) and template_id:
                    ids.add(template_id)
    return sorted(ids)


def _load_corpus(path: Path) -> list:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CompileError(
            "bad_artifact", "round-trip corpus is unreadable: {}".format(exc)
        ) from None
    events = []
    from ...event import SensorEvent

    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except ValueError:
            raise CompileError(
                "bad_artifact", "corpus line {} is not JSON".format(number)
            ) from None
        if not isinstance(raw, dict) or not isinstance(raw.get("action"), str):
            raise CompileError(
                "bad_artifact", "corpus line {} is not an event".format(number)
            )
        events.append(SensorEvent(**{key: raw[key] for key in EVENT_FIELDS
                                     if key in raw}))
    if not events:
        raise CompileError("bad_artifact", "round-trip corpus is empty")
    return events


def _shape(decision: Any) -> tuple:
    """The comparable facts of a decision, in a deterministic order."""
    verdict = getattr(decision, "verdict", None)
    name = getattr(verdict, "name", verdict)
    return (
        name,
        getattr(decision, "policy_id", None),
        getattr(decision, "reason", ""),
        getattr(decision, "modified_args", None),
    )


def _diffs(source_decisions: Iterable[Any], compiled_decisions: Iterable[Any]) -> dict:
    counts: dict = {}
    source_ids = set()
    compiled_ids = set()
    for decision in list(source_decisions):
        verdict = getattr(getattr(decision, "verdict", None), "name", "UNKNOWN")
        counts[verdict] = counts.get(verdict, 0) + 1
        if getattr(decision, "policy_id", None):
            source_ids.add(decision.policy_id)
    for decision in list(compiled_decisions):
        if getattr(decision, "policy_id", None):
            compiled_ids.add(decision.policy_id)
    return {
        "counts": dict(sorted(counts.items())),
        "policy_ids_added": sorted(compiled_ids - source_ids),
        "policy_ids_removed": sorted(source_ids - compiled_ids),
    }


def compile_from_source(
    documents: Any,
    scope: Any,
    *,
    rules_module: Optional[str] = None,
    corpus: Optional[Any] = None,
    catalog: Optional[str] = None,
    failure_policy: Optional[Mapping[str, str]] = None,
) -> CompileResult:
    """Compile authored documents and a scope document into artifact bytes."""
    normal_documents = _normalise_documents(documents)
    normal_scope = _normalise_scope(scope)
    bindings = normal_scope.get("bindings") or {}
    spec = _module_spec(rules_module)
    templates = _resolve_templates(spec, bindings)
    template_ids = _declared_template_ids(bindings)

    if not normal_documents and not bindings:
        raise CompileError(
            "bad_artifact",
            "policy is empty: no documents and no scope bindings",
        )

    try:
        source_engine = build_scoped_engine(normal_scope, templates)
        # The documents are the unscoped base layer, so the source form has to
        # carry them too: a parity check against a scope-only source would
        # compare two engines that both ignore the org's declarative rules.
        source_base = build_documents_engine(normal_documents)
    except RulesError as exc:
        raise CompileError("bad_artifact", str(exc)) from None
    except ArtifactError as exc:
        raise CompileError("bad_artifact", str(exc)) from None
    if source_base is None and not bindings:
        raise CompileError(
            "bad_artifact",
            "policy is empty: the documents declare no rules and there are no "
            "scope bindings",
        )

    try:
        policy = (
            validate_failure_policy(failure_policy)
            if failure_policy is not None
            else dict(FAILURE_POLICY_DEFAULTS)
        )
    except ArtifactError as exc:
        raise CompileError("bad_artifact", str(exc)) from None
    body = {
        "format": 1,
        "documents": normal_documents,
        "scope": normal_scope,
        "rules_module": spec,
        "template_ids": template_ids,
        "catalog": _catalog_id() if catalog is None else str(catalog),
        "failure_policy": policy,
    }
    artifact = seal_artifact(body)
    artifact_bytes = canonical_bytes(artifact)
    sha256 = hashlib.sha256(artifact_bytes).hexdigest()

    try:
        compiled = load_artifact(artifact_bytes)
    except ArtifactError as exc:
        raise CompileError("bad_artifact", str(exc)) from None

    corpus_path = Path(corpus) if corpus is not None else DEFAULT_CORPUS
    events = _load_corpus(corpus_path)
    source_decisions = [evaluate_layers(source_base, source_engine, e) for e in events]
    compiled_decisions = [compiled.evaluate(event) for event in events]
    for index, (source, generated) in enumerate(
        zip(source_decisions, compiled_decisions)
    ):
        if _shape(source) != _shape(generated):
            raise CompileError(
                "bad_artifact",
                "round-trip divergence at corpus event {}: source={!r} compiled={!r}".format(
                    index, _shape(source), _shape(generated)
                ),
            )

    scope_epochs = {}
    for key in sorted(bindings):
        path = tuple(part for part in str(key).split("/") if part)
        try:
            scope_epochs[str(key)] = source_engine.registry.for_scope(path).epoch
        except Exception:
            scope_epochs[str(key)] = None

    return CompileResult(
        artifact_bytes=artifact_bytes,
        sha256=sha256,
        epoch=artifact["epoch"],
        scope_epochs=scope_epochs,
        rules_module=spec,
        template_ids=template_ids,
        diffs=_diffs(source_decisions, compiled_decisions),
        catalog=artifact["catalog"],
        failure_policy=policy,
    )


__all__ = [
    "CompileError",
    "CompileResult",
    "DEFAULT_CORPUS",
    "RULES_MODULE_ENV",
    "canonical_bytes",
    "compile_from_source",
    "compute_epoch",
]
