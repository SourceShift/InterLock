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
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping, Optional, Union

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


class CompiledPolicy:
    """A loaded artifact plus the scoped engine it materialised.

    The engine and its per-scope cache are built once, at load/swap time.  A
    call only evaluates; it never re-parses the artifact, re-imports the
    module or rebuilds a scope.
    """

    def __init__(self, artifact: Mapping[str, Any], engine: Any, *,
                 raw: bytes, rules_module: Optional[str],
                 template_ids: list) -> None:
        self.artifact = dict(artifact)
        self.engine = engine
        self.artifact_bytes = bytes(raw)
        self.sha256 = hashlib.sha256(self.artifact_bytes).hexdigest()
        self.epoch = str(artifact.get("epoch") or "")
        self.rules_module = rules_module
        self.template_ids = list(template_ids)
        self.catalog = artifact.get("catalog") or ""
        self.failure_policy = dict(artifact.get("failure_policy") or {})
        self.documents = list(artifact.get("documents") or [])
        self.scope = dict(artifact.get("scope") or {})

    def evaluate(self, event: Any) -> Any:
        return self.engine.evaluate(event)

    def evaluate_with_epoch(self, event: Any) -> tuple:
        """``(Decision, scope_epoch)``; the scope epoch is None when unbound."""
        return self.engine.evaluate(event), self.engine.epoch_for(event)

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
) -> CompiledPolicy:
    """Validate artifact bytes and materialise the engine they describe.

    ``module`` pins the ``module:attr`` spec the caller believes it is loading;
    a mismatch with the artifact raises ``ArtifactError("module_mismatch")`` so
    two hosts cannot run different code under one artifact hash.
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
        template_ids=resolved_ids,
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
    "canonical_bytes",
    "canonical_json",
    "compute_epoch",
    "load_artifact",
    "materialize",
    "parse_artifact",
    "seal_artifact",
    "validate_failure_policy",
]
