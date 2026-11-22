"""Derive a capability scope from what the guard actually allowed.

An agent cannot be trusted to say which capabilities it needs - a sandbox the
agent authors is a sandbox the agent may widen. So derive it: read a window of
receipts, keep the actions each scope was *allowed* to take, and emit a scope
document (:mod:`interlock.policy.scopes`) whose per-scope binding names exactly
those actions, with the receipt count behind each one.

What is derived, and what cannot be
-----------------------------------
Receipts carry ``args_digest``, never argument values: the audit log is built on
"name the thing, never store it". A path, host or program name lives in
``args``, so a receipt log *cannot* yield a ``paths``/``domains``/``binaries``
set - any attempt to emit one would have to invent values the log never
recorded. The derived capability is therefore the **action envelope**: which
tool actions, per scope, the guard allowed. That is the half of a capability
scope a receipt log can prove, and :class:`Envelope` says so rather than
pretending otherwise.

Where an operator *does* hold capability values (their own gateway log, an MCP
proxy, a trace), those belong in a policy written by hand - a scope document is
data, and hand-authored bindings merge with a derived one through
:func:`merge`, which refuses to widen.

Design notes
------------
* *Only ``ALLOW`` receipts count.* Anything else is reported in
  :attr:`Envelope.excluded` and can never become part of an envelope: a refused
  action must not be laundered into "observed and fine".
* *The cluster key is the scope the guard will consult.* Each receipt is
  clustered by ``principal_path(receipt.principal)`` - the very path
  ``ScopedEngine`` derives at decision time - so a suggestion binds the scope
  that will be looked up, not a parallel notion of "who".
* *Determinism.* Scopes are emitted in path order, actions sorted, counts in
  sorted key order, and callers serialize with ``sort_keys=True``. Two runs over
  the same log are byte-identical.
* *Narrowing by default, widening only on purpose.* :func:`merge` combines a
  derived document with an existing one and reports every entry that would grant
  an action the existing scope does not already allow; with ``allow_widen=False``
  the caller gets the problems and no document.

Read-only with respect to enforcement: importing this module installs nothing,
and the CLI writes only the file it is told to write.
"""
from __future__ import annotations

import dataclasses
import json
import os
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple, Union

from .actions import canonical_action
from .policy.capability import TEMPLATE_ID
from .policy.scopes import principal_path
from .receipt import Receipt
from .report import read_receipts
from .sidecar.rules import SCOPE_DOC_VERSION

#: Receipt actions that are audit artifacts, not observed tool calls. Allowing
#: ``receipts.dropped`` would let a sink failure become a permitted action.
_ARTIFACTS = frozenset({"receipts.dropped"})

#: The excluded bucket for a receipt that names no principal: it cannot be
#: placed in a scope, so it is reported rather than guessed at.
UNSCOPED = "unscoped"

#: A path to a receipt log, or an already-parsed stream of receipts.
ReceiptSource = Union[str, bytes, os.PathLike, Iterable[Receipt]]

Scope = Tuple[str, ...]


@dataclasses.dataclass
class Envelope:
    """A receipt window reduced to per-scope allowed actions and their counts.

    ``counts`` maps a scope path to ``{action: ALLOW receipt count}``; every
    entry is an action the guard actually let through. ``excluded`` maps what
    was left out to a count - a non-``ALLOW`` verdict, the ``receipts.dropped``
    audit artifact, or :data:`UNSCOPED`. Nothing in ``excluded`` can reach the
    emitted document.
    """

    counts: Dict[Scope, Dict[str, int]] = dataclasses.field(default_factory=dict)
    excluded: Dict[str, int] = dataclasses.field(default_factory=dict)

    @property
    def scopes(self) -> List[Scope]:
        """The observed scope paths, shortest first then alphabetically."""
        return sorted(self.counts, key=lambda scope: (len(scope), scope))

    @property
    def total(self) -> int:
        """How many ``ALLOW`` receipts formed the envelope."""
        return sum(sum(actions.values()) for actions in self.counts.values())

    @property
    def empty(self) -> bool:
        """True when no scoped ``ALLOW`` observation was found."""
        return not self.counts

    def actions_at(self, scope: Scope, *, min_count: int = 1) -> List[str]:
        """The actions observed at ``scope`` with at least ``min_count`` receipts."""
        actions = self.counts.get(tuple(scope), {})
        return sorted(action for action, count in actions.items() if count >= min_count)


def count_receipts(
    receipts: Iterable[Receipt],
    *,
    since_seconds: Optional[float] = None,
    now: Optional[float] = None,
) -> Envelope:
    """Reduce receipts to the per-scope capability envelope.

    A receipt joins the envelope only when its verdict is ``ALLOW`` (matched
    case-insensitively), its action is a real tool name, and it names a
    principal. ``since_seconds`` drops receipts older than ``now -
    since_seconds`` (``now`` defaults to the newest receipt in the window, so
    the result does not depend on the clock and stays deterministic for a
    stored log).
    """
    receipts = list(receipts)
    cutoff: Optional[float] = None
    if since_seconds is not None and since_seconds > 0:
        anchor = now if now is not None else max(
            (float(getattr(r, "ts", 0.0) or 0.0) for r in receipts), default=0.0)
        cutoff = anchor - since_seconds

    counts: Dict[Scope, Dict[str, int]] = {}
    excluded: Dict[str, int] = {}
    for receipt in receipts:
        action = canonical_action(str(getattr(receipt, "action", "") or "").strip())
        if not action:
            continue
        if action in _ARTIFACTS:
            excluded[action] = excluded.get(action, 0) + 1
            continue
        verdict = str(getattr(receipt, "verdict", "") or "").strip().upper()
        if verdict != "ALLOW":
            excluded[verdict] = excluded.get(verdict, 0) + 1
            continue
        if cutoff is not None and float(getattr(receipt, "ts", 0.0) or 0.0) < cutoff:
            continue
        scope = principal_path(getattr(receipt, "principal", None))
        if not scope:
            excluded[UNSCOPED] = excluded.get(UNSCOPED, 0) + 1
            continue
        per_scope = counts.setdefault(scope, {})
        per_scope[action] = per_scope.get(action, 0) + 1
    return Envelope(counts=counts, excluded=excluded)


def suggested_document(envelope: Envelope, *, min_count: int = 1) -> Dict[str, Any]:
    """The scope document an envelope alone produces.

    One binding per observed scope, naming that scope's allowed actions and the
    receipt count behind each. Raises :class:`ValueError` on an empty envelope:
    a document with no bindings scopes nothing, and a document whose every
    binding permits nothing would escalate all traffic - refusing to build is
    the fail-closed choice.
    """
    if envelope.empty:
        raise ValueError(
            "cannot build a scope document from an empty envelope: "
            "no scoped ALLOW receipt was observed")
    bindings: Dict[str, List[Dict[str, Any]]] = {}
    for scope in envelope.scopes:
        actions = envelope.actions_at(scope, min_count=min_count)
        if not actions:
            continue
        observed = envelope.counts[scope]
        bindings["/".join(scope)] = [
            {
                "template": TEMPLATE_ID,
                "params": {"allow": actions},
                "observed": {action: observed[action] for action in actions},
            }
        ]
    if not bindings:
        raise ValueError(
            "no scope has {}+ ALLOW receipt(s); lower --min-count or widen the "
            "window".format(min_count))
    return {
        "version": SCOPE_DOC_VERSION,
        "default_scope": [],
        "allow_unscoped": False,
        "bindings": bindings,
    }


def read_document(path: str) -> Dict[str, Any]:
    """Read a scope document, or the signed envelope the sidecar publishes.

    Both spellings exist on disk: a plain document (``{"version", "bindings"}``)
    and the signed envelope (``{"version", "written_at", "policy", "mac"}``)
    whose ``policy`` field holds the canonical JSON of the document. The
    signature is *not* checked here - this module never trusts the file, it only
    compares envelopes - so a caller that needs provenance verifies it with
    :func:`interlock.wire.verify_scope_envelope` before it gets this far. A file
    that is neither shape raises :class:`ValueError`.
    """
    with open(path, "r", encoding="utf-8") as fh:
        loaded = json.load(fh)
    return _document_of(loaded)


def _document_of(loaded: Any) -> Dict[str, Any]:
    if not isinstance(loaded, Mapping):
        raise ValueError("scope document must be a JSON object")
    policy = loaded.get("policy")
    if isinstance(policy, str):
        try:
            loaded = json.loads(policy)
        except ValueError as exc:
            raise ValueError(
                "scope document envelope carries invalid policy JSON: {}".format(exc))
        if not isinstance(loaded, Mapping):
            raise ValueError("scope document envelope's policy must be an object")
    version = loaded.get("version")
    if version != SCOPE_DOC_VERSION:
        raise ValueError("scope document version must be {}, got {!r}".format(
            SCOPE_DOC_VERSION, version))
    bindings = loaded.get("bindings")
    if not isinstance(bindings, Mapping):
        raise ValueError("scope document bindings must be an object")
    return dict(loaded)


def _entries_by_scope(document: Mapping[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    bindings = document.get("bindings") or {}
    out: Dict[str, List[Dict[str, Any]]] = {}
    for key, entries in bindings.items():
        if not isinstance(entries, (list, tuple)):
            raise ValueError("scope {!r} bindings must be a list".format(key))
        clean = []
        for entry in entries:
            if not isinstance(entry, Mapping):
                raise ValueError("scope {!r} binding must be an object".format(key))
            clean.append(dict(entry))
        out[str(key)] = clean
    return out


def _allow_of(entries: Iterable[Mapping[str, Any]]) -> Optional[List[str]]:
    """The ``allow`` list of the capability binding in ``entries``, or None.

    A binding that names the template without an ``allow`` list returns ``[]``,
    not None: the factory defaults to an empty allow set, which permits nothing,
    so a derived binding beside it *would* widen the envelope and must be
    reported as such.
    """
    for entry in entries:
        if entry.get("template") != TEMPLATE_ID:
            continue
        params = entry.get("params") or {}
        allow = params.get("allow") if isinstance(params, Mapping) else None
        if isinstance(allow, (list, tuple)):
            return [str(action) for action in allow]
        return []
    return None


def _existing_allow_at(
    existing: Mapping[str, List[Dict[str, Any]]], scope: Scope
) -> Optional[FrozenSet[str]]:
    """What the existing document already permits at ``scope``, root first.

    ``None`` means the existing document binds no capability template anywhere
    on the path - nothing to widen, so the derived binding is a narrowing from
    "no rule" to "these actions". Otherwise the result is the union of every
    ``allow`` list on the path, which is what the template's override merge
    actually resolves to for a leaf bound deeper than its ancestor.
    """
    found = False
    allowed: FrozenSet[str] = frozenset()
    for i in range(1, len(scope) + 1):
        allow = _allow_of(existing.get("/".join(scope[:i])) or ())
        if allow is None:
            continue
        found = True
        allowed = allowed | frozenset(canonical_action(action) for action in allow)
    return allowed if found else None


def merge(
    derived: Mapping[str, Any],
    existing: Mapping[str, Any],
    *,
    allow_widen: bool = False,
) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """Combine a derived document with an existing one; refuse to widen.

    Every binding the existing document carries is kept verbatim, so a scope the
    window never saw is served exactly as before instead of disappearing (a
    vanished binding is a scope that resolves to no templates, which
    ``ScopedEngine`` refuses - a suggestion must not lock a scope out). Derived
    bindings are added, or folded into an existing one, and every action they
    would grant that the existing envelope at that scope does not permit is
    reported.

    Returns ``(document, problems)``. With problems and ``allow_widen=False``
    the document is ``None``: the caller must look at what changed and opt in.
    With ``allow_widen=True`` the merged document is returned alongside the
    problems, so the widening is still visible in the output the operator ships.
    """
    kept = _entries_by_scope(existing)
    derived_bindings = _entries_by_scope(derived)
    problems: List[str] = []
    merged: Dict[str, List[Dict[str, Any]]] = {}

    for key in sorted(kept):
        entries = []
        for entry in kept[key]:
            entry = dict(entry)
            params = entry.get("params")
            if entry.get("template") == TEMPLATE_ID and isinstance(params, Mapping):
                allow = params.get("allow")
                if isinstance(allow, (list, tuple)):
                    entry["params"] = dict(params)
                    entry["params"]["allow"] = sorted(
                        canonical_action(action) for action in allow)
            entries.append(entry)
        merged[key] = entries

    for key in sorted(derived_bindings):
        scope = principal_path(key)
        derived_allow = _allow_of(derived_bindings[key]) or []
        existing_allow = _existing_allow_at(kept, scope)
        if existing_allow is not None:
            extra = sorted(set(derived_allow) - existing_allow)
            if extra:
                problems.append(
                    "scope {!r} would widen its envelope: {} not allowed by the "
                    "existing document".format(key, ", ".join(extra)))
        folded = False
        for entry in merged.setdefault(key, []):
            if entry.get("template") != TEMPLATE_ID:
                continue
            params = entry.get("params")
            params = dict(params) if isinstance(params, Mapping) else {}
            allow = params.get("allow")
            allow = list(allow) if isinstance(allow, (list, tuple)) else []
            params["allow"] = sorted(set(allow) | set(derived_allow))
            entry["params"] = params
            # Evidence counts are per-window observations, never a running
            # total: an action this window saw carries this window's count, and
            # an action only the existing document recorded keeps the count it
            # already had. Summing the two would invent receipts nobody read,
            # and would change a document merged with itself.
            observed = entry.get("observed")
            observed = dict(observed) if isinstance(observed, Mapping) else {}
            observed.update(_observed_of(derived_bindings[key]))
            if observed:
                entry["observed"] = {action: observed[action] for action in sorted(observed)}
            folded = True
            break
        if not folded:
            merged[key].append(derived_bindings[key][0])

    if problems and not allow_widen:
        return None, problems
    document = {
        "version": SCOPE_DOC_VERSION,
        "default_scope": list(existing.get("default_scope") or []),
        "allow_unscoped": bool(existing.get("allow_unscoped", False)),
        "bindings": merged,
    }
    return document, problems


def _observed_of(entries: Iterable[Mapping[str, Any]]) -> Dict[str, int]:
    """The ``observed`` counts of the capability binding in ``entries``."""
    for entry in entries:
        if entry.get("template") != TEMPLATE_ID:
            continue
        observed = entry.get("observed")
        if isinstance(observed, Mapping):
            return {str(action): int(count) for action, count in observed.items()
                    if isinstance(count, int)}
    return {}


def suggest(
    source: ReceiptSource,
    *,
    since_seconds: Optional[float] = None,
    now: Optional[float] = None,
    min_count: int = 1,
    existing: Optional[Mapping[str, Any]] = None,
    allow_widen: bool = False,
) -> Tuple[Optional[Dict[str, Any]], Envelope, List[str]]:
    """Read receipts and draft a scope document.

    ``source`` is a path to a receipt log - read tolerantly, so a torn tail does
    not lose the rest - or an iterable of already-parsed
    :class:`~interlock.receipt.Receipt`. ``existing`` is a parsed scope document
    (see :func:`read_document`) the draft must not widen.

    Returns ``(document, envelope, problems)``. ``document`` is ``None`` when no
    scoped ``ALLOW`` observation was found, or when the draft would widen the
    existing document and ``allow_widen`` is false. Reading a log that cannot be
    opened raises :class:`OSError`.
    """
    receipts = _read(source)
    envelope = count_receipts(receipts, since_seconds=since_seconds, now=now)
    if envelope.empty:
        return None, envelope, []
    derived = suggested_document(envelope, min_count=min_count)
    if existing is None:
        return derived, envelope, []
    document, problems = merge(derived, existing, allow_widen=allow_widen)
    return document, envelope, problems


def render(document: Mapping[str, Any]) -> str:
    """Serialize a scope document the way every draft in this repo is written."""
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def _read(source: ReceiptSource) -> List[Receipt]:
    if isinstance(source, (str, bytes, os.PathLike)):
        path = os.fspath(source)
        receipts, _ = read_receipts(
            path.decode("utf-8", "replace") if isinstance(path, bytes) else path)
        return receipts
    return list(source)
