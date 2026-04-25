"""Hierarchical policy scopes: few templates, millions of scopes.

The policy engine (``interlock.policy.engine``) evaluates an ordered list of
rules for a single subject. This module answers a different question: when the
same small set of policy *templates* must apply to millions of distinct
subjects (agents, tenants, sessions) with per-subject overrides, how do you
keep the per-request cost flat as the subject count grows?

The model separates code from data:

* A **template** is code: a factory that turns parameters into a ``Rule``.
  There are only a handful, and they are fixed. ``egress_allowlist`` is a
  template; the specific hosts it allows are not.
* A **binding** is data: ``(template_id, params, enabled)`` attached to a node.
* A **scope** is a path in a tree, e.g. ``("root", "acme", "agent42")``.

The effective policy for a leaf scope is computed by walking root -> leaf and
merging bindings per ``template_id``. Three merge rules compose:

* **override** — a more specific binding replaces an inherited param.
* **union** — params a template marks as ``union_params`` accumulate up the
  chain (allowlists grow, they do not overwrite).
* **tombstone** — ``enabled=False`` removes an inherited binding for that
  template, unless a still-deeper node re-adds it.

Cost model: resolution walks a single root->leaf path once, compiles a
``PolicyEngine``, and caches it keyed by a per-node version tuple. The other
scopes are never touched. So scope count is a storage and lookup problem, not a
per-request compute problem: warm cost stays flat from ten scopes to a million,
while memory grows with the number of bound nodes. Editing an ancestor bumps
its version, which invalidates only the descendants that inherit from it, and
they recompile lazily on next use.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, List, Mapping, Optional, Tuple

from ..enforce import Decision
from ..event import SensorEvent
from .engine import PolicyEngine, Rule

Scope = Tuple[str, ...]
RuleFactory = Callable[..., Rule]


@dataclass(frozen=True)
class Template:
    """Code: a named rule factory plus the params that union up the hierarchy.

    ``union_params`` names the parameters that accumulate as set-union when a
    deeper binding declares them (allowlists, keyword lists). Every other param
    is override: the more specific binding wins.
    """

    template_id: str
    factory: RuleFactory
    union_params: FrozenSet[str] = frozenset()


@dataclass(frozen=True)
class Binding:
    """Data: attach a template to a scope node with concrete params.

    ``enabled=False`` is a tombstone: it removes the inherited binding for this
    template at and below this node, until a deeper node re-binds it.
    """

    template_id: str
    params: Mapping[str, Any] = field(default_factory=dict)
    enabled: bool = True


class PyScopeTree:
    """Sparse store of bindings by scope path, with per-node versions.

    Only nodes that carry bindings exist. Millions of leaves are fine because
    unbound intermediate nodes cost nothing: resolution reads whatever bindings
    happen to sit on the prefixes of a leaf's path and skips the rest.

    This is the pure-Python reference backend. It is always importable and needs
    no toolchain. When the optional native crate ``interlock_scopes`` is built
    and installed, ``ScopeTree`` below is rebound to it and this class stays
    available as the fallback and as the parity oracle in tests.
    """

    def __init__(self) -> None:
        self._bindings: Dict[Scope, List[Binding]] = {}
        self._version: Dict[Scope, int] = {}

    def bind(self, path: Scope, bindings: List[Binding]) -> None:
        """Set (replace) the bindings on ``path`` and bump its version."""
        self._bindings[path] = list(bindings)
        self._version[path] = self._version.get(path, 0) + 1

    def bindings_at(self, path: Scope) -> Tuple[Binding, ...]:
        return tuple(self._bindings.get(path, ()))

    def path_versions(self, leaf: Scope) -> Tuple[int, ...]:
        """Version of every node on the root->leaf path (0 for unbound nodes).

        This tuple is the cache key's freshness stamp: if any ancestor's version
        changed since a leaf was compiled, the tuples differ and the cache misses.
        """
        return tuple(self._version.get(leaf[:i], 0) for i in range(1, len(leaf) + 1))

    def resolve(
        self, leaf: Scope, union_lookup: Callable[[str], FrozenSet[str]]
    ) -> Dict[str, Dict[str, Any]]:
        """Walk root->leaf, merge per template_id, return effective params.

        ``union_lookup(template_id)`` supplies the set of params that union
        instead of override. It is passed in rather than stored on the tree so
        the tree holds only data, not references to factory objects.
        """
        eff: Dict[str, Optional[Dict[str, Any]]] = {}
        for i in range(1, len(leaf) + 1):
            for b in self._bindings.get(leaf[:i], ()):  # root-first
                if not b.enabled:
                    eff[b.template_id] = None  # tombstone; a deeper bind re-adds
                    continue
                cur = eff.get(b.template_id)
                if not isinstance(cur, dict):
                    eff[b.template_id] = dict(b.params)
                    continue
                merged = dict(cur)
                union = union_lookup(b.template_id)
                for k, v in b.params.items():
                    if k in union and isinstance(v, (set, list, frozenset, tuple)):
                        merged[k] = set(merged.get(k, ())) | set(v)
                    else:
                        merged[k] = v
                eff[b.template_id] = merged
        return {t: p for t, p in eff.items() if isinstance(p, dict)}


# --- backend selection -------------------------------------------------------
# The storage layer is the one place memory scales with subject count: millions
# of bound nodes mean millions of Python tuples, dicts, and Binding instances,
# each paying Python's per-object header tax. The optional native crate
# ``interlock_scopes`` reimplements exactly this class (interned segment ids,
# packed nodes, params as a compact value enum) and materializes Python objects
# only for the one resolved leaf on a cache miss. Everything above the tree, the
# ``ScopeRegistry`` cache and the ``ScopedEngine`` dispatch and the
# ``evaluate(event) -> Decision`` seam, is unchanged: the native tree satisfies
# the same ``bind`` / ``path_versions`` / ``resolve`` surface.
try:
    from interlock_scopes import ScopeTree as _NativeScopeTree  # type: ignore[import-not-found]
except Exception:  # not built, or build/ABI mismatch: fall back to pure Python
    _NativeScopeTree = None

if _NativeScopeTree is not None:
    ScopeTree = _NativeScopeTree
    SCOPE_BACKEND = "rust"
else:
    ScopeTree = PyScopeTree
    SCOPE_BACKEND = "python"


class ScopeRegistry:
    """Compile a leaf's effective policy into a ``PolicyEngine`` once, cache it,
    and recompile only when a node on its path changes version.

    The cache is a bounded LRU. Its key is the leaf scope; its stored value is
    ``(path_versions, engine)``. A hit requires both that the leaf is present and
    that its stored version tuple still matches the tree, so an ancestor edit
    transparently forces a recompile without walking the tree eagerly.
    """

    def __init__(
        self,
        tree: PyScopeTree,  # or the duck-compatible native interlock_scopes.ScopeTree
        templates: Mapping[str, Template],
        *,
        maxsize: int = 10000,
    ) -> None:
        self.tree = tree
        self.templates = dict(templates)
        self.maxsize = maxsize
        self._cache: "OrderedDict[Scope, Tuple[Tuple[int, ...], PolicyEngine]]" = (
            OrderedDict()
        )
        self.hits = 0
        self.misses = 0

    def _union_lookup(self, template_id: str) -> FrozenSet[str]:
        tmpl = self.templates.get(template_id)
        return tmpl.union_params if tmpl is not None else frozenset()

    def resolve(self, leaf: Scope) -> Dict[str, Dict[str, Any]]:
        """Effective params per template for a leaf, ignoring unknown templates."""
        resolved = self.tree.resolve(leaf, self._union_lookup)
        return {t: p for t, p in resolved.items() if t in self.templates}

    def compile(self, leaf: Scope) -> PolicyEngine:
        """Build a fresh engine for a leaf (cache miss path, also public)."""
        rules = [
            self.templates[t].factory(**p) for t, p in self.resolve(leaf).items()
        ]
        return PolicyEngine(rules=rules)

    def for_scope(self, leaf: Scope) -> PolicyEngine:
        """Return the compiled engine for a leaf, from cache when still fresh."""
        pv = self.tree.path_versions(leaf)
        hit = self._cache.get(leaf)
        if hit is not None and hit[0] == pv:
            self.hits += 1
            self._cache.move_to_end(leaf)
            return hit[1]
        self.misses += 1
        eng = self.compile(leaf)
        self._cache[leaf] = (pv, eng)
        self._cache.move_to_end(leaf)
        if len(self._cache) > self.maxsize:
            self._cache.popitem(last=False)
        return eng

    def invalidate(self, leaf: Scope) -> None:
        """Drop a leaf's cached engine. Rarely needed: version bumps already
        invalidate lazily. Useful to reclaim a slot without waiting for LRU."""
        self._cache.pop(leaf, None)


def principal_scope(event: SensorEvent) -> Scope:
    """Default scope deriver: split the principal on '/' into a path.

    A principal of ``"acme/payments/agent42"`` becomes the scope
    ``("acme", "payments", "agent42")``. No principal yields the empty scope.
    Supply your own deriver to key on tenant, span, or anything else.
    """
    p = event.principal
    if not p:
        return ()
    return tuple(part for part in p.split("/") if part)


class ScopedEngine:
    """Resolve per-subject policy at call time, then delegate to that engine.

    The guard runtime calls ``get_engine().evaluate(event)`` once per action. A
    plain ``PolicyEngine`` applies one rule set to every subject. ``ScopedEngine``
    instead derives a scope from each event (by default from ``event.principal``),
    asks a ``ScopeRegistry`` for that scope's compiled engine, and delegates. One
    small set of templates then covers many subjects, each with its own resolved
    policy, and the per-call overhead is a cache lookup plus the normal evaluate.

    It satisfies the same ``evaluate(event) -> Decision`` contract as
    ``PolicyEngine``, so ``interlock.install(engine=ScopedEngine(registry))``
    wires the whole hierarchy in with no change to ``@guard``.

    ``scope_of`` maps an event to a scope path. ``default_scope`` is used when
    ``scope_of`` returns an empty path (an unknown subject); leave it empty to
    allow such calls, or point it at a baseline node to apply a floor policy.
    """

    def __init__(
        self,
        registry: ScopeRegistry,
        scope_of: Optional[Callable[[SensorEvent], Scope]] = None,
        *,
        default_scope: Scope = (),
    ) -> None:
        self.registry = registry
        self.scope_of = scope_of or principal_scope
        self.default_scope = tuple(default_scope)

    def evaluate(self, event: SensorEvent) -> Decision:
        scope = self.scope_of(event) or self.default_scope
        if not scope:
            return Decision.allow()  # no scope, no policy: allow, like an empty engine
        return self.registry.for_scope(scope).evaluate(event)
