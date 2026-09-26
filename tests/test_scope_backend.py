"""The storage backend is pluggable: a pure-Python reference tree, or the
optional native `interlock_scopes` crate when it is built. Both must resolve
identically. These tests pin that contract so the accelerator can never drift
from the reference semantics.
"""
from typing import Optional

import pytest

from interlock import Decision
from interlock.event import SensorEvent
from interlock.policy import (
    SCOPE_BACKEND,
    Binding,
    PyScopeTree,
    ScopeRegistry,
    ScopeTree,
    Template,
)
from interlock.policy.scopes import (
    DelegationDepthExceeded,
    DelegationOverGrant,
)

try:
    from interlock_scopes import ScopeTree as NativeScopeTree  # type: ignore
except Exception:
    NativeScopeTree = None


# --- local templates, same shapes the real detectors use --------------------
def egress_allowlist(allowed_hosts):
    hosts = frozenset(allowed_hosts)

    def rule(e: SensorEvent) -> Optional[Decision]:
        if e.action in ("http_post", "fetch"):
            host = e.args.get("host") or ""
            if host and host not in hosts:
                return Decision.block("egress " + host, "egress_allowlist")
        return None

    return rule


def rate_limiter(limit: int):
    def rule(_e: SensorEvent) -> Optional[Decision]:
        return None

    return rule


def keyword_block(words):
    def rule(_e: SensorEvent) -> Optional[Decision]:
        return None

    return rule


TEMPLATES = {
    "egress_allowlist": Template(
        "egress_allowlist", egress_allowlist, frozenset({"allowed_hosts"})
    ),
    "rate_limiter": Template("rate_limiter", rate_limiter),
    "keyword_block": Template("keyword_block", keyword_block, frozenset({"words"})),
}


def _seed(tree):
    tree.bind(
        ("root",),
        [
            Binding("keyword_block", {"words": ["ignore previous"]}),
            Binding("egress_allowlist", {"allowed_hosts": ["api.internal"]}),
        ],
    )
    tree.bind(
        ("root", "acme"),
        [
            Binding("egress_allowlist", {"allowed_hosts": ["acme.example"]}),
            Binding("rate_limiter", {"limit": 5}),
        ],
    )
    tree.bind(
        ("root", "acme", "agent42"),
        [
            Binding("egress_allowlist", {"allowed_hosts": ["agent42.local"]}),
            Binding("rate_limiter", {"limit": 2}),
        ],
    )
    # a tombstone that a deeper node does NOT rebind
    tree.bind(
        ("root", "acme", "agent99"),
        [Binding("keyword_block", {}, enabled=False)],
    )
    return tree


def _norm(resolved):
    """Normalize resolve() output so union-list order does not matter."""
    out = {}
    for tid, params in resolved.items():
        np = {}
        for k, v in params.items():
            np[k] = set(v) if isinstance(v, (list, tuple, set, frozenset)) else v
        out[tid] = np
    return out


def test_backend_is_reported():
    assert SCOPE_BACKEND in {"python", "rust"}
    if SCOPE_BACKEND == "python":
        assert ScopeTree is PyScopeTree


def test_active_backend_resolves():
    reg = ScopeRegistry(_seed(ScopeTree()), TEMPLATES)
    eff = reg.resolve(("root", "acme", "agent42"))
    assert set(eff["egress_allowlist"]["allowed_hosts"]) == {
        "api.internal",
        "acme.example",
        "agent42.local",
    }
    assert eff["rate_limiter"]["limit"] == 2
    assert set(eff["keyword_block"]["words"]) == {"ignore previous"}


@pytest.mark.skipif(NativeScopeTree is None, reason="native interlock_scopes not built")
@pytest.mark.parametrize(
    "leaf",
    [
        ("root",),
        ("root", "acme"),
        ("root", "acme", "agent42"),
        ("root", "acme", "agent99"),  # tombstone path
        ("root", "unknown"),  # unbound leaf
    ],
)
def test_native_matches_python(leaf):
    py_reg = ScopeRegistry(_seed(PyScopeTree()), TEMPLATES)
    rs_reg = ScopeRegistry(_seed(NativeScopeTree()), TEMPLATES)
    assert _norm(py_reg.resolve(leaf)) == _norm(rs_reg.resolve(leaf))


@pytest.mark.skipif(NativeScopeTree is None, reason="native interlock_scopes not built")
def test_native_path_versions_invalidate():
    tree = _seed(NativeScopeTree())
    reg = ScopeRegistry(tree, TEMPLATES)
    leaf = ("root", "acme", "agent42")
    e1 = reg.for_scope(leaf)
    assert reg.for_scope(leaf) is e1  # warm cache hit
    tree.bind(("root", "acme"), [Binding("rate_limiter", {"limit": 9})])
    assert reg.for_scope(leaf) is not e1  # ancestor bump forces recompile


# --- delegated-binding parity ----------------------------------------------
# A native tree that drops `Binding.delegated_from` would still pass every
# resolve-time parity test above (delegated_from is irrelevant when the
# registry never checks it), so without this section the "native carries
# the field" claim would be unverified. The cases below exercise BOTH the
# round-trip through `bindings_at` (so the field survives bind → bindings_at)
# AND the resolve-time over-grant check on both backends.

def _delegated_seed(tree):
    """A tree where the leaf grants more than its delegator allows.

    Root grants ``egress_allowlist`` for ``["api.internal"]``. The
    ``("acme",)`` node re-binds it for ``["acme.example"]`` (a sibling of
    the leaf under root). The leaf ``("acme", "payments", "agent42")``
    claims ``["acme.example", "extra.example"]`` while declaring
    ``delegated_from=("acme", "payments")``, which only resolves to
    ``["acme.example"]`` — so the leaf over-grants.
    """
    tree.bind(
        ("root",),
        [Binding("egress_allowlist", {"allowed_hosts": ["api.internal"]})],
    )
    tree.bind(
        ("acme", "payments"),
        [Binding("egress_allowlist", {"allowed_hosts": ["acme.example"]})],
    )
    tree.bind(
        ("acme", "payments", "agent42"),
        [
            Binding(
                "egress_allowlist",
                {"allowed_hosts": ["acme.example", "extra.example"]},
                delegated_from=("acme", "payments"),
            )
        ],
    )
    return tree


@pytest.mark.skipif(NativeScopeTree is None, reason="native interlock_scopes not built")
def test_native_bindings_at_round_trip_delegated_from():
    """`bindings_at` on the native tree must reconstruct `delegated_from`."""
    py_tree = _delegated_seed(PyScopeTree())
    rs_tree = _delegated_seed(NativeScopeTree())
    py_bs = py_tree.bindings_at(("acme", "payments", "agent42"))
    rs_bs = rs_tree.bindings_at(("acme", "payments", "agent42"))
    assert len(py_bs) == len(rs_bs) == 1
    assert py_bs[0].template_id == rs_bs[0].template_id == "egress_allowlist"
    assert py_bs[0].delegated_from == rs_bs[0].delegated_from == ("acme", "payments")
    # And a non-delegated binding on the same tree stays None on both sides.
    py_root = py_tree.bindings_at(("root",))
    rs_root = rs_tree.bindings_at(("root",))
    assert py_root[0].delegated_from is None
    assert rs_root[0].delegated_from is None


@pytest.mark.skipif(NativeScopeTree is None, reason="native interlock_scopes not built")
def test_native_overgrant_parity():
    """The over-grant must raise on both backends, with the same kind."""
    py_reg = ScopeRegistry(_delegated_seed(PyScopeTree()), TEMPLATES)
    rs_reg = ScopeRegistry(_delegated_seed(NativeScopeTree()), TEMPLATES)
    leaf = ("acme", "payments", "agent42")
    with pytest.raises(DelegationOverGrant):
        py_reg.resolve(leaf)
    with pytest.raises(DelegationOverGrant):
        rs_reg.resolve(leaf)


@pytest.mark.skipif(NativeScopeTree is None, reason="native interlock_scopes not built")
def test_native_non_delegated_unaffected():
    """A binding without `delegated_from` resolves identically on both backends."""
    t = ScopeTree()
    t.bind(
        ("root",),
        [Binding("egress_allowlist", {"allowed_hosts": ["a.example"]})],
    )
    t.bind(
        ("root", "leaf"),
        [Binding("egress_allowlist", {"allowed_hosts": ["b.example"]})],
    )
    rs_t = NativeScopeTree()
    rs_t.bind(("root",), [Binding("egress_allowlist", {"allowed_hosts": ["a.example"]})])
    rs_t.bind(("root", "leaf"), [Binding("egress_allowlist", {"allowed_hosts": ["b.example"]})])
    py_reg = ScopeRegistry(t, TEMPLATES)
    rs_reg = ScopeRegistry(rs_t, TEMPLATES)
    assert _norm(py_reg.resolve(("root", "leaf"))) == _norm(rs_reg.resolve(("root", "leaf")))
