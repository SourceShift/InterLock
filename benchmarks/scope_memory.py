"""Measure the scope storage axis: RSS and warm resolve latency as the number
of bound scopes grows, for whichever backend is active.

Run it twice to compare backends:

    python benchmarks/scope_memory.py                 # pure-Python tree
    cd rust && maturin develop --release && cd ..
    python benchmarks/scope_memory.py                 # native tree

The tree it builds is the memory-heavy part; the compiled-engine LRU is bounded
and is not what grows. So the delta between the two runs is almost entirely the
native tree paying Rust-struct cost instead of Python-object cost.
"""
import os
import resource
import sys
import time

from interlock.policy import SCOPE_BACKEND, Binding, ScopeRegistry, ScopeTree, Template
from interlock.event import SensorEvent


def _noop(**_kw):
    def rule(_e: SensorEvent):
        return None

    return rule


TEMPLATES = {
    "egress_allowlist": Template("egress_allowlist", _noop, frozenset({"allowed_hosts"})),
    "rate_limiter": Template("rate_limiter", _noop),
}


def _rss_mb() -> float:
    kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # macOS reports bytes, Linux reports kilobytes
    return kb / (1024 * 1024) if sys.platform == "darwin" else kb / 1024


def build(n_leaves: int) -> ScopeRegistry:
    tree = ScopeTree()
    tree.bind(("root",), [Binding("egress_allowlist", {"allowed_hosts": ["api.internal"]})])
    for org in range(n_leaves // 100 or 1):
        tree.bind(
            ("root", "org%d" % org),
            [Binding("egress_allowlist", {"allowed_hosts": ["org%d.example" % org]})],
        )
        for agent in range(100):
            tree.bind(
                ("root", "org%d" % org, "agent%d" % agent),
                [
                    Binding("egress_allowlist", {"allowed_hosts": ["a%d.local" % agent]}),
                    Binding("rate_limiter", {"limit": agent % 7 + 1}),
                ],
            )
    return ScopeRegistry(tree, TEMPLATES, maxsize=4096)


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 100_000
    base = _rss_mb()
    reg = build(n)
    built = _rss_mb()

    # warm one leaf, then time repeated warm resolves (cache hits + evaluate)
    leaf = ("root", "org0", "agent0")
    reg.for_scope(leaf)
    iters = 50_000
    t0 = time.perf_counter()
    for _ in range(iters):
        reg.for_scope(leaf)
    warm_us = (time.perf_counter() - t0) / iters * 1e6

    print("backend           :", SCOPE_BACKEND)
    print("pid               :", os.getpid())
    print("bound scopes       : ~%d" % n)
    print("RSS after build   : %.1f MB (delta %.1f MB)" % (built, built - base))
    print("warm for_scope    : %.3f us/call" % warm_us)


if __name__ == "__main__":
    main()
