# interlock_scopes: optional native scope store

A Rust reimplementation of one class, `ScopeTree`: the store that holds
interlock's [policy scopes](../docs/guides/scopes.md) (the per-tenant, per-agent
bindings). It's the only part of interlock whose memory grows with the number of
subjects, so it's the only part with a native version.

**You probably don't need it.** interlock ships a pure-Python `ScopeTree` that
needs no compiler. Build this crate when you bind policy to a very large number
of scopes (hundreds of thousands to millions) and the memory of the scope tree
matters. It stores each node with interned ids and packed values, which cuts the
per-node cost by roughly an order of magnitude, and it only creates Python
objects for the one scope being resolved on a cache miss.

It doesn't change how fast a cached lookup is. Resolved rules are cached above
the tree by `ScopeRegistry` either way, and the rule engine, the cache, and all
105 detectors behave the same with either backend.

## Build

```bash
pip install maturin
cd rust
maturin develop --release    # builds interlock_scopes and installs it into the active environment
```

## Check it's being used

interlock picks the native tree automatically whenever `interlock_scopes` can be
imported:

```bash
python -c "from interlock.policy import SCOPE_BACKEND; print(SCOPE_BACKEND)"
# rust
```

> **Note:** if the native module fails to import for any reason (not built, or
> built for a different Python), interlock quietly falls back to the Python tree
> and `SCOPE_BACKEND` prints `python`. Check it after every build.

> **Note:** a stale `interlock_scopes*.so` left at the repository root by an
> older build is found before the freshly installed one when you run Python from
> the root. Your new build then seems to have no effect, and tests can fail in
> confusing ways. `*.so` files are git-ignored, so `git status` won't show them.
> Run `ls *.so` at the root and delete any you find.

## Verify the two backends agree

The scope tests run against whichever backend is active:

```bash
pytest tests/test_scopes.py tests/test_scope_backend.py -q
```

`tests/test_scope_backend.py` also runs the Python and Rust trees side by side
and checks that every `resolve()` returns the same result. The Python tree is the
reference.

To compare memory and lookup time, run `python benchmarks/scope_memory.py` once
without the module and once with it.

## Notes

- Built with PyO3 0.24 against the stable ABI (`abi3-py39`), so one build loads
  on CPython 3.9 and newer.
- Common parameter values (str, int, bool, float, list) are stored in a compact
  form. Anything else is kept as the original Python object, so results never
  depend on the fast path.
- `rust/target/` and `*.so` are git-ignored. `maturin develop` is the supported
  way to build.

See the [scopes guide](../docs/guides/scopes.md) for how scopes work.
