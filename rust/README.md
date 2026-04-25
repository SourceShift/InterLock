# interlock_scopes (optional native accelerator)

Native storage backend for interlock's hierarchical policy scopes. It
reimplements one class, `ScopeTree`, the sparse per-node binding store that is
the only part whose memory grows with subject count. Interned segment ids and a
packed value representation cut the per-node cost by roughly an order of
magnitude, and Python objects are materialized only for the one resolved leaf on
a cache miss.

interlock does **not** require this crate. `pip install interlock-guard` ships a
pure-Python `ScopeTree` that needs no toolchain. When this module is importable,
`interlock.policy.scopes` rebinds `ScopeTree` to it automatically and
`SCOPE_BACKEND == "rust"`; otherwise `SCOPE_BACKEND == "python"`. The
`evaluate(event) -> Decision` seam, the `ScopeRegistry` cache, and all 96
detectors are identical either way.

## Build

```bash
pip install maturin
cd rust
maturin develop --release      # builds and installs `interlock_scopes` into the active venv
```

Then confirm the backend switched:

```bash
python -c "from interlock.policy import SCOPE_BACKEND; print(SCOPE_BACKEND)"   # -> rust
```

## Verify parity

The scope test suite exercises whichever backend is active, so with the module
built:

```bash
pytest tests/test_scopes.py tests/test_scope_backend.py -q
```

`tests/test_scope_backend.py` additionally runs the pure-Python tree and the
native tree side by side and asserts identical `resolve()` output.

## Notes

- Targets PyO3 0.24 with the stable ABI (`abi3-py39`): one wheel loads on
  CPython 3.9+.
- Param values are kept in a compact enum for the common cases (str, int, bool,
  float, list). Exotic types fall back to holding the original Python object, so
  correctness never depends on the fast representation.
