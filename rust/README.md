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

## Native policy evaluator (opt-in)

`rust/engine` holds the R31 evaluator, `interlock_engine`: the declarative
policy rule subset compiled to a Rust plan and evaluated without CPython. The
wheel carries a PyO3 front end to it; a separate cdylib serves everything else.
The path is off unless `INTERLOCK_NATIVE=1`.

The plan is all-or-nothing per policy. `interlock/policy/native.py` translates a
policy only when every rule is a plain `when` over `action`/`field`/`arg` with a
built-in operator, or one of the four detectors with a Rust port
(`ansi_escape_output_guard`, `crlf_header_injection_guard`,
`download_extension_guard`, `code_eval_exec_guard`). A detector outside that
set, a parameterised detector, a `modify`, an overlay, a `disable` list, a
shadow rule, or a mesh ceiling keeps the whole policy on the Python engine. That
is what makes the two paths agree by construction. Below
`INTERLOCK_NATIVE_MIN_RULES` rules (default 8) the JSON boundary costs more than
it saves and the planner declines.

The crate on its own needs no Python:

```bash
cargo test --manifest-path rust/engine/Cargo.toml
```

Two front ends share `Plan::evaluate`:

- **PyO3:** `interlock_scopes.NativePlan(plan_json).evaluate(event_json)` returns
  `(verdict, policy_id, reason, attributed_to)`; `interlock_scopes.ENGINE_ABI`
  is the schema version.
- **C ABI:** `il_eval_plan(...)` and `il_abi_version()` in `rust/ffi` (crate
  `interlock_engine_ffi`), for a Node, Go, Rust or C host. It is a separate
  cdylib because the PyO3 extension is built with `extension-module` and
  deliberately leaves CPython symbols unresolved, so a non-Python `dlopen` of
  the wheel fails. The call is string-in, buffer-out: `0` means success and
  writes a NUL-terminated policy id and reason into caller buffers; `-1` means
  any error and writes nothing, so a caller must fail closed.

The C path has a genuinely non-Python caller in-tree: `rust/abi-smoke/smoke.c`
`dlopen`s the library and checks a block, an allow and a fail-closed error.
Build and run it with only cargo and the system C compiler:

```bash
bash scripts/check_native_abi.sh
```

`tests/test_native_engine.py` runs both engines over the same events and
compares verdict, `policy_id`, `reason`, and `attributed_to`, including the
ported detectors and the false-positive corpus. Its ctypes check uses the FFI
library when present and skips otherwise; the C smoke is the authoritative
non-Python check. Both skip when the module is absent.

## Notes

- Built with PyO3 0.24 against the stable ABI (`abi3-py39`), so one build loads
  on CPython 3.9 and newer.
- Common parameter values (str, int, bool, float, list) are stored in a compact
  form. Anything else is kept as the original Python object, so results never
  depend on the fast path.
- `rust/**/target/` and `*.so` are git-ignored. `maturin develop` is the
  supported way to build the Python extension; `cargo build` builds the FFI
  library.

See the [scopes guide](../docs/guides/scopes.md) for how scopes work.
