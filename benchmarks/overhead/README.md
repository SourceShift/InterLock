# What the guard costs per decision

`scripts/bench_overhead.py` measures the one number an operator evaluating a
request-path guard actually needs: **how much time does installing the default
policy add to a call that would have happened anyway?**

It is a difference, not a standalone throughput figure. The same corpus is run
twice - once through a `PolicyEngine` with no rules (the floor: the event loop
and nothing else) and once through `builtin:coding-agent` (what a hook
installs) - and the result is the guarded median minus the floor median, per
action and overall.

## Methodology

| | |
|---|---|
| Input | `benchmarks/fp/benign.jsonl`, 70 ordinary coding-agent events |
| Procedure | one untimed warm-up pass, then `--repeats` timed passes (default 20) |
| Samples | 1,400 event decisions per engine |
| Timing | `time.perf_counter()` around one `engine.evaluate(event)`; whole microseconds |
| Percentile | nearest-rank over the sorted samples, via the same `_percentile` the false-positive harness uses |
| Machine | macOS 24.4 (Darwin), CPython 3.9, one thread, warm process |
| Excluded | process start, hook-adapter parsing, receipt I/O, sidecar RPC, filesystem effects |

The floor and the guarded run are separate passes. Overhead is therefore a
difference of percentiles, not a paired per-event difference; at these
magnitudes the distinction is below run-to-run noise.

## Reproduce

```bash
python3 scripts/bench_overhead.py                    # table + gate
python3 scripts/bench_overhead.py --json             # machine-readable
python3 scripts/bench_overhead.py --repeats 50       # steadier tail
```

## Result - 2026-10-25

| | Floor | Guarded | Added |
|---|---|---|---|
| p50 | 2 µs | 243 µs | **241 µs** |
| p95 | 2 µs | 392 µs | **390 µs** |
| p99 | 3 µs | 445 µs | **442 µs** |

| Action | Floor p50 | Guarded p50 | Guarded p95 | Added p50 |
|---|---:|---:|---:|---:|
| `Bash` | 2 µs | 285 µs | 402 µs | 283 µs |
| `NotebookEdit` / `MultiEdit` | 2 µs | 53-56 µs | 58-74 µs | 51-54 µs |
| `Write` / `Edit` | 2 µs | 46-47 µs | 50-58 µs | 44-45 µs |
| `Read` / `Glob` / `Grep` | 2 µs | 42-43 µs | 46-49 µs | 40-41 µs |
| `WebFetch` / `WebSearch` / MCP | 2 µs | 29-37 µs | 32-42 µs | 27-35 µs |

`Bash` costs more because it is the only action whose policy asks about parsed
intent, and the default pack has a dozen such rules. The 2 µs floor is timer
resolution, not work: the empty engine only walks the rule list. That is why
the measured floor-to-guard ratio is reported as `n/a` - a ratio against a
quantisation error would be noise (see `MIN_RATIO_FLOOR_US`).

This run is after two changes that share work inside one decision:

- the shell parser is memoised per event (`memoized_parse`), so the ~12 intent
  rules and every detector that reads the command text parse it once;
- intent path checks reject a word cheaply unless it can spell `interlock`, a
  brace/glob, or a base that is already inside it.

Before those, the same corpus measured 0.61 ms p50 / 1.19 ms p95; after the
intent memo alone it was 0.24 ms p50 here, with `Bash` at 0.29 ms.

## Native comparison

`--no-native` turns this section off; without it the script also runs
`benchmarks/overhead/native-policy.json` through the Python engine and the
native plan evaluator (`INTERLOCK_NATIVE=1`, see the Rust README). The default
`coding-agent` pack cannot be compared this way: its parameterised detectors and
rewrites keep every policy containing them on Python, by design, so the
comparison needs a policy the planner can translate whole.

The native policy has twelve rules - plain conditions over `command`,
`file_path`, `limit` and `owner`, and all four ported detectors (one of them
`on`-scoped to `WebFetch`). The plan is compiled once, outside the timed passes;
each sample includes the JSON event payload the PyO3 boundary needs. The
Python baseline is loaded with `INTERLOCK_NATIVE` forced off, so an ambient
`INTERLOCK_NATIVE=1` cannot turn the comparison into native-vs-native.

| | Python | Native | Speed-up |
|---|---:|---:|---:|
| p50 | 43 µs | 16 µs | **2.7x** |
| p95 | 176 µs | 43 µs | 4.1x |
| p99 | 432 µs | 80 µs | 5.4x |

Per action, p50: `Bash` 43 → 16 µs, `Read` 40 → 14 µs, `WebFetch` 51 → 18 µs,
`Grep` 37 → 15 µs; the full table is the script's second block. These are one
warm machine (macOS 24.4, CPython 3.9, 2026-10-26); absolute values move with
load, the ratio is the within-run comparison that means something. A missing
`interlock_scopes` module or an ineligible policy prints `native: skipped (...)`
and leaves the gate untouched.

The comparison is reported, never gated: it answers "what does the opt-in fast
path save", while the gate answers "did the policy get slower". Keeping them
separate means a slow CI runner cannot fail the build on a ratio between two
numbers it did not control.

## The gate

`scripts/bench_overhead.py` exits non-zero when:

| Bound | Default | Catches |
|---|---|---|
| guarded p95 | 5,000 µs (`DEFAULT_MAX_P95_US`) | a policy that became slow on ordinary traffic |
| added p95 | 5,000 µs (`DEFAULT_MAX_OVERHEAD_US`) | the same, stated as overhead |
| guarded / floor p50 | 500x (`DEFAULT_MAX_RATIO`), only if the floor is at least 5 µs | a harness that stopped measuring a real floor |

The bounds are regression alarms, not hardware budgets. A shared CI runner can
be several times slower; the suite's own checks widen the bound for exactly
that reason.

## What this does and does not say

- It says the default pack decides a benign event in a fraction of a
  millisecond **in process**. In a hook, process startup (tens of milliseconds
  for a Python interpreter) dominates; this number matters to long-lived
  callers such as the sidecar and the SDK's `@guard` decorator.
- It does not measure a guard installed *and* block-heavy traffic: the corpus
  has no attacks and the harness is deliberately allow-heavy, because that is
  the common case. A MODIFY or BLOCK path adds the rewrite/decision work, and
  `benchmarks/fp/README.md` measures the destructive and pathological cases
  separately.
- It does not measure memory, throughput under concurrency, or the sidecar
  round trip (R13's JS smoke number covers that, with its own caveat).
- Micro-benchmarks overstate a detector measured alone and understate the
  composed policy; the per-rule table in `benchmarks/fp/README.md` shows both.
