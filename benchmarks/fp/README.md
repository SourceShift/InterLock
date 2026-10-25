# Benign-traffic corpus and the default pack's false-positive rate

`benign.jsonl` is 70 ordinary coding-agent calls: file reads and edits, the git
commands a session runs every hour, test/lint/build invocations and their
results, a few searches and fetches, and two MCP tools. No event in it should
ever be refused or questioned by `builtin:coding-agent`.

It is the reference point the [security model](../../docs/security-model.md)
promised: a number for "how often is the guard wrong on traffic that is fine".

## Measure it

```bash
python3 scripts/fp_baseline.py               # human-readable
python3 scripts/fp_baseline.py --json        # for tooling
python3 scripts/fp_baseline.py --repeats 20  # steadier latency percentiles
```

The pack is built at run time by `interlock.policy.packs.builtin_pack()`, not
read from a committed JSON: `coding_agent()` embeds the current user's home
directory in its protected paths, so a static document would either be wrong on
another machine or leak one developer's home path into the repository.

`tests/test_fp_baseline.py` runs the same measurement in the normal suite, so
the gate below is enforced by CI with every other test rather than by a
separate job.

## Result — 2026-10-25

| | |
|---|---|
| Corpus | 70 events (67 call-phase, 3 result-phase) |
| Evaluated | 210 (3 passes) |
| **False positives** | **0 — 0.0000%** |
| Rules that fired | none |
| Quarantined rules | none |
| Latency p50 / p95 / max | 0.6 ms / 1.0 ms / 1.3 ms |

Gate: `DEFAULT_MAX_FP_RATE = 0.001` (0.1%) and `DEFAULT_MAX_P95_US = 5000`
(5 ms) from `interlock/mesh/harness.py`. Measured on macOS 24.4, CPython 3.9,
one thread, warm process.

Latency is dominated by `Bash` events, but the command is now parsed once per
event: the engine opens an analysis memo keyed on `(command, cwd)` for the
duration of `evaluate()`, so the ~12 rules that ask about an intent share one
parse. Before the memo the same corpus measured 1.26 ms p50 for `Bash`; the
rest of the cost is the rules themselves, each matching its selectors against
the analyzed intents.

| Action | p50 |
|---|---|
| `Bash` | 0.67 ms |
| `NotebookEdit` / `MultiEdit` | 0.05–0.06 ms |
| `Write` / `Edit` | 0.05 ms |
| `Read` / `Grep` / `Glob` | 0.04–0.05 ms |
| `WebFetch` / `WebSearch` / MCP | 0.03 ms |

In a hook the process start dominates this cost; it matters only to callers
that run the engine in-process for every call.

## What this number does and does not say

- It says the **default pack** does not fire on the traffic recorded here on
  this machine. It is a regression gate, not a claim about all deployments:
  your traffic, your tools and your home layout may differ.
- One benign event in 70 would put the rate at 1.4%, far above the 0.1%
  budget — that is why the test asserts zero rather than the gate's ceiling.
- It does not measure **recall**. The corpus has no attacks; `interlock mesh
  harness --samples` is the tool for that, and the detector catalog's samples
  are the usual input.

## Adding to the corpus

Add one JSON object per line: `{"action": ..., "args": {...}, "phase":
"call"}`. Keep it to traffic you would be happy to see the agent run
unattended — a call that *should* escalate does not belong here. Then run the
script: a new false positive is either a corpus mistake or a policy bug, and
the failure output names the rule and the event count.
