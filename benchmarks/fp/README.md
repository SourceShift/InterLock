# Benign-traffic corpus and the default pack's false-positive rate

Two corpora of ordinary coding-agent calls: file reads and edits, the git
commands a session runs every hour, test/lint/build invocations and their
results, a few searches and fetches, and MCP tools. No event in either should
ever be refused or questioned by `builtin:coding-agent`.

| File | Events | Role |
|---|---|---|
| `benign.jsonl` | 70 | the reference corpus; policy tuning may look at it |
| `benign-heldout.jsonl` | 20 | held-out split, written after the rules, used only to check the result generalises |
| `poisons.jsonl` | 10 strings | benign-but-baity text appended to non-execution fields by the induced-blocking check |

Together they are the reference point the [security model](../../docs/security-model.md)
promised: a number for "how often is the guard wrong on traffic that is fine",
and a check that an attacker cannot *make* it wrong by putting bait in a field
that never executes.

## Measure it

```bash
python3 scripts/fp_baseline.py                        # main corpus, human-readable
python3 scripts/fp_baseline.py --per-rule             # + each rule measured alone
python3 scripts/fp_baseline.py --poisons benchmarks/fp/poisons.jsonl --stress
python3 scripts/fp_baseline.py --json                 # for tooling
```

The pack is built at run time by `interlock.policy.packs.builtin_pack()`, not
read from a committed JSON: `coding_agent()` embeds the current user's home
directory in its protected paths, so a static document would either be wrong on
another machine or leak one developer's home path into the repository.

`tests/test_fp_baseline.py` runs the same measurement in the normal suite (both
corpora, induced blocking, and the stress cases), so the gates below are
enforced by CI with every other test rather than by a separate job.

## Result - 2026-10-25

| | |
|---|---|
| Corpus | 70 events (67 call-phase, 3 result-phase) |
| Evaluated | 210 (3 passes) |
| **False positives** | **0 - 0.0000%** |
| Held-out (20 events, 1 pass) | **0 - 0.0000%** |
| Rules that fired | none |
| Quarantined rules | none |
| Latency p50 / p95 / p99 / max | 0.24 ms / 0.40 ms / 0.45 ms / 0.47 ms |

Gate: `DEFAULT_MAX_FP_RATE = 0.001` (0.1%) and `DEFAULT_MAX_P95_US = 5000`
(5 ms) from `interlock/mesh/harness.py`. Measured on macOS 24.4, CPython 3.9,
one thread, warm process.

Latency is dominated by `Bash` events, but the command is now parsed once per
event: the engine opens an analysis memo keyed on `(command, cwd)` for the
duration of `evaluate()`, and the parser itself is memoised per event, so the
~12 rules that ask about an intent and every detector that reads the command
text share one parse. Before the memo the same corpus measured 1.26 ms p50 for
`Bash`.

| Action | p50 |
|---|---|
| `Bash` | 0.29 ms |
| `NotebookEdit` / `MultiEdit` | 0.05-0.06 ms |
| `Write` / `Edit` | 0.05 ms |
| `Read` / `Grep` / `Glob` | 0.04-0.05 ms |
| `WebFetch` / `WebSearch` / MCP | 0.03-0.04 ms |

In a hook the process start dominates this cost; it matters only to callers
that run the engine in-process for every call. See
[`benchmarks/overhead/`](../overhead/README.md) for the isolated per-decision
overhead (floor vs guarded) rather than a combined throughput figure.

### Per rule, measured alone

The whole pack's zero can hide a rule that fires and is overruled by another,
so `--per-rule` loads each rule by itself (an `extends` policy minus its other
rules) and runs the corpus through it. Each of the 20 rules in the default pack
allows all 70 events on its own:

| Rule | FP | Rate | p50 | p95 |
|---|---:|---:|---:|---:|
| `self-protect-files` | 0 | 0.0000% | 4 µs | 8 µs |
| `self-protect-commands` | 0 | 0.0000% | 65 µs | 114 µs |
| `unreadable-commands` | 0 | 0.0000% | 62 µs | 115 µs |
| `destructive-commands` | 0 | 0.0000% | 68 µs | 122 µs |
| `fetch-and-execute` | 0 | 0.0000% | 63 µs | 118 µs |
| `force-push` | 0 | 0.0000% | 64 µs | 119 µs |
| `push-delete` | 0 | 0.0000% | 63 µs | 118 µs |
| `discard-work` | 0 | 0.0000% | 64 µs | 115 µs |
| `publish` | 0 | 0.0000% | 63 µs | 118 µs |
| `shell-init-write` | 0 | 0.0000% | 63 µs | 119 µs |
| `scheduled-jobs` | 0 | 0.0000% | 65 µs | 116 µs |
| `privilege` | 0 | 0.0000% | 66 µs | 126 µs |
| `git-credentials` | 0 | 0.0000% | 64 µs | 117 µs |
| `secret-files` | 0 | 0.0000% | 4 µs | 24 µs |
| `secret-file-commands` | 0 | 0.0000% | 64 µs | 115 µs |
| `env-files` | 0 | 0.0000% | 4 µs | 5 µs |
| `agent-hook-settings` | 0 | 0.0000% | 5 µs | 10 µs |
| `agent-hook-settings-commands` | 0 | 0.0000% | 64 µs | 110 µs |
| `result-injection` | 0 | 0.0000% | 3 µs | 4 µs |
| `result-secrets` | 0 | 0.0000% | 3 µs | 4 µs |

Command-reading rules cost ~60 µs because each pays for its own parse when
measured alone; in the composed pack that parse is shared. A rule whose number
moves while the pack's total does not is a rule being overruled - check whether
the overruling is intended (`first-match` vs `combine`) before tuning it.

### Per detector

A detector can be mounted under several rules; pricing it per rule splits its
false positives and charges it a parse per row. `--per-detector` groups by the
detector name and runs only that detector's rules. The default pack mounts six
detectors, and each allows all 70 events:

| Detector | Rules | FP | Rate | p50 | p95 |
|---|---|---:|---:|---:|---:|
| `command_intent_guard` | `unreadable-commands` | 0 | 0.0000% | 63 µs | 112 µs |
| `destructive_command_guard` | `destructive-commands` | 0 | 0.0000% | 67 µs | 121 µs |
| `git_credential_guard` | `git-credentials` | 0 | 0.0000% | 63 µs | 114 µs |
| `secret_path_command_guard` | `secret-file-commands`, `agent-hook-settings-commands` | 0 | 0.0000% | 83 µs | 162 µs |
| `tool_output_secret_redactor` | `result-secrets` | 0 | 0.0000% | 3 µs | 5 µs |
| `tool_result_injection_guard` | `result-injection` | 0 | 0.0000% | 3 µs | 4 µs |

The other 14 rules are declarative and appear only in the per-rule table; they
have no detector code to price separately. Use the same table for your own
policy: `measure_each_detector(policy, corpus)` is exported from
`interlock.mesh.harness`.

### Induced blocking

A rule that reads a field which never executes - `description`, `content`,
`new_string`, `prompt`, `query`, `new_source` - can be *made* to fire by data
the agent merely reads. The harness appends each of 10 poison strings to every
such field on every call-phase event that the baseline allows, and counts a
verdict change as induced.

| | |
|---|---|
| Poisoned calls | 560 (56 allowed call-phase events x 10 poisons) |
| Verdict changed | **0 - 0.0000%** |
| Ceiling | `DEFAULT_MAX_INDUCED_RATE = 0.0` |

Zero is the correct ceiling, not a tuned one: a field that is not executed must
not be able to move a verdict. The corpus is deliberately full of text that a
naive rule would match - the string `ignore previous instructions`, shell
snippets, credential paths, a low-entropy fake token - so the measure fails if
a rule starts reading prose. Result-phase events are excluded because result
detectors *are* meant to read content; their false positives are covered by the
main corpus.

### Stress - pathological but legal calls

A guard is on the request path, so expensive input is a denial-of-service
primitive: an attacker who can submit a 100 KB `Bash` command can stall every
tool call behind it. `--stress` times six legal-but-hostile cases.

| Case | Action | Bytes | p50 | p95 | Verdict |
|---|---|---:|---:|---:|---|
| 100 KB single-quoted echo | `Bash` | 100,022 | 14.5 ms | 14.6 ms | ESCALATE |
| 300 nested `$(...)` | `Bash` | 919 | 5.6 ms | 5.6 ms | ESCALATE |
| 1,000 chained `true` | `Bash` | 7,012 | 27.8 ms | 27.9 ms | ESCALATE |
| 2,000 `echo` arguments | `Bash` | 14,909 | 24.6 ms | 25.4 ms | ALLOW |
| 240 KB `Write` content | `Write` | 240,044 | 0.05 ms | 0.08 ms | ALLOW |
| 100 KB `WebSearch` query | `WebSearch` | 100,013 | 0.03 ms | 0.03 ms | ALLOW |

Ceiling: `DEFAULT_MAX_STRESS_P95_US = 50_000` (50 ms). Three cases escalate
rather than allow, which is intended: past `MAX_INPUT` (16 KB) or `MAX_ARGS`
(4,096) the parser marks the command partial and `unreadable-commands`
escalates it rather than silently reading half of it. The ALLOWed 2,000-arg
case stays under both caps and is the expensive one to keep an eye on.

The first run of this harness found a real amplification: 100 KB of `Bash`
took 0.66 s, because the command was parsed ~7 times per event and the intent
rules called `os.getcwd()` ~12,000 times, then normalised every word as a path.
The fixes - one parse per event, an event-scoped cwd, a home-component cache,
and a cheap prefilter before path resolution - cut the worst case to 28 ms.
The lesson is in the numbers: a parse cache that is sound (same string, same
cwd, same result) is the highest-leverage fix for a rule-heavy guard.

## What these numbers do and do not say

- They say the **default pack** does not fire on the traffic recorded here on
  this machine, and that bait in a non-executed field does not move a verdict.
  They are regression gates, not a claim about all deployments: your traffic,
  your tools and your home layout may differ.
- They do not measure **recall**. Neither corpus has attacks; `interlock mesh
  harness --samples` is the tool for that, and the detector catalog's samples
  are the usual input.
- The held-out split is small (20 events). It catches gross overfitting to the
  main corpus, not a subtle one; grow it with real traffic, never with cases
  written while changing a rule.
- The stress ceiling is a wall-clock bound on one machine. A shared CI runner
  can be several times slower, so the suite's assertion is wider than the
  published 50 ms; what it catches is an order-of-magnitude regression, not a
  slow CPU.

## Adding to a corpus

Add one JSON object per line: `{"action": ..., "args": {...}, "phase":
"call"}`. Keep it to traffic you would be happy to see the agent run
unattended - a call that *should* escalate does not belong here. Add new
ordinary traffic to the held-out file; add to `benign.jsonl` only when tuning a
rule against it. Then run the script: a new false positive is either a corpus
mistake or a policy bug, and the failure output names the rule and the event
count.
