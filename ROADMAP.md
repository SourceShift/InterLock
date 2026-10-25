# Roadmap

Where interlock is going, item by item, with the reasoning and the done
criteria.

The short version lives in [`README.md`](README.md#roadmap). This file is the
long version: for each item still open, **what breaks today**, **why it is
worth doing now**, **what would actually change in the tree**, **what it costs
the people using the library**, **how we know it is finished**, and **what
could stop it**.

Everything here is scoped so it can ship on its own. Nothing in this file is a
promise about a date — it is an ordering by expected value, so that if the
project stops after the next item, it stopped in the right place.

---

## How to read this

**Status** is one of:

| Status | Means |
|---|---|
| `not started` | No code in the tree for it. |
| `partial` | Some of it exists; the item names what is missing. |
| `blocked` | Waiting on a decision or an upstream change. Not used for "hard". |
| `shipped` | Done and tested. The reasoning below is kept for the record. |

**"Upcoming" is anything not `shipped`** — the items derived from the 2026
literature survey ([`research/agent-guardrails-2026.md`](research/agent-guardrails-2026.md)),
plus the open items carried over from earlier milestones. Receipts and
flow-typed policies appear as single entries rather than two, because the
literature item and the older TODO describe the same feature; the entry notes
which is which.

**Size** is a rough shape, not a schedule: `S` is a focused change to one or two
modules, `M` is a new module plus tests, `L` is a new subsystem.

**How items move.** An item is promoted by someone being able to write the
**Acceptance** line as something a test can assert. An item is dropped when the
acceptance criterion stops being worth the cost — that is a legitimate outcome,
and it is recorded by deleting the section, not by leaving it to rot. Nothing
here is dropped for being hard.

**Why a separate file.** A README is read linearly by someone deciding whether
to *use* the library; a roadmap is read selectively by someone deciding whether
to *invest* — in time, in a contribution, or in a dependency. Those are
different readers with different questions, and a README that carries both is
worse at both jobs.

### At a glance

| # | Item | Status | Size | Pull |
|---|---|---|---|---|
| R1 | Delegation chains and scope attenuation | `shipped` | M | T1 · 68 papers (top cluster) |
| R2 | `Verdict.ESCALATE` | `shipped` | S→M | T9 · 15 papers · agentjail review |
| R3 | Verdict provenance (`reason`, `attributed_to`) | `shipped` | S | T2, T3 |
| R4 | Signed execution receipts + append-only audit sink | `shipped` | M | T3 · M4 TODO resolved |
| R5 | Guardrail robustness harness (FP rate, DoS) | `shipped` | M | T5 · corpus + per-rule/per-detector FP, induced blocking, stress |
| R6 | MCP capability leases + server attestation | `shipped` | L | T4 · 57 papers |
| R7 | Tool-result and observation sanitization | `partial` | M | T8 · result phase ships, injection sanitizer blocks |
| R8 | BRACE escape-resistance suite + unprivileged egress | `shipped` | M | T7 |
| R9 | Flow-typed policy dimension | `shipped` | L | T6 · a constraint on R10 |
| R10 | Declarative YAML/JSON policies | `shipped` | L | carried from M0 → M2 · agentjail review |
| R11 | Automatic interception (import hooks) | `shipped` | L | MCP attached at import · seam contract + `attach_monitor` |
| R12 | Overhead benchmark suite, with methodology | `shipped` | S | `scripts/bench_overhead.py` · floor vs guarded p50/p95/p99 |
| R13 | Node.js sensor | `shipped` | L | carried from M0 |
| R14 | Parsed shell commands and intents | `shipped` | M | agentjail review |
| R15 | Protection attestation (`attest`, `require`, `doctor`) | `shipped` | S | agentjail review |
| R16 | Monitor and activity reports (`interlock report`) | `shipped` | S | agentjail review |
| R17 | Enforcement provenance in receipts | `shipped` | M | agentjail review |
| R18 | Coding-agent hook adapters (Claude Code, Codex, Cursor) | `shipped` | L | agentjail review |
| R19 | Tiered sidecar failure posture | `shipped` | M | agentjail review |
| R20 | Placeholder credentials | `shipped` | M | agentjail review |
| R21 | MCP inventory scan | `shipped` | S | agentjail review |
| R22 | Signed PyPI/npm distribution | `shipped` | S | agentjail review |
| H1–H7 | SQL analysis, masking engine, review queue, runbooks, HTTP rules, metrics, MCP limits | `shipped` | L | hoop review |
| R23 | OTLP event export | `shipped` | M | operational review |
| R24 | Behavioural baseline → policy generator | `shipped` | L | operational review |
| R25 | Token accounting in the budget guard | `shipped` | S | operational review |
| R26 | Console approval workflow | `shipped` | M | operational review |
| R27 | Framework sensor adapters | `shipped` | M | operational review |
| R28 | A2A policy dimension | `shipped` | M | operational review |
| R29 | MCP transport controls and scoped engine over the sidecar | `partial` | M | operational review · no client sends a scope |
| R30 | Upstream-drift detector | `shipped` | M | operational review |

---

## R1 · Delegation chains and scope attenuation

**Status:** `shipped` — `Binding.delegated_from` carries provenance, a
resolve-time check refuses a delegated binding that over-grants its parent, and
`ScopeRegistry(max_delegation_depth=...)` fails closed on an unbounded chain.
The native `ScopeTree` carries the field too, so the two backends stay in parity
(`tests/test_scope_backend.py` runs the assertion on both).
**Size:** M
**Literature:** T1, the largest cluster in the corpus (68 of 445 papers).

### Problem

interlock knows *who* acted (`SensorEvent.principal`) and can key policy on a
path derived from it (`principal_scope` splits `"acme/payments/agent42"` into
`("acme", "payments", "agent42")`). What it cannot express is that one principal
**acted on behalf of** another. So there is no way to say "the reporting agent
may read the ledger, but only because the auditor it is running under may" —
and, more importantly, no way to *refuse* the opposite: today a delegated agent
can hand itself a scope its delegator never had. The corpus is close to
unanimous that this is the load-bearing property — a delegate must receive
**strictly less** authority than its delegator, and the chain has to be
auditable hop by hop.

### Why now

It extends an abstraction that already exists rather than inventing one:
scopes are already tuples with a parent walk, `ScopeRegistry.resolve` already
merges child-over-parent, and `Binding` is already the unit of grant. The
missing piece is provenance on the grant, which is a data change, not a redesign.

### What changes

- `Binding` gains `delegated_from: Optional[Scope]` (default `None`, meaning
  "granted directly by the root").
- `ScopeRegistry.resolve(leaf)` walks the parent chain and checks that every
  delegated binding at `leaf` is a subset of what `delegated_from` resolves to.
  A violation is a resolve-time error, not a runtime surprise.
- `principal_scope` gains a sibling deriver for the chain, or the chain is read
  off the event (`event.parent_principal`), so `SensorEvent` gains one optional
  field and every existing caller is unaffected.
- A depth bound is configuration on the registry, so a delegation loop or an
  unbounded fan-out fails closed.

The native `ScopeTree` path (`rust/`) has to carry `delegated_from` too, or the
two backends diverge — `tests/test_scope_backend.py` already asserts parity
between them, so that test is the tripwire.

### Impact

API: additive only. `Binding` gains a keyword field with a default; existing
policies resolve identically because a `None` parent means no new check.
Correctness cost: one extra walk per resolve, mitigated by the existing
version-keyed cache. Policy authors get a new failure mode — a delegated binding
that over-grants — which is the point.

### Acceptance

A test constructs a parent binding granting `("acme",)` and a child binding
granting `("acme", "payments", "agent42")` but delegated from a sibling that
holds only `("acme", "payments")`; `resolve` raises. A second test asserts the
non-delegated case is unaffected. Measured over the same fixture, resolve
latency stays within the tolerance `tests/test_scope_backend.py` already uses.

### Risks & dependencies

The concept of a "delegator" has to come from somewhere — either the caller
threads it through, or the interception layer infers it. Inference is where this
gets hard: inferring wrongly is worse than not having the feature, because a
false chain gives false assurance. Phase it: explicit `delegated_from` first,
inference later, behind its own item.

---

## R2 · `Verdict.ESCALATE`

**Status:** `shipped` — `Verdict.ESCALATE = 3`, `Decision.escalate`, and
`NotApproved`. Every enforcement site (Python and Node.js) now dispatches
through one exhaustive `settle()`, so an unhandled verdict blocks instead of
falling through. Approvals were built with the bindings the agentjail review
(`research/agentjail-review.md`, R2+) showed hand-rolled approval gets wrong:
one-use by default, bound to action, args digest, principal, policy epoch, rule
and a frozen 512-byte reason; `session`/`ttl` scopes; a block always wins; no
approver means block. The Rust crate holds only scopes, so the native-engine
note below no longer applies. Tests: `tests/test_approval.py`.
**Size:** S
**Literature:** T9 (15 papers converging on approval as a distinct outcome),
plus T3's "verifiable action card".

### Problem

There is no way to say *"this is legal, but a human must decide."* Deployments
approximate it by blocking, which throws the action away and puts the burden on
the wrong person — the caller now has to notice the block, reconstruct the
intent, and re-issue it. Fifteen papers converge on the same fourth outcome:
not allow, not block, but **pause and ask, with the evidence attached**.

### Why now

`Verdict` is an `IntEnum` whose values deliberately mirror the native engine's
out-param contract (`0/1/2`). A fourth value is a small, additive type change
with outsized expressiveness — and the alternative today, encoding escalation as
a BLOCK with a magic reason string, is exactly the kind of thing that becomes
load-bearing and then unmovable.

### What changes

- `Verdict.ESCALATE = 3`, and `Decision.escalate(reason, evidence=None)`.
- **The important part is the enforcement path.** Both enforcers currently fall
  through to "return the args" for any verdict they do not recognise —
  `interlock/interceptors/mcp.py` handles `ALLOW`/monitor, `BLOCK`, `MODIFY`, and
  then returns; `interlock/interceptors/decorator.py:_enforce` does the same. Add
  a fourth enum member without touching those and an escalation **silently
  allows**. So this item is not the enum, it is the two dispatch sites plus an
  escalation hook (a callable `guard(..., on_escalate=...)`) and a defined
  default when no hook is installed — the only safe default is BLOCK.
- `PolicyEngine.evaluate` needs no change: it already returns the first verdict
  that is not `ALLOW`.

### Impact

Users who do nothing see no change (no hook, escalations block, which is the
current behaviour). Users who install a hook gain a pause-and-ask path with
evidence attached. The native engine contract in `rust/` must be updated in the
same change, or a ctypes engine will disagree with the Python enum about value
`3`. Anything that switches exhaustively on `Verdict` is a compile-time or
test-time break, which is the right kind.

### Acceptance

A rule returning `Decision.escalate(...)` against a `@guard`-wrapped function
invokes the escalation hook and does **not** call the wrapped function until the
hook resolves. With no hook installed, the call is blocked. A test asserts the
"unrecognised verdict" fallthrough cannot happen — i.e. that adding a verdict
without handling it is caught.

### Risks & dependencies

Escalation needs somewhere to escalate *to*; a hook is the least opinionated
answer, but it means the library ships the verb and the deployment supplies the
noun. Also couples to R3: an escalation without `attributed_to` gives a human
nothing to decide on, so shipping R2 without R3 produces a prompt with no
evidence.

---

## R3 · Verdict provenance (`reason`, `attributed_to`)

**Status:** `shipped` — `Decision.attributed_to` names the input slot that
triggered the verdict, plumbed to the decision record alongside `reason` and
`policy_id`. The detector sweep is enforced by test, not by convention:
`tests/test_decision_attribution.py` walks `interlock/detectors/*.py` and
requires every module to either attribute a case or be a declared gap.
**Size:** S
**Literature:** T2 (pre-execution gating by causal attribution) and T3.

### Problem

The *timing* is already right: `Decision.block`/`modify` happen before the call
runs. What is missing is the **explanation**. A verdict says what was denied and
which policy denied it, but not *which input caused it* — so a caller cannot act
on attribution, and a reviewer auditing the decision cannot see the reason
without re-deriving it. The 2026 shift in the literature is precisely from "does
this call look bad?" to "*why* was this call produced?", and the answer is
carried as data on the verdict.

### Why now

`Decision` already has `reason: str` and `policy_id: Optional[str]`, so the
shape is proven and the payload is a single additive field plumbed to the event.
This is the cheapest item on the list relative to what it unlocks: R4's receipts
and R2's escalation both consume it.

### What changes

- `Decision.attributed_to: Optional[str]` — the input slot or argument path that
  triggered the verdict (`"args.path"`, `"args.url"`, `"tool_description"`).
  Optional, defaults to `None`; nothing that does not set it changes.
- A rule that returns a decision can name the field cheaply if the engine passes
  it: `Decision.block(reason, policy_id, attributed_to="args.path")`.
- The detectors that already know which argument they matched should populate it.
  That is the bulk of the work: 105 detectors, each already computing the
  offending field inline.
- `SensorEvent` does not change; the field is on the decision, and the event is
  what gets logged. `_emit` at `interlock/interceptors/decorator.py:45` — the
  line that still carries the M4 note — is the natural place to surface it.

### Impact

Additive. Existing rules produce `attributed_to=None`, which reads as "policy
declined to attribute", not as an error. The cost is in the detector sweep: a
detector that sets it wrong is worse than one that leaves it `None`, so the
sweep has to be reviewed in chunks rather than applied mechanically.

### Acceptance

Every non-ALLOW decision produced by the shipped detector suite reports the
argument path that triggered it, or explicitly reports `None` — and a test walks
the detector registry asserting one of those two, so a new detector that forgets
to attribute is caught at test time rather than at audit time.

### Risks & dependencies

Attribution is only as good as the detector's own reasoning. Where a detector
matches across several joined fields, naming one field is a lie of omission. The
honest answer for those is `None`, and the acceptance criterion above is written
to permit it.

---

## R4 · Signed execution receipts + append-only audit sink

**Status:** `shipped` — `interlock/receipt.py` emits a decision-level `Receipt`
binding the four stamps to the verdict: `ts`, `action`, `verdict`, `reason`,
`policy_id`, `attributed_to`, `principal`, `span_id`, `phase`, `args_digest`, a
`prev` link seeded from `GENESIS`, and an HMAC `mac`. `set_sink` installs an
append-only backend (hash-chained append, plus a null default), and
`verify_chain(receipts, signer, key)` catches a byte-flip or a mid-chain
deletion. The M4 note at `interceptors/decorator.py:45` is resolved — `_emit`
now surfaces `attributed_to` on the same path the receipt is taken from.
**Size:** M
**Literature:** T3. This is also the open M4 TODO, re-specified — the tree
already names it at `interlock/interceptors/decorator.py:45`
("M4 replaces this with signed receipts + an audit sink").

### Problem

Events are logged at debug level. That is not an audit trail: it can be turned
off, it is not tamper-evident, and it does not prove anything to a third party.
The literature is specific about the gap here — a receipt must prove the
guardrail **ran**, not merely that a log exists. A log is a claim by the
operator; a receipt is evidence that survives the operator.

### Why now

The stamp detectors already exist and already sign and sequence; what is missing
is a *decision-level* record that binds the four stamps to the verdict. The
pieces are in the tree, just not connected. And the M4 note has been sitting in
the decorator since M0 — an unbuilt milestone marker is worse than no marker,
because it reads as "planned" indefinitely.

### What changes

- A `receipt` module: given a `SensorEvent` + `Decision` (+ whatever R3
  attributed), emit a signed record. Signing reuses whichever stamp detector the
  deployment already configured, so there is one key management story, not two.
- An **append-only sink** interface with at least a file backend (hash-chained
  append, no rotation that breaks the chain) and a null backend. Plugging into
  an external store is the deployment's job; the library's job is that the
  record cannot be quietly rewritten locally.
- Filling in `_emit` so the debug log and the receipt are produced from one
  place.
- **Stating the trust boundary in the docs**: a receipt proves what the guard
  decided, under a key the guard holds. It does not prove the guard was not
  bypassed entirely. That distinction is the difference between an honest
  receipt and a security theatre one, and the literature is explicit about it.

### Impact

Per-decision cost: one hash (cheap) plus one append (the thing to measure —
`benchmarks/` exists precisely so this number is stated rather than assumed).
Off by default, because a sink that cannot be opened must not take down an
agent. Users gain offline verification: a receipt verifies against a published
key with no access to the running system.

### Acceptance

**Shipped and tested:** a receipt verifies offline against the published key; a
byte-flipped record fails verification; removing a record from the middle of the
chain is detected.

**Not delivered:** a benchmark reports the added per-decision cost, and the
README's claim about overhead (see R12) is updated to match the measured number.
`benchmarks/` holds only `scope_memory.py`, so that half is still open under
R12; the `shipped` status above covers the receipts and the append-only sink.

### Risks & dependencies

Key storage is the hard part and it is not solvable in a library — the honest
scope is "bring your own key, here is the interface". Depends on R3 for the
attribution half of the record; a receipt that says "blocked, reason unknown" is
still useful but much less so.

---

## R5 · Guardrail robustness harness (false positives, induced blocking)

**Status:** `shipped` (2026-10-25) — the conformance corpora
(`tests/conformance/detectors/*.json`, 774 cases; `tests/conformance/events.json`)
remain, and the robustness half is now measured on committed traffic:
`benchmarks/fp/benign.jsonl` (70 events) and `benign-heldout.jsonl` (20 events),
driven by `scripts/fp_baseline.py` and gated in CI by
`tests/test_fp_baseline.py`. The default pack reports **0 false positives on
both corpora** (p95 0.40 ms), **per-rule** numbers for all 20 rules and
**per-detector** numbers for all six mounted detectors, **0 induced blocks out
of 560 poisoned calls** (`benchmarks/fp/poisons.jsonl`), and stays under
**28 ms** on six pathological-by-legal stress cases (50 ms gate). The stress
harness found and fixed a real 100x amplification: one parse per event and an
event-scoped cwd replaced ~7 parses and ~12k `os.getcwd()` calls per decision.
**Size:** M
**Literature:** T5 — a cluster that barely existed a year ago, and the area
where interlock has the largest gap relative to its importance.

### Problem

interlock is fail-closed by design, and that is the correct default — but it has
**no published measurement of its own false-positive rate, no cost model for a
blocked action, and no resistance to being induced to block.** The harness
exists; the traffic it should measure is what's absent. For a library whose
selling point is blocking, an unmeasured FP rate is a product risk, not merely
an evaluation gap: a detector that fires on benign traffic trains users to widen
their allowlists, and a widened allowlist is a bypass. Worse, "make the guard
block" is a denial-of-service primitive — an attacker who cannot exfiltrate can
often still stall the agent by making it refuse, and the literature now treats
that as a first-class attack.

### What shipped

- **Two corpora under `benchmarks/fp/`** — 70 events of ordinary traffic that
  policy tuning may look at, and a 20-event held-out split written after the
  rules, so a clean result is not only overfitting. `poisons.jsonl` holds the
  bait strings.
- **Per-detector numbers**, not only an aggregate:
  `measure_each_detector()` groups a detector's rules and runs only those, so
  one detector firing on everything cannot hide inside a clean pack total. All
  six default detectors report 0 FP; all 20 rules also report 0 FP measured
  alone (`--per-rule`).
- **Induced blocking:** bait appended to six non-execution argument fields on
  every baseline-ALLOW call. 0 of 560 verdicts changed; the ceiling is zero,
  not a tolerance. Result-phase content is excluded because result detectors
  are meant to read it.
- **Stress:** six pathological-but-legal calls (100 KB `Bash`, 300 nested
  substitutions, 1,000 pipes, 2,000 args, 240 KB write, 100 KB query) with a
  50 ms p95 gate. Input past `MAX_INPUT` (16 KB) or `MAX_ARGS` (4,096
  arguments) is marked partial and escalated, so the cost bound fails closed.
- **The regression gate runs in CI** inside `tests/test_fp_baseline.py` — both
  corpora, induced blocking, and stress — so a rule that starts firing on a
  routine `git status` breaks the build.

### Delivered

| | |
|---|---|
| Default pack FP | 0 / 210 evaluated (0.0000%); held-out 0 / 20 |
| Per rule (20) | all 0 FP; table in `benchmarks/fp/README.md` |
| Per detector (6) | all 0 FP; table in `benchmarks/fp/README.md` |
| Induced blocking | 0 / 560 poisoned calls |
| Stress p95 | worst 27.9 ms (1,000 chained `true`), all ≤ 28 ms |
| Gate | `DEFAULT_MAX_FP_RATE=0.001`, `DEFAULT_MAX_P95_US=5000`, `DEFAULT_MAX_INDUCED_RATE=0.0`, `DEFAULT_MAX_STRESS_P95_US=50000` |

### Residual risks

- Zero out of 70 leaves a 95% upper bound near 4%; the held-out split is 20
  events and catches gross, not subtle, overfitting. Grow both from real
  traffic, never from cases written while tuning.
- Only the default pack has published numbers. `interlock mesh harness
  --per-rule --per-detector` measures another policy, but its result is only as
  good as the corpus supplied.
- The stress ceiling is wall-clock on one machine; the CI assertion is widened
  for shared runners, so it catches order-of-magnitude regressions rather than
  slow CPUs.
- The guard can still be induced to *escalate* through legitimate-looking
  traffic that is genuinely suspicious; the measure only proves that inert
  fields cannot move a verdict.

### Impact

This is the item that changes what interlock can *claim*. Today "fail-closed" is
a design statement; with this, it is a measured one with a published cost. The
immediate user-visible effect is a table in the README — and the very real risk
that the first published number is embarrassing. That is the point: it is
cheaper to find out here than in production.

### Acceptance

Desktop README reports a false-positive rate per detector over a committed
benign corpus, and CI fails when a change worsens it beyond a stated tolerance.
A documented load fixture shows the guard degrades (latency) rather than
silently failing open under adversarial volume.

### Risks & dependencies

The corpus is the whole item, and a bad corpus is worse than none — a corpus of
trivially benign traffic yields a 0% FP rate that means nothing. The corpus needs
to be adversarial *toward the detectors* (near-miss strings, look-alike paths)
while remaining genuinely benign. Also: a published FP rate invites tuning
detectors to the corpus, which is overfitting; the mitigation is a held-out
split, and it should be decided before the first number is published.

---

## R6 · MCP capability leases + server attestation

**Status:** `shipped`, in three parts. **Lease** —
`mcp_capability_lease` + `LeaseRegistry.issue/renew/revoke`: a grant with an
issued-at and an expiry, checked at call time, denying with an attributable
reason once it lapses. **Attestation** — `mcp_server_attestation` binds a
server identity to a digest of the surface it *presents*, behind an injectable
`verifier` seam; the shipped default is a shared-token check and the module says
plainly that this is not a real attestation until a caller supplies a root of
trust. **Runtime drift** — `mcp_surface_baseline` holds the *reviewed* listing
and blocks any later one that differs (added, removed, renamed, or merely
re-described tool), revoking that server's leases on the drift so an old grant
cannot cover the new surface; re-admission is a fresh rule.
**Size:** L
**Literature:** T4 — MCP's trust model is the single hottest concrete surface
(57 papers in that cluster).

### Problem

Existing MCP detectors answer "was this server allowed, and was this tool the
one we pinned?" — at configuration time. They do not answer "**is** this the
server we pinned, right now?" (attestation) and they do not answer "was this
grant still valid when the call happened?" (a lease). There is nothing that
expires, and nothing that detects a tool *surface* that drifts after admission —
a description that changed, a tool whose arguments widened. The literature's
direction here is unambiguous: admission should be proven, and grants should
lapse.

### Why now

It extends existing detectors rather than replacing them: `mcp_tool_pinning`
already holds the expected identity, so attestation is "prove the identity we
already pinned" rather than a new trust model. And leases are how every other
capability system handles revocation without a config reload.

### What changes

- A lease: a grant with an issued-at and an expiry, checked at call time.
  `mcp_*` detectors consult the lease; an expired lease denies, and the denial
  says so (which R3's `reason` makes visible).
- Attestation: verify that the server presenting itself matches the pinned
  identity — at minimum a stable server identity token, ideally a signature over
  the tool listing.
- Runtime drift detection: hash the tool surface at admission, re-check on
  listing change, and treat a silent change as a new admission decision rather
  than a continuation of the old one.
- A renewal path, or leases will be turned off on the first expiry that breaks a
  healthy deployment — which is the failure mode that kills time-boxed systems.

### Impact

The largest single item here. It adds state (leases are stateful in a library
that is currently mostly stateless), which affects the concurrency story and the
"zero runtime dependencies" purity of the core. Renewal UX decides whether it is
adopted at all. All four existing `mcp_*` detectors need to agree on the lease
lookup or the deployment gets a split verdict.

### Acceptance

A lease expires and the next tool call on that server is denied with an
attributable reason. A server whose identity has changed fails admission rather
than being treated as the same server. A tool description that changes after
admission is re-admitted, not silently accepted.

### Risks & dependencies

Attestation needs a root of trust the library does not own; without one, this
degenerates into "compare two strings", which is a real downgrade that must be
documented rather than dressed up. Depends on nothing, but is a prerequisite for
anyone who wants a *provable* MCP posture — which is most of the 57 papers.

---

## R7 · Tool-result and observation sanitization

**Status:** `partial` — `SensorEvent` gained a `phase` field (`"call"` by
default, `"result"` on the observation path), so a result-level rule cannot fire
on a call event and vice versa. `enforce_tool_result(action, result)` mirrors
`enforce_tool_call` and returns the checked result (or raises `Blocked`), and
`Decision.modified_result` is a field of its own rather than an overload of
`modified_args`. Result-phase rewriting also ships for sensitive data:
`tool_output_secret_redactor` and `data_masking_guard` return
`Decision.modify_result` and redact secrets and PII in a result. What is not
delivered is injection sanitization: the shipped `tool_result_injection_guard`
**blocks** a poisoned result instead of rewriting it, and no built-in detector
strips an injected instruction or override from a result. The rewrite mechanism
exists; the sanitizing detector named below does not.
**Size:** M
**Literature:** T8 — the injection channel that matters is the tool *result* and
the tool *description*, not the user prompt.

### Problem

Every interceptor today guards the **call** path: name + arguments, before
effect. The tool *result* comes back unguarded. That is the wrong half to omit,
because indirect prompt injection arrives in the result (or in the tool
description) — the agent reads it and acts on it. interlock correctly identifies
the poison and then does nothing about it, leaving the caller to decide.

### Why now

The remedy already exists as a verb: `Decision.modify` rewrites arguments today.
Pointed at the observation path it would rewrite a poisoned result. The missing
piece is a place to observe results, not a new verdict — which makes this
unusually cheap for its value.

### What changes

- An `enforce_tool_result(action, result)` beside `enforce_tool_call` in
  `interlock/interceptors/mcp.py` — the same core, the other direction.
- `guard_mcp_session` wraps the result as well as the call, so the pair is
  symmetrical and there is no way to install half of it by accident.
- Detectors that currently return `MODIFY` for argument rewriting gain the
  ability to express result rewriting: sanitize the injection marker, strip the
  override instruction, neutralize the smuggled delimiter.
- Policy needs to distinguish the two directions, or a rule written for a call
  fires on a result (the `SensorEvent` model would need a direction field, or
  the event gets an explicit phase).

### Impact

API change with a real-shape question: `MODIFY` currently means "modified_args";
on the result path it means "modified_result". Overloading one field for two
meanings is the kind of thing that looks fine for one release and is painful
forever. The options are a second field or a wrapper type, and that choice
should be made deliberately here rather than accreted.

### Acceptance

A poisoned tool result is rewritten, not merely flagged, and the guarded call
returns the sanitized result to the agent. A test asserts that a result-level
rule does not fire on a call-level event and vice versa, so the two directions
cannot cross-contaminate.

### Risks & dependencies

Sanitization is destructive: a rewrite that removes legitimate content is a
correctness bug in the agent, and a partial rewrite can leave a payload that
still works. The conservative shape is to detect-and-rewrite known markers and
*refuse* (block) on ambiguity rather than attempt a clever paraphrase. Depends on
a decision about the `MODIFY` shape above.

---

## R8 · BRACE escape-resistance suite + unprivileged egress

**Status:** `shipped` — `tests/integration/test_brace_token_matrix.py` turns
every `enforced` token into a tested contract: for each backend and each token it
reports, the escape that token is meant to stop is run for real and asserted
stopped, **plus a relaxed control** proving the block is the sandbox's doing
rather than the kernel refusing a syscall. A drift test pins each backend's
reported token set to the guarantee table in `interlock/brace/__init__.py` in
both directions, so the table and the code cannot part company.

The unprivileged egress rung is **not** delivered, and the item lands saying so:
`nftables` still stays out of `_ORDER` (it is not selectable — pinning it raises
`ValueError`), and Seatbelt rejects literal remote-IP network filters outright
("host must be `*` or `localhost`"), so no unprivileged host-granular egress is
expressible on this host. That is recorded as a measured absence in the brace
docstring and the README's confinement section, not papered over.
**Size:** M
**Literature:** T7 — directly adjacent to BRACE.

### Problem

Two things. First, BRACE backends *claim* containment by returning `enforced`
tokens on `SandboxResult` (`["fs-ro", "fs-rw", "env", "pid", "net"]` for
bubblewrap, `["env"]` + `["rlimit"]` for soft), and the documented usage pattern
is to refuse a downgrade by checking them — but no test asserts that a claimed
token actually holds. A claim is not a proof. Second, the inversion: the
literature's direction is strength *without* privilege, and here the strongest
egress confinement is the one that needs root, so the strongest guarantee is
unavailable in exactly the deployments (containers, CI, unprivileged users) that
need it most.

### Why now

The gap between "reports `enforced: ["net"]`" and "net is actually confined" is
the gap between a security control and a security *feeling*. The integration
suite (`tests/integration/test_brace_confinement.py`) already attempts real
attacks, so the harness exists — this item is making the assertions exhaustive
per backend, and closing the privilege gap.

### What changes

- Per-backend escape tests, driven by the `enforced` tokens the backend reports:
  for each token, an attack that token is supposed to stop, asserted stopped.
  A backend that reports a token it does not deliver fails, and the token list
  becomes a tested contract rather than a docstring.
- The unprivileged egress path: bubblewrap's `--unshare-net` gives a
  no-network namespace without root, but nothing between "no network" and
  "nftables-with-root" exists today — a host-granular egress confinement that
  works as an unprivileged user is the missing rung. The declaration in
  `compile_profile` / `SandboxProfile.allowed_hosts` already anticipates it
  ("enforced host-granular by the nftables backend, and by the in-process
  `egress_allowlist` detector on captured calls"), so the in-process half exists;
  the out-of-process unprivileged half does not.
- Honest reporting when a token is absent: the `Sandbox(sandbox.py)` docstring
  example already refuses to run without `"net"`; that pattern should be the
  documented default for untrusted code, not an example.

### Impact

No API change. The output is a guarantee table per backend that is tested, and
an honest one — including a row that says "not available without root" if that
is where the unprivileged path lands. The `soft` backend is a speed bump and the
docs should say so rather than leaving a reader to infer it from an `enforced`
list of length two.

### Acceptance

For each backend and each `enforced` token it reports, a test performs the
escape that token is meant to prevent and asserts the sandbox stops it. Egress
confinement is demonstrably applied on an unprivileged Linux host, or the
absence is stated in the README's confinement section as a known limitation.

### Risks & dependencies

Escape tests are host- and kernel-sensitive: a test that passes because the
attack needs a syscall the CI kernel refuses, rather than because the sandbox
stopped it, is a false pass. Each test needs to fail-in-the-open when the
sandbox is disabled (a positive control) — otherwise the suite proves nothing.
Depends on `bwrap`/`sandbox-exec` availability, which is why the harness must
skip with a *reported* skip, not a silent one.

---

## R9 · Flow-typed policy dimension (source → sink)

**Status:** `shipped` — `interlock/flow.py` tracks provenance at the
interception boundary, `SensorEvent.origins` carries it, and declarative
`{"flow": {"source": ..., "sink": ...}}` conditions constrain it. The
hand-written case is expressible generally: `tests/test_flow.py` proves the
flow rule and an equivalent bespoke predicate reach the same verdict on every
case, including the canary and egress shapes.
**Size:** L
**Literature:** T6 — the policy-language literature moved from flat rules to
typed rules and source→sink flow constraints.

### Problem

Rules are Python predicates with a `Template`/`Binding` parameter model:
expressive, untyped, and **flat**. Nothing can express "data that entered via
tool X may not reach argument Y" — the single most useful constraint in an agent
setting, because it is exactly the shape of exfiltration. Today that is
approximated by an argument-matching egress rule, which fires on the *call* and
cannot see where the value came from.

### Why now

This is technically a constraint on R10 rather than an independent item: the
moment declarative policies are designed, the flat-vs-flow decision gets made by
default. Designing the flow dimension *now*, as R10's shape, costs design effort;
discovering it is needed *after* R10 ships costs the schema. That asymmetry is
the entire argument for doing it in this order.

### What changes

- A provenance edge: values carry where they entered (`tool:fetch_url`,
  `principal:acme/agent42`) and a rule constrains source→sink, not just sink.
- The natural home is the `SensorEvent`: an optional per-argument origin map,
  populated at the interception boundary (this is the link back to R1 — the
  delegation chain is one source of provenance, the tool result is another).
- `PolicyEngine.evaluate` stays the seam; flow rules are rules, they just see
  more of the event. No new evaluation model.
- Detectors that already do this in ad-hoc form (`data_egress`,
  `secret_entropy_egress_guard`, `taint`-adjacent guards) become the first
  consumers, and their bespoke logic is the specification for the general one.

### Impact

This is the item that decides whether interlock's policy layer is a real policy
language or a bag of predicates. It is also the largest design risk on the list:
flow typing has a well-known expressiveness/decidability trade, and the wrong
choice is expensive to undo. Impact on users is deferred until R10 ships, which
is why R9 is a *design and prototype* item, not a delivery item.

### What shipped

- `interlock.flow.FlowTracker`: a bounded, span-scoped memory of result text
  under `tool:<canonical action>` and `principal:<id>`, matching a recorded
  fragment inside a later argument. `record_origin()` records a source an
  integration already knows; `origin_for_tool()` is the label helper.
- `SensorEvent.origins`: argument path → immutable tuple of labels. Populated
  by `enforce_tool_call` (tracker plus an explicit `origins=` map) and the
  `@guard` event builder; `enforce_tool_result` records the value the caller
  actually receives, so a chain keeps provenance and a blocked result does not.
- Declarative `{"flow": {"source": ..., "sink": ...}}`: a load-checked
  condition with glob selectors, nested paths, and `attributed_to` naming the
  tainted argument. Both selectors are validated at load; a malformed one is
  quarantined rather than silently never firing.
- `network_egress_guard(block_origins=...)`: the first detector consumer. It
  denies an egress payload carrying matching provenance even when every
  destination is allowlisted.
- `tests/test_flow.py` covers the tracker bounds, span isolation, glob and
  nested-sink matching, the boundary round trip, the detector consumer, and
  the differential equivalence with a hand-written predicate.

### Acceptance

A rule expresses and enforces "the output of tool A must not reach argument B",
and the existing `data_egress` detector's hand-written case is expressible in the
general mechanism — that equivalence is the proof the abstraction is real and not
a second way of writing the same special case.

### Risks & dependencies

Untyped Python args mean origins have to be tracked by convention, and a
convention is bypassable — a value laundered through a string operation loses its
origin. The honest scope is to track origins at the boundary (which tool produced
this value) and accept that intra-argument laundering is not modelled; claiming
more would be false assurance. Depends on R10; should not ship before it.

---

## R10 · Declarative YAML/JSON policies

**Status:** `shipped` — `interlock/policy/declarative.py`: JSON core (YAML with
PyYAML), a closed operator set with no attribute access, shell-intent
conditions, detectors by name, hot reload that keeps the last good policy, and
the agentjail-review guardrails: typo'd fields and tool arguments fail at load,
invalid rules are quarantined, `locked` rules can't be disabled, and project
overlays are additive-only and trust-gated by content hash
(`interlock/policy/trust.py`). Differential test against the equivalent Python
rule in `tests/test_declarative_policy.py`. R9's flow typing remains open.
Previously: `not started` — M0 rules are Python (carried from M0 → M2 in the
engine docstring).
**Size:** L
**Pull:** internal. `interlock/policy/engine.py` names it: "M2 loads declarative
YAML/JSON policies with a safe condition evaluator".

### Problem

A policy written as a Python predicate is a policy that only a Python developer
can read, review, or change — and it is coupled to the internals of whatever
event shape it inspects. That makes the policy layer the least durable part of
the system: the rules survive model migrations and framework migrations only if
the thing expressing them is not code. The stated goal is exactly that: *so rules
survive model and framework migrations*.

### Why now

It is the item the whole policy layer is shaped around — `PolicyEngine.evaluate`
is explicitly the seam that "later milestones replace". Keeping it as Python
indefinitely means every policy carries an import risk, and it means the answer
to "can I change this rule without a deploy" is no. It is also the gate for
everything about the policy layer's future: R9's flow typing is designed against
this schema.

### What changes

- A schema for rules (match → verdict, with bindings), a **safe** condition
  evaluator (no `eval`, no attribute access into arbitrary objects — an
  allowlist of operations over event fields), and hot reload so a changed file
  takes effect without a restart.
- The `Template`/`Binding` model already separates code from data, so the schema
  is largely a serialization of what exists, plus the condition language.
- Loading YAML would add a dependency; the core is deliberately
  `dependencies = []`. Either JSON-only in the core, or an optional extra — which
  is a decision worth making explicitly rather than by accident (note: the
  existing `mcp = ["wrapt>=1.15"]` extra in `pyproject.toml` is declared but
  never imported — dead, and should be removed rather than left as precedent).
- Hot reload needs a failure story: a bad file must not take down a running
  guard. Fail-closed on parse error means the last-good policy stays live, and
  the parse error is loud.

### Impact

The largest user-facing change in the file: policy authoring stops requiring
Python, and rule changes stop requiring a deploy. It also creates the first real
compatibility surface — a schema that others write against — so it deserves the
care that a schema deserves, and it should not ship in the same release as R9's
flow dimension unless that is ready.

### Acceptance

A rule expressed in YAML/JSON enforces identically to the equivalent Python rule
over the same event fixture (a differential test, which is also how the schema
gets meaningfully tested). A malformed policy file leaves the running policy in
place and reports the parse error. A changed valid file takes effect without
restarting the process.

### Risks & dependencies

The condition evaluator is a security-critical component: it evaluates
deployment-supplied expressions, and a hole in it is a hole in the guard.
The acceptance bar is that it cannot reach anything outside an allowlisted set of
event operations, with tests that attack it rather than merely exercise it.
Depends on the R9 design decision; blocks nothing else.

---

## R11 · Automatic interception (import hooks)

**Status:** `shipped` (2026-10-25) — `attach()` guards MCP client sessions at
``ClientSession.call_tool`` on import (or immediately if already imported),
idempotently and reversibly, and `uncovered()` reports what is still unguarded.
The model SDKs stay adapter-guarded deliberately: they return a tool-call
request and the application dispatches it, so there is no library method to
wrap that would not also wrap the application's code. The explicit
**compatibility contract** (`MCP_SEAM`, `check_seam`, `interlock attach
--check`) and the **import monitor** (`attach_monitor()`) now ship.
Residual: the real-SDK integration test is `importorskip`ed, so CI exercises
the contract against the real package only where it is installed.
**Size:** L
**Pull:** internal. The decorator docstring: "Automatic interception (import
hooks for MCP and the model SDKs) lands in M1 and M3; this decorator is what
covers bespoke in-house tools the auto-hooks cannot see."

### Problem

Explicit wrapping means coverage is a function of discipline. A developer who
forgets `guard_mcp_session` gets no guard, silently — the failure mode of a
security library that must be remembered is that it is not used. Every
interception point the library cannot reach on its own is an unguarded path, and
the paths that matter (third-party MCP clients, model SDKs) are exactly the ones
the developer does not control.

### Why now

It is the item that converts interlock from "a guard you call" to "a guard that
is there" — and it is the milestone the architecture was explicitly laid out
for: `enforce_tool_call` is already the one transport-agnostic core that MCP and
LangChain both funnel through, so an import hook has a single place to attach
rather than one per framework.

### What shipped

- **Import hook for MCP client sessions** (earlier pass): `attach()` patches
  `ClientSession.call_tool` at the class, before or after the SDK is imported,
  through the existing `enforce_tool_call` core. Idempotent, reversible, and a
  broken install never breaks the user's import.
- **Compatibility contract:** the seam the hook relies on is data (`MCP_SEAM`:
  a `ClientSession` class with a callable `call_tool` accepting two positional
  arguments). `check_seam()` reports every break; `attach()` refuses an
  incompatible seam with `incompatible seam: ...` instead of half-guarding it;
  `inspect_surfaces()` / `python -m interlock attach --check` run the same check
  against the installed package (exit 1 on a break), so a dependency upgrade is
  verified before an agent uses it.
- **Import monitor:** `attach_monitor()` compares every guarded module against
  what `attach()` recorded - class object, wrapper identity, source-file
  SHA-256, installed version - and reports `missing`, `replaced`, `unpatched`,
  `modified`, `removed` or `version`. `attach()` runs it and repairs a
  replaced/unpatched class; a changed file is reported, never re-blessed.
- **Residual:** the model SDKs have no class seam and stay adapter-guarded by
  design. The real-SDK contract test is `importorskip`ed; environments without
  `mcp` exercise the contract against stand-ins that mirror its shape.

### Impact

Adoption cost drops to near zero and coverage stops depending on developer
memory. The cost is coupling: interlock now owns behaviour on top of third-party
APIs it does not control, and each client release is a potential break. That
trade should be made deliberately and with an opt-out that is documented as
first-class, not a hack.

### Acceptance

An agent using an MCP client (or a model SDK) without any code change is
guarded: a blocked tool call is blocked before effect, demonstrated in an
integration test that uses the real client API shape. An opt-out exists and is
tested. A `monitor` mode exists to roll it out without blocking.

### Risks & dependencies

This is the highest-fragility item on the list and should be the last of the
interception work, after R4 gives it a receipt to emit and R2/R3 give it
somewhere to send a decision. Its acceptance test must run against real client
shapes, not only fakes, or the fragility is discovered by users.

---

## R12 · Overhead benchmark suite, with methodology

**Status:** `shipped` (2026-10-25) — `scripts/bench_overhead.py` measures the
same benign corpus through an empty engine (floor) and `builtin:coding-agent`,
reports the difference at p50/p95/p99 per action, and gates it. Current result:
**guarded p50 243 µs / p95 392 µs / p99 445 µs against a 2 µs floor**;
`Bash` p50 285 µs, every other action 29-56 µs
(`benchmarks/overhead/README.md`). The harness's own run found and fixed a
6x median regression (0.61 ms -> 0.24 ms) by sharing one parse and one cwd per
event.
**Size:** S
**Pull:** internal, carried from M0.

### Problem

The library's central claim to an operator is that it can sit in the request
path. That claim is currently unquantified: there is a scope-store memory
benchmark and nothing else. Without numbers, "adds negligible overhead" is an
assertion, and an operator evaluating interlock has to guess — or measure it
themselves, which they will do by not adopting it.

### Why now

It is small, it is mostly mechanical, and it is a prerequisite for two other
items making honest claims: R4's per-receipt cost and R5's robustness results
both need somewhere to report numbers, and that somewhere should be one harness
with one methodology rather than several ad-hoc scripts.

### What shipped

- **`scripts/bench_overhead.py`** — one untimed warm-up, then `--repeats`
  timed passes (default 20). Reports guarded p50/p95/p99, the floor (empty
  engine) on the same events, the difference in µs, and a per-action breakdown.
  `--json` for tooling. The methodology, hardware line and caveats are in
  `benchmarks/overhead/README.md`; `tests/test_bench_overhead.py` pins ordering
  and the gate.
- **A gate:** non-zero exit when guarded p95 or added p95 exceeds 5 ms, or the
  guarded/floor p50 ratio exceeds 500x. The ratio is suppressed when the floor
  is under 5 µs, because at that point it is timer resolution, not work.
- **Result:** guarded p50 243 µs / p95 392 µs vs a 2 µs floor; `Bash` 285 µs,
  edits 46-56 µs, reads 42 µs, web/MCP 29-37 µs. In a hook, interpreter startup
  dominates; this number matters to the sidecar and `@guard`.
- **What it deliberately does not cover:** throughput under concurrency,
  memory, hook process startup, and a block-heavy mix. The sidecar round trip
  keeps its own JS smoke figure (`node js/bench/roundtrip.mjs`, ~47 µs/call vs
  ~0.4 µs unguarded on one reused connection) rather than being folded into
  this in-process number. R4's receipt cost remains its own measurement.

### Impact

Purely additive; no API. The output is a README table with a methodology note and
a hardware line — and the discipline that a claimed overhead must come from the
harness. The anti-goal: a benchmark tuned to produce a flattering number. The
methodology section is what makes it a measurement instead of marketing.

### Acceptance

The documented entry point (`python3 scripts/bench_overhead.py`, plus
`interlock mesh harness` for policies) produces a table including a no-guard
baseline, and `benchmarks/overhead/README.md` cites those numbers with the
hardware they were taken on. Re-running on the same hardware reproduces within
a stated tolerance; the CI gate's bounds are deliberately wider than the
published figure for that reason.

### Risks & dependencies

Micro-benchmarks overstate detector costs in isolation and understate them in
aggregate; the mitigation is measuring the composition (a realistic event mix),
not just individual detectors. No dependencies.

---

## R13 · Node.js sensor

**Status:** `shipped` — stages 1 (the Python sidecar and the conformance corpus),
2 (the `js/` client, the MCP interceptor, and the corpus replay) and 3 (the
native fs/exec/http interceptors and the model-SDK tool seam) have all landed.
**Size:** L
**Pull:** internal.

### Problem

The Python tree guards Python agents. A large share of MCP clients and agent
frameworks are JavaScript, and those integrations are out of reach today: the
policy engine, detectors, and interception core exist only in Python.

### Why now

Not urgent for a *policyless* JS sensor, but the ordering assumption that made it
wait has been removed. The original sequencing was: port the engine only after
the policy schema (R10) stabilizes, because the schema is the portable artifact
and Python predicates are not. That assumed the policy had to *travel* to JS.
Stage 1 showed it does not: the decision surface is already a narrow RPC
boundary (`PolicyEngine.evaluate(event) -> Decision`), so a process answering
that call over a socket **is** the single engine and JS only enforces. Only
evaluation moves; rules stay Python closures and the daemon ships the rules
module. R13 therefore no longer depends on R10 — it removes the dependency rather
than pre-empting it. R10 still matters for the caller who wants the policy as a
data file rather than a module.

### What changes

- **Stage 1 (landed): the Python sidecar.** One daemon owns the one engine and
  answers NDJSON frames over a `0600` unix socket in a `0700` directory. It
  refuses to start on an empty rule set — `get_engine()` lazily *creates* an
  empty engine, and an empty engine allows everything, so inheriting that default
  would be a guard that looks healthy while enforcing nothing.
- **Stage 1 (landed): the conformance corpus.** `tests/conformance/events.json`
  is generated from `interlock.testing.conformance`, and a test asserts the file
  matches the generator. It is the interface between the stages: the JS suite
  encodes these events and asserts these verdicts.
- **Stage 2 (landed): the JS client.** A `js/` tree in the monorepo (outside the
  `interlock*` package glob, so it never enters the wheel), speaking the wire
  protocol, plus the MCP interceptor. One npm package (`interlock-guard`,
  subpath exports), `tsc` + `node:test`, zero runtime dependencies. The
  acceptance test is `js/test/corpus.test.ts`: it replays the same
  `tests/conformance/events.json` the Python suite replays (13 cases, 9
  negatives) against a spawned real daemon, and the suite **fails** rather than
  skips if no daemon can start. `evaluate` is async (Node has no synchronous
  unix-socket client), so a synchronous JS tool call cannot be guarded — MCP's
  `callTool` is already async, so the interceptor fits. Nothing about policy
  crosses the language boundary.
- **Stage 3 (landed): the native interceptors and the model-SDK seam.**
  `installInterceptors()` wraps the process's `fs`, `child_process.exec` /
  `execFile`, and `fetch`, deciding each action before the effect under namespaced
  action names (`fs.readFile`, `child_process.exec`, `http.fetch`).
  `guardToolMap` / `guardToolRunner` guard a model SDK's tool seam without
  importing any SDK. Crucially, the facade returns a **coverage report**:
  `uncovered` names the holes no pure-JS patch can reach — ESM named imports and
  `import * as ns` (link-time bindings), the `*Sync` variants and the
  handle-returning openers (`fs.open`, `createReadStream`, `spawn`,
  `http.request`) whose contract is to return a value now, and result-phase rules
  on native effects (an `fs` call can return a `Stats`/`Dirent`/stream, which has
  no wire form). That list is stated, not assumed away: a guard whose coverage is
  a guess is worse than one whose coverage is named.
- The interceptors are the JS-native part; the engine is the part that is not
  reimplemented — it is not a second implementation at all, it is the same
  process.

### Impact

Doubles the addressable integrations with **one** engine rather than two, so the
"two implementations, two release trains" cost the original plan feared does not
materialise. The cost that does: a Python process must be *deployed* beside the
JS agent, and fail-closed turns "is the daemon up?" into a hard availability
dependency. That is the trade, recorded rather than hidden.

### Acceptance

Amended from the original "guarded by the same policy **file**". A JS agent using
an MCP client is guarded by the same engine as the Python equivalent — the
*spirit* of the original criterion — and the shared conformance fixtures pass on
both. It is **not** guarded by the same policy *file*: the policy is a Python
module of closures, not a YAML file, and the literal file-portability claim is
R10's to make, not this one's.

### Risks & dependencies

- **IPC + JSON encoding cost.** Every guarded call gains a round trip and two
  encodes. For high-frequency JS effects (fs/exec on a hot path) this is the item
  that decides whether the sidecar is viable at all, and it is R12's latency
  question, not R13's. Stage 1 measures it rather than assuming it.
- **Protocol drift.** The wire is now a compatibility surface with its own `v`;
  unknown values are refused rather than guessed, so drift fails loudly.
- **A widened trust boundary.** The socket carries cleartext arguments, so its
  path is part of the boundary — `0600` socket, `0700` directory, no core dumps,
  no value logging, digest-only receipts.
- ~~Depends on R10~~ — decoupled by stage 1 (see *Why now*). Depends on R11's
  lessons about which interception points are stable.

---

## R14–R22 · From the agentjail review

These items came from comparing interlock with agentjail
([`research/agentjail-review.md`](research/agentjail-review.md), which holds the
full Problem / What changes / Acceptance / Risks for each). They are recorded
here in short.

| # | What shipped | Evidence |
|---|---|---|
| R14 | `interlock.shell`: a best-effort parser (pipes, chains, wrappers, `sh -c`, substitutions, `find -exec`, interpreter string literals) and an intent classifier. `destructive_command_guard` and `git_credential_guard` gained a parsed path; the git guard's only adds findings, while the destructive guard's may also clear a raw match when the whole command parses as a harmless print; `command_intent_guard` blocks or asks by intent. The destructive guard went from 3 of 12 spellings of a root wipe to 12 of 12 | `tests/test_shell_parse.py`, `tests/test_command_intent_guard.py` |
| R15 | `interlock.posture.attest()` / `require()` and `interlock doctor`; every row of the security model's weakening-settings table maps to a check, enforced by a test | `tests/test_posture.py` |
| R16 | `interlock report`: verified-or-labelled chain, verdict counts, block rate, top rules, "would have blocked", escalations, failures, dropped receipts, latency percentiles | `tests/test_report.py` |
| R17 | Receipts gained `call_id`, `policy_epoch`, `policy_verdict`, `approval`, `outcome`/`enforcer`, `elapsed_us` (omitted when empty, so old chains verify); a failed sink write blocks fail-closed and is reported by a `receipts.dropped` receipt; `FileSink(shared=True)` for several writers | `tests/test_provenance.py` |
| R18 | `interlock install-hook` / `interlock hook` for Claude Code, Codex and Cursor, with the `builtin:coding-agent` pack. Verdicts an agent can't express degrade to deny and are recorded with both verdicts. Claude Code's tool output is withheld or redacted on the way back | `tests/test_hook_adapters.py` |
| R19 | `RemoteEngine(unreachable="deny" \| "degraded" \| "allow")` in Python and Node.js; the sidecar publishes a signed offline fallback policy (`--fallback-policy`). `deny` stays the default | `tests/test_sidecar_fallback.py`, `js/test/fallback.test.ts` |
| R20 | `interlock.credentials`: `{{secret:id}}` placeholders filled after the decision at the enforcement boundary (not as a rule, which a later rule could observe), bounded by action and host, scrubbed from results | `tests/test_credentials.py` |
| R21 | `interlock mcp scan` / `where`: every MCP server in seven clients' configs, risk notes (unpinned packages and images, plain HTTP, inline credentials), and `--emit-policy` | `tests/test_mcp_inventory.py` |
| R22 | `.github/workflows/release.yml` publishes on a `v*` tag with trusted publishing (OIDC — no registry token in the repo) and provenance: PyPI gets a PEP 740 attestation, npm gets `--provenance`, and the tag only reaches a publish step after `scripts/check_release.py` proves it agrees with `pyproject.toml`, `js/package.json`, `web/package.json` and `CHANGELOG.md`, the suite passes, and the wheel installs and reports the same version. Publishing itself waits on the trusted publisher configured on each registry (`docs/guides/releasing.md`) | `tests/test_release_check.py`; `python3 scripts/check_release.py v0.0.1` |

Also adopted from the review: `tool_output_secret_redactor`, a result-phase
detector masking credentials in tool output before the agent reads it.

---

## H1–H7 · From the hoop review

From comparing interlock with hoop's agent sidecar
([`research/hoop-review.md`](research/hoop-review.md)). Network-dependent parts
(its LLM analyzer, OPA, Slack delivery, control plane) were left out.

| # | What shipped | Evidence |
|---|---|---|
| H1 | `interlock.sql`: a dialect-aware lexer and effect classifier (CTE DML, string and comment literals, `$$` bodies, `COPY` direction, `EXPLAIN ANALYZE`), relations with read/write access, flags `unbounded`/`opaque`/`external`/`multi`; `sql_statement_guard` and the `{"sql": ...}` policy condition. `generic` unions three dialects' readings | `tests/test_sql_analysis.py` |
| H2 | `interlock.masking`: 22 entities with checksum validators and context words, strategies `redact`/`mask`/`partial`/keyed `hash`, column and path rules, table shapes; `data_masking_guard` (results) and `pii_argument_guard` (block, ask or mask arguments); `masked` counts in decisions, receipts and reports | `tests/test_masking.py` |
| H3 | `interlock.reviews`: a SQLite review queue, exactly-once release of the identical retry, two clocks, quorum, self-approval refusal; `interlock reviews` CLI and read-only MCP server; the hook adapters use it when an agent can't ask | `tests/test_reviews.py` |
| H4 | `runbook_guard`: typed command templates for shell tools | `tests/test_hoop_detectors.py` |
| H5 | `http_request_guard` (host, path globs, methods, header shapes) and `http_status_guard` | `tests/test_hoop_detectors.py` |
| H6 | `interlock.metrics` (Prometheus text) and `interlock-sidecar --admin` | `tests/test_metrics_admin.py` |
| H7 | `mcp_elicitation_guard`, `result_size_guard` | `tests/test_hoop_detectors.py` |

---

## R23–R30 · From an operational-requirements review

These came from mapping what operators who deploy agents in an enterprise
actually ask for — the questions asked when someone has to run an agent fleet
and answer to a security team — against what interlock ships today. Each is a
capability *gap*, recorded with the capability named and no reference to any
particular vendor. Seven of the eight shipped: R23–R25, R27, R28 and R30 landed
with live smoke tests, and R26 arrived onboard the console rather than as a
separate run. R29 is `partial` — its transport controls ship, but no client
sends the signed scope document, so the scoped engine is not reachable over the
wire. Each one is what makes the detectors usable in a deployment.

| # | Item | Status | Size | Pull |
|---|---|---|---|---|
| R23 | OTLP event export — receipts to a standard collector | `shipped` | M | operational review |
| R24 | Behavioural baseline → policy generator (`interlock learn`) | `shipped` | L | operational review |
| R25 | Token accounting in the budget guard | `shipped` | S | operational review |
| R26 | Console approval workflow | `shipped` | M | operational review |
| R27 | Framework sensor adapters (SDK loops, LiteLLM, CrewAI, ADK) | `shipped` | M | operational review |
| R28 | A2A policy dimension | `shipped` | M | operational review |
| R29 | MCP transport controls + scoped engine over the sidecar | `partial` | M | operational review · no client sends a scope |
| R30 | Upstream-drift detector | `shipped` | M | operational review |

---

## R23 · OTLP event export

**Status:** `shipped` — `interlock.sink.OtlpSink` exports each receipt as an
OTLP/HTTP log record (severity maps the verdict, attributes carry `span_id`).
**Size:** M

### Problem
interlock's audit trail is local: `FileSink`/`InMemorySink` receipts, Prometheus
text at `/metrics`. Operators already send every other signal to a central
collector over OpenTelemetry. A guardrail whose blocks land only in a local
NDJSON file is invisible to the SIEM and the on-call human who is supposed to act
on them. This is the single largest adoption gap: the enforcement is real, the
observation does not reach where decisions are made.

### What changes
A new sink beside `ChainedSink` that exports each receipt as an OTLP log record
over OTLP/HTTP, mapping interlock's fields onto the standard envelope (severity
from the verdict, `service.name`, `span_id` for correlation, and attributes
carrying `action`, `principal`, `policy_id`, `reason`). It writes the local
chained receipt **and** exports it, so tamper-evidence survives when a collector
is the destination. Configuration is through `interlock.install(sink=...)`; there is no
environment variable for the collector. Export is buffered and never blocks a
verdict: a collector outage changes no decision, and the buffer flushes on
recovery.

### Acceptance
With an OTLP receiver on loopback, one guarded call produces exactly one exported
record whose severity maps the verdict and whose attributes carry
action/principal/policy_id/reason, correlating to the local receipt by `span_id`.
A collector outage changes no verdict and the buffered records flush on recovery.
Argument values stay hashed and are never exported; the local chain still
verifies.

### Risks & dependencies
The exporter must never become a second source of truth — it is a projection of
the receipt, not a parallel log. Depends on nothing; benefits from R4's sink
shape.

---

## R24 · Behavioural baseline → policy generator

**Status:** `shipped` — `interlock learn` reads a window of receipt-log entries,
reduces them to the observed-allow envelope, and writes a declarative policy
whose lone rule escalates anything outside it. The draft blocks nothing and
locks nothing, so installing it stays a deliberate act.
**Size:** L

### Problem
Every guardrail here can *observe* — `@monitor()`, `install-hook --monitor`,
`interlock report --monitor` — but nothing turns what was observed into a policy.
The operator must hand-write the rules, and that authoring cost is what stops a
trial from becoming a deployment. The unlock is a policy the machine proposes
from the agent's own traffic.

### What changes
`interlock learn` reads a window of receipts (or a monitor run) and emits a
proposal in the `interlock.policy.declarative` language: the observed tool set,
per-principal action sets, destination hosts, argument shapes and volumes, as
`allow` rules covering the observed envelope, with a chosen posture for
everything else (default: escalate the unseen, block the known-bad). Output is a
file an operator reviews — never auto-enforced.

### Acceptance
From a fixture receipt log, `interlock learn` emits a policy that allows every
observed action and blocks a held-out novel action; the output loads through the
declarative engine and passes its own load-time validation; re-running on
identical input is byte-for-byte identical (deterministic, no timestamps in the
artifact).

### Risks & dependencies
A baseline over-fits the window it learned from. The proposal must show the
counted evidence behind each rule and be visibly a proposal. Depends on R4
(receipts) and R10 (declarative policies) — both shipped.

---

## R25 · Token accounting in the budget guard

**Status:** `shipped` — `interlock.tokens` (a usage ledger) and the
`token_budget_guard` detector; receipts and the report carry per-principal
totals. It meters **input-side (call-phase) text only**: every string in a call
payload is counted, including an expected or observed output embedded under any
key, but the guard does not see or count output from the result phase, so
result-phase usage is unmetered.
**Size:** S

### Problem
`cost_budget_guard` accumulates a number the caller supplies. It cannot see
tokens, so it cannot cap the quantity that actually drives spend. Any operator
who cares about cost asks for token limits first.

### What changes
A dependency-free token estimator (a characters-per-token heuristic with a
per-model correction table) and a `token_budget_guard` that accumulates estimated
input tokens per principal over a window, with bucket and refill semantics. The
cap is input-side only; result-phase output is unmetered. Receipts carry the
estimate so `interlock report` can show token spend next to verdict counts.

### Acceptance
A loop of N calls trips `token_budget_guard` at the configured ceiling; the
estimator's error against a measured sample is reported as a documented bound;
the guard composes with `cost_budget_guard` on the same call without double
counting.

### Risks & dependencies
An estimator is wrong by construction — the error bound is stated, never
presented as metering. Standalone.

---

## R26 · Console approval workflow

**Status:** `shipped` — the console's review-queue surface closes it:
`GET /api/reviews` and `POST /api/reviews/{id}/{approve|reject|revoke}`
(`interlock/console/reviews_api.py`), reachable at `#/reviews`
(`web/src/design/ReviewsScreen.tsx`). Decisions go through `ReviewQueue` exactly
as the CLI does; writes are unlock-gated (a locked approve is refused) and
four-eyes is **opt-in**: it is enforced only when the console is started with
`--four-eyes`, and self-approval is allowed otherwise.
The console polls `GET /api/reviews` every 5 seconds (`POLL_FAST` in
`web/src/store.ts`); the review screen does not use the SSE stream. Live smoke: a
seeded pending review is listed over HTTP, a locked approve is refused, an
unlocked approve releases the identical retry.
(The epic proposed `/api/approvals`; the shipped route is `/api/reviews` — the
same capability under the console's own name.)
**Size:** M

### Problem
`Verdict.ESCALATE`, `interlock.approval` and `interlock.reviews` all exist, but
the only way to release a held call is the CLI (`interlock reviews approve`). An
operator watching a run has no live surface to approve or deny. The human-in-the-
loop capability is real and has no interface.

### What changes
The console gains an approvals screen: the pending escalations read from the
review-queue database, an approve/deny action per row, and live updates reusing
the existing SSE stream. The server stays loopback-only; the only writes are the
queue transitions, and the approve route is opt-in.

### Acceptance
An escalation raised by a run appears on the console within one 5-second poll;
approving it from the console releases the identical retry exactly as
`interlock reviews approve` does; a request whose args digest no longer matches,
or that has expired, cannot be approved (400, not a silent allow).

### Risks & dependencies
An approve route is a write on a read-only-mode server — it must be
loopback-enforced, opt-in, and digest-checked. Depends on H3 (review queue,
shipped) and on the console itself landing on `main`.

---

## R27 · Framework sensor adapters

**Status:** `shipped` — `interlock/interceptors/{openai,litellm,crewai,google_adk}.py`
translate each framework's tool loop into `SensorEvent`s over a shared `_framework` base.
**Size:** M

### Problem
interlock reaches MCP sessions, LangChain tools and a generic tool seam
(`enforce_tool_call`). The most common stacks — a raw model-SDK tool loop,
LiteLLM, CrewAI, Google ADK — need the operator to wire that seam by hand, so
coverage depends on the operator's diligence rather than on installation.

### What changes
Thin adapters beside `interceptors/langchain.py` that wrap each framework's
tool-runner entrypoint through the same `enforce_tool_call` /
`enforce_tool_result` core — no new engine, no new wire format. Each adapter is
optional-import, dependency-free at runtime, and degrades to a reported
"uncovered" state rather than silently passing.

### Acceptance
For each added framework, a test drives a tool call through the framework's
public loop and asserts the interlock verdict is honoured for block, rewrite and
result-check; `interlock doctor` reports which frameworks it detected and which
surfaces remain uncovered.

### Risks & dependencies
Pinning to framework internals risks silent rot — the "uncovered" report and R30
are the mitigation. Depends on the shipped tool-seam core.

---

## R28 · A2A policy dimension

**Status:** `shipped` — `interlock/detectors/a2a_policy.py` and the A2A context in
`interlock/policy/declarative.py` constrain which peers an agent may address (`a2a_send`).
**Size:** M

### Problem
Agent-to-agent traffic is a second call surface with its own trust questions —
which peers are reachable, what their agent cards advertise — and interlock sees
none of it.

### What changes
A policy condition and a small detector family for A2A: matching on agent-card
name, description and advertised skills, plus an allowlist of reachable peers,
evaluated through the same engine and written to the same receipts.

### Acceptance
An A2A call whose peer card is not on the allowlist is blocked with a reason
naming the peer; a card whose advertised skill set changed since its baseline is
flagged; the receipt carries the peer identity in `attributed_to`.

### Risks & dependencies
The A2A wire format is young — pin to the card schema and keep the detector
allowlist-first. Standalone.

---

## R29 · MCP transport controls and scoped engine over the sidecar

**Status:** `partial` — `mcp_transport_guard` ships, and the wire carries an
optional signed scope document (`PROTOCOL_VERSION` 1), parsed and encoded in the
JS client (`js/src/wire.ts`). But no client sets the field: neither
`RemoteEngine` in Python nor the JS client populates `scope` on a request, so a
remote client still cannot ask the daemon for a scoped decision. The transport
half is shipped; the scoped-engine-over-the-sidecar half is not.
**Size:** M

### Problem
Two concrete gaps. (1) interlock pins servers, tools and resources but cannot
refuse a whole transport (HTTP, SSE, stdio), which a deployment policy needs.
(2) `ScopedEngine` — per-tenant policy — is refused by the sidecar, so the
Node.js client cannot use the multi-tenant feature at all.

### What changes
(1) An `mcp_transport_guard` with per-transport allow/deny and a
command/args exception list for stdio. (2) The sidecar wire protocol carries a
scope document, so a remote client receives the same scoped decisions as an
in-process `ScopedEngine`, with the scope document recorded in the receipt's
policy provenance.

### Acceptance
A stdio server not on the exception list is refused before launch; a denied HTTP
transport is refused with a transport-named reason. **Not met:** the Node.js
client resolves the same per-principal decision as the Python `ScopedEngine`
for an identical event — the wire can carry the signed scope document, but no
client sends one.

### Risks & dependencies
The scope document on the wire is new trust surface — signed like the fallback
policy, and the sidecar keeps refusing an unsigned overlay. Depends on R13
(Node client, shipped) and R19 (sidecar, shipped).

---

## R30 · Upstream-drift detector

**Status:** `shipped` — `interlock/drift.py` and the `interlock drift` command diff a
recorded tool listing against the live surface and exit non-zero on any addition,
removal or schema change. A weekly/PR `Drift` workflow diffs the CLI's own command
table; live smoke: a corpus of `[read, write]` vs a live `[read, write, exec]`
reports the added tool and exits 1.
**Size:** M

### Problem
The detectors and adapters encode the current shape of MCP servers, model SDKs
and coding-agent hooks. When those upstream projects move, interlock's coverage
silently rots, and nothing reports it. Today the conformance corpus proves only
today's shape, on the day it was written.

### What changes
Record each covered surface's shape as a corpus (tool-listing fingerprints, SDK
call signatures, hook payload schemas), add an `interlock drift` command that
diffs the corpus against a live surface and reports additions, removals and
changes with a severity, and a CI job that runs it against pinned upstream
versions and emits a report.

### Acceptance
Given a live MCP server whose tool set changed since the corpus was written,
`interlock drift` reports the added and removed tools and exits non-zero; an
unchanged surface exits zero; the report names the exact upstream version tested.

### Risks & dependencies
Noise — the report separates "new capability we do not cover" from "a shape
change that broke us", and files nothing automatically without an operator
threshold.

---

## Explicitly out of scope

**Logit / decoding-layer intervention.** Papers on constrained decoding,
gradient-controlled decoding, and logit-based safety primitives are excluded
deliberately, not overlooked. interlock's premise is that it sits at the process
boundary and sees **real calls with real arguments**; reaching inside the model
would change what the library is, and a half-built version of it would be worse
than none. Recorded here so the boundary is a decision rather than an omission.

---

## Shipped

Landed items keep their entry above, marked `shipped`, so the reasoning behind a
decision stays readable after the decision is taken.

Shipped before this campaign: tri-state verdicts with a fail-closed engine;
`@guard` / `monitor`; run identity; in-process MCP interception and the LangChain
adapter over one `enforce_tool_call` core; hierarchical scopes with
override/union/tombstone merge and the optional native `ScopeTree`; 105 detectors;
BRACE profile IR, `compile_profile`, `Sandbox`, and the unprivileged confinement
backends with reported guarantees; and the scope-store memory benchmark.

Shipped in the `mo/roadmap-partials` campaign — all on `main` as of merge commit
`5d42091`:

- **R1** delegation chains — `Binding.delegated_from`, per-hop attenuation, and
  the `max_delegation_depth` bound (`cc74d5e`).
- **R3** verdict provenance — `Decision.attributed_to`, swept across the detector
  suite with a registry test (`19a6378`).
- **R4** signed execution receipts + append-only sink — `interlock/receipt.py`,
  which also resolves the M4 note at `interceptors/decorator.py:45` (`da42c23`).
- **R6** MCP capability leases (`609a5c4`), server attestation behind an honest
  verifier seam (`12b11ee`), and runtime surface-drift detection (`bb7d0d5`).
- **R7** tool-result sanitization — `SensorEvent.phase`,
  `Decision.modified_result`, `enforce_tool_result` (`9bb51b6`).
- **R8** BRACE escape-resistance suite — the tested token matrix, and the
  unprivileged-egress rung recorded as a measured absence (`de1f971`).

## M0–M3 · The mesh: a shared, open policy network

From [`research/mesh-shared-policy-network.md`](research/mesh-shared-policy-network.md).
Each phase shipped on its own and is usable without the next; usage is in
[`docs/guides/mesh.md`](docs/guides/mesh.md).

| # | Phase | Status | What shipped | Evidence |
|---|---|---|---|---|
| M0 | The commons, no telemetry | `shipped` | `"extends": "mesh:<pack>@<ring>"`; TUF-shaped root/targets/snapshot/timestamp with thresholds, expiry and rollback checks over any mirror; pure-Python Ed25519; rule `status`, ring ceilings, shadow-mode monitor window with timed reload; `interlock mesh keys\|publish\|verify`; `doctor` reports a stale subscription | `tests/test_mesh_ed25519.py`, `tests/test_mesh_metadata.py`, `tests/test_mesh_commons.py` |
| M1 | Counting | `shipped` | `interlock mesh report init\|build\|submit`: rule counts, argument digests (never from redacting rules), false-positive sightings; additive secret shares to two aggregators; consensus with known-catalog check, reporter trust, distinct-org thresholds, demotion, expiry; `mesh_indicator_guard`; `interlock mesh serve` | `tests/test_mesh_report.py`, `tests/test_mesh_aggregate.py`, `tests/test_mesh_consensus.py`, `tests/test_mesh_server.py` |
| M2 | Similarity and the forge | `shipped` | decision observers; LDP fingerprints (redact, dense SimHash, randomised response); campaigns and `mesh_similarity_guard`; `interlock mesh harness` (the R5 false-positive gate); `interlock mesh forge` writing gated proposals | `tests/test_mesh_fingerprint.py`, `tests/test_mesh_harness.py`, `tests/test_mesh_forge.py` |
| M3 | Decentralise | `shipped` | RFC 6962/9162 transparency log with signed checkpoints, inclusion and consistency proofs; subscribers refuse unlogged or rewritten history; `interlock mesh log\|gossip`; `serve --role mirror` peer seeding; per-epoch membership credentials with revocation; `doctor` fails on a split view | `tests/test_mesh_log.py`, `tests/test_mesh_credential.py`, `tests/test_mesh_decentral.py` |
| R2.3 | DAP/Prio3 wire path | `shipped` | `draft-ietf-ppm-dap-20` binary wire and HPKE (RFC 9180 base mode, X25519 / HKDF-SHA256 / AES-128-GCM); `Prio3SumVec` validity proofs (`draft-irtf-cfrg-vdaf-22`, TurboSHAKE128); `interlock mesh dap task\|submit\|collect`; `serve --role dap-leader\|dap-helper` with fixed, non-overlapping batches, a `min_batch_size` floor, proof drops, replay and overlap refusals, idempotent retries; counts consent and the kill switch reused | `tests/test_mesh_vdaf.py`, `tests/test_mesh_hpke.py`, `tests/test_mesh_dap_wire.py`, `tests/test_mesh_dap_task.py`, `tests/test_mesh_dap.py`, `tests/test_mesh_dap_cli.py` |

The five governance questions (root-key custody, aggregator operators, default
reporting posture, data licence, `block` by default) were decided on 2026-10-25 in
[`research/mesh-decisions.md`](research/mesh-decisions.md), and its implementation
lists shipped as five epics on 2026-10-25, each through mini-ork's `framework-edit`
recipe with an Opus review and a hand ship: counts leave a node only as secret
shares with an aggregator batch floor (`83d5b5d`); a community `block` needs an
operator grant, ungranted blocks escalate or run as shadow (`67c9f1e`); the root
stays offline and rotates in a detached-signature ceremony, with `GOVERNANCE.md`
(`4e59446`); reporting is off, local and never retroactive by default (`9cd0545`);
packs are Apache-2.0 and data is CC0-1.0 under `LICENSE-DATA` with a DCO data
warranty (`7e0ce33`, `c8ea610`). The DAP/Prio3 wire path the record names as R2
step 3 shipped in pure Python (`interlock/mesh/dap/`, `interlock/mesh/vdaf/`),
with the official vectors and a local leader↔helper suite rather than a live
third-party interop run. What stays open is operational, not code: recruit the
two non-maintainer root keyholders and an independent DAP operator — no code can
invent people. Known upgrades the modules leave room for: leader-selected
batches and other VDAF types on the DAP path, a semantic embedder behind the
fingerprint API, and zero-knowledge membership in place of issuer-linkable
certificates.
